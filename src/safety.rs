//! Production Safety & "Do No Harm" Guardrails (Government & Critical Infrastructure).
//!
//! Enforces non-destructive scan modes, adaptive circuit breaking, request rate
//! throttling, and emergency aborts to prevent disruption to sensitive systems.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex as AsyncMutex;

/// Safety policy applied across scanning and agent execution.
#[derive(Debug, Clone)]
pub struct SafetyPolicy {
    /// Disallow mutating HTTP verbs and destructive SQL/OS commands.
    pub read_only_safe: bool,
    /// Explicit full active/attack mode for lab/development penetration testing.
    pub attack_mode: bool,
    /// Maximum requests per second (0 = unlimited).
    pub max_rps: u32,
    /// Max acceptable response latency before throttling (ms).
    pub latency_throttle_threshold_ms: u64,
    /// Latency spike abort threshold (ms).
    pub latency_abort_threshold_ms: u64,
    /// Error rate threshold (e.g., 0.05 = 5% 5xx errors) before tripping circuit breaker.
    pub max_error_rate: f64,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            read_only_safe: false,
            attack_mode: false,
            max_rps: 50,
            latency_throttle_threshold_ms: 2000,
            latency_abort_threshold_ms: 8000,
            max_error_rate: 0.05,
        }
    }
}

impl SafetyPolicy {
    /// Factory for full attack testing in dedicated development / lab testbeds.
    pub fn attack_mode_policy() -> Self {
        Self {
            read_only_safe: false,
            attack_mode: true,
            max_rps: 0,
            latency_throttle_threshold_ms: 10000,
            latency_abort_threshold_ms: 30000,
            max_error_rate: 0.50,
        }
    }

    /// Build a policy from CLI flags. `--attack` wins over defaults; `--read-only-safe`
    /// and `--max-rps` still apply on top when set.
    pub fn from_flags(attack: bool, read_only_safe: bool, max_rps: Option<u32>) -> Self {
        let mut policy = if attack {
            Self::attack_mode_policy()
        } else {
            Self::default()
        };
        if read_only_safe {
            policy.read_only_safe = true;
            policy.attack_mode = false;
        }
        if let Some(rps) = max_rps {
            policy.max_rps = rps;
        }
        policy
    }
}

/// Display an explicit warning when Attack Mode is invoked.
pub fn print_attack_mode_warning(target: &str) {
    use colored::*;
    eprintln!(
        "\n{}",
        "================================================================================"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        " ⚠️  ATTACK MODE ACTIVATED (LAB & DEVELOPMENT TESTING ONLY) ⚠️"
            .on_red()
            .white()
            .bold()
    );
    eprintln!(
        "{}",
        "================================================================================"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  WARNING: Full active, mutating, and intrusive testing is enabled."
            .yellow()
            .bold()
    );
    eprintln!("  Target: {}", target.bright_cyan().bold());
    eprintln!(
        "{}",
        "  This mode will send POST/PUT/DELETE mutations, deep injection payloads,".yellow()
    );
    eprintln!(
        "{}",
        "  and state-altering verification requests to the target.".yellow()
    );
    eprintln!();
    eprintln!(
        "{}",
        "  [!] DO NOT USE AGAINST PRODUCTION OR UNCONSENTING TARGETS."
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "================================================================================\n"
            .bright_red()
            .bold()
    );
}

/// Adaptive circuit breaker tracking target application health.
#[derive(Debug, Default)]
pub struct CircuitBreaker {
    total_requests: AtomicUsize,
    error_5xx_count: AtomicUsize,
    total_latency_ms: AtomicU64,
    tripped: std::sync::atomic::AtomicBool,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record request execution metrics.
    pub fn record_response(&self, status: u16, latency_ms: u64, policy: &SafetyPolicy) -> bool {
        let total = self.total_requests.fetch_add(1, Ordering::SeqCst) + 1;
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::SeqCst);

        if (500..=599).contains(&status) {
            let errors = self.error_5xx_count.fetch_add(1, Ordering::SeqCst) + 1;
            if total >= 20 {
                let error_rate = errors as f64 / total as f64;
                if error_rate > policy.max_error_rate {
                    self.tripped.store(true, Ordering::SeqCst);
                    tracing::error!(
                        "CIRCUIT BREAKER TRIPPED: Target 5xx error rate ({:.1}%) exceeds safety threshold ({:.1}%)",
                        error_rate * 100.0,
                        policy.max_error_rate * 100.0
                    );
                    return false;
                }
            }
        }

        if latency_ms >= policy.latency_abort_threshold_ms {
            self.tripped.store(true, Ordering::SeqCst);
            tracing::error!(
                "CIRCUIT BREAKER TRIPPED: Target response latency ({}ms) exceeds safety abort threshold ({}ms)",
                latency_ms,
                policy.latency_abort_threshold_ms
            );
            return false;
        }

        true
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::SeqCst);
        self.error_5xx_count.store(0, Ordering::SeqCst);
        self.total_latency_ms.store(0, Ordering::SeqCst);
        self.tripped.store(false, Ordering::SeqCst);
    }
}

/// Shared HTTP safety gate: policy checks, RPS throttle, circuit breaker.
#[derive(Debug)]
pub struct HttpSafetyGate {
    pub policy: SafetyPolicy,
    breaker: CircuitBreaker,
    /// Timestamps of recent request starts (for RPS window).
    recent: AsyncMutex<Vec<Instant>>,
}

impl HttpSafetyGate {
    pub fn new(policy: SafetyPolicy) -> Self {
        Self {
            policy,
            breaker: CircuitBreaker::new(),
            recent: AsyncMutex::new(Vec::new()),
        }
    }

    pub fn shared(policy: SafetyPolicy) -> Arc<Self> {
        Arc::new(Self::new(policy))
    }

    pub fn is_tripped(&self) -> bool {
        self.breaker.is_tripped()
    }

    /// Reject if circuit is open or the request violates policy; then wait for RPS.
    pub async fn before_request(
        &self,
        method: &str,
        body: Option<&str>,
    ) -> Result<(), SafetyAbort> {
        if self.breaker.is_tripped() {
            return Err(SafetyAbort::CircuitOpen);
        }
        is_request_safe(method, body, &self.policy).map_err(SafetyAbort::Policy)?;
        self.wait_for_rps().await;
        Ok(())
    }

    /// Reject if circuit is open or either URL/body violates policy; then wait for RPS.
    pub async fn before_url_request(
        &self,
        method: &str,
        url: &str,
        body: Option<&str>,
    ) -> Result<(), SafetyAbort> {
        if self.breaker.is_tripped() {
            return Err(SafetyAbort::CircuitOpen);
        }
        is_request_safe(method, Some(url), &self.policy).map_err(SafetyAbort::Policy)?;
        if let Some(b) = body {
            is_request_safe(method, Some(b), &self.policy).map_err(SafetyAbort::Policy)?;
        }
        self.wait_for_rps().await;
        Ok(())
    }

    /// Record metrics; returns `Err(CircuitOpen)` if the breaker just tripped.
    pub fn after_response(&self, status: u16, latency_ms: u64) -> Result<(), SafetyAbort> {
        if !self
            .breaker
            .record_response(status, latency_ms, &self.policy)
            || self.breaker.is_tripped()
        {
            return Err(SafetyAbort::CircuitOpen);
        }
        Ok(())
    }

    async fn wait_for_rps(&self) {
        let max = self.policy.max_rps;
        if max == 0 {
            return;
        }
        let window = Duration::from_secs(1);
        loop {
            let mut recent = self.recent.lock().await;
            let now = Instant::now();
            recent.retain(|t| now.duration_since(*t) < window);
            if (recent.len() as u32) < max {
                recent.push(now);
                return;
            }
            let oldest = recent.first().copied().unwrap_or(now);
            let sleep_for = window
                .checked_sub(now.duration_since(oldest))
                .unwrap_or(Duration::from_millis(5))
                .max(Duration::from_millis(1));
            drop(recent);
            tokio::time::sleep(sleep_for).await;
        }
    }
}

/// Why an HTTP send was aborted by the safety gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyAbort {
    Policy(&'static str),
    CircuitOpen,
}

impl std::fmt::Display for SafetyAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyAbort::Policy(msg) => write!(f, "{msg}"),
            SafetyAbort::CircuitOpen => write!(
                f,
                "circuit breaker open — target unhealthy; aborting further HTTP"
            ),
        }
    }
}

impl std::error::Error for SafetyAbort {}

/// Verify whether an HTTP request complies with safe non-destructive policies.
pub fn is_request_safe(
    method: &str,
    payload: Option<&str>,
    policy: &SafetyPolicy,
) -> Result<(), &'static str> {
    let method_upper = method.to_uppercase();

    if policy.read_only_safe && !matches!(method_upper.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return Err(
            "Mutating HTTP verb (POST/PUT/DELETE/PATCH) blocked by --read-only-safe policy",
        );
    }

    if !policy.attack_mode {
        if let Some(text) = payload {
            let text_upper = text.to_uppercase().replace('+', " ").replace("%20", " ");
            let destructive_patterns = [
                "DROP TABLE",
                "DROP DATABASE",
                "TRUNCATE TABLE",
                "DELETE FROM",
                "SHUTDOWN",
                "RM -RF",
                "DEL /F /S /Q",
                "FORMAT C:",
            ];

            for pattern in destructive_patterns {
                if text_upper.contains(pattern) {
                    return Err("Destructive command/SQL payload blocked by safety guardrail");
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_only_safety_filter() {
        let policy = SafetyPolicy {
            read_only_safe: true,
            ..Default::default()
        };

        assert!(is_request_safe("GET", None, &policy).is_ok());
        assert!(is_request_safe("HEAD", None, &policy).is_ok());
        assert!(is_request_safe("POST", None, &policy).is_err());
        assert!(is_request_safe("DELETE", None, &policy).is_err());
    }

    #[test]
    fn test_destructive_payload_blocked() {
        let policy = SafetyPolicy::default();
        assert!(is_request_safe("GET", Some("1' OR '1'='1"), &policy).is_ok());
        assert!(is_request_safe("POST", Some("1'; DROP TABLE users;--"), &policy).is_err());
        assert!(is_request_safe("POST", Some("; rm -rf / ;"), &policy).is_err());
    }

    #[test]
    fn test_circuit_breaker_trips_on_5xx_spike() {
        let cb = CircuitBreaker::new();
        let policy = SafetyPolicy {
            max_error_rate: 0.10,
            ..Default::default()
        };

        // 20 requests with 5 errors (25% error rate)
        for _ in 0..15 {
            assert!(cb.record_response(200, 50, &policy));
        }
        for _ in 0..5 {
            cb.record_response(500, 50, &policy);
        }

        assert!(cb.is_tripped());
    }

    #[test]
    fn from_flags_attack_and_read_only() {
        let p = SafetyPolicy::from_flags(true, false, Some(10));
        assert!(p.attack_mode);
        assert_eq!(p.max_rps, 10);

        let ro = SafetyPolicy::from_flags(true, true, None);
        assert!(ro.read_only_safe);
        assert!(!ro.attack_mode);
    }

    #[tokio::test]
    async fn gate_blocks_post_when_read_only() {
        let gate = HttpSafetyGate::new(SafetyPolicy {
            read_only_safe: true,
            ..Default::default()
        });
        assert!(gate.before_request("GET", None).await.is_ok());
        let err = gate.before_request("POST", Some("x")).await.unwrap_err();
        assert!(matches!(err, SafetyAbort::Policy(_)));
    }
}
