//! Production Safety & "Do No Harm" Guardrails (Government & Critical Infrastructure).
//!
//! Enforces non-destructive scan modes, adaptive circuit breaking, request rate
//! throttling, and emergency aborts to prevent disruption to sensitive systems.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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

        if status >= 500 && status <= 599 {
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

/// Verify whether an HTTP request complies with safe non-destructive policies.
pub fn is_request_safe(
    method: &str,
    payload: Option<&str>,
    policy: &SafetyPolicy,
) -> Result<(), &'static str> {
    let method_upper = method.to_uppercase();

    if policy.read_only_safe {
        if !matches!(method_upper.as_str(), "GET" | "HEAD" | "OPTIONS") {
            return Err(
                "Mutating HTTP verb (POST/PUT/DELETE/PATCH) blocked by --read-only-safe policy",
            );
        }
    }

    if !policy.attack_mode {
        if let Some(body) = payload {
            let body_upper = body.to_uppercase();
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
                if body_upper.contains(pattern) {
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
}
