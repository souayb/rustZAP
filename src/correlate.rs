//! Deterministic cross-tool correlation (Phase 2).
//!
//! - **Rule 1:** SAST SQL (Semgrep) + DAST `active/sqli*` when paths align.
//! - **Rule 2:** Trivy vulnerable package referenced in Semgrep text/paths plus
//!   HTTP(S) `active/*` / `passive/*` observations (unified audits). Links
//!   dependency risk to runtime scanning with informational correlations; may
//!   elevate when the Trivy finding is already **Critical**.

use std::collections::HashSet;

use crate::report::Correlation;
use crate::types::{uuid_v4, Finding, Severity};

/// Apply correlation rules; returns report-level correlation records and
/// mutates `findings` to populate `correlated_with` + optional severity bumps.
pub fn correlate_findings(findings: &mut [Finding]) -> Vec<Correlation> {
    let mut out = correlate_sast_sqli_dast(findings);
    out.extend(correlate_trivy_semgrep_web_dast(findings));
    out.extend(correlate_ad_relay_paths(findings));
    out
}

fn correlate_sast_sqli_dast(findings: &mut [Finding]) -> Vec<Correlation> {
    let mut out = Vec::new();

    let sast_sql: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| is_sast_sql_signal(f))
        .map(|(i, _)| i)
        .collect();

    let dast_sqli: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.plugin.starts_with("active/sqli"))
        .map(|(i, _)| i)
        .collect();

    for &si in &sast_sql {
        let sast = &findings[si];
        let sast_path = http_path(&sast.url);
        let sast_file = file_basename(sast);

        for &di in &dast_sqli {
            let dast = &findings[di];
            if !paths_correlate(sast_path.as_deref(), sast_file.as_deref(), &dast.url) {
                continue;
            }

            let id = format!("corr-{}", uuid_v4());
            let sast_id = findings[si].id.clone();
            let dast_id = findings[di].id.clone();

            findings[si].correlated_with.push(dast_id.clone());
            findings[di].correlated_with.push(sast_id.clone());

            if findings[di].severity < Severity::Critical {
                findings[di].severity = Severity::Critical;
            }

            out.push(Correlation {
                id,
                finding_ids: vec![sast_id, dast_id],
                reason: "SAST SQL sink pattern corroborated by DAST SQLi finding on the same path"
                    .to_string(),
                elevated_severity: Some(Severity::Critical),
            });
        }
    }

    out
}

/// Trivy package appears in Semgrep finding text/path and there is at least one
/// web DAST observation (implies the audit hit a deployed surface).
fn correlate_trivy_semgrep_web_dast(findings: &mut [Finding]) -> Vec<Correlation> {
    let mut out = Vec::new();

    let dast_indices: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| is_web_dast(f))
        .map(|(i, _)| i)
        .collect();

    if dast_indices.is_empty() {
        return out;
    }

    let trivy_idx: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.plugin == "sca/trivy")
        .map(|(i, _)| i)
        .collect();

    let semgrep_idx: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.plugin == "sast/semgrep")
        .map(|(i, _)| i)
        .collect();

    let mut pair_seen: HashSet<(String, String)> = HashSet::new();

    for &ti in &trivy_idx {
        let Some(pkg) = trivy_pkg_name_chomped(&findings[ti]) else {
            continue;
        };
        if pkg.len() < 2 {
            continue;
        }

        for &si in &semgrep_idx {
            if !semgrep_mentions_pkg(&findings[si], &pkg) {
                continue;
            }

            let t_id = findings[ti].id.clone();
            let s_id = findings[si].id.clone();
            if !pair_seen.insert((t_id.clone(), s_id.clone())) {
                continue;
            }

            // One representative web finding (first) keeps the group small.
            let di = dast_indices[0];
            let d_id = findings[di].id.clone();

            let id = format!("corr-{}", uuid_v4());
            let trivy_crit = findings[ti].severity == Severity::Critical;

            findings[ti].correlated_with.push(s_id.clone());
            findings[ti].correlated_with.push(d_id.clone());
            findings[si].correlated_with.push(t_id.clone());
            findings[si].correlated_with.push(d_id.clone());
            findings[di].correlated_with.push(t_id.clone());
            findings[di].correlated_with.push(s_id.clone());

            if trivy_crit && findings[di].severity < Severity::High {
                findings[di].severity = Severity::High;
            }

            out.push(Correlation {
                id,
                finding_ids: vec![t_id, s_id, d_id],
                reason:
                    "Trivy flagged a vulnerable package that Semgrep touches in-repo; runtime scan observed the app"
                        .to_string(),
                elevated_severity: if trivy_crit {
                    Some(Severity::High)
                } else {
                    None
                },
            });
        }
    }

    out
}

/// **AD relay-path rule.** When a single host shows two or more relay-enabling
/// weaknesses (LDAP signing off, LDAP channel binding off, NTLMv1, NTLM signing
/// off), consolidate them into one elevated "NTLM relay exposure on <host>"
/// finding — the attack-path view instead of four unrelated findings.
fn correlate_ad_relay_paths(findings: &mut [Finding]) -> Vec<Correlation> {
    use std::collections::BTreeMap;

    let mut by_host: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, f) in findings.iter().enumerate() {
        if is_ad_relay_enabler(&f.plugin) {
            if let Some(host) = ad_host(&f.url) {
                by_host.entry(host).or_default().push(i);
            }
        }
    }

    let mut out = Vec::new();
    for (host, idxs) in by_host {
        if idxs.len() < 2 {
            continue;
        }
        let ids: Vec<String> = idxs.iter().map(|&i| findings[i].id.clone()).collect();
        for &i in &idxs {
            for id in &ids {
                if *id != findings[i].id {
                    findings[i].correlated_with.push(id.clone());
                }
            }
        }
        // Critical when signing AND channel binding are both off (classic
        // relay-to-LDAP path); High otherwise.
        let has_signing = idxs
            .iter()
            .any(|&i| findings[i].plugin == "ad/ldap-signing");
        let has_cbt = idxs
            .iter()
            .any(|&i| findings[i].plugin == "ad/ldap-channel-binding");
        let elevated = if has_signing && has_cbt {
            Severity::Critical
        } else {
            Severity::High
        };
        for &i in &idxs {
            if findings[i].severity < elevated {
                findings[i].severity = elevated.clone();
            }
        }
        out.push(Correlation {
            id: format!("corr-{}", uuid_v4()),
            finding_ids: ids,
            reason: format!(
                "NTLM relay exposure on {host}: multiple relay-enabling weaknesses on the same host                  form an actionable attack path"
            ),
            elevated_severity: Some(elevated),
        });
    }
    out
}

fn is_ad_relay_enabler(plugin: &str) -> bool {
    matches!(
        plugin,
        "ad/ldap-signing" | "ad/ldap-channel-binding" | "ad/ntlmv1" | "ad/ntlm-signing"
    )
}

/// Host portion of an `ldap://HOST` finding url.
fn ad_host(url: &str) -> Option<String> {
    url.strip_prefix("ldap://")
        .map(|h| h.split(['/', ':']).next().unwrap_or(h).to_string())
        .filter(|h| !h.is_empty())
}

fn trivy_pkg_name_chomped(f: &Finding) -> Option<String> {
    if f.plugin != "sca/trivy" {
        return None;
    }
    let ev = f.evidence.as_deref()?;
    let mut it = ev.split_whitespace();
    it.next()?; // CVE / id token
    let pkg_at_ver = it.next()?;
    let pkg = pkg_at_ver.split('@').next()?.trim();
    if pkg.is_empty() {
        return None;
    }
    Some(pkg.to_ascii_lowercase())
}

fn semgrep_mentions_pkg(f: &Finding, pkg_lc: &str) -> bool {
    let mut blob = format!(
        "{} {} {} {}",
        f.title,
        f.description,
        f.parameter.as_deref().unwrap_or(""),
        f.evidence.as_deref().unwrap_or("")
    );
    if let Some(loc) = &f.location {
        blob.push(' ');
        blob.push_str(&loc.file);
    }
    blob.to_ascii_lowercase().contains(pkg_lc)
}

fn is_web_dast(f: &Finding) -> bool {
    if !(f.plugin.starts_with("active/") || f.plugin.starts_with("passive/")) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(&f.url) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https")
}

fn is_sast_sql_signal(f: &Finding) -> bool {
    if f.plugin != "sast/semgrep" {
        return false;
    }
    let hay = format!(
        "{} {} {}",
        f.parameter.as_deref().unwrap_or(""),
        f.title,
        f.description
    )
    .to_ascii_lowercase();
    hay.contains("sql") || hay.contains("sqli") || hay.contains("injection")
}

fn http_path(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() == "http" || parsed.scheme() == "https" {
        let path = parsed.path();
        if path.is_empty() {
            Some("/".to_string())
        } else {
            Some(path.to_string())
        }
    } else {
        None
    }
}

fn file_basename(f: &Finding) -> Option<String> {
    if let Some(loc) = &f.location {
        return std::path::Path::new(&loc.file)
            .file_name()
            .map(|s| s.to_string_lossy().to_string());
    }
    if f.url.starts_with("file://") {
        let path = f.url.trim_start_matches("file://");
        let path = path.split('#').next().unwrap_or(path);
        return std::path::Path::new(path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string());
    }
    None
}

fn file_stem(name: &str) -> Option<String> {
    std::path::Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
}

const GENERIC_STEMS: &[&str] = &[
    "index", "main", "mod", "lib", "app", "default", "util", "utils", "server", "common",
];

fn paths_correlate(sast_http_path: Option<&str>, sast_file: Option<&str>, dast_url: &str) -> bool {
    if let Some(sp) = sast_http_path {
        if let Some(dp) = http_path(dast_url) {
            return sp == dp;
        }
    }
    if let Some(file) = sast_file {
        let lower = dast_url.to_ascii_lowercase();
        if lower.contains(&file.to_ascii_lowercase()) {
            return true;
        }
        if let Some(stem) = file_stem(file) {
            let stem_lc = stem.to_ascii_lowercase();
            if !stem.is_empty() && !GENERIC_STEMS.contains(&stem_lc.as_str()) {
                if lower.contains(&stem_lc) {
                    return true;
                }
                if let Some(dp) = http_path(dast_url) {
                    return dp
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .any(|seg| seg.eq_ignore_ascii_case(&stem));
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Finding;

    fn mk(id: &str, plugin: &str, url: &str, sev: Severity, param: Option<&str>) -> Finding {
        let mut f = Finding::new("t", sev, url, "d", "s", plugin);
        f.id = id.to_string();
        if let Some(p) = param {
            f = f.with_parameter(p);
        }
        f
    }

    #[test]
    fn ad_relay_paths_consolidate_per_host() {
        let mut findings = vec![
            mk(
                "a1",
                "ad/ldap-signing",
                "ldap://dc01.corp.local",
                Severity::High,
                None,
            ),
            mk(
                "a2",
                "ad/ldap-channel-binding",
                "ldap://dc01.corp.local",
                Severity::High,
                None,
            ),
            mk(
                "a3",
                "ad/ntlmv1",
                "ldap://other.corp.local",
                Severity::High,
                None,
            ),
        ];
        let corr = correlate_findings(&mut findings);
        let ad_corr: Vec<_> = corr
            .iter()
            .filter(|c| c.reason.contains("relay exposure"))
            .collect();
        assert_eq!(ad_corr.len(), 1, "one host has 2+ enablers");
        assert_eq!(ad_corr[0].elevated_severity, Some(Severity::Critical));
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].correlated_with.contains(&"a2".to_string()));
        assert!(
            findings[2].correlated_with.is_empty(),
            "lone enabler is not correlated"
        );
    }

    #[test]
    fn correlates_sast_sql_with_dast_sqli_on_same_path() {
        let mut findings = vec![
            mk(
                "s1",
                "sast/semgrep",
                "file:///repo/src/api.py",
                Severity::High,
                Some("python.lang.security.sql-injection"),
            ),
            mk(
                "d1",
                "active/sqli-error",
                "https://app.example.com/api/users?id=1",
                Severity::High,
                None,
            ),
        ];
        // Make paths match via filename in URL
        findings[0].location = Some(crate::types::CodeLocation {
            file: "/repo/src/api.py".to_string(),
            line_start: 1,
            line_end: None,
        });

        let correlations = correlate_findings(&mut findings);
        assert_eq!(correlations.len(), 1);
        assert!(findings[1].correlated_with.contains(&"s1".to_string()));
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    #[test]
    fn no_correlation_when_paths_unrelated() {
        let mut findings = vec![
            mk(
                "s1",
                "sast/semgrep",
                "file:///repo/other.py",
                Severity::High,
                Some("python.lang.security.sql-injection"),
            ),
            mk(
                "d1",
                "active/sqli-error",
                "https://app.example.com/admin",
                Severity::High,
                None,
            ),
        ];
        let correlations = correlate_findings(&mut findings);
        assert!(correlations.is_empty());
    }

    #[test]
    fn correlates_trivy_pkg_with_semgrep_when_web_dast_present() {
        let mut t = mk(
            "t1",
            "sca/trivy",
            "file://Cargo.lock",
            Severity::High,
            Some("CVE-2024-1234"),
        );
        t = t.with_evidence("CVE-2024-1234 openssl@1.1.1");

        let mut s = mk(
            "s1",
            "sast/semgrep",
            "file:///repo/src/ssl.rs",
            Severity::Medium,
            Some("rules.openssl"),
        );
        s.title = "openssl usage".to_string();

        let p = mk(
            "p1",
            "passive/missing-headers",
            "https://app.example.com/",
            Severity::Low,
            None,
        );

        let mut findings = vec![t, s, p];
        let correlations = correlate_findings(&mut findings);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].finding_ids.len(), 3);
        assert!(findings[0].correlated_with.contains(&"p1".to_string()));
    }

    #[test]
    fn no_trivy_semgrep_correlation_without_web_dast() {
        let mut t = mk(
            "t1",
            "sca/trivy",
            "file://Cargo.lock",
            Severity::High,
            Some("CVE-2024-1234"),
        );
        t = t.with_evidence("CVE-2024-1234 openssl@1.1.1");

        let mut s = mk(
            "s1",
            "sast/semgrep",
            "file:///repo/src/ssl.rs",
            Severity::Medium,
            Some("rules.openssl"),
        );
        s.title = "openssl usage".to_string();

        let mut findings = vec![t, s];
        let correlations = correlate_findings(&mut findings);
        assert!(correlations.is_empty());
    }
}
