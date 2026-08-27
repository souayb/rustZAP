//! Ghost-SPN detection: a `servicePrincipalName` whose host has no DNS record is
//! a potential relay/interception path (an attacker who can register that name
//! receives authentication intended for the service).

use std::collections::BTreeSet;

use crate::types::{Confidence, Finding, Severity};

use super::probe::{DnsResolver, SpnRecord};
use super::{host_url, OWASP_AUTH};

/// Parse the host portion out of an SPN string.
///
/// SPNs look like `service/host[:port][/name]`, e.g.
/// `MSSQLSvc/db01.corp.local:1433` or `HOST/DC01`. Returns the host lowercased.
pub fn spn_host(spn: &str) -> Option<String> {
    let after = spn.split_once('/')?.1;
    let host = after
        .split(['/', ':'])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Build ghost-SPN findings from the set of SPN records whose host did not
/// resolve. One finding per distinct unresolved host. Pure (no I/O).
pub fn ghost_findings(unresolved: &[&SpnRecord]) -> Vec<Finding> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for rec in unresolved {
        if !seen.insert(rec.host.clone()) {
            continue;
        }
        out.push(
            Finding::new(
                format!("Ghost SPN: {} has no DNS record", rec.host),
                Severity::Medium,
                host_url(&rec.host),
                format!(
                    "The service principal name `{}` (owner `{}`) points at a host that does not \
                     resolve in DNS. An attacker able to register or claim that hostname could \
                     receive Kerberos/NTLM authentication intended for the service.",
                    rec.spn, rec.owner
                ),
                "Remove stale SPNs for decommissioned hosts, or create the missing DNS record so \
                 the name cannot be claimed by an attacker.",
                "ad/ghost-spn",
            )
            .with_source_tool("rustzap-ad")
            .with_parameter(rec.spn.clone())
            .with_confidence(Confidence::Firm)
            .with_cwe(294)
            .with_owasp(OWASP_AUTH),
        );
    }
    out
}

/// Async orchestration: resolve every distinct SPN host, then classify the
/// unresolved ones. Kept thin so the classification stays testable.
pub async fn detect(spns: &[SpnRecord], dns: &dyn DnsResolver) -> Vec<Finding> {
    let mut checked: BTreeSet<String> = BTreeSet::new();
    let mut unresolved: Vec<&SpnRecord> = Vec::new();
    for rec in spns {
        if !checked.insert(rec.host.clone()) {
            continue;
        }
        if !dns.resolves(&rec.host).await {
            unresolved.push(rec);
        }
    }
    ghost_findings(&unresolved)
}

#[cfg(test)]
mod tests {
    use super::super::probe::mock::MockDns;
    use super::*;

    fn rec(spn: &str) -> SpnRecord {
        SpnRecord {
            spn: spn.to_string(),
            host: spn_host(spn).unwrap(),
            owner: "svc$".to_string(),
        }
    }

    #[test]
    fn parses_various_spn_shapes() {
        assert_eq!(
            spn_host("MSSQLSvc/db01.corp.local:1433").as_deref(),
            Some("db01.corp.local")
        );
        assert_eq!(spn_host("HOST/DC01").as_deref(), Some("dc01"));
        assert_eq!(
            spn_host("HTTP/web.corp.local/corp.local").as_deref(),
            Some("web.corp.local")
        );
        assert_eq!(spn_host("bogus"), None);
    }

    #[tokio::test]
    async fn flags_only_unresolved_hosts_once() {
        let spns = vec![
            rec("MSSQLSvc/db01.corp.local:1433"),
            rec("HOST/db01.corp.local"), // same host, must not double-count
            rec("HTTP/gone.corp.local"),
        ];
        let dns = MockDns::with(&["db01.corp.local"]);
        let findings = detect(&spns, &dns).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ad/ghost-spn");
        assert_eq!(findings[0].url, "ldap://gone.corp.local");
    }
}
