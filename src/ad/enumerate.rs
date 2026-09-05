//! Domain computer inventory (`--audit`). Emits one Info finding per computer so
//! the enumerated attack surface is visible in the report, and returns the host
//! list the per-host checks (LDAP posture, NTLM) run against.

use crate::types::{Confidence, Finding, Severity};

use super::host_url;
use super::probe::ComputerRecord;

/// Build inventory findings from enumerated computers.
pub fn computer_findings(computers: &[ComputerRecord]) -> Vec<Finding> {
    computers
        .iter()
        .map(|c| {
            let host = c.dns_host.clone().unwrap_or_else(|| c.sam.clone());
            let os = c.os.as_deref().unwrap_or("unknown OS");
            Finding::new(
                format!("Domain computer: {host}"),
                Severity::Info,
                host_url(&host),
                format!("Enumerated domain computer `{}` ({os}).", c.sam),
                "Informational inventory from LDAP; review the per-host relay findings.",
                "ad/computer",
            )
            .with_source_tool("rustzap-ad")
            .with_confidence(Confidence::Firm)
        })
        .collect()
}

/// Host targets to run per-host checks against (dNSHostName, else sAMAccountName).
pub fn computer_targets(computers: &[ComputerRecord]) -> Vec<String> {
    computers
        .iter()
        .map(|c| c.dns_host.clone().unwrap_or_else(|| c.sam.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_info_per_computer_and_targets() {
        let computers = vec![
            ComputerRecord {
                sam: "DC01$".into(),
                dns_host: Some("dc01.corp.local".into()),
                os: Some("Windows Server 2022".into()),
            },
            ComputerRecord {
                sam: "WS1$".into(),
                dns_host: None,
                os: None,
            },
        ];
        let f = computer_findings(&computers);
        assert_eq!(f.len(), 2);
        assert!(f
            .iter()
            .all(|x| x.plugin == "ad/computer" && x.severity == Severity::Info));
        assert_eq!(f[0].url, "ldap://dc01.corp.local");
        assert_eq!(
            computer_targets(&computers),
            vec!["dc01.corp.local", "WS1$"]
        );
    }
}
