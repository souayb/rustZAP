//! LDAP relay-posture verdicts (signing + channel binding) from an
//! [`LdapPosture`] observation. Pure — unit-tested without a live DC.

use crate::types::{Confidence, Finding, Severity};

use super::probe::{LdapPosture, Protection};
use super::{host_url, OWASP_AUTH};

/// Turn an LDAP posture observation for `host` into findings.
///
/// Only `Protection::NotEnforced` produces a finding; `Unknown` is silent so we
/// never assert a weakness we could not actually observe.
pub fn posture_findings(host: &str, posture: &LdapPosture) -> Vec<Finding> {
    let mut out = Vec::new();
    let url = host_url(host);

    if posture.signing == Protection::NotEnforced {
        out.push(
            Finding::new(
                format!("LDAP signing not required on {host}"),
                Severity::High,
                url.clone(),
                "The domain controller accepted an unsigned LDAP bind, so LDAP signing is \
                 not enforced. An attacker who relays NTLM authentication to LDAP can act as \
                 the coerced account (e.g. to grant RBCD or DCSync rights).",
                "Enforce LDAP server signing via the \"Domain controller: LDAP server signing \
                 requirements\" policy (Require signing) and deploy it to all DCs.",
                "ad/ldap-signing",
            )
            .with_source_tool("rustzap-ad")
            .with_confidence(Confidence::Firm)
            .with_cwe(294)
            .with_owasp(OWASP_AUTH),
        );
    }

    if posture.channel_binding == Protection::NotEnforced {
        out.push(
            Finding::new(
                format!("LDAP channel binding (EPA) not enforced on {host}"),
                Severity::High,
                url,
                "LDAPS did not enforce channel binding tokens (EPA/CBT), so NTLM authentication \
                 can be relayed to LDAPS even when TLS is in use.",
                "Set the \"Domain controller: LDAP server channel binding token requirements\" \
                 policy to \"Always\" once all clients support it.",
                "ad/ldap-channel-binding",
            )
            .with_source_tool("rustzap-ad")
            .with_confidence(Confidence::Firm)
            .with_cwe(294)
            .with_owasp(OWASP_AUTH),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posture(s: Protection, cb: Protection) -> LdapPosture {
        LdapPosture {
            signing: s,
            channel_binding: cb,
        }
    }

    #[test]
    fn not_enforced_signing_emits_high() {
        let f = posture_findings(
            "DC01.corp.local",
            &posture(Protection::NotEnforced, Protection::Unknown),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].plugin, "ad/ldap-signing");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].url, "ldap://DC01.corp.local");
        assert_eq!(f[0].source_tool.as_deref(), Some("rustzap-ad"));
    }

    #[test]
    fn enforced_and_unknown_are_silent() {
        assert!(
            posture_findings("DC01", &posture(Protection::Enforced, Protection::Enforced))
                .is_empty()
        );
        assert!(
            posture_findings("DC01", &posture(Protection::Unknown, Protection::Unknown)).is_empty()
        );
    }

    #[test]
    fn both_not_enforced_emits_two() {
        let f = posture_findings(
            "DC01",
            &posture(Protection::NotEnforced, Protection::NotEnforced),
        );
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|x| x.plugin == "ad/ldap-channel-binding"));
    }
}
