//! Observation types and I/O traits for the Active Directory detector.
//!
//! All network I/O sits behind these traits so the verdict logic in the sibling
//! modules (`ldap`, `spn`, `ntlm`, `enumerate`) can be unit-tested with in-memory
//! mocks and **no live domain controller** — the same "pure core" discipline the
//! rest of RustZAP uses.

use anyhow::Result;
use async_trait::async_trait;

/// Whether a relay-relevant protection (LDAP/NTLM signing, channel binding) is
/// enforced by the target, as far as we could determine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// The target requires the protection — not relay-exposed on this vector.
    Enforced,
    /// The target does not require it — a potential relay target.
    NotEnforced,
    /// Could not be determined; no finding is emitted for `Unknown`.
    Unknown,
}

/// A `servicePrincipalName` value pulled from the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpnRecord {
    pub spn: String,
    /// Host portion parsed out of the SPN (e.g. `db01.corp.local`).
    pub host: String,
    /// The AD object that owns the SPN (sAMAccountName).
    pub owner: String,
}

/// A domain computer object (for `--audit` enumeration / inventory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerRecord {
    pub sam: String,
    pub dns_host: Option<String>,
    pub os: Option<String>,
}

/// NTLM CHALLENGE (type-2) negotiate flags observed from a target/port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtlmFlags {
    pub sign: bool,
    pub seal: bool,
    pub extended_session_security: bool,
}

/// LDAP posture for one host, as far as we could determine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdapPosture {
    pub signing: Protection,
    pub channel_binding: Protection,
}

/// Directory queries + LDAP posture (backed by `ldap3` in the live impl).
#[async_trait]
pub trait LdapDirectory: Send + Sync {
    async fn list_spns(&self) -> Result<Vec<SpnRecord>>;
    async fn list_computers(&self) -> Result<Vec<ComputerRecord>>;
    async fn ldap_posture(&self, host: &str) -> Result<LdapPosture>;
}

/// Elicits an NTLM type-2 CHALLENGE from a target and returns its flags.
#[async_trait]
pub trait NtlmProbe: Send + Sync {
    /// `Ok(None)` means the target did not speak NTLM on that port (no finding).
    async fn challenge_flags(&self, host: &str, port: u16) -> Result<Option<NtlmFlags>>;
}

/// DNS resolution (backed by `hickory-resolver` in the live impl).
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolves(&self, host: &str) -> bool;
}

#[cfg(test)]
pub mod mock {
    //! In-memory trait impls for unit tests.
    use super::*;
    use std::collections::{HashMap, HashSet};

    pub struct MockDirectory {
        pub spns: Vec<SpnRecord>,
        pub computers: Vec<ComputerRecord>,
        pub posture: LdapPosture,
    }

    #[async_trait]
    impl LdapDirectory for MockDirectory {
        async fn list_spns(&self) -> Result<Vec<SpnRecord>> {
            Ok(self.spns.clone())
        }
        async fn list_computers(&self) -> Result<Vec<ComputerRecord>> {
            Ok(self.computers.clone())
        }
        async fn ldap_posture(&self, _host: &str) -> Result<LdapPosture> {
            Ok(self.posture)
        }
    }

    pub struct MockDns {
        pub known: HashSet<String>,
    }

    impl MockDns {
        pub fn with(hosts: &[&str]) -> Self {
            MockDns {
                known: hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
            }
        }
    }

    #[async_trait]
    impl DnsResolver for MockDns {
        async fn resolves(&self, host: &str) -> bool {
            self.known.contains(&host.to_ascii_lowercase())
        }
    }

    pub struct MockNtlm {
        pub flags: HashMap<u16, NtlmFlags>,
    }

    #[async_trait]
    impl NtlmProbe for MockNtlm {
        async fn challenge_flags(&self, _host: &str, port: u16) -> Result<Option<NtlmFlags>> {
            Ok(self.flags.get(&port).copied())
        }
    }
}
