//! Live LDAP directory access (`ldap3`): SPN + computer enumeration and a
//! simple-bind LDAP-signing posture probe. The pure helpers
//! (`domain_to_base_dn`, entry parsing) are unit-tested; the network path is
//! exercised only against a lab DC.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use super::probe::{ComputerRecord, LdapDirectory, LdapPosture, Protection, SpnRecord};
use super::spn::spn_host;

/// `corp.local` → `DC=corp,DC=local`.
pub fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Result code 8 = `strongerAuthRequired`: the DC refused an unsigned simple
/// bind, i.e. LDAP signing is enforced. 0 = accepted (not enforced).
pub fn posture_from_bind_rc(rc: u32) -> Protection {
    match rc {
        0 => Protection::NotEnforced,
        8 => Protection::Enforced,
        _ => Protection::Unknown,
    }
}

fn parse_spn_entries(entries: Vec<SearchEntry>) -> Vec<SpnRecord> {
    let mut out = Vec::new();
    for se in entries {
        let owner = se
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        if let Some(spns) = se.attrs.get("servicePrincipalName") {
            for spn in spns {
                if let Some(host) = spn_host(spn) {
                    out.push(SpnRecord {
                        spn: spn.clone(),
                        host,
                        owner: owner.clone(),
                    });
                }
            }
        }
    }
    out
}

fn parse_computer_entries(entries: Vec<SearchEntry>) -> Vec<ComputerRecord> {
    entries
        .into_iter()
        .map(|se| ComputerRecord {
            sam: se
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default(),
            dns_host: se.attrs.get("dNSHostName").and_then(|v| v.first()).cloned(),
            os: se
                .attrs
                .get("operatingSystem")
                .and_then(|v| v.first())
                .cloned(),
        })
        .collect()
}

/// Live directory bound with the configured credentials.
pub struct LiveDirectory {
    pub url: String,
    pub bind_dn: Option<String>,
    pub password: Option<String>,
    pub base_dn: String,
    pub insecure: bool,
}

impl LiveDirectory {
    async fn connect(&self) -> Result<ldap3::Ldap> {
        let settings = LdapConnSettings::new()
            .set_no_tls_verify(self.insecure)
            .set_conn_timeout(Duration::from_secs(8));
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.url)
            .await
            .with_context(|| format!("connect LDAP {}", self.url))?;
        ldap3::drive!(conn);
        let dn = self.bind_dn.clone().unwrap_or_default();
        let pw = self.password.clone().unwrap_or_default();
        ldap.simple_bind(&dn, &pw)
            .await
            .context("LDAP bind")?
            .success()
            .context("LDAP bind rejected")?;
        Ok(ldap)
    }

    async fn search(&self, filter: &str, attrs: &[&str]) -> Result<Vec<SearchEntry>> {
        let mut ldap = self.connect().await?;
        let (rs, _res) = ldap
            .search(&self.base_dn, Scope::Subtree, filter, attrs.to_vec())
            .await
            .context("LDAP search")?
            .success()
            .context("LDAP search failed")?;
        let _ = ldap.unbind().await;
        Ok(rs.into_iter().map(SearchEntry::construct).collect())
    }
}

#[async_trait]
impl LdapDirectory for LiveDirectory {
    async fn list_spns(&self) -> Result<Vec<SpnRecord>> {
        let entries = self
            .search(
                "(servicePrincipalName=*)",
                &["servicePrincipalName", "sAMAccountName", "dNSHostName"],
            )
            .await?;
        Ok(parse_spn_entries(entries))
    }

    async fn list_computers(&self) -> Result<Vec<ComputerRecord>> {
        let entries = self
            .search(
                "(objectClass=computer)",
                &["sAMAccountName", "dNSHostName", "operatingSystem"],
            )
            .await?;
        Ok(parse_computer_entries(entries))
    }

    async fn ldap_posture(&self, host: &str) -> Result<LdapPosture> {
        // Fresh unauthenticated-transport simple bind against :389 to read the
        // signing-requirement result code. Channel binding needs an LDAPS
        // differential probe (staged) → Unknown for now.
        let url = format!("ldap://{host}:389");
        let settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(8));
        let signing = match LdapConnAsync::with_settings(settings, &url).await {
            Ok((conn, mut ldap)) => {
                ldap3::drive!(conn);
                let dn = self.bind_dn.clone().unwrap_or_default();
                let pw = self.password.clone().unwrap_or_default();
                match ldap.simple_bind(&dn, &pw).await {
                    Ok(res) => posture_from_bind_rc(res.rc),
                    Err(_) => Protection::Unknown,
                }
            }
            Err(_) => Protection::Unknown,
        };
        Ok(LdapPosture {
            signing,
            channel_binding: Protection::Unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_dn_from_domain() {
        assert_eq!(domain_to_base_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(
            domain_to_base_dn("a.b.c.example"),
            "DC=a,DC=b,DC=c,DC=example"
        );
        assert_eq!(domain_to_base_dn(""), "");
    }

    #[test]
    fn bind_rc_maps_to_protection() {
        assert_eq!(posture_from_bind_rc(0), Protection::NotEnforced);
        assert_eq!(posture_from_bind_rc(8), Protection::Enforced);
        assert_eq!(posture_from_bind_rc(49), Protection::Unknown);
    }
}
