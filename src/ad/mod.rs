//! Active Directory / NTLM-relay detector (Tier A: LDAP + SPN + NTLM).
//!
//! **Detection only** — this module enumerates the directory and reads relay
//! posture; it never generates a relay-target list or triggers coercion.
//! Because AD scanning sends authentication traffic to hosts you may not own, it
//! is gated behind an explicit authorization prompt (or `--yes` in CI), never
//! runs by default, and hard-codes no targets. Findings flow through the same
//! `Finding` model, correlation engine, and report/SARIF pipeline as the rest of
//! RustZAP.

pub mod directory;
pub mod dns;
pub mod enumerate;
pub mod ldap;
pub mod ntlm;
pub mod probe;
pub mod spn;

use std::io::{self, IsTerminal, Write};
use std::time::Instant;

use anyhow::{bail, Context, Result};

use crate::analyze::{confirm_reply_is_yes, write_report};
use crate::types::{summarize_modules, Finding};

use directory::LiveDirectory;
use dns::LiveDns;
use ntlm::HttpNtlmProbe;
use probe::{DnsResolver, LdapDirectory, NtlmProbe};

/// OWASP category shared by every AD finding.
pub const OWASP_AUTH: &str = "A07:2021 – Identification and Authentication Failures";

/// Stable AD module ids (kept even when quiet, so the report lists them).
pub const AD_MODULE_IDS: &[&str] = &[
    "ad/ldap-signing",
    "ad/ldap-channel-binding",
    "ad/ghost-spn",
    "ad/ntlmv1",
    "ad/ntlm-signing",
    "ad/computer",
];

/// Host identity used in `Finding::url`, so correlation + the tree key on host.
pub fn host_url(host: &str) -> String {
    format!("ldap://{host}")
}

/// Which check families to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdChecks {
    pub ldap: bool,
    pub spn: bool,
    pub ntlm: bool,
}

impl AdChecks {
    /// Parse a `--checks` value: `all`, or a comma list of `ldap,spn,ntlm`.
    pub fn parse(spec: &str) -> Self {
        let spec = spec.trim().to_ascii_lowercase();
        if spec.is_empty() || spec == "all" {
            return AdChecks {
                ldap: true,
                spn: true,
                ntlm: true,
            };
        }
        let set: Vec<&str> = spec.split(',').map(|s| s.trim()).collect();
        AdChecks {
            ldap: set.contains(&"ldap"),
            spn: set.contains(&"spn"),
            ntlm: set.contains(&"ntlm"),
        }
    }
}

/// Fully-resolved AD scan configuration.
#[derive(Debug, Clone)]
pub struct AdConfig {
    pub domain: String,
    pub dc_ip: String,
    pub targets: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub null_auth: bool,
    pub kerberos: bool,
    pub audit: bool,
    pub checks: AdChecks,
    pub insecure: bool,
    pub output: String,
    pub sarif_out: Option<String>,
    pub assume_yes: bool,
}

/// Consent gate outcome, mirroring the analyze repo-access gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdAuthGate {
    Granted,
    Prompt,
}

/// Decide whether to proceed silently, prompt, or refuse.
pub fn ad_auth_gate(assume_yes: bool, stdin_is_tty: bool) -> Result<AdAuthGate> {
    if assume_yes {
        return Ok(AdAuthGate::Granted);
    }
    if !stdin_is_tty {
        bail!(
            "Non-interactive stdin requires --yes to confirm AD authorization \
             (e.g. `rustzap ad --domain corp.local --dc-ip 10.0.0.1 --null-auth --yes`)."
        );
    }
    Ok(AdAuthGate::Prompt)
}

/// Print the authorization warning and require an explicit `y`.
pub fn confirm_ad_authorization(cfg: &AdConfig, assume_yes: bool) -> Result<()> {
    match ad_auth_gate(assume_yes, io::stdin().is_terminal())? {
        AdAuthGate::Granted => Ok(()),
        AdAuthGate::Prompt => {
            println!(
                "RustZAP will send LDAP and NTLM authentication traffic to Active Directory \
                 hosts in `{}` (DC {}).",
                cfg.domain, cfg.dc_ip
            );
            println!("This is intrusive network probing. Only scan AD you own or are explicitly authorized to test.");
            print!("Proceed? [y/N]: ");
            io::stdout().flush().ok();
            let mut buf = String::new();
            io::stdin()
                .read_line(&mut buf)
                .context("read AD authorization confirmation")?;
            if confirm_reply_is_yes(&buf) {
                Ok(())
            } else {
                bail!("AD authorization declined");
            }
        }
    }
}

/// Resolve the host list the per-host checks run against.
fn resolve_targets(cfg: &AdConfig, enumerated: &[String]) -> Vec<String> {
    let mut targets: Vec<String> = cfg.targets.clone();
    targets.extend(enumerated.iter().cloned());
    if targets.is_empty() {
        targets.push(cfg.dc_ip.clone());
    }
    targets.sort();
    targets.dedup();
    targets
}

/// Core orchestration over injected trait objects (tests pass mocks).
pub async fn run_ad(
    cfg: &AdConfig,
    dir: &dyn LdapDirectory,
    ntlm: &dyn NtlmProbe,
    dns: &dyn DnsResolver,
) -> Result<Vec<Finding>> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut enumerated: Vec<String> = Vec::new();

    if cfg.audit {
        let computers = dir.list_computers().await.context("enumerate computers")?;
        enumerated = enumerate::computer_targets(&computers);
        findings.extend(enumerate::computer_findings(&computers));
    }

    let targets = resolve_targets(cfg, &enumerated);

    if cfg.checks.spn {
        let spns = dir.list_spns().await.context("enumerate SPNs")?;
        findings.extend(spn::detect(&spns, dns).await);
    }

    if cfg.checks.ldap {
        for host in &targets {
            if let Ok(posture) = dir.ldap_posture(host).await {
                findings.extend(ldap::posture_findings(host, &posture));
            }
        }
    }

    if cfg.checks.ntlm {
        for host in &targets {
            for port in [5985u16, 5986, 443] {
                if let Ok(Some(flags)) = ntlm.challenge_flags(host, port).await {
                    findings.extend(ntlm::ntlm_findings(host, &flags));
                    break;
                }
            }
        }
    }

    Ok(findings)
}

/// CLI entry point: consent → live scan → report (correlated JSON/SARIF).
pub async fn run_ad_cli(cfg: AdConfig) -> Result<()> {
    confirm_ad_authorization(&cfg, cfg.assume_yes)?;

    let bind_dn = match (&cfg.username, cfg.null_auth) {
        (Some(user), false) => Some(format!("{user}@{}", cfg.domain)),
        _ => None,
    };
    let dir = LiveDirectory {
        url: format!("ldap://{}:389", cfg.dc_ip),
        bind_dn,
        password: cfg.password.clone(),
        base_dn: directory::domain_to_base_dn(&cfg.domain),
        insecure: cfg.insecure,
    };
    let ntlm = HttpNtlmProbe::new(cfg.insecure)?;
    let dns = LiveDns::new(&cfg.dc_ip);

    let started = Instant::now();
    let findings = run_ad(&cfg, &dir, &ntlm, &dns).await?;
    let elapsed = started.elapsed();

    let modules = summarize_modules(&findings, AD_MODULE_IDS);
    let report = write_report(
        &cfg.domain,
        modules,
        vec![],
        findings,
        true,
        elapsed,
        &cfg.output,
        cfg.sarif_out.as_deref(),
        None,
    )
    .await?;

    println!(
        "AD scan complete: {} finding(s), risk score {} → {}",
        report.summary.total_findings, report.summary.risk_score, cfg.output
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::probe::mock::{MockDirectory, MockDns, MockNtlm};
    use super::probe::{ComputerRecord, LdapPosture, NtlmFlags, Protection, SpnRecord};
    use super::*;
    use std::collections::HashMap;

    fn base_cfg() -> AdConfig {
        AdConfig {
            domain: "corp.local".into(),
            dc_ip: "10.0.0.1".into(),
            targets: vec!["dc01.corp.local".into()],
            username: Some("svc".into()),
            password: Some("pw".into()),
            null_auth: false,
            kerberos: false,
            audit: false,
            checks: AdChecks {
                ldap: true,
                spn: true,
                ntlm: true,
            },
            insecure: false,
            output: "ad-report.json".into(),
            sarif_out: None,
            assume_yes: true,
        }
    }

    #[test]
    fn checks_parse() {
        assert_eq!(
            AdChecks::parse("all"),
            AdChecks {
                ldap: true,
                spn: true,
                ntlm: true
            }
        );
        assert_eq!(
            AdChecks::parse("spn"),
            AdChecks {
                ldap: false,
                spn: true,
                ntlm: false
            }
        );
        assert_eq!(
            AdChecks::parse("ldap,ntlm"),
            AdChecks {
                ldap: true,
                spn: false,
                ntlm: true
            }
        );
    }

    #[test]
    fn gate_requires_yes_when_non_tty() {
        assert_eq!(ad_auth_gate(true, false).unwrap(), AdAuthGate::Granted);
        assert_eq!(ad_auth_gate(false, true).unwrap(), AdAuthGate::Prompt);
        assert!(ad_auth_gate(false, false).is_err());
    }

    #[tokio::test]
    async fn end_to_end_over_mocks_produces_all_families() {
        let dir = MockDirectory {
            spns: vec![SpnRecord {
                spn: "MSSQLSvc/gone.corp.local:1433".into(),
                host: "gone.corp.local".into(),
                owner: "svc$".into(),
            }],
            computers: vec![ComputerRecord {
                sam: "DC01$".into(),
                dns_host: Some("dc01.corp.local".into()),
                os: Some("Windows Server 2022".into()),
            }],
            posture: LdapPosture {
                signing: Protection::NotEnforced,
                channel_binding: Protection::Unknown,
            },
        };
        let dns = MockDns::with(&["dc01.corp.local"]); // gone.corp.local is a ghost
        let mut flags = HashMap::new();
        flags.insert(
            5985u16,
            NtlmFlags {
                sign: false,
                seal: false,
                extended_session_security: false,
            },
        );
        let ntlm = MockNtlm { flags };

        let mut cfg = base_cfg();
        cfg.audit = true;
        let findings = run_ad(&cfg, &dir, &ntlm, &dns).await.unwrap();

        let plugins: Vec<&str> = findings.iter().map(|f| f.plugin.as_str()).collect();
        assert!(plugins.contains(&"ad/ghost-spn"), "{plugins:?}");
        assert!(plugins.contains(&"ad/ldap-signing"), "{plugins:?}");
        assert!(plugins.contains(&"ad/ntlmv1"), "{plugins:?}");
        assert!(plugins.contains(&"ad/computer"), "{plugins:?}");
    }
}
