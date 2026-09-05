//! End-to-end: AD detector pipeline → correlated JSON report (the shape the VS
//! Code extension and downstream consumers read). Uses inline trait impls so no
//! live DC is required.

use anyhow::Result;
use async_trait::async_trait;

use rustzap::ad::probe::{
    ComputerRecord, DnsResolver, LdapDirectory, LdapPosture, NtlmFlags, NtlmProbe, Protection,
    SpnRecord,
};
use rustzap::ad::{run_ad, AdChecks, AdConfig, AD_MODULE_IDS};
use rustzap::analyze::write_report;
use rustzap::types::summarize_modules;

struct FakeDir;

#[async_trait]
impl LdapDirectory for FakeDir {
    async fn list_spns(&self) -> Result<Vec<SpnRecord>> {
        Ok(vec![SpnRecord {
            spn: "MSSQLSvc/gone.corp.local:1433".into(),
            host: "gone.corp.local".into(),
            owner: "svc$".into(),
        }])
    }
    async fn list_computers(&self) -> Result<Vec<ComputerRecord>> {
        Ok(vec![ComputerRecord {
            sam: "DC01$".into(),
            dns_host: Some("dc01.corp.local".into()),
            os: Some("Windows Server 2022".into()),
        }])
    }
    async fn ldap_posture(&self, _host: &str) -> Result<LdapPosture> {
        // Both off → the correlation rule should elevate to Critical.
        Ok(LdapPosture {
            signing: Protection::NotEnforced,
            channel_binding: Protection::NotEnforced,
        })
    }
}

struct FakeDns;

#[async_trait]
impl DnsResolver for FakeDns {
    async fn resolves(&self, host: &str) -> bool {
        host.eq_ignore_ascii_case("dc01.corp.local") // gone.corp.local is a ghost
    }
}

struct FakeNtlm;

#[async_trait]
impl NtlmProbe for FakeNtlm {
    async fn challenge_flags(&self, _host: &str, port: u16) -> Result<Option<NtlmFlags>> {
        if port == 5985 {
            Ok(Some(NtlmFlags {
                sign: false,
                seal: false,
                extended_session_security: false,
            }))
        } else {
            Ok(None)
        }
    }
}

fn cfg() -> AdConfig {
    AdConfig {
        domain: "corp.local".into(),
        dc_ip: "10.0.0.1".into(),
        targets: vec![],
        username: Some("svc".into()),
        password: Some("pw".into()),
        null_auth: false,
        kerberos: false,
        audit: true,
        checks: AdChecks {
            ldap: true,
            spn: true,
            ntlm: true,
        },
        insecure: false,
        output: "ignored.json".into(),
        sarif_out: None,
        assume_yes: true,
    }
}

#[tokio::test]
async fn ad_pipeline_writes_correlated_report() {
    let cfg = cfg();
    let findings = run_ad(&cfg, &FakeDir, &FakeNtlm, &FakeDns).await.unwrap();
    let modules = summarize_modules(&findings, AD_MODULE_IDS);

    let out = std::env::temp_dir().join(format!("rustzap-ad-{}.json", rustzap::types::uuid_v4()));
    let report = write_report(
        &cfg.domain,
        modules,
        vec![],
        findings,
        true,
        std::time::Duration::from_secs(0),
        out.to_str().unwrap(),
        None,
        None,
    )
    .await
    .expect("write report");

    let json = std::fs::read_to_string(&out).expect("read report");

    // AD module rows present.
    assert!(json.contains("\"ad/ldap-signing\""), "{json}");
    assert!(json.contains("\"ad/ghost-spn\""));
    assert!(json.contains("\"ad/ntlmv1\""));
    assert!(json.contains("\"ad/computer\""));

    // Correlation consolidated the per-host relay path and elevated to critical.
    assert!(json.contains("\"correlations\""));
    assert!(json.contains("relay exposure on dc01.corp.local"), "{json}");
    assert!(report
        .correlations
        .iter()
        .any(|c| c.reason.contains("relay exposure on dc01.corp.local")));

    let _ = std::fs::remove_file(out);
}
