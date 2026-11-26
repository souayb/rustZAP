//! Multi-identity BOLA / authorization-matrix lab (#43, #51).
//!
//! Each fixture is a loopback app with three users keyed by `Authorization`:
//! alice (tenant t1, user), bob (tenant t1, user), carol (tenant t2, user) and
//! root (tenant t1, admin). Vulnerable variants skip ownership / tenant / role
//! checks; fixed variants enforce them. Non-finding fixtures return a generic
//! 200 error body or a login redirect instead of the object.

#[path = "support/lab.rs"]
mod lab;

use lab::{du_get, serve_full, Req, Resp};
use rustzap::active::authz::{run, AuthzOptions};
use rustzap::active::plugin_by_name;
use rustzap::scanner::ScanConfig;
use rustzap::types::{Confidence, DiscoveredUrl, Finding, Severity};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Vulnerable,
    Fixed,
    /// Denials are `200 {"error":"not allowed"}` (shared error body).
    Generic200,
    /// Denials are a 302 to a 200 login page.
    LoginRedirect,
}

/// (token, user, tenant, is_admin)
const USERS: &[(&str, &str, &str, bool)] = &[
    ("Bearer alice", "alice", "t1", false),
    ("Bearer bob", "bob", "t1", false),
    ("Bearer carol", "carol", "t2", false),
    ("Bearer root", "root", "t1", true),
];

/// (record id, owner, tenant)
const RECORDS: &[(&str, &str, &str)] = &[
    ("1001", "alice", "t1"),
    ("1002", "bob", "t1"),
    ("2002", "bob", "t1"),
    ("3003", "carol", "t2"),
];

fn app(mode: Mode) -> impl Fn(&Req) -> Resp + Send + Sync + 'static {
    move |req: &Req| {
        if req.path == "/login" {
            return Resp::html("<html><form>Please log in</form></html>");
        }
        let user = req
            .headers
            .get("authorization")
            .and_then(|a| USERS.iter().find(|u| u.0 == a));
        let deny = |code: u16| match mode {
            Mode::Generic200 => {
                Resp::ok("{\"error\":\"not allowed\"}").header("Content-Type", "application/json")
            }
            Mode::LoginRedirect => Resp::redirect("/login"),
            _ if code == 401 => {
                Resp::ok("{\"error\":\"unauthorized\"}").status(401, "Unauthorized")
            }
            _ => Resp::ok("{\"error\":\"forbidden\"}").status(403, "Forbidden"),
        };
        let Some(&(_, name, tenant, admin)) = user else {
            return deny(401);
        };
        let enforce = matches!(mode, Mode::Fixed | Mode::Generic200 | Mode::LoginRedirect);

        if req.path == "/me" {
            return Resp::ok(format!("{{\"user\":\"{name}\"}}"));
        }
        if req.path == "/admin/users" {
            if enforce && !admin {
                return deny(403);
            }
            return Resp::ok(
                "{\"users\":[\"alice\",\"bob\",\"carol\",\"root\"],\"admin_panel\":true}",
            )
            .header("Content-Type", "application/json");
        }
        if let Some(id) = req.path.strip_prefix("/records/") {
            let Some(&(rid, owner, rtenant)) = RECORDS.iter().find(|r| r.0 == id) else {
                return Resp::ok("{\"error\":\"not found\"}").status(404, "Not Found");
            };
            // Admins may read (not write) records in their own tenant.
            let ok = owner == name || (admin && rtenant == tenant && req.method == "GET");
            if enforce && !ok {
                return deny(403);
            }
            if req.method == "PUT" {
                return Resp::ok(format!("{{\"updated\":\"{rid}\"}}"));
            }
            return Resp::ok(format!(
                "{{\"id\":\"{rid}\",\"owner\":\"{owner}\",\"tenant\":\"{rtenant}\",\"diagnosis\":\"confidential-{rid}\",\"api_token\":\"s3cr3t-{rid}\"}}"
            ))
            .header("Content-Type", "application/json");
        }
        Resp::ok("not found").status(404, "Not Found")
    }
}

fn config(target: &str, read_only_safe: bool) -> ScanConfig {
    ScanConfig {
        target_url: target.to_string(),
        max_depth: 1,
        concurrency: 2,
        passive_only: false,
        output_file: String::new(),
        sarif_out: None,
        timeout_secs: 10,
        user_agent: None,
        cookies: None,
        auth_header: None,
        api_key: None,
        basic_auth: None,
        insecure: false,
        plugins: vec![],
        openapi_path: None,
        openapi_url: None,
        har_path: None,
        paths_file: None,
        discover_openapi: false,
        nuclei: false,
        nuclei_jsonl: None,
        active_all_paths: false,
        passive_all_methods: false,
        safety: rustzap::safety::SafetyPolicy::from_flags(false, read_only_safe, Some(0)),
        authz: AuthzOptions::default(),
        jwt_crack: false,
        browser_discovery: None,
    }
}

fn of<'a>(f: &'a [Finding], plugin: &str) -> Vec<&'a Finding> {
    f.iter()
        .filter(|x| x.plugin == plugin && x.severity > Severity::Info)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// --auth-a / --auth-b
// ─────────────────────────────────────────────────────────────────────────────

async fn two_identity(mode: Mode) -> Vec<Finding> {
    let base = serve_full(app(mode)).await;
    // bob's record and the admin panel; A = alice (low), B = bob / root.
    let opts = |b: &str| AuthzOptions {
        auth_a: Some("Bearer alice".into()),
        auth_b: Some(b.into()),
        matrix: None,
    };
    let mut out = run(
        &opts("Bearer bob"),
        &config(&base, false),
        &[du_get(&format!("{base}/records/2002"), &[])],
    )
    .await
    .unwrap();
    out.extend(
        run(
            &opts("Bearer root"),
            &config(&base, false),
            &[du_get(&format!("{base}/admin/users"), &[])],
        )
        .await
        .unwrap(),
    );
    out
}

#[tokio::test]
async fn two_identity_flags_cross_user_and_vertical_on_vulnerable_app() {
    let f = two_identity(Mode::Vulnerable).await;
    let bola = of(&f, "active/bola-cross-identity");
    assert_eq!(bola.len(), 1, "{f:?}");
    assert!(bola[0].url.ends_with("/records/2002"));
    let ev = bola[0].evidence.as_deref().unwrap();
    assert!(
        !ev.contains("s3cr3t-2002"),
        "evidence must be redacted: {ev}"
    );
    assert_eq!(of(&f, "active/privesc-vertical").len(), 1, "{f:?}");
}

#[tokio::test]
async fn two_identity_quiet_on_fixed_generic200_and_login_redirect() {
    for mode in [Mode::Fixed, Mode::Generic200, Mode::LoginRedirect] {
        let f = two_identity(mode).await;
        assert!(f.is_empty(), "mode produced findings: {f:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// --authz-matrix
// ─────────────────────────────────────────────────────────────────────────────

const MATRIX: &str = r#"
identities:
  - { name: alice, role: user,  tenant: t1, auth: "Bearer alice" }
  - { name: bob,   role: user,  tenant: t1, auth: "Bearer bob", check_url: /me }
  - { name: carol, role: user,  tenant: t2, auth: "Bearer carol" }
  - { name: root,  role: admin, tenant: t1, auth: "Bearer root" }
  - { name: ghost, role: user,  tenant: t1, auth: "Bearer expired", check_url: /me }
checks:
  - { operation: read,  url: /records/1001, id: "1001", owner: alice, tenant: t1, allow: [alice, root] }
  - { operation: read,  url: /records/3003, id: "3003", owner: carol, tenant: t2, allow: [carol] }
  - { operation: list,  url: /admin/users, id: admin_panel, allow: [admin] }
  - { operation: write, method: PUT, url: /records/2002, body: '{"note":"x"}', owner: bob, tenant: t1, allow: [bob] }
"#;

async fn matrix(mode: Mode, read_only_safe: bool) -> Vec<Finding> {
    let base = serve_full(app(mode)).await;
    let p = std::env::temp_dir().join(format!("rz-matrix-{}.yaml", rustzap::types::uuid_v4()));
    std::fs::write(&p, MATRIX).unwrap();
    let opts = AuthzOptions {
        matrix: Some(p.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let f = run(&opts, &config(&base, read_only_safe), &[])
        .await
        .unwrap();
    std::fs::remove_file(&p).ok();
    f
}

fn violation<'a>(f: &'a [Finding], who: &str, url_end: &str) -> Option<&'a Finding> {
    of(f, "active/authz-matrix")
        .into_iter()
        .find(|x| x.parameter.as_deref() == Some(who) && x.url.ends_with(url_end))
}

#[tokio::test]
async fn matrix_flags_cross_user_cross_tenant_role_and_write_on_vulnerable_app() {
    let f = matrix(Mode::Vulnerable, false).await;

    let cross_user = violation(&f, "bob", "/records/1001").expect("bob → alice");
    assert_eq!(cross_user.confidence, Confidence::Confirmed);
    let ev = cross_user.evidence.as_deref().unwrap();
    assert!(
        ev.contains("Expected: deny") && ev.contains("Observed: granted"),
        "{ev}"
    );
    assert!(ev.contains("cross-user"), "{ev}");
    assert!(!ev.contains("s3cr3t"), "evidence must be redacted: {ev}");

    let cross_tenant = violation(&f, "alice", "/records/3003").expect("alice → carol (t2)");
    assert!(cross_tenant
        .evidence
        .as_deref()
        .unwrap()
        .contains("cross-tenant"));
    assert_eq!(cross_tenant.severity, Severity::Critical);

    let role = violation(&f, "alice", "/admin/users").expect("user → admin route");
    assert!(role
        .evidence
        .as_deref()
        .unwrap()
        .contains("role-restricted"));

    assert!(
        violation(&f, "alice", "/records/2002").is_some(),
        "write violation"
    );

    // Allowed cells are never reported; the expired identity is never judged.
    assert!(violation(&f, "root", "/records/1001").is_none());
    assert!(violation(&f, "ghost", "/records/1001").is_none());
    assert!(f
        .iter()
        .any(|x| x.title.contains("Not Validated") && x.description.contains("ghost")));
}

#[tokio::test]
async fn matrix_quiet_on_fixed_generic200_and_login_redirect() {
    for mode in [Mode::Fixed, Mode::Generic200, Mode::LoginRedirect] {
        let f = matrix(mode, false).await;
        let v = of(&f, "active/authz-matrix");
        assert!(v.is_empty(), "violations in non-vulnerable mode: {v:?}");
    }
}

#[tokio::test]
async fn matrix_write_checks_blocked_by_read_only_safe() {
    let f = matrix(Mode::Vulnerable, true).await;
    assert!(violation(&f, "alice", "/records/2002").is_none(), "{f:?}");
    // Reads still run.
    assert!(violation(&f, "bob", "/records/1001").is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-session plugin: path ids, tentative only
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn single_session_bola_on_path_id_is_tentative() {
    let base = serve_full(app(Mode::Vulnerable)).await;
    let client = reqwest::Client::builder()
        .default_headers({
            let mut h = reqwest::header::HeaderMap::new();
            h.insert("authorization", "Bearer alice".parse().unwrap());
            h
        })
        .build()
        .unwrap();
    // alice's own 1001 → tampered 1002 (bob's) answers 200 with a different object.
    let du: DiscoveredUrl = du_get(&format!("{base}/records/1001"), &[]);
    let f = plugin_by_name("bola").unwrap().scan(&client, &du).await;
    let path = of(&f, "active/bola-path");
    assert!(!path.is_empty(), "{f:?}");
    assert!(path.iter().all(|x| x.confidence == Confidence::Tentative));
}
