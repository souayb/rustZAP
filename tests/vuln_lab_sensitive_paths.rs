//! `sensitive-paths` (opt-in) against synthetic local fixtures: SPA shells,
//! custom error pages, true exposed files, management surfaces in their three
//! states, and security.txt media-type validation (passive A1).

#[path = "support/lab.rs"]
mod lab;

use lab::{client_nofollow, du_get, serve_full, Resp};
use rustzap::active::plugin_by_name;
use rustzap::types::{Finding, Severity};

async fn run(base: &str) -> Vec<Finding> {
    plugin_by_name("sensitive-paths")
        .expect("sensitive-paths registered")
        .scan(&client_nofollow(), &du_get(&format!("{base}/"), &[]))
        .await
}

fn titles(findings: &[Finding]) -> Vec<String> {
    findings.iter().map(|f| f.title.clone()).collect()
}

const SMALL_SPA: &str =
    "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>";

fn large_spa() -> String {
    format!(
        "<!doctype html><html><head><title>App</title></head><body>{}</body></html>",
        "<div class=\"filler\">lorem ipsum dolor sit amet</div>".repeat(1200)
    )
}

fn not_found() -> Resp {
    Resp::html("not found").status(404, "Not Found")
}

#[tokio::test]
async fn small_spa_shell_is_quiet() {
    let base = serve_full(|_| Resp::html(SMALL_SPA)).await;
    let f = run(&base).await;
    assert!(f.is_empty(), "{:?}", titles(&f));
}

#[tokio::test]
async fn large_spa_shell_is_quiet() {
    let spa = large_spa();
    let base = serve_full(move |_| Resp::html(spa.clone())).await;
    let f = run(&base).await;
    assert!(f.is_empty(), "{:?}", titles(&f));
}

#[tokio::test]
async fn custom_error_page_echoing_path_is_quiet() {
    // Soft 404: 200 with a branded page that echoes the requested path and a nonce.
    let base = serve_full(|req| {
        Resp::html(format!(
            "<html><body><h1>Oops</h1><p>We could not find {} (ref {})</p></body></html>",
            req.path,
            req.path.len() * 7919
        ))
    })
    .await;
    let f = run(&base).await;
    assert!(f.is_empty(), "{:?}", titles(&f));
}

#[tokio::test]
async fn true_exposed_files_behind_spa_fallback_are_reported_and_redacted() {
    let base = serve_full(|req| match req.path.as_str() {
        "/.git/config" => {
            Resp::ok("[core]\n\trepositoryformatversion = 0\n").header("Content-Type", "text/plain")
        }
        "/.env" => Resp::ok("API_TOKEN=supersecretvalue\nADMIN_EMAIL=ops@corp.example\n")
            .header("Content-Type", "application/octet-stream"),
        _ => Resp::html(SMALL_SPA),
    })
    .await;
    let f = run(&base).await;
    let mut t = titles(&f);
    t.sort();
    assert_eq!(
        t,
        vec![
            "Sensitive Path Exposed: /.env".to_string(),
            "Sensitive Path Exposed: /.git/config".to_string(),
        ]
    );
    for finding in &f {
        let ev = finding.evidence.as_deref().unwrap_or("");
        assert!(!ev.contains("supersecretvalue"), "{ev}");
        assert!(!ev.contains("ops@corp.example"), "{ev}");
        assert!(finding.poc_validated);
    }
}

#[tokio::test]
async fn protected_management_routes_are_informational_observations() {
    let base = serve_full(|req| match req.path.as_str() {
        "/admin/realms" => Resp::ok("{\"error\":\"HTTP 401 Unauthorized\"}")
            .status(401, "Unauthorized")
            .header("Content-Type", "application/json"),
        "/api/v1/applications" => Resp::ok("{\"error\":\"no session information\"}")
            .status(403, "Forbidden")
            .header("Content-Type", "application/json"),
        "/admin/master/console/" => Resp::html(
            "<html><head><title>Keycloak Administration Console</title></head><body></body></html>",
        ),
        _ => not_found(),
    })
    .await;
    let f = run(&base).await;
    assert_eq!(f.len(), 3, "{:?}", titles(&f));
    let sev = |prefix: &str| {
        f.iter()
            .find(|x| x.title.starts_with(prefix))
            .map(|x| x.severity.clone())
    };
    assert_eq!(
        sev("Authentication-Protected Management Endpoint: Keycloak admin API"),
        Some(Severity::Info)
    );
    assert_eq!(
        sev("Authentication-Protected Management Endpoint: Argo CD API"),
        Some(Severity::Info)
    );
    assert_eq!(
        sev("Management Sign-in Page Reachable: Keycloak admin console"),
        Some(Severity::Low)
    );
}

#[tokio::test]
async fn auth_wall_on_every_path_is_not_a_protected_api_observation() {
    let base = serve_full(|_| {
        Resp::ok("{\"error\":\"unauthorized\"}")
            .status(401, "Unauthorized")
            .header("Content-Type", "application/json")
    })
    .await;
    let f = run(&base).await;
    assert!(f.is_empty(), "{:?}", titles(&f));
}

#[tokio::test]
async fn public_metrics_and_open_management_api_are_high() {
    let base = serve_full(|req| match req.path.as_str() {
        "/metrics" => Resp::ok(
            "# HELP http_requests_total Total requests.\n# TYPE http_requests_total counter\nhttp_requests_total{code=\"200\"} 1027\n",
        )
        .header("Content-Type", "text/plain; version=0.0.4"),
        "/api/v1/applications" => {
            Resp::ok("{\"metadata\":{},\"items\":[{\"metadata\":{\"name\":\"prod\"}}]}")
                .header("Content-Type", "application/json")
        }
        _ => Resp::html(SMALL_SPA),
    })
    .await;
    let f = run(&base).await;
    let mut t = titles(&f);
    t.sort();
    assert_eq!(
        t,
        vec![
            "Exposed Operational Data: Argo CD API".to_string(),
            "Exposed Operational Data: Prometheus metrics".to_string(),
        ]
    );
    assert!(f.iter().all(|x| x.severity == Severity::High));
}

#[tokio::test]
async fn argo_cd_spa_is_a_single_sign_in_observation() {
    // Argo CD's UI is itself an SPA: every path returns its index.html.
    let base = serve_full(|req| match req.path.as_str() {
        "/api/v1/applications" => Resp::ok("{\"error\":\"no session information\"}")
            .status(401, "Unauthorized")
            .header("Content-Type", "application/json"),
        _ => Resp::html(
            "<!doctype html><html><head><title>Argo CD</title></head><body></body></html>",
        ),
    })
    .await;
    let f = run(&base).await;
    let mut t = titles(&f);
    t.sort();
    assert_eq!(
        t,
        vec![
            "Authentication-Protected Management Endpoint: Argo CD API".to_string(),
            "Management Sign-in Page Reachable: Argo CD".to_string(),
        ]
    );
}

// ── security.txt (passive A1) ───────────────────────────────────────────────

async fn security_txt(handler: fn(&lab::Req) -> Resp) -> Vec<String> {
    let base = serve_full(handler).await;
    titles(&rustzap::passive::check_security_txt(&client_nofollow(), &base).await)
}

#[tokio::test]
async fn security_txt_spa_fallback_is_treated_as_missing() {
    let t = security_txt(|_| Resp::html(SMALL_SPA)).await;
    assert_eq!(t, vec!["security.txt Missing".to_string()]);
}

#[tokio::test]
async fn security_txt_valid_plain_text_is_quiet() {
    let t = security_txt(|req| match req.path.as_str() {
        "/.well-known/security.txt" => {
            Resp::ok("Contact: mailto:security@example.com\nExpires: 2999-12-31T00:00:00Z\n")
                .header("Content-Type", "text/plain; charset=utf-8")
        }
        _ => not_found(),
    })
    .await;
    assert!(t.is_empty(), "{t:?}");
}

#[tokio::test]
async fn security_txt_plain_text_missing_fields_is_flagged() {
    let t = security_txt(|req| match req.path.as_str() {
        "/.well-known/security.txt" => {
            Resp::ok("# nothing useful\n").header("Content-Type", "text/plain")
        }
        _ => not_found(),
    })
    .await;
    assert!(
        t.contains(&"security.txt Missing Contact Field".to_string()),
        "{t:?}"
    );
    assert!(
        t.contains(&"security.txt Missing Expires".to_string()),
        "{t:?}"
    );
}
