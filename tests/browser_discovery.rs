//! Browser-assisted discovery against local SPA fixtures. Every test here
//! auto-skips (passes with a note) when no Chromium/Chrome/Edge is installed.

#[path = "support/lab.rs"]
mod lab;

use std::sync::{Arc, Mutex};

use lab::{serve_full, Req, Resp};
use rustzap::browser_discovery::{
    discover, find_browser, BrowserDiscoveryConfig, LoginScript, DEFAULT_EXCLUDES,
};
use rustzap::types::UrlSource;

fn config(login: Option<LoginScript>) -> BrowserDiscoveryConfig {
    BrowserDiscoveryConfig {
        browser_path: None,
        max_navigations: 10,
        max_requests: 100,
        allow_origins: vec![],
        excludes: vec![],
        login,
    }
}

fn no_browser() -> bool {
    let missing = find_browser(None).is_none();
    if missing {
        eprintln!("skipping: no Chromium/Chrome/Edge installed");
    }
    missing
}

/// SPA whose API paths are assembled at runtime, so only JS execution reveals them.
const SPA: &str = r##"<!doctype html><html><body>
<a href="#/reports">Reports</a> <a href="/logout">Log out</a>
<script>
const api = p => '/api/' + p.split('').reverse().join('');
fetch(api('smeti') + '?page=1');
fetch(api('sredro'), {method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf-secret-value'},
  body: JSON.stringify({sku: 'A1', qty: 2})});
fetch('http://example.invalid/track').catch(() => {});
window.addEventListener('hashchange', () => fetch(api('stroper')));
</script></body></html>"##;

#[tokio::test]
async fn spa_api_found_only_after_js_execution() {
    if no_browser() {
        return;
    }
    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = hits.clone();
    let base = serve_full(move |r: &Req| {
        log.lock().unwrap().push(format!("{} {}", r.method, r.path));
        match r.path.as_str() {
            "/" => Resp::html(SPA),
            "/api/items" | "/api/orders" | "/api/reports" => {
                Resp::ok("{}").header("Content-Type", "application/json")
            }
            _ => Resp::ok("nope").status(404, "Not Found"),
        }
    })
    .await;

    let (urls, finding) = discover(&config(None), &format!("{base}/"), &[], false).await;
    let ev = finding.evidence.clone().unwrap_or_default();
    assert_eq!(finding.title, "Browser Discovery Completed", "{ev}");
    assert!(urls.iter().all(|u| u.source == UrlSource::Browser));

    let get = |m: &str, p: &str| {
        urls.iter()
            .find(|u| u.method == m && u.url.contains(p))
            .unwrap_or_else(|| panic!("{m} {p} not discovered; got {urls:#?}"))
    };
    assert!(get("GET", "/api/items").parameters.contains(&"page".into()));
    let order = get("POST", "/api/orders");
    assert_eq!(order.body.as_deref(), Some(r#"{"qty":0,"sku":"string"}"#));
    assert!(order
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-csrf-token") && v == "[REDACTED]"));
    get("GET", "/api/reports"); // only reachable via the hash route

    // Logout was excluded, never requested; the third-party beacon was blocked.
    assert!(DEFAULT_EXCLUDES.contains(&"logout"));
    assert!(!hits.lock().unwrap().iter().any(|h| h.contains("logout")));
    assert!(ev.contains("/logout"), "{ev}");
    assert!(!ev.contains("\"blocked_out_of_scope\":0"), "{ev}");
    assert!(!ev.contains("csrf-secret-value"));
}

const LOGIN_PAGE: &str = r#"<!doctype html><html><body>
<input id="user"><input id="pass" type="password"><button id="go">Sign in</button>
<script>
document.getElementById('go').onclick = async () => {
  const r = await fetch('/api/session', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user: document.getElementById('user').value, pass: document.getElementById('pass').value})});
  if (r.ok) location.href = '/app';
};
</script></body></html>"#;

const APP_PAGE: &str = r#"<!doctype html><html><body><div id="dash">Dashboard</div>
<script>fetch('/api/' + ['pro', 'file'].join(''));</script></body></html>"#;

fn login_app() -> impl Fn(&Req) -> Resp + Send + Sync + 'static {
    |r: &Req| {
        let authed = r
            .headers
            .get("cookie")
            .is_some_and(|c| c.contains("sid=s3ss10n"));
        match (r.method.as_str(), r.path.as_str()) {
            (_, "/login") => Resp::html(LOGIN_PAGE),
            ("POST", "/api/session") if r.body.contains("\"pass\":\"hunter2\"") => {
                Resp::ok("{}").header("Set-Cookie", "sid=s3ss10n; Path=/")
            }
            ("POST", "/api/session") => Resp::ok("{}").status(401, "Unauthorized"),
            (_, "/app") if authed => Resp::html(APP_PAGE),
            (_, "/api/profile") if authed => Resp::ok("{}"),
            _ => Resp::html("<h1>login required</h1>").status(401, "Unauthorized"),
        }
    }
}

fn login_script(pass_env: &str, success: &str) -> LoginScript {
    serde_yaml::from_str(&format!(
        "steps:\n  - navigate: /login\n  - fill: {{ selector: '#user', value: alice }}\n  - fill: {{ selector: '#pass', value_env: {pass_env} }}\n  - click: '#go'\n  - wait_for: '{success}'\nsuccess_selector: '{success}'\n"
    ))
    .unwrap()
}

#[tokio::test]
async fn synthetic_login_unlocks_authenticated_api() {
    if no_browser() {
        return;
    }
    std::env::set_var("RZ_TEST_BROWSER_PASS_OK", "hunter2");
    let base = serve_full(login_app()).await;
    let cfg = config(Some(login_script("RZ_TEST_BROWSER_PASS_OK", "#dash")));
    let (urls, finding) = discover(&cfg, &format!("{base}/app"), &[], false).await;
    let ev = finding.evidence.clone().unwrap_or_default();
    assert!(ev.contains("\"login\":\"ok\""), "{ev}");
    assert!(
        urls.iter().any(|u| u.url.ends_with("/api/profile")),
        "{urls:#?}"
    );
    let session = urls
        .iter()
        .find(|u| u.method == "POST" && u.url.ends_with("/api/session"))
        .expect("login API captured");
    assert_eq!(
        session.body.as_deref(),
        Some(r#"{"pass":"string","user":"string"}"#)
    );
    // Credentials never stored raw.
    let dump = format!("{urls:?}{ev}");
    assert!(
        !dump.contains("hunter2") && !dump.contains("s3ss10n"),
        "{dump}"
    );
}

#[tokio::test]
async fn failed_login_and_inaccessible_screen_are_recorded() {
    if no_browser() {
        return;
    }
    std::env::set_var("RZ_TEST_BROWSER_PASS_BAD", "wrong");
    let base = serve_full(login_app()).await;
    let mut script = login_script("RZ_TEST_BROWSER_PASS_BAD", "#dash");
    if let Some(rustzap::browser_discovery::LoginStep::WaitFor(_)) = script.steps.last() {
        script.steps.pop(); // fail fast at the success check instead of twice
    }
    let (urls, finding) = discover(&config(Some(script)), &format!("{base}/app"), &[], false).await;
    let ev = finding.evidence.clone().unwrap_or_default();
    assert!(ev.contains("\"login\":\"failed"), "{ev}");
    assert!(ev.contains("/app: HTTP 401"), "{ev}");
    assert!(!urls.iter().any(|u| u.url.ends_with("/api/profile")));
}
