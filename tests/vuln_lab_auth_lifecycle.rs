//! Auth-lifecycle scenarios (#42/#52) against a stateful loopback app, in a
//! vulnerable and a fixed variant. Covers sessions surviving reset/change,
//! reusable/non-expiring reset tokens, missing-field reset with a hard-coded
//! fallback (predictable credential), echoed passwords, refresh rotation,
//! logout revocation, cookie+CSRF+redirect sessions, inconclusive outcomes,
//! the safety refusals, and that no secret reaches the findings.

#[path = "support/lab.rs"]
mod lab;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lab::{serve_full, Req, Resp};
use rustzap::active::auth_lifecycle::{run, Scenario};
use rustzap::safety::SafetyPolicy;
use rustzap::types::{Confidence, Finding};

const ORIGINAL_PW: &str = "Orig-Synth-Pw-71";
const NEW_PW: &str = "New-Synth-Pw-93";
const FALLBACK_PW: &str = "Welcome-Fallback-123";

#[derive(Default)]
struct State {
    password: String,
    n: u64,
    sessions: HashSet<String>,
    refresh: HashSet<String>,
    /// token → (issued, used)
    reset_tokens: HashMap<String, (Instant, bool)>,
}

fn json(body: String) -> Resp {
    Resp::ok(body).header("Content-Type", "application/json")
}

fn deny() -> Resp {
    json("{\"error\":\"unauthorized\"}".into()).status(401, "Unauthorized")
}

fn field(body: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get(key)?.as_str().map(str::to_string)
}

fn form_field(body: &str, key: &str) -> Option<String> {
    body.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == key).then(|| lab::pct_decode(v))
    })
}

fn cookie(req: &Req, name: &str) -> Option<String> {
    req.headers.get("cookie")?.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// Stateful auth app. `vuln = true` keeps sessions after reset/change/logout,
/// accepts reused/expired reset tokens, falls back to a fixed password when
/// `new_password` is missing, echoes passwords, and never rotates refresh tokens.
fn auth_app(vuln: bool) -> impl Fn(&Req) -> Resp + Send + Sync + 'static {
    let st = Arc::new(Mutex::new(State {
        password: ORIGINAL_PW.into(),
        ..Default::default()
    }));
    move |req: &Req| {
        let mut s = st.lock().unwrap();
        let bearer = req
            .headers
            .get("authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::to_string)
            .unwrap_or_default();
        match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/api/login") => {
                if field(&req.body, "password").as_deref() != Some(s.password.as_str()) {
                    return deny();
                }
                s.n += 1;
                let (t, r) = (format!("tokSECRET{}x", s.n), format!("rftSECRET{}x", s.n));
                s.sessions.insert(t.clone());
                s.refresh.insert(r.clone());
                json(format!("{{\"token\":\"{t}\",\"refresh_token\":\"{r}\"}}"))
            }
            ("GET", "/api/me") if s.sessions.contains(&bearer) => json("{\"me\":\"synth\"}".into()),
            ("GET", "/api/me") => deny(),
            ("POST", "/api/reset-request") => {
                s.n += 1;
                let t = format!("rstSECRET{}x", s.n);
                s.reset_tokens.insert(t.clone(), (Instant::now(), false));
                json(format!("{{\"reset_token\":\"{t}\"}}"))
            }
            ("POST", "/api/reset") => {
                let tok = field(&req.body, "token").unwrap_or_default();
                let Some(&(issued, used)) = s.reset_tokens.get(&tok) else {
                    return deny();
                };
                if !vuln && (used || issued.elapsed() > Duration::from_secs(1)) {
                    return deny();
                }
                let new_pw = field(&req.body, "new_password").unwrap_or_default();
                if new_pw.is_empty() {
                    if !vuln {
                        return json("{\"error\":\"new_password required\"}".into())
                            .status(400, "Bad Request");
                    }
                    s.password = FALLBACK_PW.into();
                    return json(format!(
                        "{{\"status\":\"ok\",\"temp_password\":\"{FALLBACK_PW}\"}}"
                    ));
                }
                s.password = new_pw.clone();
                if !vuln {
                    s.reset_tokens.insert(tok, (issued, true));
                    s.sessions.clear();
                    s.refresh.clear();
                    return json("{\"status\":\"ok\"}".into());
                }
                json(format!("{{\"status\":\"ok\",\"password\":\"{new_pw}\"}}"))
            }
            ("POST", "/api/admin/temp-reset") => {
                s.n += 1;
                let temp = if vuln {
                    FALLBACK_PW.to_string()
                } else {
                    format!("TmpSECRET{}x", s.n)
                };
                json(format!("{{\"temp_password\":\"{temp}\"}}"))
            }
            ("POST", "/api/refresh") => {
                let r = field(&req.body, "refresh_token").unwrap_or_default();
                if !s.refresh.contains(&r) {
                    return deny();
                }
                s.n += 1;
                let t = format!("tokSECRET{}x", s.n);
                s.sessions.insert(t.clone());
                let next = if vuln {
                    r
                } else {
                    s.refresh.remove(&r);
                    let n = format!("rftSECRET{}x", s.n);
                    s.refresh.insert(n.clone());
                    n
                };
                json(format!(
                    "{{\"token\":\"{t}\",\"refresh_token\":\"{next}\"}}"
                ))
            }
            ("POST", "/api/logout") => {
                if !vuln {
                    s.sessions.remove(&bearer);
                    s.refresh.clear();
                }
                json("{\"ok\":true}".into())
            }
            ("POST", "/lab/restore") => {
                s.password = ORIGINAL_PW.into();
                json("{\"ok\":true}".into())
            }

            // ── cookie + CSRF + redirect web flow ──
            ("GET", "/web/login") => Resp::html(
                "<form><input type=\"hidden\" name=\"csrf\" value=\"csrfSECRETv\"></form>",
            ),
            ("POST", "/web/login") => {
                if form_field(&req.body, "csrf").as_deref() != Some("csrfSECRETv")
                    || form_field(&req.body, "password").as_deref() != Some(s.password.as_str())
                {
                    return Resp::html("bad login").status(403, "Forbidden");
                }
                s.n += 1;
                let sid = format!("sidSECRET{}x", s.n);
                s.sessions.insert(sid.clone());
                Resp::redirect("/web/home").header("Set-Cookie", &format!("sid={sid}; HttpOnly"))
            }
            ("GET", "/web/home") => match cookie(req, "sid") {
                Some(sid) if s.sessions.contains(&sid) => Resp::html("Welcome back"),
                _ => Resp::redirect("/web/login"),
            },
            ("POST", "/web/change") => {
                let ok = cookie(req, "sid").is_some_and(|sid| s.sessions.contains(&sid))
                    && form_field(&req.body, "csrf").as_deref() == Some("csrfSECRETv");
                if !ok {
                    return Resp::html("denied").status(403, "Forbidden");
                }
                s.password = form_field(&req.body, "new_password").unwrap_or_default();
                if !vuln {
                    s.sessions.clear();
                }
                Resp::redirect("/web/home")
            }
            _ => Resp::html("not found").status(404, "Not Found"),
        }
    }
}

const API_STEPS: &str = r#"
steps:
  login:
    method: POST
    url: /api/login
    headers: { Content-Type: application/json }
    body: '{"username":"${username}","password":"${password}"}'
    extract:
      token: { json: /token }
      refresh_token: { json: /refresh_token }
    success: { status: [200] }
  session_check:
    url: /api/me
    headers: { Authorization: "Bearer ${token}" }
    success: { status: [200] }
  reset_request:
    method: POST
    url: /api/reset-request
    extract: { reset_token: { json: /reset_token } }
  reset:
    method: POST
    url: /api/reset
    headers: { Content-Type: application/json }
    body: '{"token":"${reset_token}","new_password":"${new_password}"}'
    success: { status: [200] }
  refresh:
    method: POST
    url: /api/refresh
    body: '{"refresh_token":"${refresh_token}"}'
    extract: { refresh_token: { json: /refresh_token } }
    success: { status: [200] }
  logout:
    method: POST
    url: /api/logout
    headers: { Authorization: "Bearer ${token}" }
  cleanup:
    method: POST
    url: /lab/restore
"#;

fn scenario(base: &str, policy: &str, steps: &str) -> Scenario {
    let yaml = format!(
        r#"
base_url: {base}
synthetic_identity: {{ username: rz-synthetic-01, synthetic: true }}
mutation_scope: {{ acknowledge_state_changes: true }}
variables:
  password: "{ORIGINAL_PW}"
  new_password: "{NEW_PW}"
policy:
{policy}
{steps}
"#
    );
    serde_yaml::from_str(&yaml).expect("scenario parses")
}

const FULL_POLICY: &str = "
  revoke_sessions_on_reset: true
  reset_token_single_use: true
  reset_token_ttl_secs: 1
  reject_missing_new_password: true
  refresh_rotation: true
  revoke_session_on_logout: true
  refresh_revoked_on_logout: true";

async fn run_ok(sc: &Scenario) -> Vec<Finding> {
    run(sc, SafetyPolicy::default(), false, 5)
        .await
        .expect("scenario runs")
}

fn has(findings: &[Finding], plugin: &str) -> bool {
    findings
        .iter()
        .any(|f| f.plugin == plugin && f.confidence == Confidence::Confirmed)
}

fn violations(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.plugin != "active/auth-lifecycle")
        .collect()
}

fn inconclusive(findings: &[Finding]) -> usize {
    findings
        .iter()
        .filter(|f| f.title.contains("Inconclusive"))
        .count()
}

#[tokio::test]
async fn vulnerable_api_flags_every_policy_violation() {
    let base = serve_full(auth_app(true)).await;
    let f = run_ok(&scenario(&base, FULL_POLICY, API_STEPS)).await;
    for plugin in [
        "active/auth-session-not-revoked",
        "active/auth-reset-token-reuse",
        "active/auth-reset-token-expiry",
        "active/auth-missing-field-reset",
        "active/auth-predictable-credential",
        "active/auth-credential-echo",
        "active/auth-refresh-token",
        "active/auth-logout",
    ] {
        assert!(has(&f, plugin), "missing {plugin}: {f:#?}");
    }
    assert_eq!(inconclusive(&f), 0, "{f:#?}");
    for v in violations(&f) {
        assert!(v.cwe.is_some() && v.owasp_category.is_some() && !v.solution.is_empty());
    }
    // Setup/cleanup results are recorded.
    let log = f
        .iter()
        .find(|f| f.title == "Auth Lifecycle Scenario Run Log")
        .unwrap();
    assert!(log.evidence.as_deref().unwrap().contains("cleanup after"));
}

#[tokio::test]
async fn fixed_api_reports_no_violation() {
    let base = serve_full(auth_app(false)).await;
    let f = run_ok(&scenario(&base, FULL_POLICY, API_STEPS)).await;
    assert!(violations(&f).is_empty(), "{f:#?}");
    assert_eq!(inconclusive(&f), 0, "{f:#?}");
}

#[tokio::test]
async fn secrets_never_appear_in_findings() {
    let base = serve_full(auth_app(true)).await;
    let f = run_ok(&scenario(&base, FULL_POLICY, API_STEPS)).await;
    let out = serde_json::to_string(&f).unwrap();
    for secret in [ORIGINAL_PW, NEW_PW, FALLBACK_PW, "SECRET"] {
        assert!(!out.contains(secret), "leaked `{secret}` in {out}");
    }
}

const TEMP_STEPS: &str = r#"
steps:
  reset:
    method: POST
    url: /api/admin/temp-reset
    extract: { temp_password: { json: /temp_password } }
"#;

#[tokio::test]
async fn temp_credential_uniqueness_vulnerable_vs_fixed() {
    let policy = "  unique_temp_passwords: true\n  password_in_response_allowed: true";
    let vuln = run_ok(&scenario(
        &serve_full(auth_app(true)).await,
        policy,
        TEMP_STEPS,
    ))
    .await;
    assert!(
        has(&vuln, "active/auth-predictable-credential"),
        "{vuln:#?}"
    );
    let fixed = run_ok(&scenario(
        &serve_full(auth_app(false)).await,
        policy,
        TEMP_STEPS,
    ))
    .await;
    assert!(violations(&fixed).is_empty(), "{fixed:#?}");
}

const COOKIE_STEPS: &str = r#"
steps:
  login:
    - url: /web/login
      extract: { csrf: { regex: 'name="csrf" value="([^"]+)"' } }
    - method: POST
      url: /web/login
      headers: { Content-Type: application/x-www-form-urlencoded }
      body: "csrf=${csrf}&username=${username}&password=${password}"
      extract: { sid: { cookie: sid } }
      success: { status: [302] }
  session_check:
    url: /web/home
    headers: { Cookie: "sid=${sid}" }
    follow_redirects: true
    success: { status: [200], body_contains: Welcome }
  change_password:
    method: POST
    url: /web/change
    headers: { Cookie: "sid=${sid}", Content-Type: application/x-www-form-urlencoded }
    body: "csrf=${csrf}&new_password=${new_password}"
    success: { status: [302] }
  cleanup:
    method: POST
    url: /lab/restore
"#;

#[tokio::test]
async fn cookie_csrf_session_survives_password_change() {
    let policy = "  revoke_sessions_on_change: true";
    let vuln = run_ok(&scenario(
        &serve_full(auth_app(true)).await,
        policy,
        COOKIE_STEPS,
    ))
    .await;
    assert!(has(&vuln, "active/auth-session-not-revoked"), "{vuln:#?}");
    assert!(!serde_json::to_string(&vuln).unwrap().contains("SECRET"));
    let fixed = run_ok(&scenario(
        &serve_full(auth_app(false)).await,
        policy,
        COOKIE_STEPS,
    ))
    .await;
    assert!(violations(&fixed).is_empty(), "{fixed:#?}");
    assert_eq!(inconclusive(&fixed), 0, "{fixed:#?}");
}

#[tokio::test]
async fn unusable_scenario_is_inconclusive_not_a_finding() {
    let base = serve_full(auth_app(true)).await;
    // Wrong password: login never succeeds, so nothing can be concluded.
    let mut sc = scenario(&base, "  revoke_sessions_on_reset: true", API_STEPS);
    sc.variables
        .insert("password".into(), "wrong-password".into());
    let f = run_ok(&sc).await;
    assert!(violations(&f).is_empty(), "{f:#?}");
    assert_eq!(inconclusive(&f), 1, "{f:#?}");
}

#[tokio::test]
async fn refuses_without_opt_ins_or_under_read_only_safe() {
    let base = serve_full(auth_app(true)).await;
    let sc = scenario(&base, FULL_POLICY, API_STEPS);
    let ro = SafetyPolicy {
        read_only_safe: true,
        ..Default::default()
    };
    assert!(run(&sc, ro, false, 5).await.is_err());

    let mut no_synth = sc.clone();
    no_synth.synthetic_identity.synthetic = false;
    assert!(run(&no_synth, SafetyPolicy::default(), false, 5)
        .await
        .is_err());

    let mut no_ack = sc.clone();
    no_ack.mutation_scope.acknowledge_state_changes = false;
    assert!(run(&no_ack, SafetyPolicy::default(), false, 5)
        .await
        .is_err());

    let mut off_scope = sc;
    off_scope.mutation_scope.hosts = vec!["other.example".into()];
    let f = run_ok(&off_scope).await;
    assert!(violations(&f).is_empty() && inconclusive(&f) > 0, "{f:#?}");
}
