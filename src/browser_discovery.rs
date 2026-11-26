//! Opt-in browser-assisted discovery (SPA + authenticated API surface).
//!
//! Drives an already-installed Chromium / Chrome / Edge over the Chrome
//! DevTools Protocol (no browser-automation crate): the browser is spawned
//! headless with a fresh temporary profile (deleted afterwards), every request
//! it makes is paused via `Fetch.requestPaused`, checked against origin scope,
//! exclusions and the request budget, and either recorded + continued or
//! blocked. Recorded requests become `DiscoveredUrl { source: Browser }` with
//! body *shapes* (types, not values) and redacted credential headers.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio::time::{timeout, timeout_at, Instant};
use url::Url;

use crate::agent::trace::redact_string;
use crate::types::{DiscoveredUrl, Finding, Severity, UrlSource};

/// Always-on exclusions, matched on `"METHOD path?query"` (case-insensitive).
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "logout", "log-out", "signout", "sign-out", "delete", "destroy",
];
const PLUGIN: &str = "passive/browser-discovery";
const SETTLE: Duration = Duration::from_millis(1200);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Browser-generated headers that say nothing about the API contract.
const NOISE_HEADERS: &[&str] = &[
    "user-agent",
    "accept-language",
    "accept-encoding",
    "referer",
    "origin",
    "upgrade-insecure-requests",
    "dnt",
    "cache-control",
    "pragma",
    "connection",
    "host",
];
/// Header names whose values are credentials and are never stored.
const SENSITIVE_HEADER_PARTS: &[&str] = &[
    "auth", "cookie", "token", "csrf", "xsrf", "key", "secret", "session",
];

/// CLI flags (flattened into `rustzap scan`).
#[derive(clap::Args, Debug, Clone, Default)]
pub struct BrowserDiscoveryArgs {
    /// Opt-in: drive a local headless Chromium/Chrome/Edge (isolated temp profile) and import the requests it makes
    #[arg(long)]
    pub browser_discovery: bool,
    /// Browser executable (default: auto-detect Chrome/Chromium/Edge, or env RUSTZAP_BROWSER)
    #[arg(long, value_name = "PATH")]
    pub browser_path: Option<String>,
    /// Max page navigations during browser discovery
    #[arg(long, default_value = "20")]
    pub browser_max_navigations: usize,
    /// Max in-scope requests the browser may issue; later ones are blocked
    #[arg(long, default_value = "300")]
    pub browser_max_requests: usize,
    /// Extra origins the browser may contact (comma-separated; default: target origin only)
    #[arg(long, value_delimiter = ',', value_name = "ORIGIN")]
    pub browser_allow_origin: Vec<String>,
    /// Extra exclusion substrings on "METHOD path?query" (logout/signout/delete/destroy always excluded)
    #[arg(long, value_delimiter = ',', value_name = "PATTERN")]
    pub browser_exclude: Vec<String>,
    /// YAML/JSON synthetic-login script (steps: navigate / fill / click / wait / wait_for)
    #[arg(long, value_name = "FILE")]
    pub browser_login: Option<String>,
}

impl BrowserDiscoveryArgs {
    /// `None` unless `--browser-discovery` was given.
    pub fn into_config(self) -> Result<Option<BrowserDiscoveryConfig>> {
        if !self.browser_discovery {
            return Ok(None);
        }
        let login = match self.browser_login {
            Some(p) => {
                let s = std::fs::read_to_string(&p)
                    .with_context(|| format!("Read browser login script {p}"))?;
                Some(serde_yaml::from_str(&s).with_context(|| format!("Parse {p}"))?)
            }
            None => None,
        };
        Ok(Some(BrowserDiscoveryConfig {
            browser_path: self.browser_path.map(PathBuf::from),
            max_navigations: self.browser_max_navigations,
            max_requests: self.browser_max_requests,
            allow_origins: self.browser_allow_origin,
            excludes: self.browser_exclude,
            login,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct BrowserDiscoveryConfig {
    pub browser_path: Option<PathBuf>,
    pub max_navigations: usize,
    pub max_requests: usize,
    /// Origins allowed in addition to the target's.
    pub allow_origins: Vec<String>,
    /// Exclusions in addition to [`DEFAULT_EXCLUDES`].
    pub excludes: Vec<String>,
    pub login: Option<LoginScript>,
}

/// Synthetic-login workflow, e.g.
/// ```yaml
/// steps:
///   - navigate: /login
///   - fill: { selector: "#user", value: alice }
///   - fill: { selector: "#pass", value_env: RZ_LOGIN_PASS }
///   - click: "#submit"
///   - wait_for: "#dashboard"
/// success_selector: "#dashboard"
/// ```
#[derive(Clone, Deserialize)]
pub struct LoginScript {
    // serde_yaml 0.9 wants `!tag` for enums; accept the documented `- navigate: /x` map form.
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub steps: Vec<LoginStep>,
    #[serde(default)]
    pub success_selector: Option<String>,
}

// Never print fill values (they are credentials).
impl std::fmt::Debug for LoginScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LoginScript({} steps)", self.steps.len())
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginStep {
    Navigate(String),
    Fill {
        selector: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        value_env: Option<String>,
    },
    Click(String),
    /// Milliseconds.
    Wait(u64),
    WaitFor(String),
}

/// What the browser saw and could not see; serialized into the finding evidence.
#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub browser: Option<String>,
    pub visited: Vec<String>,
    pub inaccessible: Vec<String>,
    pub excluded: Vec<String>,
    pub blocked_out_of_scope: usize,
    pub requests_allowed: usize,
    pub requests_captured: usize,
    pub navigation_budget_exhausted: bool,
    pub request_budget_exhausted: bool,
    pub login: Option<String>,
    pub error: Option<String>,
}

/// Locate a Chromium-family browser: explicit path, `RUSTZAP_BROWSER`, well-known
/// install locations, then PATH (shared `executable` discovery).
pub fn find_browser(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.is_file().then(|| p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("RUSTZAP_BROWSER") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    #[allow(unused_mut)]
    let mut fixed: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    {
        for (var, tail) in [
            ("ProgramFiles", r"Google\Chrome\Application\chrome.exe"),
            ("ProgramFiles(x86)", r"Google\Chrome\Application\chrome.exe"),
            ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
            ("ProgramFiles", r"Chromium\Application\chrome.exe"),
            (
                "ProgramFiles(x86)",
                r"Microsoft\Edge\Application\msedge.exe",
            ),
            ("ProgramFiles", r"Microsoft\Edge\Application\msedge.exe"),
        ] {
            if let Some(base) = std::env::var_os(var) {
                fixed.push(PathBuf::from(base).join(tail));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        fixed.extend(
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ]
            .map(PathBuf::from),
        );
    }
    if let Some(p) = fixed.into_iter().find(|p| p.is_file()) {
        return Some(p);
    }
    let d = crate::executable::Discovery::default();
    [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "msedge",
        "microsoft-edge",
    ]
    .iter()
    .find_map(|n| d.find(n))
}

/// Run browser discovery. Never fails: a missing browser or a CDP error is
/// printed and recorded in the returned finding's coverage evidence.
pub async fn discover(
    cfg: &BrowserDiscoveryConfig,
    target: &str,
    seeds: &[DiscoveredUrl],
    insecure: bool,
) -> (Vec<DiscoveredUrl>, Finding) {
    let mut st = State::new(Url::parse(target).ok().as_ref(), cfg);
    let res = match (Url::parse(target), find_browser(cfg.browser_path.as_deref())) {
        (Err(e), _) => Err(anyhow!("invalid target {target}: {e}")),
        (_, None) => Err(anyhow!(
            "no Chromium/Chrome/Edge executable found; install one or pass --browser-path / set RUSTZAP_BROWSER"
        )),
        (Ok(t), Some(exe)) => {
            st.cov.browser = Some(exe.display().to_string());
            run(&exe, cfg, &t, seeds, insecure, &mut st).await
        }
    };
    if let Err(e) = res {
        eprintln!("⚠ browser discovery: {e:#}");
        st.cov.error = Some(format!("{e:#}"));
    }
    st.cov.requests_allowed = st.allowed;
    st.cov.requests_captured = st.found.len();
    let title = match (&st.cov.browser, &st.cov.error) {
        (None, _) => "Browser Discovery Unavailable",
        (Some(_), Some(_)) => "Browser Discovery Incomplete",
        _ => "Browser Discovery Completed",
    };
    let finding = Finding::new(
        title,
        Severity::Info,
        target,
        format!(
            "Browser-assisted discovery captured {} request(s) over {} navigation(s); {} inaccessible screen(s), {} excluded action(s).",
            st.found.len(),
            st.cov.visited.len(),
            st.cov.inaccessible.len(),
            st.cov.excluded.len()
        ),
        "Review the coverage evidence: inaccessible screens, excluded actions, budget limits and login status show what the browser could not reach.",
        PLUGIN,
    )
    .with_evidence(serde_json::to_string(&st.cov).unwrap_or_default());
    (st.found, finding)
}

/// Deduping merge keyed by method + URL (query names only) + body shape, so
/// distinct methods and payload shapes are never collapsed.
pub fn merge(into: &mut Vec<DiscoveredUrl>, extra: Vec<DiscoveredUrl>) {
    let mut seen: HashSet<String> = into.iter().map(dedupe_key).collect();
    into.extend(extra.into_iter().filter(|d| seen.insert(dedupe_key(d))));
}

pub fn dedupe_key(du: &DiscoveredUrl) -> String {
    let (base, names) = match Url::parse(&du.url) {
        Ok(mut u) => {
            let mut n: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
            n.sort();
            n.dedup();
            u.set_query(None);
            u.set_fragment(None);
            (u.to_string(), n.join("&"))
        }
        Err(_) => (du.url.clone(), String::new()),
    };
    format!(
        "{} {}?{} {}",
        du.method,
        base,
        names,
        du.body.as_deref().unwrap_or("")
    )
}

/// Convert a CDP `Network.Request` object (as carried by `Fetch.requestPaused`
/// / `Network.requestWillBeSent`) into a redacted, shape-only `DiscoveredUrl`.
pub fn request_to_discovered(req: &Value) -> Option<DiscoveredUrl> {
    let mut url = Url::parse(req["url"].as_str()?).ok()?;
    url.set_fragment(None);
    let method = req["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
    let mut du = DiscoveredUrl::new(redact_string(url.as_str()), method, UrlSource::Browser);
    for (name, val) in req["headers"].as_object().into_iter().flatten() {
        let lower = name.to_ascii_lowercase();
        if NOISE_HEADERS.contains(&lower.as_str()) || lower.starts_with("sec-") {
            continue;
        }
        let val = val.as_str().unwrap_or("");
        if lower == "content-type" {
            du.content_type = Some(val.to_string());
        }
        let stored = if SENSITIVE_HEADER_PARTS.iter().any(|s| lower.contains(s)) {
            "[REDACTED]".to_string()
        } else {
            redact_string(val)
        };
        du.headers.push((name.clone(), stored));
    }
    if let Some(body) = req["postData"].as_str() {
        let ct = du
            .content_type
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let keys: Vec<String> = if ct.contains("x-www-form-urlencoded") {
            let keys: Vec<String> = url::form_urlencoded::parse(body.as_bytes())
                .map(|(k, _)| k.into_owned())
                .collect();
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            for k in &keys {
                ser.append_pair(k, "");
            }
            du.body = Some(ser.finish());
            keys
        } else if let Ok(v) = serde_json::from_str::<Value>(body) {
            du.body = Some(shape(&v).to_string());
            v.as_object()
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for k in keys {
            if !du.parameters.contains(&k) {
                du.parameters.push(k);
            }
        }
    }
    Some(du)
}

/// JSON body shape: keys and types kept, values replaced with type placeholders.
fn shape(v: &Value) -> Value {
    match v {
        Value::String(_) => json!("string"),
        Value::Number(_) => json!(0),
        Value::Bool(_) => json!(false),
        Value::Null => Value::Null,
        Value::Array(a) => Value::Array(a.first().map(shape).into_iter().collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), shape(x))).collect()),
    }
}

/// Scope / exclusion / budget gate plus the captured inventory.
struct State {
    origins: HashSet<String>,
    excludes: Vec<String>,
    max_requests: usize,
    allowed: usize,
    seen: HashSet<String>,
    found: Vec<DiscoveredUrl>,
    cov: Coverage,
}

impl State {
    fn new(target: Option<&Url>, cfg: &BrowserDiscoveryConfig) -> Self {
        let origins = target
            .map(|t| t.origin().ascii_serialization())
            .into_iter()
            .chain(
                cfg.allow_origins
                    .iter()
                    .filter_map(|o| Url::parse(o.trim()).ok())
                    .map(|u| u.origin().ascii_serialization()),
            )
            .collect();
        let excludes = DEFAULT_EXCLUDES
            .iter()
            .map(|s| s.to_string())
            .chain(cfg.excludes.iter().map(|s| s.trim().to_ascii_lowercase()))
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            origins,
            excludes,
            max_requests: cfg.max_requests,
            allowed: 0,
            seen: HashSet::new(),
            found: Vec::new(),
            cov: Coverage::default(),
        }
    }

    fn in_scope(&self, url: &str) -> bool {
        Url::parse(url)
            .map(|u| self.origins.contains(&u.origin().ascii_serialization()))
            .unwrap_or(false)
    }

    /// Host is ignored so a target named e.g. `delete-me.test` is still usable.
    fn excluded(&self, method: &str, url: &str) -> bool {
        let Ok(u) = Url::parse(url) else {
            return false;
        };
        let s = format!("{method} {}?{}", u.path(), u.query().unwrap_or("")).to_ascii_lowercase();
        self.excludes.iter().any(|e| s.contains(e))
    }

    /// Gate one browser request; returns true when it may proceed.
    fn on_request(&mut self, req: &Value, resource_type: &str) -> bool {
        let method = req["method"].as_str().unwrap_or("GET");
        let url = req["url"].as_str().unwrap_or("");
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return true; // data:/blob: never leave the browser
        }
        if !self.in_scope(url) {
            self.cov.blocked_out_of_scope += 1;
            return false;
        }
        if self.excluded(method, url) {
            let e = format!("{method} {}", redact_string(url));
            if !self.cov.excluded.contains(&e) {
                self.cov.excluded.push(e);
            }
            return false;
        }
        if self.allowed >= self.max_requests {
            self.cov.request_budget_exhausted = true;
            return false;
        }
        self.allowed += 1;
        if matches!(
            resource_type,
            "Document" | "XHR" | "Fetch" | "EventSource" | "Other"
        ) {
            if let Some(du) = request_to_discovered(req) {
                if self.seen.insert(dedupe_key(&du)) {
                    self.found.push(du);
                }
            }
        }
        true
    }
}

async fn run(
    exe: &Path,
    cfg: &BrowserDiscoveryConfig,
    target: &Url,
    seeds: &[DiscoveredUrl],
    insecure: bool,
    st: &mut State,
) -> Result<()> {
    let profile = std::env::temp_dir().join(format!("rustzap-browser-{}", crate::types::uuid_v4()));
    std::fs::create_dir_all(&profile).context("create temporary browser profile")?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args([
        "--headless=new",
        "--remote-debugging-port=0",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-component-update",
        "--disable-default-apps",
        "--mute-audio",
    ])
    .arg(format!("--user-data-dir={}", profile.display()));
    if insecure {
        cmd.arg("--ignore-certificate-errors");
    }
    if std::env::var_os("RUSTZAP_BROWSER_NO_SANDBOX").is_some() {
        cmd.arg("--no-sandbox"); // containers running as root
    }
    cmd.arg("about:blank")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let res = match cmd.spawn() {
        Ok(mut child) => {
            let res = drive(&mut child, cfg, target, seeds, st).await;
            if timeout(Duration::from_secs(5), child.wait()).await.is_err() {
                let _ = child.kill().await;
            }
            res
        }
        Err(e) => Err(anyhow!("failed to launch {}: {e}", exe.display())),
    };
    // Helper processes may hold the profile for a moment after exit.
    for _ in 0..15 {
        if std::fs::remove_dir_all(&profile).is_ok() || !profile.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    res
}

async fn drive(
    child: &mut tokio::process::Child,
    cfg: &BrowserDiscoveryConfig,
    target: &Url,
    seeds: &[DiscoveredUrl],
    st: &mut State,
) -> Result<()> {
    let stderr = child.stderr.take().context("browser stderr")?;
    let mut lines = BufReader::new(stderr).lines();
    let ws_url = timeout(Duration::from_secs(20), async {
        while let Some(l) = lines.next_line().await? {
            if let Some(i) = l.find("ws://") {
                return Ok::<String, anyhow::Error>(l[i..].trim().to_string());
            }
        }
        bail!("browser exited before exposing a DevTools endpoint")
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for the DevTools endpoint"))??;
    // Keep draining so a chatty browser never blocks on a full pipe.
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });

    let (w, rx) = ws_connect(&ws_url).await?;
    let mut d = Driver {
        w,
        rx,
        next_id: 0,
        session: None,
        st,
    };
    let t = d
        .call("Target.createTarget", json!({"url": "about:blank"}))
        .await?;
    let a = d
        .call(
            "Target.attachToTarget",
            json!({"targetId": t["targetId"], "flatten": true}),
        )
        .await?;
    d.session = a["sessionId"].as_str().map(String::from);
    d.call("Page.enable", json!({})).await?;
    d.call("Network.enable", json!({})).await?;
    d.call("Fetch.enable", json!({"patterns": [{"urlPattern": "*"}]}))
        .await?;

    if let Some(script) = &cfg.login {
        let status = match d.login(script, target).await {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("failed: {e:#}"),
        };
        d.st.cov.login = Some(status);
    }

    let mut queue: VecDeque<String> = VecDeque::from([target.to_string()]);
    queue.extend(
        seeds
            .iter()
            .filter(|s| s.method == "GET" && matches!(s.source, UrlSource::Seed | UrlSource::Link))
            .map(|s| s.url.clone()),
    );
    let mut queued: HashSet<String> = queue.iter().cloned().collect();
    while let Some(next) = queue.pop_front() {
        if !d.st.in_scope(&next) {
            continue;
        }
        if d.st.excluded("GET", &next) {
            let e = format!("GET {}", redact_string(&next));
            if !d.st.cov.excluded.contains(&e) {
                d.st.cov.excluded.push(e);
            }
            continue;
        }
        if d.st.cov.request_budget_exhausted {
            break;
        }
        if d.st.cov.visited.len() >= cfg.max_navigations {
            d.st.cov.navigation_budget_exhausted = true;
            break;
        }
        d.st.cov.visited.push(redact_string(&next));
        let nav = d.call("Page.navigate", json!({"url": next})).await?;
        if let Some(err) = nav["errorText"].as_str() {
            d.st.cov
                .inaccessible
                .push(format!("{}: {err}", redact_string(&next)));
            continue;
        }
        d.pump(SETTLE).await?;
        // Page may be mid-navigation; a failed link harvest just yields no links.
        let links = d
            .eval("Array.from(document.querySelectorAll('a[href]'), a => a.href)")
            .await
            .unwrap_or(Value::Null);
        for l in links
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if queued.insert(l.to_string()) {
                queue.push_back(l.to_string());
            }
        }
    }
    d.session = None;
    let _ = d.send("Browser.close", json!({})).await;
    Ok(())
}

struct Driver<'a> {
    w: OwnedWriteHalf,
    rx: mpsc::UnboundedReceiver<String>,
    next_id: u64,
    session: Option<String>,
    st: &'a mut State,
}

impl Driver<'_> {
    async fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        self.next_id += 1;
        let mut m = json!({"id": self.next_id, "method": method, "params": params});
        if let Some(s) = &self.session {
            m["sessionId"] = json!(s);
        }
        self.w
            .write_all(&encode_frame(&m.to_string(), rand::random()))
            .await?;
        Ok(self.next_id)
    }

    /// Send a command and wait for its reply, handling events in the meantime
    /// (a navigation only completes once its paused request is continued).
    async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.send(method, params).await?;
        let deadline = Instant::now() + CALL_TIMEOUT;
        loop {
            let msg = timeout_at(deadline, self.rx.recv())
                .await
                .map_err(|_| anyhow!("CDP {method} timed out"))?
                .ok_or_else(|| anyhow!("browser closed the DevTools connection"))?;
            let v: Value = serde_json::from_str(&msg).unwrap_or(Value::Null);
            if v["id"].as_u64() == Some(id) {
                if let Some(e) = v.get("error") {
                    bail!("CDP {method} failed: {e}");
                }
                return Ok(v["result"].clone());
            }
            self.on_message(v).await?;
        }
    }

    /// Process events for `d` (lets the page's JS issue its requests).
    async fn pump(&mut self, d: Duration) -> Result<()> {
        let deadline = Instant::now() + d;
        while let Ok(m) = timeout_at(deadline, self.rx.recv()).await {
            let m = m.ok_or_else(|| anyhow!("browser closed the DevTools connection"))?;
            self.on_message(serde_json::from_str(&m).unwrap_or(Value::Null))
                .await?;
        }
        Ok(())
    }

    async fn on_message(&mut self, v: Value) -> Result<()> {
        let p = &v["params"];
        match v["method"].as_str() {
            Some("Fetch.requestPaused") => {
                let id = p["requestId"].clone();
                if self
                    .st
                    .on_request(&p["request"], p["resourceType"].as_str().unwrap_or("Other"))
                {
                    self.send("Fetch.continueRequest", json!({"requestId": id}))
                        .await?;
                } else {
                    self.send(
                        "Fetch.failRequest",
                        json!({"requestId": id, "errorReason": "BlockedByClient"}),
                    )
                    .await?;
                }
            }
            Some("Network.responseReceived") if p["type"] == "Document" => {
                let status = p["response"]["status"].as_u64().unwrap_or(0);
                if status >= 400 {
                    let url = redact_string(p["response"]["url"].as_str().unwrap_or(""));
                    self.st
                        .cov
                        .inaccessible
                        .push(format!("{url}: HTTP {status}"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn eval(&mut self, expr: &str) -> Result<Value> {
        let r = self
            .call(
                "Runtime.evaluate",
                json!({"expression": expr, "returnByValue": true, "awaitPromise": true}),
            )
            .await?;
        if let Some(ex) = r.get("exceptionDetails") {
            bail!("script error: {}", ex["text"]);
        }
        Ok(r["result"]["value"].clone())
    }

    async fn login(&mut self, script: &LoginScript, target: &Url) -> Result<()> {
        for (i, step) in script.steps.iter().enumerate() {
            let n = i + 1;
            match step {
                LoginStep::Navigate(u) => {
                    let url = target.join(u)?;
                    if !self.st.in_scope(url.as_str()) {
                        bail!("step {n}: {url} is out of scope");
                    }
                    let r = self
                        .call("Page.navigate", json!({"url": url.as_str()}))
                        .await?;
                    if let Some(e) = r["errorText"].as_str() {
                        bail!("step {n}: navigate {url} failed: {e}");
                    }
                    self.pump(SETTLE).await?;
                }
                LoginStep::Fill {
                    selector,
                    value,
                    value_env,
                } => {
                    let v = match (value, value_env) {
                        (_, Some(env)) => std::env::var(env)
                            .map_err(|_| anyhow!("step {n}: env var {env} is not set"))?,
                        (Some(v), None) => v.clone(),
                        (None, None) => bail!("step {n}: fill needs value or value_env"),
                    };
                    // Native setter + input event so framework-controlled inputs see the value.
                    let js = format!(
                        "(() => {{ const el = document.querySelector({}); if (!el) return false; el.focus(); \
                         const d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value'); \
                         if (d && d.set) d.set.call(el, {v}); else el.value = {v}; \
                         el.dispatchEvent(new Event('input', {{bubbles: true}})); \
                         el.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }})()",
                        json!(selector),
                        v = json!(v)
                    );
                    if self.eval(&js).await? != json!(true) {
                        bail!("step {n}: selector {selector} not found");
                    }
                }
                LoginStep::Click(sel) => {
                    let js = format!(
                        "(() => {{ const el = document.querySelector({}); if (!el) return false; el.click(); return true; }})()",
                        json!(sel)
                    );
                    if self.eval(&js).await? != json!(true) {
                        bail!("step {n}: selector {sel} not found");
                    }
                    self.pump(SETTLE).await?;
                }
                LoginStep::Wait(ms) => self.pump(Duration::from_millis(*ms)).await?,
                LoginStep::WaitFor(sel) => self
                    .wait_for(sel)
                    .await
                    .with_context(|| format!("step {n}"))?,
            }
        }
        if let Some(sel) = &script.success_selector {
            self.wait_for(sel).await.context("success check")?;
        }
        Ok(())
    }

    async fn wait_for(&mut self, sel: &str) -> Result<()> {
        let js = format!("!!document.querySelector({})", json!(sel));
        for _ in 0..20 {
            if self.eval(&js).await.unwrap_or(Value::Null) == json!(true) {
                return Ok(());
            }
            self.pump(Duration::from_millis(500)).await?;
        }
        bail!("selector {sel} did not appear within 10s")
    }
}

// ── Minimal WebSocket client (RFC 6455) for the loopback DevTools socket ──

async fn ws_connect(ws_url: &str) -> Result<(OwnedWriteHalf, mpsc::UnboundedReceiver<String>)> {
    let u = Url::parse(ws_url).context("DevTools WebSocket URL")?;
    let host = u.host_str().context("DevTools URL host")?.to_string();
    let port = u.port().context("DevTools URL port")?;
    let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let (rd, mut wr) = stream.into_split();
    let key = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
    wr.write_all(
        format!(
            "GET {} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
            u.path()
        )
        .as_bytes(),
    )
    .await?;
    let mut rd = BufReader::new(rd);
    let mut status = String::new();
    rd.read_line(&mut status).await?;
    if !status.contains(" 101 ") {
        bail!("DevTools WebSocket handshake failed: {}", status.trim());
    }
    loop {
        let mut l = String::new();
        if rd.read_line(&mut l).await? == 0 {
            bail!("DevTools WebSocket closed during handshake");
        }
        if l == "\r\n" {
            break;
        }
    }
    let (tx, rx) = mpsc::unbounded_channel();
    // A reader task keeps frame parsing cancellation-safe for the timeouts above.
    tokio::spawn(async move {
        while let Ok(Some(m)) = read_message(&mut rd).await {
            if tx.send(m).is_err() {
                break;
            }
        }
    });
    Ok((wr, rx))
}

/// Masked client text frame.
fn encode_frame(text: &str, mask: [u8; 4]) -> Vec<u8> {
    let p = text.as_bytes();
    let mut f = vec![0x81u8];
    match p.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n <= 0xffff => {
            f.push(0x80 | 126);
            f.extend((n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend((n as u64).to_be_bytes());
        }
    }
    f.extend(mask);
    f.extend(p.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// Next complete text message; `None` on a close frame.
async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<String>> {
    let mut msg = Vec::new();
    loop {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await?;
        let (fin, op) = (h[0] & 0x80 != 0, h[0] & 0x0f);
        let len = match h[1] & 0x7f {
            126 => r.read_u16().await? as u64,
            127 => r.read_u64().await?,
            n => n as u64,
        };
        let mask = if h[1] & 0x80 != 0 {
            let mut m = [0u8; 4];
            r.read_exact(&mut m).await?;
            Some(m)
        } else {
            None
        };
        let mut p = vec![0u8; len as usize];
        r.read_exact(&mut p).await?;
        if let Some(m) = mask {
            p.iter_mut().enumerate().for_each(|(i, b)| *b ^= m[i % 4]);
        }
        match op {
            8 => return Ok(None),
            0..=2 => msg.extend(p),
            // shortcut: ping/pong ignored, Chrome does not ping CDP clients; reply if that changes.
            _ => continue,
        }
        if fin {
            return Ok(Some(String::from_utf8_lossy(&msg).into_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BrowserDiscoveryConfig {
        BrowserDiscoveryConfig {
            browser_path: None,
            max_navigations: 5,
            max_requests: 3,
            allow_origins: vec!["https://api.example.com".into()],
            excludes: vec!["/admin/reset".into()],
            login: None,
        }
    }

    fn state() -> State {
        State::new(Url::parse("https://app.example.com/").ok().as_ref(), &cfg())
    }

    fn req(method: &str, url: &str) -> Value {
        json!({"method": method, "url": url, "headers": {}})
    }

    #[test]
    fn converts_cdp_request_to_shape_and_redacts() {
        let r = json!({
            "method": "post",
            "url": "https://app.example.com/api/orders?token=abc123&page=2#frag",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJsecretsecret",
                "X-CSRF-Token": "csrfvalue",
                "X-Client": "web",
                "User-Agent": "Chrome",
                "sec-ch-ua": "x"
            },
            "postData": "{\"sku\":\"A1\",\"qty\":2,\"items\":[{\"id\":7}],\"gift\":true}"
        });
        let du = request_to_discovered(&r).unwrap();
        assert_eq!(du.method, "POST");
        assert_eq!(du.source, UrlSource::Browser);
        assert!(!du.url.contains("abc123") && !du.url.contains("frag"));
        assert_eq!(du.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            du.body.as_deref(),
            Some(r#"{"gift":false,"items":[{"id":0}],"qty":0,"sku":"string"}"#)
        );
        for p in ["token", "page", "sku", "qty", "items", "gift"] {
            assert!(du.parameters.iter().any(|x| x == p), "{p}");
        }
        let h = |n: &str| {
            du.headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(h("Authorization"), Some("[REDACTED]"));
        assert_eq!(h("X-CSRF-Token"), Some("[REDACTED]"));
        assert_eq!(h("X-Client"), Some("web"));
        assert_eq!(h("User-Agent"), None);
        assert_eq!(h("sec-ch-ua"), None);
    }

    #[test]
    fn form_body_keeps_keys_only() {
        let r = json!({"method": "POST", "url": "https://app.example.com/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "postData": "user=alice&pass=hunter2"});
        let du = request_to_discovered(&r).unwrap();
        assert_eq!(du.body.as_deref(), Some("user=&pass="));
        assert!(du.parameters.contains(&"pass".to_string()));
    }

    #[test]
    fn dedupe_keeps_distinct_methods_and_shapes() {
        let mk = |m: &str, body: &str| {
            request_to_discovered(
                &json!({"method": m, "url": "https://app.example.com/api/x?id=1",
                "headers": {"Content-Type": "application/json"}, "postData": body}),
            )
            .unwrap()
        };
        let mut inv = vec![DiscoveredUrl::new(
            "https://app.example.com/api/x?id=9",
            "GET",
            UrlSource::Link,
        )];
        merge(
            &mut inv,
            vec![
                request_to_discovered(&req("GET", "https://app.example.com/api/x?id=2")).unwrap(),
                mk("POST", r#"{"a":1}"#),
                mk("POST", r#"{"a":2}"#),   // same shape → collapsed
                mk("POST", r#"{"a":"s"}"#), // different type → kept
                mk("PUT", r#"{"a":1}"#),
            ],
        );
        let sig: Vec<String> = inv.iter().map(|d| d.method.clone()).collect();
        assert_eq!(sig, ["GET", "POST", "POST", "PUT"]);
    }

    #[test]
    fn scope_blocks_foreign_origins_allows_extra_and_data() {
        let mut st = state();
        assert!(st.on_request(&req("GET", "https://app.example.com/a"), "XHR"));
        assert!(st.on_request(&req("GET", "https://api.example.com/v1"), "Fetch"));
        assert!(!st.on_request(&req("GET", "https://cdn.evil.com/x.js"), "Script"));
        assert!(!st.on_request(&req("GET", "http://app.example.com/a"), "XHR"));
        assert!(st.on_request(&req("GET", "data:text/plain,hi"), "Other"));
        assert_eq!(st.cov.blocked_out_of_scope, 2);
        assert_eq!(st.found.len(), 2);
    }

    #[test]
    fn exclusions_block_logout_and_destructive_actions() {
        let mut st = state();
        assert!(!st.on_request(&req("GET", "https://app.example.com/logout"), "Document"));
        assert!(!st.on_request(&req("DELETE", "https://app.example.com/api/u/1"), "XHR"));
        assert!(!st.on_request(&req("POST", "https://app.example.com/Admin/Reset"), "XHR"));
        assert!(!st.on_request(
            &req("GET", "https://app.example.com/a?action=signout"),
            "XHR"
        ));
        assert_eq!(st.cov.excluded.len(), 4);
        assert!(st.found.is_empty());
        // Host names are not matched against exclusions.
        let t = Url::parse("https://delete-me.test/").unwrap();
        let mut st2 = State::new(Some(&t), &cfg());
        assert!(st2.on_request(&req("GET", "https://delete-me.test/home"), "Document"));
    }

    #[test]
    fn request_budget_blocks_after_limit() {
        let mut st = state();
        for i in 0..3 {
            assert!(st.on_request(&req("GET", &format!("https://app.example.com/{i}")), "XHR"));
        }
        assert!(!st.on_request(&req("GET", "https://app.example.com/9"), "XHR"));
        assert!(st.cov.request_budget_exhausted);
        assert_eq!(st.found.len(), 3);
    }

    #[test]
    fn static_assets_count_toward_budget_but_are_not_inventory() {
        let mut st = state();
        assert!(st.on_request(&req("GET", "https://app.example.com/app.js"), "Script"));
        assert_eq!(st.allowed, 1);
        assert!(st.found.is_empty());
    }

    #[test]
    fn login_script_parses_yaml() {
        let s: LoginScript = serde_yaml::from_str(
            "steps:\n  - navigate: /login\n  - fill: { selector: '#u', value: alice }\n  - fill: { selector: '#p', value_env: RZ_PASS }\n  - click: '#go'\n  - wait: 500\n  - wait_for: '#dash'\nsuccess_selector: '#dash'\n",
        )
        .unwrap();
        assert_eq!(s.steps.len(), 6);
        assert!(matches!(
            s.steps[2],
            LoginStep::Fill {
                value_env: Some(_),
                ..
            }
        ));
        assert!(matches!(s.steps[4], LoginStep::Wait(500)));
        assert!(!format!("{s:?}").contains("alice"));
    }

    #[tokio::test]
    async fn websocket_frames_round_trip() {
        for n in [5usize, 300, 70_000] {
            let text = "x".repeat(n);
            let frame = encode_frame(&text, [1, 2, 3, 4]);
            let mut r: &[u8] = &frame;
            assert_eq!(
                read_message(&mut r).await.unwrap().as_deref(),
                Some(text.as_str())
            );
        }
        // Fragmented unmasked server message with an interleaved ping.
        let mut r: &[u8] = &[0x01, 2, b'a', b'b', 0x89, 0, 0x80, 1, b'c'];
        assert_eq!(read_message(&mut r).await.unwrap().as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn missing_browser_is_reported_not_skipped() {
        let mut c = cfg();
        c.browser_path = Some(PathBuf::from("/definitely/not/a/browser"));
        let (urls, f) = discover(&c, "https://app.example.com/", &[], false).await;
        assert!(urls.is_empty());
        assert_eq!(f.title, "Browser Discovery Unavailable");
        assert_eq!(f.plugin, PLUGIN);
        assert!(f.evidence.unwrap_or_default().contains("no Chromium"));
    }
}
