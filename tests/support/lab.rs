//! Shared test harness for the deliberately-vulnerable loopback lab.
//!
//! Files under `tests/support/` are NOT compiled as their own test binaries by
//! Cargo; each consumer pulls this in with `#[path = "support/lab.rs"] mod lab;`.
//!
//! `serve_full` extends the fixed `200 OK`/`text/html` server in
//! `tests/no_self_validation.rs` with custom status codes, arbitrary (and
//! repeatable) headers, request bodies, and path routing — everything the
//! passive checks, open-redirect, http-methods, and POST-based plugins need.
//!
//! `vulnerable_app` is the single source of truth for the vulnerable responder,
//! shared by the active/pipeline/passive/spider matrices. Every branch honors
//! the evidence model (`src/verify.rs`): the untouched baseline GET is CLEAN and
//! the tell-tale signature appears ONLY when the payload marker is present.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rustzap::types::{DiscoveredUrl, UrlSource};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ── Request / Response model ────────────────────────────────────────────────

/// A parsed inbound request the handler sees.
pub struct Req {
    pub method: String,
    pub path: String,
    /// Raw, still-percent-encoded query string (no leading `?`).
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl Req {
    /// Decoded value of a query parameter (`+` → space, `%XX` → byte).
    pub fn query_param(&self, key: &str) -> Option<String> {
        for pair in self.query.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            if k == key {
                return Some(pct_decode(it.next().unwrap_or("")));
            }
        }
        None
    }

    /// The full decoded query string (all params joined) — handy for plugins
    /// that inject into whichever param exists.
    pub fn query_decoded(&self) -> String {
        pct_decode(&self.query)
    }
}

/// What the handler wants sent back.
pub struct Resp {
    pub status: u16,
    pub reason: &'static str,
    /// Header list (a Vec so `Set-Cookie` and friends can repeat).
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Resp {
    pub fn html(body: impl Into<String>) -> Resp {
        Resp {
            status: 200,
            reason: "OK",
            headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
            body: body.into(),
        }
    }

    /// A bare 200 with a body and no default headers (caller adds them).
    pub fn ok(body: impl Into<String>) -> Resp {
        Resp {
            status: 200,
            reason: "OK",
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn status(mut self, status: u16, reason: &'static str) -> Resp {
        self.status = status;
        self.reason = reason;
        self
    }

    pub fn header(mut self, k: &str, v: &str) -> Resp {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }

    pub fn body(mut self, b: impl Into<String>) -> Resp {
        self.body = b.into();
        self
    }

    /// A 302 redirect to `loc`.
    pub fn redirect(loc: &str) -> Resp {
        Resp {
            status: 302,
            reason: "Found",
            headers: vec![("Location".into(), loc.to_string())],
            body: String::new(),
        }
    }
}

// ── Loopback server ─────────────────────────────────────────────────────────

/// Boot a one-connection-per-request HTTP/1.1 server on an ephemeral loopback
/// port. `handler` maps a parsed `Req` to a `Resp`. Returns the base URL
/// (`http://127.0.0.1:PORT`).
pub async fn serve_full<F>(handler: F) -> String
where
    F: Fn(&Req) -> Resp + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let Some(req) = read_request(&mut sock).await else {
                    return;
                };
                let resp = handler(&req);
                let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason);
                let mut has_len = false;
                for (k, v) in &resp.headers {
                    if k.eq_ignore_ascii_case("content-length") {
                        has_len = true;
                    }
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                if !has_len {
                    out.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
                }
                out.push_str("Connection: close\r\n\r\n");
                out.push_str(&resp.body);
                let _ = sock.write_all(out.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}")
}

/// Read one request: request line + headers, then `Content-Length` body bytes.
async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    // Read until we have the header terminator.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 1 << 20 {
            return None; // 1 MB header guard
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // Body (Content-Length bytes past the terminator).
    let body_start = header_end + 4;
    let want: usize = headers
        .get("content-length")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buf[body_start..].to_vec();
    while body.len() < want {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if want > 0 {
        body.truncate(want);
    }

    Some(Req {
        method,
        path,
        query,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Percent-decode a query fragment: `+` → space, `%XX` → byte.
pub fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ── DiscoveredUrl builders ──────────────────────────────────────────────────

pub fn du_get(url: &str, params: &[&str]) -> DiscoveredUrl {
    DiscoveredUrl {
        url: url.to_string(),
        method: "GET".to_string(),
        parameters: params.iter().map(|s| s.to_string()).collect(),
        source: UrlSource::Link,
    }
}

pub fn du_post(url: &str, params: &[&str]) -> DiscoveredUrl {
    DiscoveredUrl {
        url: url.to_string(),
        method: "POST".to_string(),
        parameters: params.iter().map(|s| s.to_string()).collect(),
        source: UrlSource::Form,
    }
}

/// A reqwest client with redirects disabled (open-redirect / redirect-chain).
pub fn client_nofollow() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

// ── The vulnerable application ──────────────────────────────────────────────

/// A shared secret marker embedded in the mock LLM's "system prompt".
pub const LLM_SYSTEM_MARKER: &str = "rustzap-lab-secret-directive";

/// The single vulnerable responder. Stateless endpoints only; the second-order
/// SQLi endpoint needs its own stateful handler (see `second_order_app`).
pub fn vulnerable_app(req: &Req) -> Resp {
    // OPTIONS anywhere → advertise dangerous methods (http-methods, always_run).
    if req.method == "OPTIONS" {
        return Resp::ok("")
            .status(204, "No Content")
            .header("Allow", "GET, POST, PUT, DELETE, TRACE");
    }

    match req.path.as_str() {
        "/" | "/index.html" => Resp::html(index_html()),
        "/robots.txt" => Resp::ok(
            "User-agent: *\nDisallow: /admin/\nSitemap: /sitemap.xml\n",
        )
        .header("Content-Type", "text/plain"),
        "/sitemap.xml" => Resp::ok(sitemap_xml()).header("Content-Type", "application/xml"),
        "/static/app.js" => Resp::ok("fetch('/dast/search?q=1');").header("Content-Type", "application/javascript"),

        "/dast/xss" => dast_xss(req),
        "/dast/sqli" => dast_sqli(req),
        "/dast/traversal" => dast_traversal(req),
        "/dast/redirect" => dast_redirect(req),
        "/dast/fetch" => dast_ssrf(req),
        "/dast/ping" => dast_cmd(req),
        "/dast/render" => dast_ssti(req),
        "/dast/blind" => dast_boolean(req),
        "/dast/union" => dast_union(req),
        "/dast/version" => dast_fingerprint(req),
        "/dast/xml" => dast_xxe(req),
        "/dast/login" => dast_nosql_post(req),
        "/dast/search" => dast_nosql_get(req),
        "/graphql" => dast_graphql(req),

        // Redirect loop (relative Locations) → redirect-chain "Redirect Loop".
        "/dast/chain1" => Resp::ok("").status(302, "Found").header("Location", "/dast/chain2"),
        "/dast/chain2" => Resp::ok("").status(302, "Found").header("Location", "/dast/chain1"),

        // Passive variants.
        "/passive/naked" => Resp::ok("<html><body>hello</body></html>")
            .header("Content-Type", "text/html")
            .header("Server", "Apache/2.4.1")
            .header("X-Powered-By", "Express"),
        "/passive/cookie" => Resp::html("ok").header("Set-Cookie", "session=abc123; Path=/"),
        "/passive/cors" => Resp::html("ok")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Credentials", "true"),
        "/passive/csp" => Resp::html("ok").header(
            "Content-Security-Policy",
            "default-src 'unsafe-inline' 'unsafe-eval' *",
        ),
        "/passive/leak" => Resp::html(
            "config: password=\"hunter2example\" token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.somesignatureGoesHere1234",
        ),
        "/passive/error" => Resp::ok(
            "java.lang.NullPointerException: Exception at com.app.Main (Main.java:42)\nTraceback",
        )
        .status(500, "Internal Server Error")
        .header("Content-Type", "text/html"),
        "/.well-known/security.txt" => {
            Resp::ok("Contact: mailto:sec@example.com\nExpires: 2000-01-01T00:00:00Z\n")
                .header("Content-Type", "text/plain")
        }

        _ => Resp::html("<html><body>not found</body></html>").status(404, "Not Found"),
    }
}

// -- active endpoint bodies (baseline clean, payload-triggered) --

fn dast_xss(req: &Req) -> Resp {
    // Reflect the raw decoded value so a `<svg/onload=..>` breakout appears verbatim.
    let q = req.query_param("q").unwrap_or_default();
    Resp::html(format!("<html><body>Results for: {q}</body></html>"))
}

fn dast_sqli(req: &Req) -> Resp {
    let v = req.query_decoded();
    if v.contains('\'') || v.contains('"') || v.contains(')') {
        return Resp::html(
            "<b>Database error</b>: You have an error in your SQL syntax; check the manual near '''",
        );
    }
    Resp::html("<ul><li>item 1</li><li>item 2</li></ul>")
}

fn dast_traversal(req: &Req) -> Resp {
    let v = req.query_decoded();
    if v.contains("etc/passwd") {
        return Resp::ok(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        );
    }
    Resp::html("<pre>README.txt</pre>")
}

fn dast_redirect(req: &Req) -> Resp {
    let v = req
        .query_param("q")
        .or_else(|| req.query_param("next"))
        .unwrap_or_default();
    if v.contains("rustzap-canary") {
        return Resp::redirect(&v);
    }
    Resp::html("home")
}

fn dast_ssrf(req: &Req) -> Resp {
    let v = req.query_decoded();
    if v.contains("169.254.169.254") {
        // Metadata indicators that are NOT substrings of the payload URL.
        return Resp::ok(
            "ami-id: ami-0abc\ninstance-id: i-1234567890\niam/security-credentials/role",
        );
    }
    Resp::html("fetched a page")
}

fn dast_cmd(req: &Req) -> Resp {
    let v = req.query_decoded();
    if v.contains("cat /etc/passwd") {
        return Resp::ok("root:x:0:0:root:/root:/bin/bash");
    }
    if v.contains(";id") || v.contains("|id") || v.contains("`id`") || v.contains("$(id)") {
        return Resp::ok("uid=0(root) gid=0(root) groups=0(root)");
    }
    Resp::html("pong")
}

fn dast_ssti(req: &Req) -> Resp {
    // Evaluate the injected A*B arithmetic; emit only the product (never the raw expr).
    let v = req.query_decoded();
    if let Some(product) = eval_mul(&v) {
        return Resp::html(format!("<html><body>Hello {product}</body></html>"));
    }
    Resp::html("<html><body>Hello guest</body></html>")
}

/// Find a `*` flanked by digits and multiply them. Scans every `*` so it works
/// for `{{a*b}}`, `${a*b}`, `<%= a*b %>`, and leading-`*` forms like `*{a*b}`.
fn eval_mul(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c != b'*' {
            continue;
        }
        let left: String = s[..i]
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let right: String = s[i + 1..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let (Ok(a), Ok(b)) = (left.parse::<i64>(), right.parse::<i64>()) {
            return Some(a * b);
        }
    }
    None
}

fn dast_boolean(req: &Req) -> Resp {
    let v = req.query_decoded().to_lowercase();
    // TRUE branch → byte-identical to baseline; FALSE branch → clearly shorter.
    let is_false = v.contains("1=2") || v.contains("and 1=2") || v.contains("' and '1'='2");
    if is_false {
        return Resp::html("<html><body>no results</body></html>");
    }
    Resp::html(
        "<html><body>Welcome back, user #1. Your dashboard has 3 items and 2 alerts.</body></html>",
    )
}

fn dast_union(req: &Req) -> Resp {
    let v = req.query_decoded().to_lowercase();
    if v.contains("union") && v.contains("rustzap9x") {
        return Resp::html("<html><body>rustzap9x</body></html>");
    }
    Resp::html("<html><body>report</body></html>")
}

fn dast_fingerprint(req: &Req) -> Resp {
    let v = req.query_decoded().to_lowercase();
    if v.contains("union") && (v.contains("@@version") || v.contains("version()")) {
        return Resp::html("<html><body>8.0.32-MySQL Community Server (GPL)</body></html>");
    }
    Resp::html("<html><body>v1</body></html>")
}

fn dast_xxe(req: &Req) -> Resp {
    if req.method == "POST" && req.body.contains("file:///etc/passwd") {
        return Resp::ok("root:x:0:0:root:/root:/bin/bash");
    }
    if req.method != "POST" {
        return Resp::html("send XML").status(405, "Method Not Allowed");
    }
    Resp::ok("<result>ok</result>")
}

fn dast_nosql_post(req: &Req) -> Resp {
    // Operator injection (`{"$ne":""}`) succeeds; benign string creds fail.
    let has_operator = req.body.contains("$ne")
        || req.body.contains("$gt")
        || req.body.contains("$regex")
        || req.body.contains("$where")
        || req.body.contains("$in");
    if req.method == "POST" && has_operator {
        return Resp::ok("{\"token\":\"eyJ.WELCOME.\",\"success\":true,\"welcome\":\"dashboard\"}")
            .header("Content-Type", "application/json");
    }
    Resp::ok("{\"error\":\"invalid credentials\"}")
        .status(401, "Unauthorized")
        .header("Content-Type", "application/json")
}

fn dast_nosql_get(req: &Req) -> Resp {
    let raw = req.query.to_lowercase();
    if raw.contains("%24ne") || raw.contains("$ne") || raw.contains("%5b%24") || raw.contains("[$")
    {
        // Operator injection grows the body far past the baseline.
        return Resp::ok(
            "[{\"id\":1,\"name\":\"alice\"},{\"id\":2,\"name\":\"bob\"},{\"id\":3,\"name\":\"carol\"},{\"id\":4,\"name\":\"dave\"},{\"id\":5,\"name\":\"erin\"}]",
        )
        .header("Content-Type", "application/json");
    }
    Resp::ok("[{\"id\":1,\"name\":\"alice\"}]").header("Content-Type", "application/json")
}

fn dast_graphql(req: &Req) -> Resp {
    if req.method == "POST" && req.body.contains("__schema") {
        return Resp::ok(
            "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"types\":[{\"name\":\"User\"}]}}}",
        )
        .header("Content-Type", "application/json");
    }
    Resp::ok("{\"data\":null}").header("Content-Type", "application/graphql")
}

// -- stateful second-order SQLi --

/// A handler whose `/dast/profile` stores a posted value and, on the next GET,
/// emits a DB error if the stored value contained a quote.
pub fn second_order_app() -> impl Fn(&Req) -> Resp + Send + Sync + 'static {
    let store: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    move |req: &Req| {
        if req.path == "/dast/profile" {
            if req.method == "POST" {
                *store.lock().unwrap() = Some(req.body.clone());
                return Resp::html("saved");
            }
            // GET retrieval — reflect stored value; error if it held a quote.
            // The plugin posts the payload URL/form-encoded, so decode first.
            let stored = pct_decode(&store.lock().unwrap().clone().unwrap_or_default());
            if stored.contains('\'') || stored.contains('"') {
                return Resp::html("You have an error in your SQL syntax near your stored profile");
            }
            return Resp::html(format!("<html><body>profile: {stored}</body></html>"));
        }
        vulnerable_app(req)
    }
}

// -- spider surface --

fn index_html() -> String {
    r#"<html><body>
<h1>Vuln Lab</h1>
<ul>
  <li><a href="/dast/sqli?id=1">sqli</a></li>
  <li><a href="/dast/xss?q=1">xss</a></li>
  <li><a href="/dast/traversal?file=a">traversal</a></li>
  <li><a href="/dast/render?name=x">ssti</a></li>
  <li><a href="/dast/ping?host=h">ping</a></li>
</ul>
<form method="POST" action="/dast/login">
  <input type="text" name="username" />
  <input type="password" name="password" />
</form>
<a href="http://evil.example/off-host">off-host (must be excluded)</a>
<script src="/static/app.js"></script>
<script>fetch('/dast/search?q=1');</script>
</body></html>"#
        .to_string()
}

fn sitemap_xml() -> String {
    r#"<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/dast/traversal?file=a</loc></url>
  <url><loc>/dast/version?id=1</loc></url>
</urlset>"#
        .to_string()
}
