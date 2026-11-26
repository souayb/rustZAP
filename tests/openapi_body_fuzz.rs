//! #40: `--paths` entries keep path / query / fragment as separate components.
//! #53: OpenAPI-synthesized JSON bodies are fuzzed field-by-field by the
//! active injection plugins, through `HttpSafetyGate` (`--read-only-safe`
//! still blocks the non-GET body requests).

#[path = "support/lab.rs"]
mod lab;

use std::sync::{Arc, Mutex};

use lab::{serve_full, Req, Resp};
use rustzap::active::{plugin_by_name, ActiveScanner};
use rustzap::openapi::{load_paths_file, parse_openapi_json};
use rustzap::safety::SafetyPolicy;
use serde_json::Value;

#[tokio::test]
async fn paths_file_sends_path_and_query_separately() {
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let rec = seen.clone();
    let base = serve_full(move |req: &Req| {
        rec.lock()
            .unwrap()
            .push((req.path.clone(), req.query.clone()));
        Resp::ok("ok")
    })
    .await;

    let file = std::env::temp_dir().join(format!("rz-paths-http-{}.txt", std::process::id()));
    std::fs::write(
        &file,
        "GET /items?search=probe\n/multi?x=1&x=2&empty=\n/enc?q=a%26b%3Dc\n/frag?k=v#section\n",
    )
    .unwrap();
    let (urls, _) = load_paths_file(file.to_str().unwrap(), &base).expect("load");
    std::fs::remove_file(&file).ok();

    let client = reqwest::Client::new();
    for du in &urls {
        client.get(&du.url).send().await.expect("send");
    }

    let seen = seen.lock().unwrap().clone();
    let want = [
        ("/items", "search=probe"),
        ("/multi", "x=1&x=2&empty="),
        // Already-encoded delimiters pass through untouched (no `%2526`).
        ("/enc", "q=a%26b%3Dc"),
        // The fragment is never part of the path or the query.
        ("/frag", "k=v"),
    ];
    for (path, query) in want {
        assert!(
            seen.iter().any(|(p, q)| p == path && q == query),
            "server should receive path {path} + query {query}; got {seen:?}"
        );
    }
}

const SPEC: &str = r##"{
  "openapi": "3.0.0",
  "paths": {
    "/api/search": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Search"}}}
        }
      }
    }
  },
  "components": {
    "schemas": {
      "Search": {
        "type": "object",
        "required": ["name", "limit", "filter"],
        "properties": {
          "name": {"type": "string"},
          "limit": {"type": "integer"},
          "filter": {
            "type": "object",
            "required": ["tag"],
            "properties": {"tag": {"type": "string", "enum": ["a", "b"]}}
          }
        }
      }
    }
  }
}"##;

/// The handler a strict JSON API would have: bodies missing a required field
/// (or of the wrong type) bounce with 400; `name` is concatenated into SQL.
fn search_app(rec: Arc<Mutex<Vec<(String, bool)>>>) -> impl Fn(&Req) -> Resp + Send + Sync {
    move |req: &Req| {
        if req.path != "/api/search" {
            return Resp::ok("").status(404, "Not Found");
        }
        if req.method != "POST" {
            return Resp::ok("method not allowed").status(405, "Method Not Allowed");
        }
        let v: Value = serde_json::from_str(&req.body).unwrap_or(Value::Null);
        let valid = v["name"].is_string() && v["limit"].is_i64() && v["filter"]["tag"].is_string();
        rec.lock().unwrap().push((req.body.clone(), valid));
        if !valid {
            return Resp::ok("missing field").status(400, "Bad Request");
        }
        if v["name"].as_str().unwrap_or("").contains('\'') {
            Resp::ok("You have an error in your SQL syntax near ''' at line 1")
        } else {
            Resp::ok("[]")
        }
    }
}

#[tokio::test]
async fn openapi_json_body_fields_are_fuzzed_and_gated() {
    let posts: Arc<Mutex<Vec<(String, bool)>>> = Arc::default();
    let base = serve_full(search_app(posts.clone())).await;
    let (urls, _) = parse_openapi_json(SPEC, &base).expect("parse");
    let du = urls
        .iter()
        .find(|u| u.method == "POST")
        .expect("POST op")
        .clone();
    assert!(
        !du.url.contains('?'),
        "body-only op has no query: {}",
        du.url
    );

    // Direct plugin run: the payload reaches the JSON field, the body stays valid.
    let f = plugin_by_name("sqli")
        .unwrap()
        .scan(&reqwest::Client::new(), &du)
        .await;
    let hit = f
        .iter()
        .find(|f| f.plugin == "active/sqli")
        .unwrap_or_else(|| panic!("sqli should fire on body.name: {f:?}"));
    assert_eq!(hit.parameter.as_deref(), Some("body.name"));
    {
        let posts = posts.lock().unwrap();
        assert!(!posts.is_empty());
        assert!(
            posts.iter().all(|(_, valid)| *valid),
            "every fuzzed body must still deserialize: {posts:?}"
        );
        assert!(posts
            .iter()
            .any(|(b, _)| { serde_json::from_str::<Value>(b).unwrap()["name"] == "'" }));
    }

    // Through the scanner (same test: the active gate is process-global).
    // `--read-only-safe` blocks every body-bearing POST at the gate.
    posts.lock().unwrap().clear();
    let client = Arc::new(reqwest::Client::new());
    let ro = ActiveScanner::new(
        client.clone(),
        vec!["sqli".into(), "nosql-injection".into()],
        2,
        false,
        SafetyPolicy::from_flags(false, true, None),
    );
    let pb = indicatif::ProgressBar::hidden();
    let f = ro.scan_all(std::slice::from_ref(&du), &pb).await.unwrap();
    assert!(
        posts.lock().unwrap().is_empty(),
        "read-only-safe sent POSTs"
    );
    assert!(!f.iter().any(|f| f.plugin == "active/sqli"));

    // Default policy: the URL has no `?`, yet the JSON body passes the
    // active gating rule deliberately and the finding is produced.
    let scanner = ActiveScanner::new(
        client,
        vec!["sqli".into()],
        2,
        false,
        SafetyPolicy::default(),
    );
    let f = scanner
        .scan_all(std::slice::from_ref(&du), &pb)
        .await
        .unwrap();
    assert!(
        f.iter()
            .any(|f| f.plugin == "active/sqli" && f.parameter.as_deref() == Some("body.name")),
        "scan_all should fuzz the JSON body: {f:?}"
    );
}
