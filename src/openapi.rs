//! OpenAPI 3.x import → synthetic `DiscoveredUrl` rows (Phase 3).
//!
//! Supports JSON OpenAPI documents (file or fetched URL). Path templates
//! like `/users/{id}` are materialized with a placeholder value so active
//! plugins that require query/path parameters can still run.

use anyhow::{Context, Result};
use serde_json::Value;
use url::Url;

use crate::types::{DiscoveredUrl, Finding, Severity, UrlSource};

const OPENAPI_MAX_OPS: usize = 500;
const PATH_PLACEHOLDER: &str = "1";

/// Load OpenAPI JSON from a local path and expand operations against `target`.
pub fn load_openapi_file(path: &str, target: &str) -> Result<(Vec<DiscoveredUrl>, Finding)> {
    let bytes = std::fs::read(path).with_context(|| format!("Read OpenAPI file {}", path))?;
    let s = String::from_utf8(bytes).context("OpenAPI file must be UTF-8 JSON")?;
    parse_openapi_json(&s, target)
}

/// Fetch OpenAPI JSON from a URL (once) and expand operations.
pub async fn load_openapi_url(
    client: &reqwest::Client,
    openapi_url: &str,
    target: &str,
) -> Result<(Vec<DiscoveredUrl>, Finding)> {
    let resp = client
        .get(openapi_url)
        .send()
        .await
        .with_context(|| format!("Fetch OpenAPI {}", openapi_url))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("OpenAPI fetch returned HTTP {}", status);
    }
    let body = resp.text().await.context("Read OpenAPI response body")?;
    parse_openapi_json(&body, target)
}

pub fn parse_openapi_json(json: &str, target: &str) -> Result<(Vec<DiscoveredUrl>, Finding)> {
    let doc: Value = serde_json::from_str(json).context("Parse OpenAPI JSON")?;
    let base = Url::parse(target).context("Invalid scan target for OpenAPI join")?;

    let paths = doc
        .get("paths")
        .and_then(|p| p.as_object())
        .context("OpenAPI document missing paths object")?;

    let mut out = Vec::new();
    let methods = ["get", "post", "put", "patch", "delete", "head", "options"];

    'ops: for (path_tmpl, item) in paths {
        let Some(item_obj) = item.as_object() else {
            continue;
        };
        for method in methods {
            let Some(op) = item_obj.get(method) else {
                continue;
            };
            if out.len() >= OPENAPI_MAX_OPS {
                break 'ops;
            }
            let params = collect_param_names(item_obj.get("parameters"), op.get("parameters"));
            let headers = extract_headers(item_obj.get("parameters"), op.get("parameters"));
            let (content_type, body) = extract_body_and_ct(&doc, op);
            let concrete = materialize_path(path_tmpl, &params);
            let Ok(joined) = join_target_path(&base, &concrete) else {
                continue;
            };
            let url = append_query_placeholders(&joined, &params);
            out.push(DiscoveredUrl {
                url,
                method: method.to_ascii_uppercase(),
                headers,
                body,
                content_type,
                parameters: params,
                source: UrlSource::OpenApi,
            });
        }
    }

    let finding = Finding::new(
        "OpenAPI Surface Imported",
        Severity::Info,
        target,
        format!(
            "Imported {} operation(s) from an OpenAPI document into the scan surface.",
            out.len()
        ),
        "Review imported paths for accuracy; path templates were filled with placeholder values.",
        "passive/openapi-import",
    )
    .with_evidence(format!("{} operations", out.len()));

    Ok((out, finding))
}

fn collect_param_names(path_level: Option<&Value>, op_level: Option<&Value>) -> Vec<String> {
    let mut names = Vec::new();
    for block in [path_level, op_level].into_iter().flatten() {
        let Some(arr) = block.as_array() else {
            continue;
        };
        for p in arr {
            if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                if !names.iter().any(|n| n == name) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

fn extract_headers(path_level: Option<&Value>, op_level: Option<&Value>) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for block in [path_level, op_level].into_iter().flatten() {
        let Some(arr) = block.as_array() else {
            continue;
        };
        for p in arr {
            if p.get("in").and_then(|i| i.as_str()) == Some("header") {
                if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                    let val = p
                        .get("example")
                        .and_then(|e| e.as_str())
                        .unwrap_or("test_header_val");
                    headers.push((name.to_string(), val.to_string()));
                }
            }
        }
    }
    headers
}

fn extract_body_and_ct(doc: &Value, op: &Value) -> (Option<String>, Option<String>) {
    let Some(rb) = op.get("requestBody").map(|rb| resolve_ref(doc, rb)) else {
        return (None, None);
    };
    let Some(content) = rb.get("content").and_then(|c| c.as_object()) else {
        return (None, None);
    };
    // `application/json` first, then any `+json` / `json` media type.
    let json_media = content.get("application/json").or_else(|| {
        content
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase().contains("json"))
            .map(|(_, v)| v)
    });
    if let Some(json_content) = json_media {
        let ct = Some("application/json".to_string());
        let body = if let Some(ex) = json_content.get("example") {
            ex.to_string()
        } else if let Some(schema) = json_content.get("schema") {
            sample_from_schema(doc, schema, 0).to_string()
        } else {
            "{}".to_string()
        };
        return (ct, Some(body));
    }
    if content.get("application/x-www-form-urlencoded").is_some() {
        let ct = Some("application/x-www-form-urlencoded".to_string());
        return (ct, Some("param=test".to_string()));
    }
    (None, None)
}

/// Max object/array nesting for synthesized bodies; past it only `required`
/// properties are emitted, and a hard cap stops recursive `$ref` cycles.
const SCHEMA_MAX_DEPTH: usize = 6;

/// Follow local `$ref`s (`#/components/schemas/X`, `#/definitions/X`).
fn resolve_ref<'a>(doc: &'a Value, mut v: &'a Value) -> &'a Value {
    for _ in 0..16 {
        let Some(r) = v.get("$ref").and_then(|r| r.as_str()) else {
            break;
        };
        match r.strip_prefix('#').and_then(|p| doc.pointer(p)) {
            Some(target) => v = target,
            None => break,
        }
    }
    v
}

/// Synthesize a schema-valid sample value: honors `example`/`default`/`enum`,
/// `$ref`, `allOf`/`oneOf`/`anyOf`, string formats, and nested objects/arrays.
fn sample_from_schema(doc: &Value, schema: &Value, depth: usize) -> Value {
    use serde_json::json;
    let s = resolve_ref(doc, schema);
    if depth > SCHEMA_MAX_DEPTH + 2 {
        return Value::Null;
    }
    for key in ["example", "default", "const"] {
        if let Some(v) = s.get(key) {
            return v.clone();
        }
    }
    if let Some(first) = s
        .get("enum")
        .and_then(|e| e.as_array())
        .and_then(|e| e.first())
    {
        return first.clone();
    }
    if let Some(parts) = s.get("allOf").and_then(|a| a.as_array()) {
        let mut merged = serde_json::Map::new();
        for p in parts {
            match sample_from_schema(doc, p, depth + 1) {
                Value::Object(o) => merged.extend(o),
                other if parts.len() == 1 => return other,
                _ => {}
            }
        }
        return Value::Object(merged);
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(first) = s
            .get(key)
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
        {
            return sample_from_schema(doc, first, depth + 1);
        }
    }
    // OAS 3.1 allows `type: ["string", "null"]`.
    let typ = match s.get("type") {
        Some(Value::String(t)) => t.as_str(),
        Some(Value::Array(ts)) => ts
            .iter()
            .filter_map(|t| t.as_str())
            .find(|t| *t != "null")
            .unwrap_or("null"),
        _ if s.get("properties").is_some() => "object",
        _ if s.get("items").is_some() => "array",
        _ => "string",
    };
    match typ {
        "object" => {
            let required: Vec<&str> = s
                .get("required")
                .and_then(|r| r.as_array())
                .map(|r| r.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            let mut obj = serde_json::Map::new();
            if let Some(props) = s.get("properties").and_then(|p| p.as_object()) {
                for (k, v) in props {
                    if depth < SCHEMA_MAX_DEPTH || required.contains(&k.as_str()) {
                        obj.insert(k.clone(), sample_from_schema(doc, v, depth + 1));
                    }
                }
            }
            Value::Object(obj)
        }
        "array" => match s.get("items") {
            Some(items) if depth < SCHEMA_MAX_DEPTH => {
                json!([sample_from_schema(doc, items, depth + 1)])
            }
            _ => json!([]),
        },
        "integer" => s
            .get("minimum")
            .and_then(|m| m.as_i64())
            .map_or(json!(1), |m| json!(m.max(1))),
        "number" => s
            .get("minimum")
            .and_then(|m| m.as_f64())
            .map_or(json!(1), |m| json!(m.max(1.0))),
        "boolean" => json!(true),
        "null" => Value::Null,
        _ => {
            let fmt = s.get("format").and_then(|f| f.as_str()).unwrap_or("");
            let sample = match fmt {
                "date-time" => "2024-01-01T00:00:00Z",
                "date" => "2024-01-01",
                "email" => "test@example.com",
                "uuid" => "00000000-0000-4000-8000-000000000000",
                "uri" | "url" => "https://example.com/",
                "ipv4" => "127.0.0.1",
                _ => "test",
            };
            let min = s.get("minLength").and_then(|m| m.as_u64()).unwrap_or(0) as usize;
            if sample.len() < min {
                json!("t".repeat(min))
            } else {
                json!(sample)
            }
        }
    }
}

fn materialize_path(tmpl: &str, params: &[String]) -> String {
    let mut path = tmpl.to_string();
    // Replace `{name}` and `:name` style segments.
    for name in params {
        let brace = format!("{{{}}}", name);
        path = path.replace(&brace, PATH_PLACEHOLDER);
        let colon = format!(":{}", name);
        // Only replace path-style `:id` segments, not query noise.
        if path.contains(&colon) {
            path = path.replace(&colon, PATH_PLACEHOLDER);
        }
    }
    let mut path = fill_placeholders(path);
    if !path.starts_with('/') {
        path = format!("/{}", path);
    }
    path
}

/// Replace any remaining `{…}` template placeholders.
fn fill_placeholders(mut path: String) -> String {
    while let Some(start) = path.find('{') {
        let Some(end) = path[start..].find('}') else {
            break;
        };
        let end = start + end;
        path.replace_range(start..=end, PATH_PLACEHOLDER);
    }
    path
}

/// Resolve an origin-relative reference (`/p?q=1#f`) against the target. URL
/// parsing splits path / query / fragment and keeps existing percent-encoding
/// (`set_path` would encode `?` into the path, #40). The result must stay on
/// the target origin (`//host` or `/\host` references are rejected).
fn join_target_path(base: &Url, path: &str) -> Result<String> {
    let joined = base
        .join(path)
        .with_context(|| format!("Invalid path {}", path))?;
    if joined.origin() != base.origin() {
        anyhow::bail!("Path {} escapes the target origin", path);
    }
    Ok(joined.to_string())
}

fn append_query_placeholders(url: &str, params: &[String]) -> String {
    // Always append named parameters as query placeholders when the URL has no
    // query yet, so active plugins that require `?` can exercise the surface.
    if url.contains('?') || params.is_empty() {
        return url.to_string();
    }
    let qs: Vec<String> = params
        .iter()
        .map(|p| format!("{}={}", p, PATH_PLACEHOLDER))
        .collect();
    format!("{}?{}", url.trim_end_matches('?'), qs.join("&"))
}

/// Common locations where web frameworks expose an OpenAPI/Swagger JSON
/// document. Probed (same-origin) when the user supplies no explicit spec, so a
/// headless API whose root 404s still gets a meaningful scan surface.
pub const COMMON_OPENAPI_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/.well-known/openapi.json",
];

/// Probe common spec locations against the target origin. Returns the first
/// location that answers 2xx with a body that parses as a non-empty OpenAPI
/// document. Network/parse failures on individual probes are ignored.
pub async fn discover_openapi(
    client: &reqwest::Client,
    target: &str,
) -> Option<(Vec<DiscoveredUrl>, Finding)> {
    let base = Url::parse(target).ok()?;
    for path in COMMON_OPENAPI_PATHS {
        let mut probe = base.clone();
        probe.set_query(None);
        probe.set_fragment(None);
        probe.set_path(path);
        let url = probe.to_string();
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.text().await else {
            continue;
        };
        if let Ok((urls, _)) = parse_openapi_json(&body, target) {
            if urls.is_empty() {
                continue;
            }
            let count = urls.len();
            let finding = Finding::new(
                "OpenAPI Surface Auto-Discovered",
                Severity::Info,
                target,
                format!(
                    "Auto-discovered an OpenAPI document at {url} and imported {count} \
                     operation(s) into the scan surface."
                ),
                "Confirm this specification is meant to be publicly reachable; if not, \
                 restrict access to it.",
                "passive/openapi-discovery",
            )
            .with_evidence(url);
            return Some((urls, finding));
        }
    }
    None
}

/// Load a plain list of routes/paths and expand them into the scan surface.
/// Each non-empty line that does not start with `#` is either `/path`,
/// `METHOD /path`, or a full `http(s)://` URL. `{id}`-style templates are
/// materialized with a placeholder, like OpenAPI paths.
pub fn load_paths_file(path: &str, target: &str) -> Result<(Vec<DiscoveredUrl>, Finding)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("Read paths file {}", path))?;
    let base = Url::parse(target).context("Invalid scan target for --paths join")?;

    let mut out = Vec::new();
    let mut skipped = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if out.len() >= OPENAPI_MAX_OPS {
            break;
        }
        // Optional leading HTTP method token (`POST /items`).
        let (method, rest) = match line.split_once(char::is_whitespace) {
            Some((m, r)) if is_http_method(m) => (m.to_ascii_uppercase(), r.trim()),
            _ => ("GET".to_string(), line),
        };
        let url = if rest.starts_with("http://") || rest.starts_with("https://") {
            // Same-origin scope policy as HAR import: off-target URLs are dropped.
            match Url::parse(&fill_placeholders(rest.to_string())) {
                Ok(u) if u.origin() == base.origin() => u.to_string(),
                _ => {
                    skipped += 1;
                    continue;
                }
            }
        } else {
            match join_target_path(&base, &materialize_path(rest, &[])) {
                Ok(u) => u,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            }
        };
        out.push(DiscoveredUrl::new(url, method, UrlSource::PathsFile));
    }

    let finding = Finding::new(
        "Paths File Imported",
        Severity::Info,
        target,
        format!(
            "Imported {} path(s) from a --paths file into the scan surface.",
            out.len()
        ),
        "Review the imported paths for accuracy and scope.",
        "passive/paths-import",
    )
    .with_evidence(format!(
        "{} paths ({} skipped: invalid or outside the target origin)",
        out.len(),
        skipped
    ));

    Ok((out, finding))
}

fn is_http_method(s: &str) -> bool {
    matches!(
        s.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "openapi": "3.0.0",
      "info": {"title": "Demo", "version": "1.0"},
      "paths": {
        "/users/{id}": {
          "get": {
            "parameters": [
              {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}},
              {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
            ]
          }
        },
        "/health": {
          "get": {}
        },
        "/items": {
          "post": {
            "parameters": [
              {"name": "q", "in": "query"}
            ]
          }
        }
      }
    }"#;

    #[test]
    fn parses_operations_into_discovered_urls() {
        let (urls, finding) = parse_openapi_json(SAMPLE, "https://api.example.com").expect("parse");
        assert!(urls.len() >= 3);
        assert_eq!(finding.plugin, "passive/openapi-import");
        assert!(urls.iter().any(|u| u.url.contains("/users/1")));
        assert!(urls.iter().any(|u| u.method == "GET"));
        assert!(urls.iter().any(|u| u.method == "POST"));
        assert!(urls.iter().all(|u| u.source == UrlSource::OpenApi));
        let users = urls
            .iter()
            .find(|u| u.url.contains("/users/"))
            .expect("users");
        assert!(users.parameters.iter().any(|p| p == "id"));
        assert!(users.url.contains('?'));
    }

    #[test]
    fn paths_file_imports_methods_and_templates() {
        let p = std::env::temp_dir().join(format!("rz-paths-{}.txt", crate::types::uuid_v4()));
        std::fs::write(&p, "# a comment\n\n/health\nPOST /items\n/users/{id}\n").expect("write");
        let (urls, finding) =
            load_paths_file(p.to_str().unwrap(), "https://api.example.com").expect("load");
        std::fs::remove_file(&p).ok();

        assert_eq!(finding.plugin, "passive/paths-import");
        assert!(urls
            .iter()
            .any(|u| u.method == "GET" && u.url.ends_with("/health")));
        assert!(urls
            .iter()
            .any(|u| u.method == "POST" && u.url.ends_with("/items")));
        assert!(urls.iter().any(|u| u.url.contains("/users/1")));
        assert!(urls.iter().all(|u| u.source == UrlSource::PathsFile));
    }

    #[test]
    fn paths_file_keeps_query_fragment_and_scope() {
        let p = std::env::temp_dir().join(format!("rz-paths-{}.txt", crate::types::uuid_v4()));
        std::fs::write(
            &p,
            "GET /items?search=probe\n\
             /multi?x=1&x=2&empty=\n\
             /enc?q=a%26b%3Dc\n\
             /frag?k=v#sec?not=query\n\
             PUT /users/{id}?v={v}\n\
             https://api.example.com/abs?a=1\n\
             https://evil.example.net/abs?a=1\n\
             //evil.example.net/x\n\
             /\\evil.example.net/x\n",
        )
        .expect("write");
        let (urls, finding) =
            load_paths_file(p.to_str().unwrap(), "https://api.example.com/base?old=1")
                .expect("load");
        std::fs::remove_file(&p).ok();

        let got: Vec<&str> = urls.iter().map(|u| u.url.as_str()).collect();
        assert_eq!(
            got,
            vec![
                "https://api.example.com/items?search=probe",
                "https://api.example.com/multi?x=1&x=2&empty=",
                "https://api.example.com/enc?q=a%26b%3Dc",
                "https://api.example.com/frag?k=v#sec?not=query",
                "https://api.example.com/users/1?v=1",
                "https://api.example.com/abs?a=1",
            ]
        );
        assert_eq!(urls[0].parameters, vec!["search".to_string()]);
        assert_eq!(urls[4].method, "PUT");
        assert!(finding
            .evidence
            .as_deref()
            .unwrap_or("")
            .contains("3 skipped"));
    }

    #[test]
    fn synthesizes_schema_valid_json_body() {
        let spec = r##"{
          "openapi": "3.0.0",
          "paths": {"/orders": {"post": {"requestBody": {"$ref": "#/components/requestBodies/Order"}}}},
          "components": {
            "requestBodies": {"Order": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Order"}}}}},
            "schemas": {
              "Order": {
                "type": "object",
                "required": ["customer", "qty"],
                "properties": {
                  "customer": {"$ref": "#/components/schemas/Customer"},
                  "qty": {"type": "integer", "minimum": 3},
                  "status": {"type": "string", "enum": ["open", "closed"]},
                  "tags": {"type": "array", "items": {"type": "string"}},
                  "child": {"$ref": "#/components/schemas/Order"}
                }
              },
              "Customer": {
                "type": "object",
                "properties": {"email": {"type": "string", "format": "email"}, "id": {"type": "string", "format": "uuid"}}
              }
            }
          }
        }"##;
        let (urls, _) = parse_openapi_json(spec, "https://api.example.com").expect("parse");
        let op = &urls[0];
        assert_eq!(op.content_type.as_deref(), Some("application/json"));
        let body: Value = serde_json::from_str(op.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["qty"], 3);
        assert_eq!(body["status"], "open");
        assert_eq!(body["customer"]["email"], "test@example.com");
        assert_eq!(body["tags"], serde_json::json!(["test"]));
        // Recursive `$ref` terminates; deep levels keep only required fields.
        let mut depth = 0;
        let mut cur = &body;
        while let Some(next) = cur.get("child") {
            cur = next;
            depth += 1;
        }
        assert!(depth <= SCHEMA_MAX_DEPTH);
        assert!(cur.get("customer").is_some() && cur.get("qty").is_some());
    }

    #[test]
    fn materialize_replaces_braces() {
        assert_eq!(
            materialize_path("/a/{x}/b/{y}", &["x".into(), "y".into()]),
            "/a/1/b/1"
        );
    }
}
