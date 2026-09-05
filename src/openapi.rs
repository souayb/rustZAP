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
            let (content_type, body) = extract_body_and_ct(op);
            let concrete = materialize_path(path_tmpl, &params);
            let joined = join_target_path(&base, &concrete)?;
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

fn extract_body_and_ct(op: &Value) -> (Option<String>, Option<String>) {
    let Some(rb) = op.get("requestBody") else {
        return (None, None);
    };
    let Some(content) = rb.get("content").and_then(|c| c.as_object()) else {
        return (None, None);
    };
    if let Some(json_content) = content.get("application/json") {
        let ct = Some("application/json".to_string());
        let body = if let Some(ex) = json_content.get("example") {
            Some(ex.to_string())
        } else if let Some(props) = json_content
            .get("schema")
            .and_then(|s| s.get("properties"))
            .and_then(|p| p.as_object())
        {
            let mut sample = serde_json::Map::new();
            for (k, v) in props {
                let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                let sample_val = match typ {
                    "integer" | "number" => serde_json::json!(1),
                    "boolean" => serde_json::json!(true),
                    _ => serde_json::json!("test"),
                };
                sample.insert(k.clone(), sample_val);
            }
            Some(Value::Object(sample).to_string())
        } else {
            Some("{}".to_string())
        };
        return (ct, body);
    }
    if content.get("application/x-www-form-urlencoded").is_some() {
        let ct = Some("application/x-www-form-urlencoded".to_string());
        return (ct, Some("param=test".to_string()));
    }
    (None, None)
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
    // Any remaining `{…}` placeholders
    while let Some(start) = path.find('{') {
        let Some(end) = path[start..].find('}') else {
            break;
        };
        let end = start + end;
        path.replace_range(start..=end, PATH_PLACEHOLDER);
    }
    if !path.starts_with('/') {
        path = format!("/{}", path);
    }
    path
}

fn join_target_path(base: &Url, path: &str) -> Result<String> {
    let mut joined = base.clone();
    joined.set_query(None);
    joined.set_fragment(None);
    // Replace path; keep target origin.
    joined.set_path(path);
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
    fn materialize_replaces_braces() {
        assert_eq!(
            materialize_path("/a/{x}/b/{y}", &["x".into(), "y".into()]),
            "/a/1/b/1"
        );
    }
}
