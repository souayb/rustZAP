//! Broken Object Level Authorization (BOLA / IDOR) Plugin (OWASP API1:2023 & CWE-639).
//!
//! Single-session heuristic: mutates resource identifiers (query params, numeric /
//! UUID path segments, JSON request-body fields) and compares responses. One
//! session cannot tell "my object" from "someone else's object", so every finding
//! here is `tentative`. The multi-identity oracle (`--auth-a/--auth-b`,
//! `--authz-matrix`) lives in `super::authz` and is what produces firm/confirmed
//! BOLA results.

use async_trait::async_trait;
use regex::Regex;
use url::Url;

use crate::active::{get_response_body, post_response_body, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity, UrlSource};
use crate::verify::body_similarity;

/// Where an object identifier was found in a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdLocation {
    /// Query parameter name.
    Query(String),
    /// Index into `Url::path_segments()`.
    Path(usize),
    /// Top-level JSON body field name.
    Body(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdCandidate {
    pub location: IdLocation,
    pub value: String,
}

fn id_name_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i:^(?:id|uid|uuid|guid)$|(?:_|-)(?:id|uuid|guid)$)|[a-z](?:Id|ID|Uuid)$"#)
            .unwrap()
    })
}

fn uuid_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"#,
        )
        .unwrap()
    })
}

fn looks_like_id_value(v: &str) -> bool {
    (!v.is_empty() && v.len() <= 10 && v.chars().all(|c| c.is_ascii_digit()))
        || uuid_regex().is_match(v)
}

/// Object-ID candidates from the query string, numeric/UUID path segments, and
/// top-level JSON request-body fields. OpenAPI-imported rows carry placeholder
/// values (`1`) for every parameter, so there only the declared parameter *name*
/// decides whether a query/body field is an object id.
pub(crate) fn object_id_candidates(target: &DiscoveredUrl) -> Vec<IdCandidate> {
    let mut out = Vec::new();
    let Ok(parsed) = Url::parse(&target.url) else {
        return out;
    };
    let from_openapi = target.source == UrlSource::OpenApi;

    for (k, v) in parsed.query_pairs() {
        if id_name_regex().is_match(&k) || (!from_openapi && looks_like_id_value(&v)) {
            out.push(IdCandidate {
                location: IdLocation::Query(k.to_string()),
                value: v.to_string(),
            });
        }
    }

    if let Some(segs) = parsed.path_segments() {
        for (i, seg) in segs.enumerate() {
            if looks_like_id_value(seg) {
                out.push(IdCandidate {
                    location: IdLocation::Path(i),
                    value: seg.to_string(),
                });
            }
        }
    }

    if let Some(serde_json::Value::Object(map)) = target
        .body
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    {
        for (k, v) in map {
            let val = match &v {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                _ => continue,
            };
            if id_name_regex().is_match(&k) {
                out.push(IdCandidate {
                    location: IdLocation::Body(k),
                    value: val,
                });
            }
        }
    }
    out
}

/// Rebuild `(url, body)` for `target` with `cand` replaced by `new_value`.
pub(crate) fn with_id(
    target: &DiscoveredUrl,
    cand: &IdCandidate,
    new_value: &str,
) -> Option<(String, Option<String>)> {
    let mut url = Url::parse(&target.url).ok()?;
    let mut body = target.body.clone();
    match &cand.location {
        IdLocation::Query(name) => {
            let pairs: Vec<(String, String)> = url
                .query_pairs()
                .map(|(k, v)| {
                    let v = if &k == name {
                        new_value.to_string()
                    } else {
                        v.to_string()
                    };
                    (k.to_string(), v)
                })
                .collect();
            url.query_pairs_mut().clear().extend_pairs(pairs);
        }
        IdLocation::Path(i) => {
            let mut segs: Vec<String> = url.path_segments()?.map(str::to_string).collect();
            *segs.get_mut(*i)? = new_value.to_string();
            url.set_path(&format!("/{}", segs.join("/")));
        }
        IdLocation::Body(field) => {
            let mut v: serde_json::Value = serde_json::from_str(body.as_deref()?).ok()?;
            let slot = v.get_mut(field)?;
            // Keep the JSON type: numeric ids stay numbers.
            *slot = match new_value.parse::<i64>() {
                Ok(n) if slot.is_number() => serde_json::json!(n),
                _ => serde_json::json!(new_value),
            };
            body = Some(v.to_string());
        }
    }
    Some((url.to_string(), body))
}

pub struct BolaPlugin;

impl Default for BolaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl BolaPlugin {
    pub fn new() -> Self {
        Self
    }

    /// Generate modified/tampered IDs for testing authorization boundaries.
    fn generate_tampered_ids(&self, original_id: &str) -> Vec<String> {
        let mut variants = Vec::new();

        if let Ok(num) = original_id.parse::<i64>() {
            variants.push((num + 1).to_string());
            if num > 1 {
                variants.push((num - 1).to_string());
            }
            variants.push("1".to_string());
            variants.push("0".to_string());
            variants.push("100".to_string());
        } else if uuid_regex().is_match(original_id) {
            // Permute UUID by replacing first character or testing nil UUID
            variants.push("00000000-0000-0000-0000-000000000000".to_string());
            let mut permuted = original_id.to_string();
            if let Some(first_char) = permuted.chars().next() {
                let replacement = if first_char == 'a' { 'b' } else { 'a' };
                permuted.replace_range(..1, &replacement.to_string());
                variants.push(permuted);
            }
        } else {
            // String ID / Slug
            variants.push("admin".to_string());
            variants.push("root".to_string());
            variants.push("guest".to_string());
            variants.push("test".to_string());
        }

        variants.retain(|v| v != original_id);
        variants
    }
}

/// GET for bodiless requests; POST for JSON bodies (other verbs are skipped —
/// replaying PUT/PATCH/DELETE with a foreign id would mutate someone's data).
async fn send(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    body: Option<&str>,
) -> Option<(u16, String)> {
    match body {
        None => get_response_body(client, url).await,
        Some(b) if method.eq_ignore_ascii_case("POST") => {
            post_response_body(client, url, "application/json", b).await
        }
        Some(_) => None,
    }
}

#[async_trait]
impl ScanPlugin for BolaPlugin {
    fn name(&self) -> &str {
        "bola"
    }

    fn description(&self) -> &str {
        "Detects Broken Object Level Authorization (BOLA/IDOR) by mutating resource identifiers across objects (single session = tentative; use --auth-a/--auth-b or --authz-matrix for confirmation)"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();
        let candidates = object_id_candidates(target);
        if candidates.is_empty() {
            return findings;
        }
        // Body ids are only exercised on JSON POST rows; everything else is a GET.
        let body = if target.method.eq_ignore_ascii_case("GET") {
            None
        } else {
            target.body.as_deref()
        };
        let Some((baseline_status, baseline_body)) =
            send(client, &target.method, &target.url, body).await
        else {
            return findings;
        };

        for cand in candidates {
            if matches!(cand.location, IdLocation::Body(_)) && body.is_none() {
                continue;
            }
            for tampered in self.generate_tampered_ids(&cand.value) {
                let Some((mutated_url, mutated_body)) = with_id(target, &cand, &tampered) else {
                    continue;
                };
                let mutated_body = if body.is_some() { mutated_body } else { None };
                let Some((test_status, test_body)) = send(
                    client,
                    &target.method,
                    &mutated_url,
                    mutated_body.as_deref(),
                )
                .await
                else {
                    continue;
                };
                if test_status != 200 || test_body.len() <= 20 {
                    continue;
                }
                let is_idor = if baseline_status == 200 {
                    body_similarity(&baseline_body, &test_body) < 0.95
                        && (test_body.contains('{') || test_body.contains('<'))
                } else {
                    matches!(baseline_status, 401 | 403 | 404)
                };
                if !is_idor {
                    continue;
                }

                let snippet = if test_body.len() > 80 {
                    format!(
                        "{}...[TRUNCATED]",
                        crate::types::safe_truncate(&test_body, 80)
                    )
                } else {
                    test_body.clone()
                };
                let (title, plugin, param) = match &cand.location {
                    IdLocation::Query(p) => (
                        "Broken Object Level Authorization (BOLA / IDOR)",
                        "active/bola",
                        p.clone(),
                    ),
                    IdLocation::Path(i) => (
                        "Broken Object Level Authorization (BOLA / IDOR in Path)",
                        "active/bola-path",
                        format!("path_seg_{i}"),
                    ),
                    IdLocation::Body(f) => (
                        "Broken Object Level Authorization (BOLA / IDOR in JSON Body)",
                        "active/bola-body",
                        f.clone(),
                    ),
                };
                findings.push(
                    Finding::new(
                        title,
                        Severity::High,
                        &mutated_url,
                        format!(
                            "Object identifier '{}' was modified from '{}' to '{}' and the same session received a different object (HTTP 200). \
                             Single-session heuristic: the object may legitimately belong to this user — re-run with --auth-a/--auth-b or --authz-matrix to confirm.",
                            param, cand.value, tampered
                        ),
                        "Implement robust user authorization checks on the server side to ensure the authenticated user owns or is permitted to access the requested object ID.",
                        plugin,
                    )
                    .with_parameter(param.clone())
                    .with_evidence(format!(
                        "{}: {} -> {}\nResponse Snippet: {}",
                        param, cand.value, tampered, snippet
                    ))
                    .with_cwe(639) // CWE-639: Authorization Bypass Through User-Controlled Key
                    .with_owasp("API1:2023 – Broken Object Level Authorization")
                    .tentative(),
                );
                break; // Avoid spamming findings for same id location
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bola_plugin_id_extraction() {
        let du = DiscoveredUrl::new(
            "https://example.com/api/user?user_id=1001&view=summary",
            "GET",
            UrlSource::Link,
        );
        let candidates = object_id_candidates(&du);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].location, IdLocation::Query("user_id".into()));
        assert_eq!(candidates[0].value, "1001");
    }

    #[test]
    fn extracts_path_uuid_and_json_body_ids() {
        let uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        let mut du = DiscoveredUrl::new(
            format!("https://example.com/health-records/42/files/{uuid}"),
            "POST",
            UrlSource::Link,
        );
        du.body = Some(r#"{"accountId": 7, "owner_id": "9", "note": "x"}"#.into());
        let c = object_id_candidates(&du);
        assert!(c.contains(&IdCandidate {
            location: IdLocation::Path(1),
            value: "42".into()
        }));
        assert!(c.contains(&IdCandidate {
            location: IdLocation::Path(3),
            value: uuid.into()
        }));
        assert!(c
            .iter()
            .any(|x| x.location == IdLocation::Body("accountId".into())));
        assert!(c
            .iter()
            .any(|x| x.location == IdLocation::Body("owner_id".into())));
        assert!(!c
            .iter()
            .any(|x| x.location == IdLocation::Body("note".into())));

        let (url, _) = with_id(&du, &c[0], "43").unwrap();
        assert!(url.ends_with(&format!("/health-records/43/files/{uuid}")));
        let body_cand = c
            .iter()
            .find(|x| x.location == IdLocation::Body("accountId".into()))
            .unwrap();
        let (_, body) = with_id(&du, body_cand, "8").unwrap();
        assert!(body.unwrap().contains(r#""accountId":8"#));
    }

    #[test]
    fn openapi_rows_use_declared_names_not_placeholder_values() {
        // The OpenAPI importer fills every param with `1`; only id-named ones count.
        let du = DiscoveredUrl::new(
            "https://example.com/docs?documentId=1&verbose=1&paid=1",
            "GET",
            UrlSource::OpenApi,
        );
        let c = object_id_candidates(&du);
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].location, IdLocation::Query("documentId".into()));
    }

    #[test]
    fn test_bola_tampered_id_generation() {
        let plugin = BolaPlugin::new();
        let variants = plugin.generate_tampered_ids("42");
        assert!(variants.contains(&"43".to_string()));
        assert!(variants.contains(&"41".to_string()));
        assert!(variants.contains(&"1".to_string()));
    }
}
