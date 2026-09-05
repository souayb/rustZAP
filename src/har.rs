//! HAR (HTTP Archive) import — same-origin request seeds (Phase 3).

use std::collections::HashSet;

use anyhow::{Context, Result};
use serde::Deserialize;
use url::Url;

use crate::types::{DiscoveredUrl, UrlSource};

const HAR_MAX_ENTRIES: usize = 1000;

#[derive(Debug, Deserialize)]
struct HarFile {
    log: HarLog,
}

#[derive(Debug, Deserialize)]
struct HarLog {
    #[serde(default)]
    entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
struct HarEntry {
    request: HarRequest,
}

#[derive(Debug, Deserialize)]
struct HarRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<HarHeader>,
    #[serde(default, rename = "postData")]
    post_data: Option<HarPostData>,
    #[serde(default)]
    query_string: Vec<HarQueryParam>,
}

#[derive(Debug, Deserialize)]
struct HarHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct HarPostData {
    #[serde(default, rename = "mimeType")]
    mime_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HarQueryParam {
    name: String,
}

/// Parse a HAR JSON file and return same-origin requests relative to `target`.
pub fn load_har_file(path: &str, target: &str) -> Result<Vec<DiscoveredUrl>> {
    let bytes = std::fs::read(path).with_context(|| format!("Read HAR file {}", path))?;
    let s = String::from_utf8(bytes).context("HAR file must be UTF-8 JSON")?;
    parse_har_json(&s, target)
}

pub fn parse_har_json(json: &str, target: &str) -> Result<Vec<DiscoveredUrl>> {
    let har: HarFile = serde_json::from_str(json).context("Parse HAR JSON")?;
    let target_url = Url::parse(target).context("Invalid target for HAR origin filter")?;
    let target_origin = origin_key(&target_url)?;

    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for entry in har.log.entries {
        if out.len() >= HAR_MAX_ENTRIES {
            break;
        }
        let Ok(req_url) = Url::parse(&entry.request.url) else {
            continue;
        };
        let Ok(req_origin) = origin_key(&req_url) else {
            continue;
        };
        if req_origin != target_origin {
            continue;
        }

        let method = entry.request.method.to_ascii_uppercase();
        let mut parameters: Vec<String> = entry
            .request
            .query_string
            .iter()
            .map(|q| q.name.clone())
            .collect();
        // Also pull query names from the URL itself.
        for (k, _) in req_url.query_pairs() {
            let name = k.to_string();
            if !parameters.iter().any(|p| p == &name) {
                parameters.push(name);
            }
        }

        let key = format!("{} {}", method, entry.request.url);
        if !seen.insert(key) {
            continue;
        }

        let headers: Vec<(String, String)> = entry
            .request
            .headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect();

        let (content_type, body) = match entry.request.post_data {
            Some(pd) => (pd.mime_type, pd.text),
            None => (None, None),
        };

        out.push(DiscoveredUrl {
            url: entry.request.url,
            method,
            headers,
            body,
            content_type,
            parameters,
            source: UrlSource::Har,
        });
    }

    Ok(out)
}

fn origin_key(u: &Url) -> Result<String> {
    let host = u
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL missing host"))?;
    let port = u.port_or_known_default().unwrap_or(0);
    Ok(format!("{}://{}:{}", u.scheme(), host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "log": {
        "version": "1.2",
        "entries": [
          {
            "request": {
              "method": "GET",
              "url": "https://app.example.com/api/users?id=1",
              "queryString": [{"name": "id", "value": "1"}]
            }
          },
          {
            "request": {
              "method": "POST",
              "url": "https://app.example.com/api/login",
              "queryString": []
            }
          },
          {
            "request": {
              "method": "GET",
              "url": "https://other.example.com/evil",
              "queryString": []
            }
          },
          {
            "request": {
              "method": "GET",
              "url": "https://app.example.com/api/users?id=1",
              "queryString": [{"name": "id", "value": "1"}]
            }
          }
        ]
      }
    }"#;

    #[test]
    fn filters_to_same_origin_and_dedupes() {
        let urls = parse_har_json(SAMPLE, "https://app.example.com/").expect("parse");
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().all(|u| u.source == UrlSource::Har));
        assert!(urls
            .iter()
            .any(|u| u.method == "GET" && u.url.contains("id=")));
        assert!(urls.iter().any(|u| u.method == "POST"));
        assert!(!urls.iter().any(|u| u.url.contains("other.example.com")));
    }
}
