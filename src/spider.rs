use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use colored::*;
use indicatif::ProgressBar;
use scraper::{Html, Selector};
use tracing::{info, warn};
use url::Url;

use crate::types::{DiscoveredUrl, UrlSource};

/// Hard caps for robots.txt / sitemap parsing to keep the spider polite.
const ROBOTS_MAX_BYTES: usize = 256 * 1024;
const SITEMAP_MAX_BYTES: usize = 1024 * 1024;
const SITEMAP_MAX_FETCHES: usize = 5;
const ROBOTS_SITEMAP_MAX_URLS: usize = 500;

pub struct Spider {
    client: Arc<reqwest::Client>,
    base_url: String,
    base_host: String,
    max_depth: usize,
    concurrency: usize,
}

impl Spider {
    pub fn new(
        client: Arc<reqwest::Client>,
        base_url: String,
        max_depth: usize,
        concurrency: usize,
    ) -> Self {
        let parsed = Url::parse(&base_url).expect("Invalid base URL");
        let base_host = parsed.host_str().unwrap_or("").to_string();

        Spider {
            client,
            base_url,
            base_host,
            max_depth,
            concurrency,
        }
    }

    /// Crawl the target and return all discovered URLs
    pub async fn crawl(&self, pb: &ProgressBar) -> Result<Vec<DiscoveredUrl>> {
        self.crawl_with_cache(pb, None).await
    }

    /// Crawl the target with optional response caching for zero-network passive scanning.
    pub async fn crawl_with_cache(
        &self,
        pb: &ProgressBar,
        cache: Option<&crate::types::HttpResponseCache>,
    ) -> Result<Vec<DiscoveredUrl>> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut results: Vec<DiscoveredUrl> = Vec::new();
        let mut queue: VecDeque<(DiscoveredUrl, usize)> = VecDeque::new();

        let seed = DiscoveredUrl::new(self.base_url.clone(), "GET", UrlSource::Seed);
        visited.insert(self.base_url.clone());
        results.push(seed.clone());
        queue.push_back((seed, 0));

        // A2: robots.txt + sitemap enrichment
        if let Ok(base) = Url::parse(&self.base_url) {
            let enriched = self.fetch_robots_and_sitemaps(&base, &self.base_host).await;
            for du in enriched {
                if visited.insert(du.url.clone()) {
                    results.push(du.clone());
                    queue.push_back((du, 0));
                }
            }
        }

        use futures::stream::FuturesUnordered;
        use futures::StreamExt;
        let mut in_flight = FuturesUnordered::new();

        loop {
            // Fill in-flight pool up to concurrency limit
            while in_flight.len() < self.concurrency && !queue.is_empty() {
                if let Some((du, depth)) = queue.pop_front() {
                    if depth >= self.max_depth {
                        continue;
                    }
                    let client = self.client.clone();
                    let base_host = self.base_host.clone();
                    in_flight.push(async move {
                        let resp_result = client.get(&du.url).send().await;
                        match resp_result {
                            Ok(resp) => {
                                let status = resp.status().as_u16();
                                if !resp.status().is_success() {
                                    return (du, depth, None);
                                }
                                let headers: Vec<(String, String)> = resp
                                    .headers()
                                    .iter()
                                    .map(|(k, v)| {
                                        (k.to_string(), v.to_str().unwrap_or("").to_string())
                                    })
                                    .collect();
                                match resp.text().await {
                                    Ok(body) => {
                                        let base_url = Url::parse(&du.url).ok();
                                        let extracted =
                                            extract_urls(&body, base_url.as_ref(), &base_host);
                                        (du, depth, Some((status, headers, body, extracted)))
                                    }
                                    Err(_) => (du, depth, None),
                                }
                            }
                            Err(e) => {
                                warn!("Failed to fetch {}: {}", du.url, e);
                                (du, depth, None)
                            }
                        }
                    });
                }
            }

            if in_flight.is_empty() && queue.is_empty() {
                break;
            }

            if let Some((du, depth, maybe_data)) = in_flight.next().await {
                pb.set_message(format!(
                    "depth={} {}",
                    depth,
                    &du.url[..du.url.len().min(60)]
                ));
                if let Some((status, headers, body, extracted)) = maybe_data {
                    if let Some(c) = cache {
                        c.insert(du.url.clone(), status, headers, body).await;
                    }
                    for discovered in extracted {
                        let url_str = discovered.url.clone();
                        if visited.insert(url_str) {
                            results.push(discovered.clone());
                            if depth + 1 < self.max_depth {
                                queue.push_back((discovered, depth + 1));
                            }
                            pb.set_message(format!("Found {} URLs", results.len()));
                        }
                    }
                }
            }
        }

        info!("Spider finished: {} URLs discovered", results.len());
        Ok(results)
    }

    /// Fetch `{origin}/robots.txt`, parse it, then fetch any declared sitemaps
    /// (bounded by the constants above) and return discovered URLs. Returns
    /// `vec![]` on any network error — robots is best-effort.
    async fn fetch_robots_and_sitemaps(&self, base: &Url, base_host: &str) -> Vec<DiscoveredUrl> {
        let mut out: Vec<DiscoveredUrl> = Vec::new();
        let Ok(robots_url) = base.join("/robots.txt") else {
            return out;
        };

        let robots_text =
            match fetch_capped(&self.client, robots_url.as_str(), ROBOTS_MAX_BYTES).await {
                Some(t) => t,
                None => return out,
            };

        let parsed = parse_robots_txt(&robots_text);

        // Allow/Disallow → enqueue as same-host URLs
        for path in parsed.paths.iter() {
            if out.len() >= ROBOTS_SITEMAP_MAX_URLS {
                break;
            }
            if let Some(resolved) = resolve_url(path, Some(base)) {
                if is_same_host(&resolved, base_host) && is_http_url(&resolved) {
                    let params = extract_query_params(&resolved);
                    out.push(DiscoveredUrl {
                        url: normalize_url(&resolved),
                        method: "GET".to_string(),
                        headers: Vec::new(),
                        body: None,
                        content_type: None,
                        parameters: params,
                        source: UrlSource::Robots,
                    });
                }
            }
        }

        // Sitemaps → fetch, parse, enqueue same-host URLs
        for (i, sitemap_url) in parsed.sitemaps.iter().enumerate() {
            if i >= SITEMAP_MAX_FETCHES || out.len() >= ROBOTS_SITEMAP_MAX_URLS {
                break;
            }
            let Some(xml) = fetch_capped(&self.client, sitemap_url, SITEMAP_MAX_BYTES).await else {
                continue;
            };
            let urls = parse_sitemap_xml(&xml, ROBOTS_SITEMAP_MAX_URLS - out.len());
            for u in urls {
                if let Ok(parsed_url) = Url::parse(&u) {
                    if is_same_host(&parsed_url, base_host) && is_http_url(&parsed_url) {
                        let params = extract_query_params(&parsed_url);
                        out.push(DiscoveredUrl {
                            url: normalize_url(&parsed_url),
                            method: "GET".to_string(),
                            headers: Vec::new(),
                            body: None,
                            content_type: None,
                            parameters: params,
                            source: UrlSource::Sitemap,
                        });
                    }
                }
                if out.len() >= ROBOTS_SITEMAP_MAX_URLS {
                    break;
                }
            }
        }

        out
    }
}

/// Bounded GET that reads at most `max_bytes` of the response body as text.
/// Returns `None` on transport error or non-2xx status.
async fn fetch_capped(client: &reqwest::Client, url: &str, max_bytes: usize) -> Option<String> {
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(6))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // reqwest doesn't expose a clean byte cap mid-stream; read fully then truncate.
    // The Content-Length check below short-circuits the common case.
    if let Some(len) = resp.content_length() {
        if (len as usize) > max_bytes.saturating_mul(4) {
            warn!("robots/sitemap response too large: {} bytes", len);
            return None;
        }
    }
    let body = resp.text().await.ok()?;
    if body.len() > max_bytes {
        Some(body[..max_bytes].to_string())
    } else {
        Some(body)
    }
}

/// Parsed view of a robots.txt file. We deliberately ignore `User-agent`
/// scoping — for scanning purposes we want *every* path the site mentions.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RobotsInfo {
    /// Combined Allow + Disallow paths (verbatim values, may be relative).
    pub paths: Vec<String>,
    /// Absolute sitemap URLs declared via `Sitemap:` lines.
    pub sitemaps: Vec<String>,
}

/// Parse robots.txt into a `RobotsInfo`. Comments (`#`) and empty values
/// are dropped. `Disallow: /` (block everything) is *kept* because a scanner
/// wants to probe paths the site is trying to hide.
pub fn parse_robots_txt(text: &str) -> RobotsInfo {
    let mut info = RobotsInfo::default();
    for raw in text.lines() {
        // Strip inline comments.
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.as_str() {
            "allow" | "disallow" => info.paths.push(value.to_string()),
            "sitemap" => info.sitemaps.push(value.to_string()),
            _ => {}
        }
    }
    info
}

/// Extract `<loc>` URLs from a sitemap (urlset) or sitemapindex XML payload.
/// `max` caps the number of URLs returned. This is a deliberately tiny
/// parser — we look for `<loc>...</loc>` text content via byte scan rather
/// than pulling in a full XML library.
pub fn parse_sitemap_xml(xml: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = xml.as_bytes();
    let mut i = 0;
    while i < bytes.len() && out.len() < max {
        if let Some(start) = find_subslice(&bytes[i..], b"<loc>") {
            let abs_start = i + start + b"<loc>".len();
            if let Some(end) = find_subslice(&bytes[abs_start..], b"</loc>") {
                let raw = &xml[abs_start..abs_start + end];
                let url = decode_xml_entities(raw.trim());
                if !url.is_empty() {
                    out.push(url);
                }
                i = abs_start + end + b"</loc>".len();
                continue;
            }
        }
        break;
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn decode_xml_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Extract all links, form actions, and JS fetch targets from HTML
fn extract_urls(html: &str, base: Option<&Url>, base_host: &str) -> Vec<DiscoveredUrl> {
    let document = Html::parse_document(html);
    let mut found = Vec::new();

    // <a href>
    if let Ok(sel) = Selector::parse("a[href]") {
        for el in document.select(&sel) {
            if let Some(href) = el.value().attr("href") {
                if let Some(url) = resolve_url(href, base) {
                    if is_same_host(&url, base_host) && is_http_url(&url) {
                        let params = extract_query_params(&url);
                        found.push(DiscoveredUrl {
                            url: normalize_url(&url),
                            method: "GET".to_string(),
                            headers: Vec::new(),
                            body: None,
                            content_type: None,
                            parameters: params,
                            source: UrlSource::Link,
                        });
                    }
                }
            }
        }
    }

    // <form action>
    if let Ok(form_sel) = Selector::parse("form") {
        for form in document.select(&form_sel) {
            let action = form.value().attr("action").unwrap_or("");
            let method = form.value().attr("method").unwrap_or("get").to_uppercase();
            let target_url = if action.is_empty() {
                base.map(|b| b.to_string()).unwrap_or_default()
            } else {
                resolve_url(action, base)
                    .map(|u| normalize_url(&u))
                    .unwrap_or_else(|| action.to_string())
            };

            if target_url.is_empty() {
                continue;
            }

            // Extract input names
            let mut params = Vec::new();
            if let Ok(input_sel) = Selector::parse("input, select, textarea") {
                for input in form.select(&input_sel) {
                    if let Some(name) = input.value().attr("name") {
                        params.push(name.to_string());
                    }
                }
            }

            if let Ok(parsed) = Url::parse(&target_url) {
                if is_same_host(&parsed, base_host) {
                    found.push(DiscoveredUrl {
                        url: target_url,
                        method,
                        headers: Vec::new(),
                        body: None,
                        content_type: None,
                        parameters: params,
                        source: UrlSource::Form,
                    });
                }
            }
        }
    }

    // <script src> - just add as a URL to visit headers
    if let Ok(sel) = Selector::parse("script[src]") {
        for el in document.select(&sel) {
            if let Some(src) = el.value().attr("src") {
                if let Some(url) = resolve_url(src, base) {
                    if is_same_host(&url, base_host) {
                        found.push(DiscoveredUrl {
                            url: normalize_url(&url),
                            method: "GET".to_string(),
                            headers: Vec::new(),
                            body: None,
                            content_type: None,
                            parameters: vec![],
                            source: UrlSource::Script,
                        });
                    }
                }
            }
        }
    }

    // Extract URLs from inline JS (simple regex-like scan)
    let js_urls = extract_js_urls(html, base, base_host);
    found.extend(js_urls);

    found
}

/// Very naive inline JS URL extraction
fn extract_js_urls(html: &str, base: Option<&Url>, base_host: &str) -> Vec<DiscoveredUrl> {
    let mut found = Vec::new();
    // Look for fetch('/api/...'), axios.get('/api/...'), href = '/path'
    let patterns = [
        r#"fetch\(['"](/[^'"]+)['"]\)"#,
        r#"\.get\(['"](/[^'"]+)['"]\)"#,
        r#"\.post\(['"](/[^'"]+)['"]\)"#,
        r#"href\s*=\s*['"](/[^'"]+)['"]\)"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for cap in re.captures_iter(html) {
                if let Some(path) = cap.get(1) {
                    if let Some(url) = resolve_url(path.as_str(), base) {
                        if is_same_host(&url, base_host) {
                            found.push(DiscoveredUrl {
                                url: normalize_url(&url),
                                method: "GET".to_string(),
                                headers: Vec::new(),
                                body: None,
                                content_type: None,
                                parameters: vec![],
                                source: UrlSource::Script,
                            });
                        }
                    }
                }
            }
        }
    }
    found
}

fn resolve_url(href: &str, base: Option<&Url>) -> Option<Url> {
    if href.starts_with("javascript:") || href.starts_with("mailto:") || href.starts_with('#') {
        return None;
    }
    if let Ok(url) = Url::parse(href) {
        return Some(url);
    }
    if let Some(base) = base {
        base.join(href).ok()
    } else {
        None
    }
}

fn is_same_host(url: &Url, base_host: &str) -> bool {
    url.host_str().map(|h| h == base_host).unwrap_or(false)
}

fn is_http_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

fn normalize_url(url: &Url) -> String {
    // Remove fragments
    let mut u = url.clone();
    u.set_fragment(None);
    u.to_string()
}

fn extract_query_params(url: &Url) -> Vec<String> {
    url.query_pairs().map(|(k, _)| k.to_string()).collect()
}

/// CLI entry point for spider-only command
pub async fn run_spider_cli(target: &str, depth: usize, output: Option<String>) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};

    println!(
        "{} {}",
        "▶ Spidering:".bright_white().bold(),
        target.bright_cyan()
    );

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("RustZAP/0.1 Spider")
            .cookie_store(true)
            .build()?,
    );

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {prefix:.bold} {msg}")
            .unwrap(),
    );
    pb.set_prefix("SPIDER");
    pb.enable_steady_tick(Duration::from_millis(100));

    let spider = Spider::new(client, target.to_string(), depth, 10);
    let results = spider.crawl(&pb).await?;
    pb.finish_with_message(format!("✓ {} URLs", results.len()));

    // Print results
    println!("\n{} Discovered URLs:", "►".bright_cyan());
    for url in &results {
        println!(
            "  {} {} {}",
            url.method.bright_yellow(),
            url.url,
            if url.parameters.is_empty() {
                String::new()
            } else {
                format!("[params: {}]", url.parameters.join(", "))
                    .dimmed()
                    .to_string()
            }
        );
    }

    // Save if requested
    if let Some(path) = output {
        let json = serde_json::to_string_pretty(&results)?;
        tokio::fs::write(&path, json).await?;
        println!("\n{} {}", "✓ Saved to:".bright_green(), path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_robots_extracts_paths_and_sitemaps() {
        let text = "\
User-agent: *
Disallow: /admin/
Allow: /admin/public/
Disallow: /private # admin only
# Standalone comment
Sitemap: https://example.com/sitemap.xml
sitemap: https://example.com/sitemap2.xml
";
        let info = parse_robots_txt(text);
        assert_eq!(info.paths, vec!["/admin/", "/admin/public/", "/private"]);
        assert_eq!(
            info.sitemaps,
            vec![
                "https://example.com/sitemap.xml",
                "https://example.com/sitemap2.xml"
            ]
        );
    }

    #[test]
    fn parse_robots_skips_empty_values_and_unknown_keys() {
        let text = "Disallow:\nCrawl-delay: 5\nSitemap: \n";
        let info = parse_robots_txt(text);
        assert!(info.paths.is_empty());
        assert!(info.sitemaps.is_empty());
    }

    #[test]
    fn parse_sitemap_extracts_loc_tags() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/a</loc></url>
  <url><loc>https://example.com/b?x=1&amp;y=2</loc></url>
  <url><loc> https://example.com/c </loc></url>
</urlset>"#;
        let urls = parse_sitemap_xml(xml, 100);
        assert_eq!(
            urls,
            vec![
                "https://example.com/a",
                "https://example.com/b?x=1&y=2",
                "https://example.com/c",
            ]
        );
    }

    #[test]
    fn parse_sitemap_respects_max() {
        let xml = "<urlset><url><loc>https://example.com/a</loc></url>\
<url><loc>https://example.com/b</loc></url>\
<url><loc>https://example.com/c</loc></url></urlset>";
        let urls = parse_sitemap_xml(xml, 2);
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn parse_sitemap_handles_index_with_uppercase_tags() {
        let xml =
            "<sitemapindex><sitemap><LOC>https://example.com/s1.xml</LOC></sitemap></sitemapindex>";
        let urls = parse_sitemap_xml(xml, 10);
        assert_eq!(urls, vec!["https://example.com/s1.xml"]);
    }

    #[test]
    fn parse_sitemap_returns_empty_for_garbage() {
        assert!(parse_sitemap_xml("not xml", 10).is_empty());
        assert!(parse_sitemap_xml("", 10).is_empty());
    }
}
