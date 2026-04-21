use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use colored::*;
use indicatif::ProgressBar;
use scraper::{Html, Selector};
use tokio::sync::Mutex;
use tracing::{info, warn};
use url::Url;

use crate::types::{DiscoveredUrl, UrlSource};

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
        let visited: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let results: Arc<Mutex<Vec<DiscoveredUrl>>> = Arc::new(Mutex::new(Vec::new()));

        // Seed URL
        let seed = DiscoveredUrl {
            url: self.base_url.clone(),
            method: "GET".to_string(),
            parameters: vec![],
            source: UrlSource::Seed,
        };

        {
            let mut vis = visited.lock().await;
            vis.insert(self.base_url.clone());
        }

        let queue: Arc<Mutex<VecDeque<(DiscoveredUrl, usize)>>> = Arc::new(Mutex::new(VecDeque::new()));
        {
            let mut q = queue.lock().await;
            q.push_back((seed.clone(), 0));
        }

        results.lock().await.push(seed);

        loop {
            // Drain up to `concurrency` items
            let batch: Vec<(DiscoveredUrl, usize)> = {
                let mut q = queue.lock().await;
                let take = self.concurrency.min(q.len());
                q.drain(..take).collect()
            };

            if batch.is_empty() {
                break;
            }

            let tasks: Vec<_> = batch
                .into_iter()
                .map(|(du, depth)| {
                    let client = self.client.clone();
                    let visited = visited.clone();
                    let results = results.clone();
                    let queue = queue.clone();
                    let base_host = self.base_host.clone();
                    let max_depth = self.max_depth;
                    let pb = pb.clone();

                    tokio::spawn(async move {
                        if depth >= max_depth {
                            return;
                        }

                        pb.set_message(format!("depth={} {}", depth, &du.url[..du.url.len().min(60)]));

                        let body = match client.get(&du.url).send().await {
                            Ok(resp) => {
                                if !resp.status().is_success() {
                                    return;
                                }
                                match resp.text().await {
                                    Ok(t) => t,
                                    Err(_) => return,
                                }
                            }
                            Err(e) => {
                                warn!("Failed to fetch {}: {}", du.url, e);
                                return;
                            }
                        };

                        let base_url = Url::parse(&du.url).ok();
                        let extracted = extract_urls(&body, base_url.as_ref(), &base_host);

                        for discovered in extracted {
                            let url_str = discovered.url.clone();
                            let mut vis = visited.lock().await;
                            if !vis.contains(&url_str) {
                                vis.insert(url_str);
                                results.lock().await.push(discovered.clone());
                                queue.lock().await.push_back((discovered, depth + 1));
                                pb.set_message(format!("Found {} URLs", results.lock().await.len()));
                            }
                        }
                    })
                })
                .collect();

            for t in tasks {
                let _ = t.await;
            }
        }

        let final_results = results.lock().await.clone();
        info!("Spider finished: {} URLs discovered", final_results.len());
        Ok(final_results)
    }
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

            if target_url.is_empty() { continue; }

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
    url.query_pairs()
        .map(|(k, _)| k.to_string())
        .collect()
}

/// CLI entry point for spider-only command
pub async fn run_spider_cli(target: &str, depth: usize, output: Option<String>) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};

    println!("{} {}", "▶ Spidering:".bright_white().bold(), target.bright_cyan());

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
                format!("[params: {}]", url.parameters.join(", ")).dimmed().to_string()
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
