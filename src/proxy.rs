use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use colored::*;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, StatusCode};
use tokio::sync::Mutex;
use tracing::warn;

use crate::types::{HttpRequest, HttpResponse, HttpTransaction};

pub struct ProxyState {
    pub transactions: Vec<HttpTransaction>,
    pub passive_mode: bool,
    pub dump_path: Option<String>,
}

#[allow(dead_code)]
impl ProxyState {
    fn dump_path(&self) -> Option<&String> {
        self.dump_path.as_ref()
    }
}

/// Run the intercepting proxy
pub async fn run_proxy(listen: &str, dump: Option<String>, passive: bool) -> Result<()> {
    let addr: SocketAddr = listen.parse()?;

    println!(
        "{} {}",
        "▶ Proxy listening on:".bright_white().bold(),
        listen.bright_cyan()
    );

    if passive {
        println!(
            "{}",
            "  ↳ Passive analysis enabled on intercepted traffic".dimmed()
        );
    }
    if let Some(path) = &dump {
        println!(
            "  {} {}",
            "↳ Dumping requests to:".dimmed(),
            path.bright_yellow()
        );
    }

    println!(
        "{}",
        "\n  Configure your browser to use this proxy, then browse normally.".bright_white()
    );
    println!(
        "{}",
        "  Press Ctrl+C to stop and generate the report.\n".dimmed()
    );

    let state = Arc::new(Mutex::new(ProxyState {
        transactions: Vec::new(),
        passive_mode: passive,
        dump_path: dump.clone(),
    }));

    let state_clone = state.clone();

    let make_svc = make_service_fn(move |_conn| {
        let state = state_clone.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| handle_request(req, state.clone()))) }
    });

    let server = Server::bind(&addr).serve(make_svc);

    // Graceful shutdown on Ctrl+C
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let state_for_shutdown = state.clone();
    let dump_path_for_shutdown = dump.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("\n{}", "\n▶ Stopping proxy...".bright_yellow());

        let s = state_for_shutdown.lock().await;
        println!(
            "{} {} transactions captured",
            "✓".bright_green(),
            s.transactions.len()
        );

        // Save dump
        if let Some(path) = &dump_path_for_shutdown {
            let json = serde_json::to_string_pretty(&s.transactions).unwrap_or_default();
            let _ = std::fs::write(path, json);
            println!("{} {}", "✓ Transactions saved to:".bright_green(), path);
        }

        let _ = tx.send(());
    });

    server
        .with_graceful_shutdown(async {
            rx.await.ok();
        })
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}

async fn handle_request(
    req: Request<Body>,
    state: Arc<Mutex<ProxyState>>,
) -> Result<Response<Body>, Infallible> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Log to console
    println!(
        "  {} {} {}",
        method.bright_yellow(),
        uri.bright_white(),
        "→ forwarding".dimmed()
    );

    // Handle CONNECT (HTTPS tunneling)
    if method == "CONNECT" {
        let host_port = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .or_else(|| {
                headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == "host")
                    .map(|(_, v)| v.clone())
            })
            .unwrap_or_else(|| uri.clone());

        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(mut upgraded) => match tokio::net::TcpStream::connect(&host_port).await {
                    Ok(mut server) => {
                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                        {
                            tracing::debug!("CONNECT tunnel closed for {}: {}", host_port, e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to connect to target {}: {}", host_port, e);
                    }
                },
                Err(e) => {
                    warn!("CONNECT upgrade failed for {}: {}", host_port, e);
                }
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    // Forward the request
    let client: Client<hyper::client::HttpConnector> = Client::new();

    // Rebuild URI as absolute
    let forward_uri = if uri.starts_with("http") {
        uri.clone()
    } else {
        // Relative URL - try to reconstruct from host header
        let host = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "host")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        format!("http://{}{}", host, uri)
    };

    let (parts, body_stream) = req.into_parts();
    let body_bytes = match hyper::body::to_bytes(body_stream).await {
        Ok(b) => b,
        Err(_) => return Ok(error_response("Failed to read request body")),
    };

    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    let http_req = HttpRequest {
        method: method.clone(),
        url: forward_uri.clone(),
        headers: headers.clone(),
        body: if body_str.is_empty() {
            None
        } else {
            Some(body_str.clone())
        },
    };

    // Build forwarded request
    let mut forward_req = Request::builder()
        .method(parts.method.clone())
        .uri(&forward_uri);

    for (k, v) in &headers {
        // Skip proxy-specific headers
        if k.to_lowercase() != "proxy-connection" && k.to_lowercase() != "proxy-authorization" {
            if let Ok(name) = hyper::header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(value) = hyper::header::HeaderValue::from_str(v) {
                    forward_req = forward_req.header(name, value);
                }
            }
        }
    }

    let start = std::time::Instant::now();
    let forward_req = match forward_req.body(Body::from(body_bytes)) {
        Ok(r) => r,
        Err(_) => return Ok(error_response("Failed to build forward request")),
    };

    match client.request(forward_req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let resp_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let elapsed_ms = start.elapsed().as_millis() as u64;

            let (resp_parts, resp_body) = resp.into_parts();
            let resp_bytes = hyper::body::to_bytes(resp_body).await.unwrap_or_default();
            let resp_body_str = String::from_utf8_lossy(&resp_bytes).to_string();

            let http_resp = HttpResponse {
                status,
                headers: resp_headers.clone(),
                body: resp_body_str.clone(),
                elapsed_ms,
            };

            println!(
                "  {} {} {} {}ms",
                "←".bright_green(),
                status.to_string().bright_cyan(),
                forward_uri.dimmed(),
                elapsed_ms
            );

            // Run passive checks if enabled
            let passive_mode = {
                let s = state.lock().await;
                s.passive_mode
            };

            if passive_mode && status == 200 {
                // Quick passive check on response headers
                if !resp_headers
                    .iter()
                    .any(|(k, _)| k.to_lowercase() == "x-frame-options")
                {
                    println!(
                        "    {} Missing X-Frame-Options at {}",
                        "[PASSIVE][LOW]".bright_yellow(),
                        forward_uri
                    );
                }
                if !resp_headers
                    .iter()
                    .any(|(k, _)| k.to_lowercase() == "content-security-policy")
                {
                    println!(
                        "    {} Missing CSP at {}",
                        "[PASSIVE][MED]".yellow(),
                        forward_uri
                    );
                }
            }

            // Record transaction
            {
                let mut s = state.lock().await;
                s.transactions.push(HttpTransaction {
                    id: crate::types::uuid_v4(),
                    request: http_req,
                    response: Some(http_resp),
                    timestamp: chrono::Utc::now(),
                });
            }

            // Build response to client
            let mut response = Response::builder().status(resp_parts.status);
            for (k, v) in resp_headers {
                if let (Ok(name), Ok(val)) = (
                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                    hyper::header::HeaderValue::from_str(&v),
                ) {
                    response = response.header(name, val);
                }
            }

            Ok(response
                .body(Body::from(resp_bytes))
                .unwrap_or_else(|_| Response::new(Body::from("Error building response"))))
        }
        Err(e) => {
            warn!("Proxy forward error: {}", e);
            Ok(error_response(&format!("Proxy error: {}", e)))
        }
    }
}

fn error_response(msg: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from(format!("RustZAP Proxy Error: {}", msg)))
        .unwrap()
}
