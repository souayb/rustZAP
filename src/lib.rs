//! RustZAP library — scanner modules (binary entrypoint: `src/main.rs`).

// `#[async_trait]` expands async trait methods into functions that return an
// already-`#[must_use]` boxed future while also attaching its own `#[must_use]`,
// which Rust 1.99's clippy flags as `double_must_use` on every async-trait in the
// crate. The attribute is macro-generated and harmless, so allow it crate-wide.
#![allow(clippy::double_must_use)]

pub mod active;
pub mod ad;
pub mod agent;
pub mod analyze;
pub mod cache_abuse;
pub mod correlate;
pub mod crypto_sig;
pub mod events;
pub mod executable;
pub mod har;
pub mod installer;
pub mod intel;
pub mod mcp;
pub mod nuclei;
pub mod openapi;
pub mod passive;
pub mod proxy;
pub mod rate_limit;
pub mod replay;
pub mod report;
pub mod safety;
pub mod sarif;
pub mod scanner;
pub mod sensitive_paths;
pub mod spider;
pub mod sqli_advanced;
pub mod stress;
pub mod tls;
pub mod tools;
pub mod tui;
pub mod types;
pub mod verify;
