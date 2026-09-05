//! Live DNS resolver (`hickory-resolver`). Ghost-SPN detection must resolve
//! against the *domain's* DNS (the DC), so when a `--dc-ip` is supplied we build
//! a resolver that queries it directly; otherwise we fall back to system DNS.

use std::net::IpAddr;

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use super::probe::DnsResolver;

pub struct LiveDns {
    resolver: TokioAsyncResolver,
}

impl LiveDns {
    /// Build a resolver aimed at `dc_ip` (port 53) when it parses as an IP,
    /// else the system resolver.
    pub fn new(dc_ip: &str) -> Self {
        let resolver = match dc_ip.parse::<IpAddr>() {
            Ok(ip) => {
                let group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
                let config = ResolverConfig::from_parts(None, vec![], group);
                TokioAsyncResolver::tokio(config, ResolverOpts::default())
            }
            Err(_) => TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            }),
        };
        LiveDns { resolver }
    }
}

#[async_trait]
impl DnsResolver for LiveDns {
    async fn resolves(&self, host: &str) -> bool {
        self.resolver
            .lookup_ip(host)
            .await
            .map(|r| r.iter().next().is_some())
            .unwrap_or(false)
    }
}
