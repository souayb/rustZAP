//! Live DNS resolver (`hickory-resolver`). Ghost-SPN detection must resolve
//! against the *domain's* DNS (the DC), so when a `--dc-ip` is supplied we build
//! a resolver that queries it directly; otherwise we fall back to system DNS.

use std::net::IpAddr;

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

use super::probe::DnsResolver;

pub struct LiveDns {
    resolver: TokioResolver,
}

impl LiveDns {
    /// Build a resolver aimed at `dc_ip` (port 53) when it parses as an IP,
    /// else the system resolver. Falls back to a default-config resolver if the
    /// system configuration cannot be read.
    pub fn new(dc_ip: &str) -> Self {
        let resolver = match dc_ip.parse::<IpAddr>() {
            Ok(ip) => {
                // Query the DC directly over UDP+TCP on port 53.
                let config =
                    ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp(ip)]);
                Self::from_config(config)
            }
            Err(_) => TokioResolver::builder_tokio()
                .and_then(|builder| builder.build())
                .unwrap_or_else(|_| Self::from_config(ResolverConfig::default())),
        };
        LiveDns { resolver }
    }

    fn from_config(config: ResolverConfig) -> TokioResolver {
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .expect("building a hickory resolver from an explicit config is infallible")
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
