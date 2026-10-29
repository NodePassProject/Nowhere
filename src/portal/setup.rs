// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal construction from URL configuration.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{
    DEFAULT_RATE_LIMIT, DialPolicy, Logger, OutboundDialer, ServiceEndpoint, SocksConfig,
    new_server_configs_with_reload_interval, query_first, rate_limit_bytes_per_second,
    resolve_bind_addrs,
};
use crate::protocol::Credentials;
use crate::transport::{Buffers, MorphKeys, RateLimiter, Stats};

use super::{
    Portal, PortalInner, admission,
    egress::EgressRegistry,
    forward::{Forwarder, Outlet},
};

const PORTAL_QUERY_PARAMETERS: &[&str] = &[
    "tls", "crt", "key", "rate", "etar", "dial", "dial4", "dial6", "morph", "out",
];

impl Portal {
    pub fn new_with_listen_host(
        url: Url,
        listen_host: Option<&str>,
        logger: Logger,
    ) -> Result<Self> {
        if url.scheme() != "portal" || url.password().is_some() || url.fragment().is_some() {
            anyhow::bail!("invalid Portal URL");
        }
        let query = query_first(&url, PORTAL_QUERY_PARAMETERS)?;
        validate_query(&query)?;
        let endpoint = ServiceEndpoint::parse(&url, true, "portal endpoint")?;
        let bind_host = listen_host.unwrap_or(&endpoint.host);
        let credentials = Credentials::for_service(&url, "Portal listener")?;
        let handshake_timeout =
            crate::common::read_handshake_timeout(&mut crate::common::env_value, &url)?;
        let runtime = super::config::PortalRuntimeConfig::from_env(handshake_timeout)?;
        let morph_keys = (query.get("morph").is_none_or(|s| s == "1"))
            .then(|| MorphKeys::from_url(&url))
            .transpose()?;
        let out = query.get("out").map(String::as_str).unwrap_or("direct");
        let registry = if out == "egress" {
            if ["dial", "dial4", "dial6"]
                .iter()
                .any(|key| query.contains_key(*key))
            {
                anyhow::bail!("out=egress conflicts with explicit dial settings");
            }
            Some(Arc::new(EgressRegistry::new(
                runtime.egress_tls_pending_max,
            )))
        } else {
            None
        };
        let dial = DialPolicy::from_query(&query)?;
        let socks = if !matches!(out, "direct" | "egress") {
            SocksConfig::from_url(&url)?
        } else {
            None
        };
        let out_label = socks
            .as_ref()
            .map_or_else(|| out.to_owned(), SocksConfig::endpoint);
        let rate = parse_rate(&query, "rate")?;
        let etar = parse_rate(&query, "etar")?;
        let (tls_mode, tls_server_config, mut quic_server_config) =
            new_server_configs_with_reload_interval(&url, runtime.reload_interval, logger)?;
        super::listener::configure_transport(
            &mut quic_server_config,
            runtime.udp_idle_timeout,
            Some(std::time::Duration::from_secs(15)),
            morph_keys.is_some(),
        )?;
        let effective = format!(
            "portal://{}?out={out_label}&tls={tls_mode}{}&morph={}&rate={rate}&etar={etar}",
            endpoint.canonical(),
            if registry.is_some() {
                String::new()
            } else {
                format!("&{}", dial.to_string().replace(' ', "&"))
            },
            u8::from(morph_keys.is_some())
        );
        let outbound = match &registry {
            Some(registry) => Outlet::Egress(registry.clone()),
            None => Outlet::Network(Arc::new(OutboundDialer::new(dial, socks))),
        };
        let forward = Arc::new(Forwarder {
            runtime,
            outbound,
            logger,
            stats: Arc::new(Stats::default()),
            buffers: Buffers::new(runtime.tcp_data_buf_size),
            rate: RateLimiter::new(
                rate_limit_bytes_per_second(rate) as i64,
                rate_limit_bytes_per_second(etar) as i64,
            )
            .map(Arc::new),
            flows: Arc::new(Semaphore::new(1024)),
            shutdown: CancellationToken::new(),
        });
        Ok(Self {
            inner: Arc::new(PortalInner {
                credentials,
                prelude_replay: (morph_keys.is_some() && endpoint.tcp.is_some())
                    .then(super::replay::ReplayProtection::new),
                morph_keys,
                tcp_bind_addrs: endpoint
                    .tcp
                    .map(|e| resolve_bind_addrs(bind_host, e))
                    .transpose()?
                    .unwrap_or_default(),
                udp_bind_addrs: endpoint
                    .udp
                    .map(|e| resolve_bind_addrs(bind_host, e))
                    .transpose()?
                    .unwrap_or_default(),
                allow_tcp_family_degrade: endpoint.host == "*"
                    && endpoint
                        .tcp
                        .is_some_and(|e| e.family == crate::common::AddressFamily::Any),
                allow_udp_family_degrade: endpoint.host == "*"
                    && endpoint
                        .udp
                        .is_some_and(|e| e.family == crate::common::AddressFamily::Any),
                tls_server_config,
                quic_server_config,
                unauthenticated_admission: Arc::new(admission::UnauthenticatedAdmission::new()),
                connection_admission: Arc::new(Semaphore::new(1024)),
                forward,
                egress_registry: registry,
                effective,
                runtime,
            }),
        })
    }
}

fn validate_query(query: &std::collections::HashMap<String, String>) -> Result<()> {
    for name in ["tls", "crt", "key", "rate", "etar", "dial", "out"] {
        if query.get(name).is_some_and(String::is_empty) {
            anyhow::bail!("empty {name} parameter");
        }
    }
    if let Some(tls) = query.get("tls")
        && !matches!(tls.as_str(), "1" | "2")
    {
        anyhow::bail!("tls=1 or tls=2 required");
    }
    if let Some(morph) = query.get("morph")
        && !matches!(morph.as_str(), "0" | "1")
    {
        anyhow::bail!("morph must be 0 or 1");
    }
    let tls_is_ca = query.get("tls").is_some_and(|value| value == "2");
    let has_crt = query.contains_key("crt");
    let has_key = query.contains_key("key");
    if (tls_is_ca && !(has_crt && has_key)) || (!tls_is_ca && (has_crt || has_key)) {
        anyhow::bail!("crt and key are required exactly when tls=2");
    }
    Ok(())
}

fn parse_rate(query: &std::collections::HashMap<String, String>, name: &str) -> Result<i32> {
    query.get(name).map_or(Ok(DEFAULT_RATE_LIMIT), |value| {
        value
            .parse::<i32>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow::anyhow!("{name} must be a non-negative integer"))
    })
}

#[cfg(test)]
#[path = "../tests/portal/setup.rs"]
mod tests;
