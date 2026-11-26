// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Validated Egress configuration and shared target-forwarding construction.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{DialPolicy, Logger, OutboundDialer, parse_rate, query_first};
use crate::portal::forward::{Forwarder, Outlet};
use crate::protocol::Credentials;
use crate::transport::{Buffers, MorphKeys, RateLimiter, Stats};
use crate::vector::{PortalClientConfig, tls::ClientTls};

use super::Egress;

impl Egress {
    pub fn new(url: Url, logger: Logger) -> Result<Self> {
        if url.scheme() != "egress" {
            bail!("Egress configuration: URL scheme must be egress");
        }
        crate::common::validate_timeout_env()?;
        let query = query_first(
            &url,
            &[
                "sni", "pin", "morph", "grade", "cipher", "dial", "dial4", "dial6", "rate", "etar",
            ],
        )?;
        let config = PortalClientConfig::parse(&url, &query)?;
        let credentials = Credentials::new(&url)?;
        let upload = parse_rate(&query, "rate")?;
        let download = parse_rate(&query, "etar")?;
        let runtime =
            crate::portal::config::PortalRuntimeConfig::from_env(config.handshake_timeout)?;
        let tls = ClientTls::new(&config)?;
        let dial = DialPolicy::from_query(&query)?;
        let effective = format!(
            "egress://{}?sni={}&pin={}&{}&{}&rate={upload}&etar={download}",
            config.endpoint(),
            config.sni.as_deref().unwrap_or(config.host()),
            config.pin.as_deref().unwrap_or("none"),
            dial.to_string().replace(' ', "&"),
            MorphKeys::effective_query(config.morph_keys.as_ref())
        );
        let tls_pool_max = if config.net == crate::vector::config::CarrierMode::Tcp {
            tls_pool_max_from_env()?
        } else {
            128
        };
        let forward = Arc::new(Forwarder {
            runtime,
            outbound: Outlet::Network(Arc::new(OutboundDialer::new(dial, None))),
            logger,
            stats: Arc::new(Stats::default()),
            buffers: Buffers::new(runtime.tcp_data_buf_size),
            rate: RateLimiter::new(
                crate::common::rate_limit_bytes_per_second(upload) as i64,
                crate::common::rate_limit_bytes_per_second(download) as i64,
            )
            .map(Arc::new),
            flows: Arc::new(Semaphore::new(1024)),
            shutdown: CancellationToken::new(),
        });
        Ok(Self {
            config,
            credentials,
            forward,
            tls,
            effective,
            tls_pool_max,
        })
    }
}

#[cfg(test)]
#[path = "../tests/egress/setup.rs"]
mod tests;

fn tls_pool_max_from_env() -> Result<usize> {
    match std::env::var("NOW_EGRESS_TLS_POOL_MAX") {
        Ok(raw) => parse_tls_pool_max(&raw),
        Err(std::env::VarError::NotPresent) => Ok(128),
        Err(error) => Err(error.into()),
    }
}

fn parse_tls_pool_max(raw: &str) -> Result<usize> {
    let value = raw
        .parse::<usize>()
        .context("invalid NOW_EGRESS_TLS_POOL_MAX")?;
    if value == 0 || value > Semaphore::MAX_PERMITS {
        bail!(
            "NOW_EGRESS_TLS_POOL_MAX must be in 1..={}",
            Semaphore::MAX_PERMITS
        );
    }
    Ok(value)
}
