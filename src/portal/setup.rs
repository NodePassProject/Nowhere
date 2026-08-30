// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal construction from URL configuration.

use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{
    DEFAULT_RATE_LIMIT, LifeMode, LifeReason, LifeState, Lifecycle, Logger, OutboundDialer,
    SocksConfig, bind_udp_addrs, first_raw_query_value, init_dialer_ip,
    new_server_configs_with_reload_interval, query_first, rate_limit_bytes_per_second,
};
use crate::protocol::Credentials;
use crate::telemetry::{InstanceRole, TelemetryHub};
use crate::transport::{Buffers, RateLimiter, Stats};
use crate::vector::{PortalClient, PortalClientConfig};

use super::listener::{configure_transport, format_endpoint_addr};
use super::{NetworkMode, Portal, PortalInner, UdpFlowLimits, admission, outbound::PortalOutbound};

const PORTAL_QUERY_PARAMETERS: &[&str] = &[
    "net", "tls", "crt", "key", "rate", "etar", "dial", "socks", "next", "log",
];
const PORTAL_UPSTREAM_PARAMETERS: &[&str] = &["up", "down", "mux", "sni", "pin"];

impl Portal {
    /// Builds a portal using the listen host encoded in the URL.
    pub fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        Self::new_with_listen_host(parsed_url, None, logger)
    }

    /// Builds a portal while optionally overriding the URL listen host.
    ///
    /// Tests use the override to bind ephemeral local endpoints without
    /// changing the URL-derived visible configuration.
    pub fn new_with_listen_host(
        parsed_url: Url,
        listen_host: Option<&str>,
        logger: Logger,
    ) -> Result<Self> {
        let lifecycle = Arc::new(Lifecycle::new(LifeMode::Portal));
        lifecycle.transition(&logger, LifeState::Starting, LifeReason::Startup);
        let result = Self::build(parsed_url, listen_host, logger.clone(), lifecycle.clone());
        if result.is_err() {
            lifecycle.transition(&logger, LifeState::Stopped, LifeReason::StartFailed);
            logger.flush();
        }
        result
    }

    fn build(
        parsed_url: Url,
        listen_host: Option<&str>,
        logger: Logger,
        lifecycle: Arc<Lifecycle>,
    ) -> Result<Self> {
        if parsed_url.scheme() != "portal" {
            anyhow::bail!("portal::new: URL scheme must be portal");
        }
        if parsed_url.password().is_some() {
            anyhow::bail!("portal::new: password userinfo is not supported");
        }
        if parsed_url.fragment().is_some() {
            anyhow::bail!("portal::new: URL fragments are not supported");
        }
        if !parsed_url.path().is_empty() {
            anyhow::bail!("portal::new: URL paths are not supported");
        }
        let mut query = query_first(&parsed_url, PORTAL_QUERY_PARAMETERS)
            .map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        validate_query(&query).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let port = parsed_url
            .port()
            .ok_or_else(|| anyhow::anyhow!("portal::new: missing listen port"))?;
        if port == 0 {
            anyhow::bail!("portal::new: listen port must be non-zero");
        }
        let credentials =
            Credentials::new(&parsed_url).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let runtime = super::config::PortalRuntimeConfig::from_env()
            .map_err(|e| anyhow::anyhow!("portal::new: invalid runtime configuration: {e}"))?;
        let network_mode =
            NetworkMode::from_url(&parsed_url).map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;
        let (tls_mode, tls_server_config, mut quic_server_config) =
            new_server_configs_with_reload_interval(
                &parsed_url,
                runtime.reload_interval,
                logger.clone(),
            )
            .map_err(|e| anyhow::anyhow!("portal::new: {e}"))?;

        let host = listen_host.unwrap_or_else(|| parsed_url.host_str().unwrap_or_default());
        let endpoint_addr = format_endpoint_addr(host, port);
        let bind_addrs = bind_udp_addrs(host, port)
            .map_err(|e| anyhow::anyhow!("portal::new: failed to bind listen address: {e}"))?;

        let dialer_ip = init_dialer_ip(query.get("dial").map(String::as_str));
        let socks = SocksConfig::from_url(&parsed_url).map_err(|e| {
            anyhow::anyhow!("portal::new: failed to parse socks configuration: {e}")
        })?;
        let next = match query.get("next").map(String::as_str) {
            None | Some("none") => None,
            Some("") => anyhow::bail!("portal::new: empty next parameter"),
            Some(_) => {
                query.extend(
                    query_first(&parsed_url, PORTAL_UPSTREAM_PARAMETERS)
                        .map_err(|e| anyhow::anyhow!("portal::new: {e}"))?,
                );
                let raw = first_raw_query_value(&parsed_url, "next")
                    .expect("decoded next came from the raw query");
                Some(
                    PortalClientConfig::from_upstream_authority(raw, &query, &dialer_ip)
                        .map_err(|error| anyhow::anyhow!("portal::new: {error}"))?,
                )
            }
        };
        if socks.is_some() && next.is_some() {
            anyhow::bail!("portal::new: socks and next are mutually exclusive");
        }
        let rate_limit = parse_rate(&query, "rate")?;
        let etar_limit = parse_rate(&query, "etar")?;

        configure_transport(&mut quic_server_config, runtime.udp_idle_timeout, None)?;

        let read_bps = rate_limit_bytes_per_second(rate_limit) as i64;
        let write_bps = rate_limit_bytes_per_second(etar_limit) as i64;
        let rate_limiter = RateLimiter::new(read_bps, write_bps).map(Arc::new);
        let udp_flow_limits = UdpFlowLimits {
            max_flows: runtime.max_udp_flows,
            queue_bytes: runtime.udp_queue_bytes,
        };
        let socks_endpoint = socks
            .as_ref()
            .map(SocksConfig::endpoint)
            .unwrap_or_else(|| "none".to_owned());
        let next_summary = next.as_ref().map_or_else(
            || "next=none".to_owned(),
            |(config, _)| format!("next={} {}", config.endpoint(), config.effective_route()),
        );
        let telemetry_summary = format!(
            "net={network_mode} tls={tls_mode} rate={rate_limit} etar={etar_limit} dial={dialer_ip} socks={socks_endpoint} {next_summary}",
        );
        let telemetry = TelemetryHub::for_current_process(
            InstanceRole::Portal,
            endpoint_addr.clone(),
            telemetry_summary,
            runtime.telemetry_interval,
        );
        let outbound = match next {
            Some((config, credentials)) => PortalOutbound::portal(PortalClient::new(
                config,
                &credentials,
                Arc::new(Stats::default()),
                false,
                telemetry.clone(),
                CancellationToken::new(),
            )?),
            None => PortalOutbound::network(OutboundDialer::new(dialer_ip, socks)),
        };

        Ok(Self {
            inner: Arc::new(PortalInner {
                credentials,
                tls_mode,
                network_mode,
                endpoint_addr,
                bind_addrs,
                listen_port: port,
                outbound,
                rate_limit,
                etar_limit,
                logger,
                lifecycle,
                telemetry,
                drain: CancellationToken::new(),
                runtime,
                stats: Arc::new(Stats::default()),
                buffers: Buffers::new(runtime.tcp_data_buf_size, runtime.udp_data_buf_size),
                rate_limiter,
                udp_flow_limits,
                tls_server_config,
                quic_server_config,
                unauthenticated_admission: Arc::new(admission::UnauthenticatedAdmission::new()),
                pairing: Arc::new(super::pairing::PairingRegistry::new(
                    runtime.max_tcp_flows as usize,
                    udp_flow_limits.max_flows,
                    runtime.max_pending_pairs,
                    runtime.flow_pair_timeout,
                )),
                ready_gate: super::tasks::ReadyGate::default(),
                connection_tasks: Arc::new(super::tasks::FlowTaskTracker::default()),
                relay_tasks: Arc::new(super::tasks::FlowTaskTracker::default()),
            }),
        })
    }
}

fn validate_query(query: &std::collections::HashMap<String, String>) -> Result<()> {
    for name in [
        "log", "tls", "crt", "key", "net", "rate", "etar", "dial", "socks",
    ] {
        if query.get(name).is_some_and(String::is_empty) {
            anyhow::bail!("empty {name} parameter");
        }
    }
    if let Some(log) = query.get("log")
        && !matches!(
            log.as_str(),
            "none" | "debug" | "info" | "warn" | "error" | "event"
        )
    {
        anyhow::bail!("invalid log level");
    }
    if let Some(tls) = query.get("tls")
        && !matches!(tls.as_str(), "1" | "2")
    {
        anyhow::bail!("tls=1 or tls=2 required");
    }
    if let Some(net) = query.get("net")
        && !matches!(net.as_str(), "mix" | "tcp" | "udp")
    {
        anyhow::bail!("invalid net mode");
    }
    let tls_is_ca = query.get("tls").is_some_and(|value| value == "2");
    let has_crt = query.contains_key("crt");
    let has_key = query.contains_key("key");
    if (tls_is_ca && !(has_crt && has_key)) || (!tls_is_ca && (has_crt || has_key)) {
        anyhow::bail!("crt and key are required exactly when tls=2");
    }
    if let Some(dial) = query.get("dial")
        && dial != "auto"
        && dial.parse::<std::net::IpAddr>().is_err()
    {
        anyhow::bail!("dial must be auto or an IP literal");
    }
    Ok(())
}

fn parse_rate(query: &std::collections::HashMap<String, String>, name: &str) -> Result<i32> {
    query.get(name).map_or(Ok(DEFAULT_RATE_LIMIT), |value| {
        value
            .parse::<i32>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow::anyhow!("invalid {name} rate limit"))
    })
}
