// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Native Rust client exposed by the `vector://` command URL.

mod config;
mod event;
pub(crate) mod flow;
mod flow_id;
mod route;
mod session;
mod socks;
mod tls;
pub(crate) mod udp_flow;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use url::Url;

pub(crate) use self::config::PortalClientConfig;
use self::config::VectorConfig;
use self::flow_id::FlowIdAllocator;
use self::session::{ClientSignals, QuicManager, TlsManager};
use self::tls::ClientTls;
use crate::common::{
    LatencyTracker, LifeMode, LifeReason, LifeState, Lifecycle, Logger, ShutdownSignals,
    max_tcp_flows, max_udp_flows, rate_limit_bytes_per_second, shutdown_timeout, tcp_data_buf_size,
    telemetry_interval, udp_data_buf_size,
};
use crate::protocol::{Credentials, SESSION_ID_LEN};
use crate::telemetry::TelemetryServer;
use crate::telemetry::{InstanceRole, TelemetryHub};
use crate::transport::{Buffers, RateLimiter, Stats};

/// Runnable native client serving a local SOCKS5 endpoint.
pub struct Vector {
    inner: Arc<VectorInner>,
}

pub(super) struct VectorInner {
    config: VectorConfig,
    logger: Logger,
    lifecycle: Arc<Lifecycle>,
    telemetry: Arc<TelemetryHub>,
    telemetry_interval: std::time::Duration,
    stats: Arc<Stats>,
    buffers: Buffers,
    rate_limiter: Option<Arc<RateLimiter>>,
    client: Arc<PortalClient>,
    local_udp_budget: Arc<Semaphore>,
    socks_admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

/// Authenticated, transport-only Portal client shared by Vector and chained
/// Portal egress. It owns no listener and performs no SOCKS conversion.
pub(crate) struct PortalClient {
    config: PortalClientConfig,
    telemetry: Arc<TelemetryHub>,
    stats: Arc<Stats>,
    account_stats: bool,
    latency: Arc<LatencyTracker>,
    flow_ids: Arc<FlowIdAllocator>,
    tcp_flow_permits: Arc<Semaphore>,
    udp_flow_permits: Arc<Semaphore>,
    tls_manager: Arc<TlsManager>,
    quic: Arc<QuicManager>,
    route_seed: u64,
    shutdown: CancellationToken,
}

impl PortalClient {
    pub(crate) fn new(
        config: PortalClientConfig,
        credentials: &Credentials,
        stats: Arc<Stats>,
        account_stats: bool,
        telemetry: Arc<TelemetryHub>,
        shutdown: CancellationToken,
    ) -> Result<Arc<Self>> {
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id).map_err(|error| {
            anyhow::anyhow!(
                "vector::PortalClient::new: failed to generate logical session ID: {error}"
            )
        })?;
        Self::with_session_id(
            config,
            credentials,
            stats,
            account_stats,
            telemetry,
            shutdown,
            session_id,
        )
    }

    pub(crate) fn with_session_id(
        config: PortalClientConfig,
        credentials: &Credentials,
        stats: Arc<Stats>,
        account_stats: bool,
        telemetry: Arc<TelemetryHub>,
        shutdown: CancellationToken,
        session_id: [u8; SESSION_ID_LEN],
    ) -> Result<Arc<Self>> {
        let tls = ClientTls::new(&config)
            .context("vector::PortalClient::new: failed to build client TLS policy")?;
        let route_seed = route::seed_from_session(session_id);
        let latency = LatencyTracker::new();
        let signals = ClientSignals::new(stats.clone(), telemetry.clone(), latency.clone());
        let tls_manager = TlsManager::new(
            &config,
            tls.clone(),
            credentials,
            session_id,
            signals.clone(),
        );
        let quic = QuicManager::new(
            config.clone(),
            tls,
            credentials,
            session_id,
            signals,
            shutdown.clone(),
        );
        let tcp_limit = max_tcp_flows().max(1) as usize;
        let udp_limit = max_udp_flows();
        Ok(Arc::new(Self {
            config,
            telemetry,
            stats,
            account_stats,
            latency,
            flow_ids: FlowIdAllocator::new(tcp_limit.saturating_add(udp_limit)),
            tcp_flow_permits: Arc::new(Semaphore::new(tcp_limit)),
            udp_flow_permits: Arc::new(Semaphore::new(udp_limit)),
            tls_manager,
            quic,
            route_seed,
            shutdown,
        }))
    }

    pub(crate) fn endpoint(&self) -> String {
        self.config.endpoint()
    }

    pub(crate) fn dialer_ip(&self) -> &str {
        &self.config.dialer_ip
    }

    pub(crate) fn effective_route(&self) -> String {
        self.config.effective_route()
    }

    pub(crate) async fn open_tcp(
        self: &Arc<Self>,
        target: &crate::protocol::Target,
        hops: u8,
    ) -> std::result::Result<flow::TcpTunnel, flow::OpenFlowError> {
        flow::open_tcp(self.clone(), target, hops).await
    }

    pub(crate) async fn open_udp(
        self: &Arc<Self>,
        target: &crate::protocol::Target,
        hops: u8,
    ) -> std::result::Result<udp_flow::UdpTunnel, flow::OpenFlowError> {
        udp_flow::open_udp(self.clone(), target, hops).await
    }

    pub(crate) async fn refresh_latency(&self) {
        self.quic.refresh_latency().await;
    }

    pub(crate) fn ping_ms(&self) -> u64 {
        self.latency.current_ms()
    }

    pub(crate) async fn close(&self, deadline: Instant) {
        self.shutdown.cancel();
        self.quic.close(deadline).await;
    }
}

impl Vector {
    /// Validates a `vector://` URL and prepares client transport state.
    pub fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        let lifecycle = Arc::new(Lifecycle::new(LifeMode::Vector));
        lifecycle.transition(&logger, LifeState::Starting, LifeReason::Startup);
        let result = Self::build(parsed_url, logger.clone(), lifecycle.clone());
        if result.is_err() {
            lifecycle.transition(&logger, LifeState::Stopped, LifeReason::StartFailed);
            logger.flush();
        }
        result
    }

    fn build(parsed_url: Url, logger: Logger, lifecycle: Arc<Lifecycle>) -> Result<Self> {
        let config = VectorConfig::from_url(&parsed_url)
            .context("vector::Vector::new: invalid Vector configuration")?;
        let telemetry_interval =
            telemetry_interval().context("vector::Vector::new: invalid NOW_TELEMETRY_INTERVAL")?;
        let credentials =
            Credentials::new(&parsed_url).context("vector::Vector::new: invalid shared key")?;
        let telemetry_summary = format!(
            "portal={} up={} down={} mux={} socks={}",
            config.portal_endpoint(),
            config.up,
            config.down,
            config.mux,
            config.socks.endpoint(),
        );
        let telemetry = TelemetryHub::for_current_process(
            InstanceRole::Vector,
            config.socks.endpoint(),
            telemetry_summary,
            telemetry_interval,
        );
        let stats = Arc::new(Stats::default());
        let shutdown = CancellationToken::new();
        let tcp_limit = max_tcp_flows().max(1) as usize;
        let udp_limit = max_udp_flows();
        let read_bps = rate_limit_bytes_per_second(config.rate_mbps) as i64;
        let write_bps = rate_limit_bytes_per_second(config.etar_mbps) as i64;
        let rate_limiter = RateLimiter::new(read_bps, write_bps).map(Arc::new);
        let udp_queue_bytes = crate::common::env_int("NOW_QUIC_UDP_QUEUE_BYTES", 4 * 1024 * 1024)
            .clamp(1, i32::MAX) as usize;
        let client = PortalClient::new(
            config.portal_client_config(),
            &credentials,
            stats.clone(),
            true,
            telemetry.clone(),
            shutdown.clone(),
        )?;
        Ok(Self {
            inner: Arc::new(VectorInner {
                config,
                logger,
                lifecycle,
                telemetry,
                telemetry_interval,
                stats,
                buffers: Buffers::new(tcp_data_buf_size(), udp_data_buf_size()),
                rate_limiter,
                client,
                local_udp_budget: Arc::new(Semaphore::new(udp_queue_bytes)),
                socks_admission: Arc::new(Semaphore::new(tcp_limit.saturating_add(udp_limit))),
                shutdown,
            }),
        })
    }

    /// Runs SOCKS listeners, transport maintenance, telemetry, and graceful shutdown.
    pub async fn run(self) -> Result<()> {
        self.inner.lifecycle.transition(
            &self.inner.logger,
            LifeState::Starting,
            LifeReason::Startup,
        );
        self.inner.telemetry.set_lifecycle(
            LifeState::Starting.to_string(),
            LifeReason::Startup.to_string(),
        );
        let mut signals = match ShutdownSignals::new()
            .context("vector::Vector::run: failed to install shutdown signal handlers")
        {
            Ok(signals) => signals,
            Err(error) => return self.start_failed(error),
        };
        let listeners =
            match socks::listen(&self.inner.config.socks.host, self.inner.config.socks.port)
                .context("vector::Vector::run: failed to open SOCKS listener")
            {
                Ok(listeners) => listeners,
                Err(error) => return self.start_failed(error),
            };
        let telemetry_shutdown = CancellationToken::new();
        let mut telemetry_tasks: JoinSet<()> = JoinSet::new();
        match TelemetryServer::bind(self.inner.telemetry.clone()) {
            Ok(server) => {
                telemetry_tasks.spawn(server.run(telemetry_shutdown.clone()));
                telemetry_tasks.spawn(event::telemetry_loop(
                    self.inner.clone(),
                    telemetry_shutdown.clone(),
                ));
            }
            Err(error) => self.inner.logger.warn(format_args!(
                "vector::Vector::run: TUI telemetry unavailable; continuing without it: {error:#}"
            )),
        }
        self.inner.logger.info(format_args!(
            "vector::Vector::run: starting: {}",
            self.inner.config.effective_url()
        ));
        if self.inner.config.socks.authenticated() {
            self.inner.logger.info(format_args!(
                "vector::Vector::run: local SOCKS5 RFC1929 authentication enabled"
            ));
        }

        let mut listener_tasks = JoinSet::new();
        for listener in listeners {
            listener_tasks.spawn(socks::serve_listener(
                self.inner.clone(),
                listener,
                self.inner.shutdown.clone(),
            ));
        }

        self.inner.lifecycle.transition(
            &self.inner.logger,
            LifeState::Ready,
            LifeReason::Listening,
        );
        self.inner.telemetry.set_lifecycle(
            LifeState::Ready.to_string(),
            LifeReason::Listening.to_string(),
        );
        let mut auxiliary_tasks = JoinSet::new();
        auxiliary_tasks.spawn(event::event_loop(
            self.inner.clone(),
            self.inner.shutdown.clone(),
        ));
        let (reason, failure) = tokio::select! {
            signal = signals.recv() => match signal {
                Ok(reason) => (reason, None),
                Err(error) => (
                    LifeReason::SigInt,
                    Some(error.context("vector::Vector::run: shutdown signal stream failed")),
                ),
            },
            result = listener_tasks.join_next(), if !listener_tasks.is_empty() => (
                LifeReason::SocksListenerExit,
                Some(vector_listener_exit_error(result)),
            ),
        };
        self.inner.shutdown.cancel();
        let deadline = Instant::now() + shutdown_timeout();
        self.inner
            .lifecycle
            .transition(&self.inner.logger, LifeState::Draining, reason);
        self.inner
            .telemetry
            .set_lifecycle(LifeState::Draining.to_string(), reason.to_string());

        let cleanup = async {
            while listener_tasks.join_next().await.is_some() {}
            while auxiliary_tasks.join_next().await.is_some() {}
            self.inner.client.close(deadline).await;
        };
        let outcome = tokio::select! {
            biased;
            signal = signals.recv() => {
                if let Err(error) = signal {
                    self.inner.logger.error(format_args!(
                        "vector::Vector::run: shutdown signal stream failed during cleanup: {error}"
                    ));
                }
                LifeReason::Forced
            }
            result = timeout_at(deadline, cleanup) => match result {
                Ok(()) => LifeReason::CleanupComplete,
                Err(_) => LifeReason::Timeout,
            }
        };
        if outcome != LifeReason::CleanupComplete {
            listener_tasks.abort_all();
            auxiliary_tasks.abort_all();
            while listener_tasks.join_next().await.is_some() {}
            while auxiliary_tasks.join_next().await.is_some() {}
            let close_deadline = if outcome == LifeReason::Forced {
                Instant::now()
            } else {
                deadline
            };
            self.inner.client.close(close_deadline).await;
        }
        if let Some(rate) = &self.inner.rate_limiter {
            rate.reset();
        }
        self.inner
            .lifecycle
            .transition(&self.inner.logger, LifeState::Stopped, outcome);
        self.inner
            .telemetry
            .set_lifecycle(LifeState::Stopped.to_string(), outcome.to_string());
        self.inner
            .telemetry
            .capture_and_publish(&self.inner.stats, self.inner.client.ping_ms());
        tokio::task::yield_now().await;
        telemetry_shutdown.cancel();
        while telemetry_tasks.join_next().await.is_some() {}
        self.inner.logger.info(format_args!(
            "vector::Vector::run: Vector shutdown complete"
        ));
        self.inner.logger.flush();
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn start_failed(&self, error: anyhow::Error) -> Result<()> {
        self.inner.lifecycle.transition(
            &self.inner.logger,
            LifeState::Stopped,
            LifeReason::StartFailed,
        );
        self.inner.telemetry.set_lifecycle(
            LifeState::Stopped.to_string(),
            LifeReason::StartFailed.to_string(),
        );
        self.inner.logger.flush();
        Err(error)
    }
}

fn vector_listener_exit_error(
    result: Option<std::result::Result<(), tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(())) => anyhow::anyhow!("vector::Vector::run: SOCKS listener exited unexpectedly"),
        Some(Err(error)) => {
            anyhow::anyhow!("vector::Vector::run: SOCKS listener task failed: {error}")
        }
        None => {
            anyhow::anyhow!("vector::Vector::run: SOCKS listener set became empty unexpectedly")
        }
    }
}

#[cfg(test)]
#[path = "../tests/vector.rs"]
mod tests;
