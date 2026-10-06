// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Native Rust client exposed by the `vector://` command URL.

mod client;
mod config;
mod event;
mod flow;
mod flow_id;
mod route;
mod session;
mod socks;
mod tls;
mod udp_flow;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use url::Url;

pub(crate) use self::client::PortalClient;
pub(crate) use self::config::PortalClientConfig;
use self::config::VectorConfig;
pub(crate) use self::flow::{BoxReader, BoxWriter, OpenFlowError, TcpTunnel, TcpTunnelGuard};
use self::flow_id::FlowIdAllocator;
use self::session::{ClientSignals, QuicManager, TlsManager};
use self::tls::ClientTls;
pub(crate) use self::tls::fetch_certificate_fingerprint;
pub(crate) use self::udp_flow::{ReceivedUdpPacket, UdpTunnel, UdpTunnelReceiver, UdpTunnelSender};
use crate::common::{
    LatencyTracker, LifeReason, LifeState, Logger, ShutdownSignals, rate_limit_bytes_per_second,
    shutdown_timeout, tcp_data_buf_size, telemetry_interval, udp_data_buf_size,
};
use crate::protocol::{Credentials, SESSION_ID_LEN};
use crate::telemetry::TelemetryServer;
use crate::telemetry::{InstanceRole, TelemetryHub};
use crate::transport::{Buffers, RateLimiter, Stats};

const SOCKS_CLIENT_RESOURCE_LIMIT: usize = 1024;
const SOCKS_UDP_TARGET_RESOURCE_LIMIT: usize = 1024;

pub struct Vector {
    inner: Arc<VectorInner>,
}

pub(super) struct VectorInner {
    config: VectorConfig,
    logger: Logger,
    telemetry: Arc<TelemetryHub>,
    telemetry_interval: std::time::Duration,
    stats: Arc<Stats>,
    buffers: Buffers,
    rate_limiter: Option<Arc<RateLimiter>>,
    client: Arc<PortalClient>,
    local_udp_budget: Arc<Semaphore>,
    socks_client_admission: Arc<Semaphore>,
    socks_udp_target_admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

impl Vector {
    pub fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        let result = Self::build(parsed_url, logger.clone());
        if result.is_err() {
            logger.flush();
        }
        result
    }

    fn build(parsed_url: Url, logger: Logger) -> Result<Self> {
        let config = VectorConfig::from_url(&parsed_url)?;
        let telemetry_interval =
            telemetry_interval().context("vector::Vector::new: invalid NOW_TELEMETRY_INTERVAL")?;
        let credentials = Credentials::new(&parsed_url)?;
        let telemetry_summary = format!(
            "portal={} up={} down={} mux={} morph={} socks={} rate={} etar={} sni={} pin={}",
            config.portal_endpoint(),
            config.up,
            config.down,
            config.mux,
            u8::from(config.morph),
            config.socks.endpoint(),
            config.rate_mbps,
            config.etar_mbps,
            config.sni.as_deref().unwrap_or("none"),
            if config.pin.is_some() {
                "present"
            } else {
                "none"
            },
        );
        let telemetry = TelemetryHub::for_current_process(
            InstanceRole::Vector,
            config.socks.endpoint(),
            telemetry_summary,
            telemetry_interval,
        );
        let stats = Arc::new(Stats::default());
        let shutdown = CancellationToken::new();
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
                telemetry,
                telemetry_interval,
                stats,
                buffers: Buffers::new(tcp_data_buf_size(), udp_data_buf_size()),
                rate_limiter,
                client,
                local_udp_budget: Arc::new(Semaphore::new(udp_queue_bytes)),
                socks_client_admission: Arc::new(Semaphore::new(SOCKS_CLIENT_RESOURCE_LIMIT)),
                socks_udp_target_admission: Arc::new(Semaphore::new(
                    SOCKS_UDP_TARGET_RESOURCE_LIMIT,
                )),
                shutdown,
            }),
        })
    }

    pub async fn run(self) -> Result<()> {
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
            Err(_) => self.inner.logger.warn(format_args!(
                "vector::Vector::run: LOCAL_IPC_UNAVAILABLE; continuing without telemetry"
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

        self.inner.telemetry.set_lifecycle(
            LifeState::Ready.to_string(),
            LifeReason::Listening.to_string(),
        );
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
            .telemetry
            .set_lifecycle(LifeState::Draining.to_string(), reason.to_string());

        let cleanup = async {
            while listener_tasks.join_next().await.is_some() {}
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
            while listener_tasks.join_next().await.is_some() {}
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
