// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Native Rust client exposed by the `vector://` command URL.

pub(crate) mod client;
pub(crate) mod config;
mod flow;
mod socks;
pub(crate) mod tls;
pub(crate) mod udp_flow;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{
    Logger, ShutdownSignals, rate_limit_bytes_per_second, shutdown_timeout, tcp_data_buf_size,
};
use crate::protocol::Credentials;
use crate::telemetry::{InstanceRole, TelemetryServer};
use crate::transport::{Buffers, RateLimiter, Stats};

use self::config::VectorConfig;

pub(crate) use self::client::PortalClient;
pub(crate) use self::config::PortalClientConfig;
pub(crate) use self::flow::{BoxReader, BoxWriter, OpenFlowError, TcpTunnel, TcpTunnelGuard};
pub(crate) use self::tls::fetch_certificate_fingerprint;
pub(crate) use self::udp_flow::{ReceivedUdpPacket, UdpTunnel, UdpTunnelReceiver, UdpTunnelSender};

const SOCKS_CLIENT_RESOURCE_LIMIT: usize = 1024;
const SOCKS_UDP_TARGET_RESOURCE_LIMIT: usize = 1024;

pub struct Vector {
    runtime: VectorRuntime,
}

struct VectorRuntime {
    inner: Arc<VectorInner>,
}

impl Vector {
    pub fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        VectorRuntime::new(parsed_url, logger).map(|runtime| Self { runtime })
    }

    pub async fn run(self) -> Result<()> {
        self.runtime.run().await
    }
}

pub(super) struct VectorInner {
    config: VectorConfig,
    logger: Logger,
    stats: Arc<Stats>,
    buffers: Buffers,
    rate_limiter: Option<Arc<RateLimiter>>,
    client: Arc<PortalClient>,
    local_udp_budget: Arc<Semaphore>,
    socks_client_admission: Arc<Semaphore>,
    socks_udp_target_admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

impl VectorRuntime {
    fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        let result = Self::build(parsed_url, logger);
        if result.is_err() {
            logger.flush();
        }
        result
    }

    fn build(parsed_url: Url, logger: Logger) -> Result<Self> {
        crate::common::validate_timeout_env()?;
        let udp_queue_bytes =
            crate::common::read_quic_udp_queue_bytes(&mut crate::common::env_value)?;
        let config = VectorConfig::from_url(&parsed_url)?;
        let credentials = Credentials::new(&parsed_url)?;
        let stats = Arc::new(Stats::default());
        let shutdown = CancellationToken::new();
        let read_bps = rate_limit_bytes_per_second(config.rate_mbps) as i64;
        let write_bps = rate_limit_bytes_per_second(config.etar_mbps) as i64;
        let rate_limiter = RateLimiter::new(read_bps, write_bps).map(Arc::new);
        let client = PortalClient::new(
            config.portal_client_config(),
            &credentials,
            udp_queue_bytes,
            stats.clone(),
            true,
            shutdown.clone(),
        )?;
        Ok(Self {
            inner: Arc::new(VectorInner {
                config,
                logger,
                stats,
                buffers: Buffers::new(tcp_data_buf_size()),
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
        match TelemetryServer::bind(
            InstanceRole::Vector,
            self.inner.config.socks.endpoint(),
            self.inner.stats.clone(),
        ) {
            Ok(server) => {
                telemetry_tasks.spawn(server.run(telemetry_shutdown.clone()));
            }
            Err(error) => self
                .inner
                .logger
                .error(format_args!("local ipc unavailable: {error:#}")),
        }
        self.inner.logger.info(format_args!(
            "vector starting: {}",
            self.inner.config.effective_url()
        ));

        let mut listener_tasks = JoinSet::new();
        for listener in listeners {
            listener_tasks.spawn(socks::serve_listener(
                self.inner.clone(),
                listener,
                self.inner.shutdown.clone(),
            ));
        }

        let failure = tokio::select! {
            signal = signals.recv() => signal.err(),
            result = listener_tasks.join_next(), if !listener_tasks.is_empty() => Some(vector_listener_exit_error(result)),
        };
        self.inner.shutdown.cancel();
        let deadline = Instant::now() + shutdown_timeout();

        let cleanup = async {
            while listener_tasks.join_next().await.is_some() {}
            self.inner.client.close(deadline).await;
        };
        let (drained, forced) = tokio::select! {
            biased;
            signal = signals.recv() => {
                if let Err(error) = signal {
                    self.inner.logger.error(format_args!(
                        "shutdown signal failed: {error:#}"
                    ));
                }
                (false, true)
            }
            result = timeout_at(deadline, cleanup) => match result {
                Ok(()) => (true, false),
                Err(_) => (false, false),
            }
        };
        if !drained {
            listener_tasks.abort_all();
            while listener_tasks.join_next().await.is_some() {}
            let close_deadline = if forced { Instant::now() } else { deadline };
            self.inner.client.close(close_deadline).await;
        }
        if let Some(rate) = &self.inner.rate_limiter {
            rate.reset();
        }
        telemetry_shutdown.cancel();
        while telemetry_tasks.join_next().await.is_some() {}
        self.inner
            .logger
            .info(format_args!("vector shutdown complete"));
        self.inner.logger.flush();
        match failure {
            Some(error) => Err(error),
            None if !drained && !forced => anyhow::bail!("Vector shutdown timed out"),
            None => Ok(()),
        }
    }

    fn start_failed(&self, error: anyhow::Error) -> Result<()> {
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
