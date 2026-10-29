// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal listener supervision, independent telemetry, and graceful shutdown.

mod binding;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::common::ShutdownSignals;
use crate::telemetry::TelemetryServer;

use super::{Portal, PortalInner, conn};

impl Portal {
    pub async fn run(self) -> Result<()> {
        let forward = &self.inner.forward;
        let mut signals = ShutdownSignals::new()?;
        let tcp = self.listen_tcp_listeners()?;
        let endpoints = self.listen_endpoints()?;
        let stop = CancellationToken::new();
        let mut listeners = JoinSet::new();
        for listener in tcp {
            let portal = self.inner.clone();
            let stop = stop.clone();
            listeners.spawn(async move { tcp_loop(portal, listener, stop).await });
        }
        for endpoint in &endpoints {
            let portal = self.inner.clone();
            let stop = stop.clone();
            let endpoint = endpoint.clone();
            listeners.spawn(async move { quic_loop(portal, endpoint, stop).await });
        }
        let telemetry_stop = CancellationToken::new();
        let mut observation = JoinSet::new();
        match TelemetryServer::bind(
            crate::telemetry::InstanceRole::Portal,
            self.inner
                .effective
                .split('?')
                .next()
                .unwrap_or_default()
                .trim_start_matches("portal://"),
            forward.stats.clone(),
        ) {
            Ok(server) => {
                observation.spawn(server.run(telemetry_stop.clone()));
            }
            Err(error) => forward
                .logger
                .error(format_args!("local ipc unavailable: {error:#}")),
        }
        forward
            .logger
            .info(format_args!("portal starting: {}", self.inner.effective));
        let failure = tokio::select! {
            signal = signals.recv() => signal.err(),
            exit = listeners.join_next() => Some(match exit {
                Some(Ok(Err(error))) => error,
                Some(Err(error)) => error.into(),
                _ => anyhow::anyhow!("Portal listener exited unexpectedly"),
            }),
        };
        stop.cancel();
        forward.shutdown.cancel();
        let drained = tokio::time::timeout(self.inner.runtime.shutdown_timeout, async {
            while listeners.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        listeners.abort_all();
        while listeners.join_next().await.is_some() {}
        for endpoint in endpoints {
            endpoint.close(0u32.into(), b"shutdown");
        }
        telemetry_stop.cancel();
        while observation.join_next().await.is_some() {}
        forward
            .logger
            .info(format_args!("portal shutdown complete"));
        forward.logger.flush();
        if let Some(error) = failure {
            return Err(error);
        }
        if !drained {
            anyhow::bail!("Portal shutdown timed out");
        }
        Ok(())
    }
}

pub(super) async fn tcp_loop(
    portal: Arc<PortalInner>,
    listener: tokio::net::TcpListener,
    stop: CancellationToken,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let mut rejected = SilentRejections::new();
    let mut accept_at = tokio::time::Instant::now();
    let mut backoff = Duration::from_millis(10);
    let result = loop {
        tokio::select! {
            _ = stop.cancelled() => break Ok(()),
            accepted = async {
                tokio::time::sleep_until(accept_at).await;
                listener.accept().await
            } => match accepted {
                Ok((stream, peer)) => {
                    let accepted_at = tokio::time::Instant::now();
                    let deadline = accepted_at + portal.runtime.handshake_timeout;
                    backoff = Duration::from_millis(10);
                    let morph = portal.morph_keys.is_some();
                    if morph && stream.set_zero_linger().is_err() { continue; }
                    let admission = portal.unauthenticated_admission.try_acquire(peer.ip());
                    if !morph && admission.is_none() { continue; }
                    let permit = if admission.is_some() {
                        let Ok(permit) = portal.connection_admission.clone().try_acquire_owned() else { continue; };
                        Some(permit)
                    } else { None };
                    let p = portal.clone();
                    tasks.spawn(async move {
                        let admission = match admission {
                            Some(admission) => admission,
                            None => tokio::select! {
                                biased;
                                _ = p.forward.shutdown.cancelled() => return conn::TcpOutcome::Closed,
                                _ = tokio::time::sleep_until(deadline) => return conn::TcpOutcome::Closed,
                                admission = p.unauthenticated_admission.acquire(peer.ip()) => admission,
                            },
                        };
                        if morph && tokio::time::Instant::now() >= deadline { return conn::TcpOutcome::Closed; }
                        let permit = match permit {
                            Some(permit) => permit,
                            None => match p.connection_admission.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => return conn::TcpOutcome::Closed,
                            },
                        };
                        let outcome = conn::tcp(p.clone(), stream, admission, accepted_at, permit).await;
                        if let Err(error) = &outcome && !crate::common::is_normal_close(error) {
                            p.forward.logger.error(format_args!("tls connection failed: {error:#}"));
                        }
                        outcome.unwrap_or(conn::TcpOutcome::Closed)
                    });
                }
                Err(error) if accept_resource_exhausted(&error) => {
                    accept_at = tokio::time::Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_millis(250));
                }
                Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::Interrupted) => {},
                Err(error) => break Err(error.into()),
            },
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(outcome)) = joined { rejected.record(outcome, &portal.forward.logger); }
            },
        }
    };
    if result.is_err() {
        tasks.abort_all();
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok(outcome) = joined {
            rejected.record(outcome, &portal.forward.logger);
        }
    }
    rejected.report(&portal.forward.logger);
    result
}

fn accept_resource_exhausted(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    let resource_errors = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
    #[cfg(windows)]
    let resource_errors = [10024, 10055];
    error.kind() == std::io::ErrorKind::OutOfMemory
        || error
            .raw_os_error()
            .is_some_and(|code| resource_errors.contains(&code))
}

struct SilentRejections {
    count: u64,
    reported_at: tokio::time::Instant,
}

impl SilentRejections {
    fn new() -> Self {
        Self {
            count: 0,
            reported_at: tokio::time::Instant::now(),
        }
    }

    fn record(&mut self, outcome: conn::TcpOutcome, logger: &crate::common::Logger) {
        if matches!(outcome, conn::TcpOutcome::SilentPreHello) {
            self.count = self.count.saturating_add(1);
        }
        if self.reported_at.elapsed() >= std::time::Duration::from_secs(60) {
            self.report(logger);
        }
    }

    fn report(&mut self, logger: &crate::common::Logger) {
        if self.count != 0 {
            logger.info(format_args!(
                "Morph TCP silent pre-hello rejections: {}",
                self.count
            ));
            self.count = 0;
        }
        self.reported_at = tokio::time::Instant::now();
    }
}

pub(super) async fn quic_loop(
    portal: Arc<PortalInner>,
    endpoint: quinn::Endpoint,
    stop: CancellationToken,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = stop.cancelled() => break Ok(()),
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break Err(anyhow::anyhow!("QUIC listener closed")); };
                if !incoming.remote_address_validated() {
                    let _ = incoming.retry();
                    continue;
                }
                let Some(admission) = portal.unauthenticated_admission.try_acquire(incoming.remote_address().ip()) else { incoming.ignore(); continue; };
                let Ok(permit) = portal.connection_admission.clone().try_acquire_owned() else { incoming.ignore(); continue; };
                let p = portal.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = conn::quic(p.clone(), incoming, admission).await && !crate::common::is_normal_close(&error) {
                        p.forward.logger.error(format_args!("quic connection failed: {error:#}"));
                    }
                });
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    };
    if result.is_err() {
        tasks.abort_all();
    }
    while tasks.join_next().await.is_some() {}
    result
}
