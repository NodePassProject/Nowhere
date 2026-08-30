// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal runtime orchestration, listener supervision, and bounded flow drain.

use anyhow::{Context, Result};
use quinn::{Endpoint, VarInt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::common::{LifeReason, LifeState, ShutdownSignals};
use crate::telemetry::TelemetryServer;

use super::listener::{accept_endpoint_loop, accept_tcp_loop, listen_endpoint, listen_tcp};
use super::{Portal, event};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownOutcome {
    Drained,
    Timeout,
    Forced,
}

impl ShutdownOutcome {
    fn life_reason(self) -> LifeReason {
        match self {
            Self::Drained => LifeReason::Drained,
            Self::Timeout => LifeReason::Timeout,
            Self::Forced => LifeReason::Forced,
        }
    }
}

struct ShutdownTrigger {
    reason: LifeReason,
    failure: Option<anyhow::Error>,
}

impl Portal {
    /// Starts listeners, supervises them, and drains READY relays on shutdown.
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
            .context("portal::run: failed to install shutdown signal handlers")
        {
            Ok(signals) => signals,
            Err(error) => return self.start_failed(error),
        };
        let endpoints = match self.listen_endpoints() {
            Ok(endpoints) => endpoints,
            Err(error) => return self.start_failed(error),
        };
        let tcp_listeners = match self.listen_tcp_listeners() {
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
                "portal::run: TUI telemetry unavailable; continuing without it: {error:#}"
            )),
        }

        self.log_info("starting");
        let stop_accepting = CancellationToken::new();
        let force_shutdown = CancellationToken::new();

        let mut quic_listeners = JoinSet::new();
        for endpoint in endpoints.iter().cloned() {
            let portal = self.inner.clone();
            let stop_accepting = stop_accepting.clone();
            let force_shutdown = force_shutdown.clone();
            quic_listeners.spawn(async move {
                accept_endpoint_loop(portal, endpoint, stop_accepting, force_shutdown).await;
            });
        }

        let mut tcp_listener_tasks = JoinSet::new();
        for listener in tcp_listeners {
            let portal = self.inner.clone();
            let stop_accepting = stop_accepting.clone();
            let force_shutdown = force_shutdown.clone();
            tcp_listener_tasks.spawn(async move {
                accept_tcp_loop(portal, listener, stop_accepting, force_shutdown).await;
            });
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
            force_shutdown.clone(),
        ));
        let trigger = tokio::select! {
            signal = signals.recv() => match signal {
                Ok(reason) => ShutdownTrigger { reason, failure: None },
                Err(error) => ShutdownTrigger {
                    reason: LifeReason::SigInt,
                    failure: Some(error.context("portal::run: shutdown signal stream failed")),
                },
            },
            result = quic_listeners.join_next(), if !quic_listeners.is_empty() => {
                ShutdownTrigger {
                    reason: LifeReason::QuicListenerExit,
                    failure: Some(listener_exit_error("QUIC", result)),
                }
            },
            result = tcp_listener_tasks.join_next(), if !tcp_listener_tasks.is_empty() => {
                ShutdownTrigger {
                    reason: LifeReason::TcpListenerExit,
                    failure: Some(listener_exit_error("TCP", result)),
                }
            },
        };

        let deadline = Instant::now() + self.inner.runtime.shutdown_timeout;

        // Establish the admission barrier before cancelling listeners. A flow
        // that activated before this point is tracked; every later setup gets
        // the v1 FLOW_LIMIT result through its authoritative downlink.
        self.inner.pairing.close_admission();
        self.inner.ready_gate.close();
        self.inner.drain.cancel();
        self.inner.relay_tasks.close();
        for endpoint in &endpoints {
            endpoint.set_server_config(None);
        }
        stop_accepting.cancel();
        self.inner
            .lifecycle
            .transition(&self.inner.logger, LifeState::Draining, trigger.reason);
        self.inner
            .telemetry
            .set_lifecycle(LifeState::Draining.to_string(), trigger.reason.to_string());

        let drain = async {
            self.inner.pairing.begin_drain().await;
            self.inner.relay_tasks.wait().await;
        };
        let mut outcome = tokio::select! {
            biased;
            signal = signals.recv() => {
                match signal {
                    Ok(_) => ShutdownOutcome::Forced,
                    Err(error) => {
                        self.inner.logger.error(format_args!(
                            "portal::run: shutdown signal stream failed during drain: {error}"
                        ));
                        ShutdownOutcome::Forced
                    }
                }
            }
            result = timeout_at(deadline, drain) => match result {
                Ok(()) => ShutdownOutcome::Drained,
                Err(_) => ShutdownOutcome::Timeout,
            }
        };

        // No new setup is possible now. End physical carriers and auxiliary
        // work; READY relays have either completed or are being forced below.
        force_shutdown.cancel();
        self.inner.outbound.close(deadline).await;
        for endpoint in &endpoints {
            endpoint.close(VarInt::from_u32(0), b"");
        }
        self.inner.connection_tasks.close();
        if outcome != ShutdownOutcome::Drained {
            self.inner.relay_tasks.abort_all();
            self.inner.connection_tasks.abort_all();
            quic_listeners.abort_all();
            tcp_listener_tasks.abort_all();
            auxiliary_tasks.abort_all();
        }

        let mut endpoint_tasks = JoinSet::new();
        for endpoint in &endpoints {
            let endpoint = endpoint.clone();
            endpoint_tasks.spawn(async move {
                endpoint.wait_idle().await;
            });
        }

        let cleanup = async {
            self.inner.pairing.cancel_all().await;
            while endpoint_tasks.join_next().await.is_some() {}
            while quic_listeners.join_next().await.is_some() {}
            while tcp_listener_tasks.join_next().await.is_some() {}
            while auxiliary_tasks.join_next().await.is_some() {}
            self.inner.connection_tasks.wait().await;
            self.inner.relay_tasks.wait().await;
        };
        let cleanup_deadline = if outcome == ShutdownOutcome::Forced {
            Instant::now()
        } else {
            deadline
        };
        if timeout_at(cleanup_deadline, cleanup).await.is_err() {
            if outcome == ShutdownOutcome::Drained {
                outcome = ShutdownOutcome::Timeout;
            }
            endpoint_tasks.abort_all();
            quic_listeners.abort_all();
            tcp_listener_tasks.abort_all();
            auxiliary_tasks.abort_all();
            self.inner.connection_tasks.abort_all();
            self.inner.relay_tasks.abort_all();
            while endpoint_tasks.join_next().await.is_some() {}
            while quic_listeners.join_next().await.is_some() {}
            while tcp_listener_tasks.join_next().await.is_some() {}
            while auxiliary_tasks.join_next().await.is_some() {}
            self.inner.connection_tasks.wait().await;
            self.inner.relay_tasks.wait().await;
            self.inner.pairing.cancel_all().await;
        }

        if let Some(rate) = &self.inner.rate_limiter {
            rate.reset();
        }
        self.inner.lifecycle.transition(
            &self.inner.logger,
            LifeState::Stopped,
            outcome.life_reason(),
        );
        self.inner.telemetry.set_lifecycle(
            LifeState::Stopped.to_string(),
            outcome.life_reason().to_string(),
        );
        self.inner
            .telemetry
            .capture_and_publish(&self.inner.stats, self.inner.outbound.ping_ms());
        tokio::task::yield_now().await;
        telemetry_shutdown.cancel();
        while telemetry_tasks.join_next().await.is_some() {}
        self.inner
            .logger
            .info(format_args!("portal::run: portal shutdown complete"));
        self.inner.logger.flush();

        match trigger.failure {
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

    fn log_info(&self, prefix: &str) {
        self.inner.logger.info(format_args!(
            "portal::run: {prefix}: {}",
            self.effective_url()
        ));
    }

    /// Returns the effective startup URL that is logged for operators.
    pub(super) fn effective_url(&self) -> String {
        let base = format!(
            "portal://{}?net={}&tls={}&rate={}&etar={}&dial={}&socks={}&next={}",
            self.inner.endpoint_addr,
            self.inner.network_mode,
            self.inner.tls_mode,
            self.inner.rate_limit,
            self.inner.etar_limit,
            self.inner.outbound.dialer_ip(),
            self.inner.outbound.socks_endpoint(),
            self.inner.outbound.next_endpoint(),
        );
        self.inner
            .outbound
            .next_transport()
            .map_or(base.clone(), |transport| {
                format!("{base}&{}", transport.replace(' ', "&"))
            })
    }

    /// Opens QUIC endpoints for network modes that accept UDP service.
    pub(super) fn listen_endpoints(&self) -> Result<Vec<Endpoint>> {
        if !self.inner.network_mode.listens_udp() {
            return Ok(Vec::new());
        }
        self.inner
            .bind_addrs
            .iter()
            .copied()
            .map(|addr| listen_endpoint(self.inner.quic_server_config.clone(), addr))
            .collect()
    }

    /// Opens TLS/TCP listeners for network modes that accept TCP service.
    pub(super) fn listen_tcp_listeners(&self) -> Result<Vec<TcpListener>> {
        if !self.inner.network_mode.listens_tcp() {
            return Ok(Vec::new());
        }
        self.inner
            .bind_addrs
            .iter()
            .copied()
            .map(listen_tcp)
            .collect()
    }
}

fn listener_exit_error(
    name: &str,
    result: Option<std::result::Result<(), tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(())) => anyhow::anyhow!("portal::run: {name} listener exited unexpectedly"),
        Some(Err(error)) => {
            anyhow::anyhow!("portal::run: {name} listener task failed: {error}")
        }
        None => anyhow::anyhow!("portal::run: {name} listener set became empty unexpectedly"),
    }
}
