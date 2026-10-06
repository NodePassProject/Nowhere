// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared Portal client state, connection setup, and lifecycle control.

use super::*;

pub(crate) struct PortalClient {
    pub(super) config: PortalClientConfig,
    pub(super) telemetry: Arc<TelemetryHub>,
    pub(super) stats: Arc<Stats>,
    pub(super) account_stats: bool,
    pub(super) latency: Arc<LatencyTracker>,
    pub(super) flow_ids: Arc<FlowIdAllocator>,
    pub(super) tls_manager: Arc<TlsManager>,
    pub(super) quic: Arc<QuicManager>,
    pub(super) route_seed: u64,
    pub(super) shutdown: CancellationToken,
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
        Ok(Arc::new(Self {
            config,
            telemetry,
            stats,
            account_stats,
            latency,
            flow_ids: FlowIdAllocator::new(),
            tls_manager,
            quic,
            route_seed,
            shutdown,
        }))
    }

    pub(crate) fn endpoint(&self) -> String {
        self.config.endpoint()
    }

    pub(crate) fn dial_policy(&self) -> &crate::common::DialPolicy {
        &self.config.dial_policy
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
        self.tls_manager.close().await;
        self.quic.close(deadline).await;
    }
}
