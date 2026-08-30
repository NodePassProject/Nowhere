// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal server state and module wiring.

mod admission;
mod config;
mod conn;
mod event;
mod listener;
mod mode;
mod outbound;
mod pairing;
mod runtime;
mod setup;
mod tasks;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::common::{Lifecycle, Logger, TLSMode};
use crate::protocol::Credentials;
use crate::telemetry::TelemetryHub;
use crate::transport::{Buffers, RateLimiter, Stats};

use self::config::PortalRuntimeConfig;
pub(crate) use self::mode::NetworkMode;
use self::outbound::PortalOutbound;

const DEFAULT_QUIC_UDP_QUEUE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct UdpFlowLimits {
    max_flows: usize,
    queue_bytes: usize,
}

/// Portal server configured from a `portal://` URL.
#[derive(Clone)]
pub struct Portal {
    inner: Arc<PortalInner>,
}

struct PortalInner {
    credentials: Credentials,
    tls_mode: TLSMode,
    network_mode: NetworkMode,
    endpoint_addr: String,
    bind_addrs: Vec<SocketAddr>,
    listen_port: u16,
    outbound: PortalOutbound,
    rate_limit: i32,
    etar_limit: i32,
    logger: Logger,
    lifecycle: Arc<Lifecycle>,
    telemetry: Arc<TelemetryHub>,
    /// Cancels only work that has not committed a v1 READY result yet.
    drain: CancellationToken,
    runtime: PortalRuntimeConfig,
    stats: Arc<Stats>,
    buffers: Buffers,
    rate_limiter: Option<Arc<RateLimiter>>,
    udp_flow_limits: UdpFlowLimits,
    tls_server_config: Arc<rustls::ServerConfig>,
    quic_server_config: quinn::ServerConfig,
    unauthenticated_admission: Arc<admission::UnauthenticatedAdmission>,
    pairing: Arc<pairing::PairingRegistry>,
    ready_gate: tasks::ReadyGate,
    connection_tasks: Arc<tasks::FlowTaskTracker>,
    relay_tasks: Arc<tasks::FlowTaskTracker>,
}

#[cfg(test)]
#[path = "../tests/portal.rs"]
mod tests;
