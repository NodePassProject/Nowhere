// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! On-demand TLS and shared QUIC carrier lifecycle.

use std::collections::{HashMap, hash_map::Entry};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::io::AsyncWriteExt;
use tokio::net::lookup_host;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::common::{
    BudgetedDatagram, LatencyGuard, LatencyTracker, UdpDatagramSend, filter_addrs,
    handshake_timeout, parse_local_ip, reserve_udp_budget, send_quic_udp_packet, service_cooldown,
    udp_idle_timeout,
};
use crate::mux::{MUX_IDLE_TIMEOUT, MuxConfig, MuxHandle, MuxStream};
use crate::protocol::{
    AuthFrame, AuthKey, AuthTransport, Credentials, DatagramReassembler, FlowId, OwnedUdpFragment,
    OwnedUdpFrame, ProtocolVersion, ReassemblyConfig, ReassemblyOutcome, SessionId,
    decode_udp_frame_owned, encode_auth_frame, encode_udp_close,
};
use crate::telemetry::{RuntimeEvent, RuntimeKind, RuntimeLevel, TelemetryHub};
use crate::transport::{Stats, quic_flow_control};

use super::config::PortalClientConfig;
use super::tls::{ClientTls, EXPORTER_LABEL, quic_protocol_version};

const QUIC_DATAGRAM_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const TLS_MUX_FLOWS_PER_SHARD: usize = 4;

#[derive(Clone)]
pub(super) struct ClientSignals {
    stats: Arc<Stats>,
    telemetry: Arc<TelemetryHub>,
    latency: Arc<LatencyTracker>,
}

impl ClientSignals {
    pub(super) fn new(
        stats: Arc<Stats>,
        telemetry: Arc<TelemetryHub>,
        latency: Arc<LatencyTracker>,
    ) -> Self {
        Self {
            stats,
            telemetry,
            latency,
        }
    }
}

pub(super) struct TlsLane {
    pub(super) stream: TlsStream<tokio::net::TcpStream>,
    pub(super) version: ProtocolVersion,
    pending_auth: Option<AuthFrame>,
    _link: LinkGuard,
    latency: LatencyGuard,
}

pub(super) struct TlsLaneParts {
    pub(super) reader: tokio::io::ReadHalf<TlsStream<tokio::net::TcpStream>>,
    pub(super) writer: tokio::io::WriteHalf<TlsStream<tokio::net::TcpStream>>,
    pub(super) pending_auth: Option<AuthFrame>,
    pub(super) link: LinkGuard,
    pub(super) latency: LatencyGuard,
    pub(super) version: ProtocolVersion,
}

impl TlsLane {
    pub(super) fn into_parts(self) -> TlsLaneParts {
        let Self {
            stream,
            version,
            pending_auth,
            _link,
            latency,
        } = self;
        let (reader, writer) = tokio::io::split(stream);
        TlsLaneParts {
            reader,
            writer,
            pending_auth,
            link: _link,
            latency,
            version,
        }
    }
}

pub(super) struct LinkGuard {
    stats: Arc<Stats>,
    telemetry: Arc<TelemetryHub>,
    quic: bool,
}

impl LinkGuard {
    fn new(stats: Arc<Stats>, telemetry: Arc<TelemetryHub>, quic: bool) -> Self {
        if quic {
            stats.link_udp.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.link_tcp.fetch_add(1, Ordering::Relaxed);
        }
        telemetry.emit_runtime(RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Carrier,
            if quic {
                "QUIC carrier connected"
            } else {
                "TLS/TCP carrier connected"
            },
        ));
        Self {
            stats,
            telemetry,
            quic,
        }
    }
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        if self.quic {
            self.stats.link_udp.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.stats.link_tcp.fetch_sub(1, Ordering::Relaxed);
        }
        self.telemetry.emit_runtime(RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Carrier,
            if self.quic {
                "QUIC carrier disconnected"
            } else {
                "TLS/TCP carrier disconnected"
            },
        ));
    }
}

mod quic;
mod tls;

pub(super) use self::quic::{QueuedDatagram, QuicManager, QuicSession};
pub(super) use self::tls::{MuxDirection, OpenedTls, TlsManager};

#[cfg(test)]
#[path = "../tests/vector/session.rs"]
mod tests;
