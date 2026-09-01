// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Logical TCP flow setup across every carrier combination.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

use crate::common::socks::{
    REPLY_CONNECTION_NOT_ALLOWED, REPLY_GENERAL_FAILURE, REPLY_HOST_UNREACHABLE,
    REPLY_NETWORK_UNREACHABLE, REPLY_SUCCEEDED, REPLY_TTL_EXPIRED, SocksAddress,
};
use crate::common::{
    LatencyGuard, flow_setup_timeout, handshake_timeout, mix_fallback_timeout, tcp_read_timeout,
};
use crate::protocol::{
    AUTH_FRAME_LEN, AuthFrame, Carrier, FLOW_HEADER_LEN, FlowHeader, FlowKind, FlowResult,
    FlowRole, ProtocolVersion, SetupResult, TARGET_MAX_ENCODED_LEN, Target, encode_target_into,
    read_flow_result, write_flow_header,
};
use crate::telemetry::{AccessOutcome, AccessSpan, RuntimeEvent, RuntimeKind, RuntimeLevel};

use super::config::CarrierMode;
use super::flow_id::FlowLease;
use super::route::{ResolvedRoute, RoutePlan};
use super::session::{LinkGuard, MuxDirection, OpenedTls, QuicSession};
use super::{PortalClient, VectorInner};
mod tcp;

pub(crate) use self::tcp::{TcpTunnel, TcpTunnelGuard};
pub(super) use self::tcp::{open_tcp, relay_tcp};

pub(crate) type BoxReader = Pin<Box<dyn AsyncRead + Send>>;
pub(crate) type BoxWriter = Pin<Box<dyn AsyncWrite + Send>>;

pub(super) struct PhysicalLane {
    pub(super) reader: Option<BoxReader>,
    pub(super) writer: Option<BoxWriter>,
    pending_auth: Option<AuthFrame>,
    pending_quic_auth: bool,
    _link: Option<LinkGuard>,
    _latency: Option<LatencyGuard>,
    pub(super) _quic: Option<Arc<QuicSession>>,
    pub(super) version: ProtocolVersion,
}

impl PhysicalLane {
    pub(super) fn take_reader(&mut self) -> BoxReader {
        self.reader.take().expect("physical lane reader")
    }

    pub(super) fn take_writer(&mut self) -> BoxWriter {
        self.writer.take().expect("physical lane writer")
    }

    pub(super) fn take_pending_auth(&mut self) -> Option<AuthFrame> {
        self.pending_auth.take()
    }

    pub(super) fn mark_auth_sent(&mut self) {
        self.pending_quic_auth = false;
    }
}

impl Drop for PhysicalLane {
    fn drop(&mut self) {
        if self.pending_quic_auth
            && let Some(session) = &self._quic
        {
            session
                .connection
                .close(quinn::VarInt::from_u32(0), b"authentication abandoned");
        }
    }
}

pub(super) async fn open_lane(
    client: Arc<PortalClient>,
    carrier: Carrier,
    flow_id: u32,
    direction: MuxDirection,
) -> Result<PhysicalLane> {
    match carrier {
        Carrier::TlsTcp => {
            let opened = client
                .tls_manager
                .open(flow_id, direction)
                .await
                .map_err(|error| {
                    client.telemetry.emit_runtime(RuntimeEvent::new(
                        RuntimeLevel::Warn,
                        RuntimeKind::Carrier,
                        format!("TLS carrier connection failed: {error}"),
                    ));
                    error
                })?;
            match opened {
                OpenedTls::Mux(stream, version) => {
                    let (reader, writer) = stream.into_split();
                    Ok(PhysicalLane {
                        reader: Some(Box::pin(reader)),
                        writer: Some(Box::pin(writer)),
                        pending_auth: None,
                        pending_quic_auth: false,
                        _link: None,
                        _latency: None,
                        _quic: None,
                        version,
                    })
                }
                OpenedTls::Dedicated(lane) => {
                    let parts = (*lane).into_parts();
                    Ok(PhysicalLane {
                        reader: Some(Box::pin(parts.reader)),
                        writer: Some(Box::pin(parts.writer)),
                        pending_auth: parts.pending_auth,
                        pending_quic_auth: false,
                        _link: Some(parts.link),
                        _latency: Some(parts.latency),
                        _quic: None,
                        version: parts.version,
                    })
                }
            }
        }
        Carrier::Quic => {
            let session = match client.quic.get().await {
                Ok(session) => session,
                Err(error) => {
                    client.telemetry.emit_runtime(RuntimeEvent::new(
                        RuntimeLevel::Warn,
                        RuntimeKind::Reconnect,
                        format!("QUIC carrier connection failed: {error}"),
                    ));
                    return Err(error);
                }
            };
            let (writer, reader, pending_auth) = match session.open_bi().await {
                Ok(stream) => stream,
                Err(error) => {
                    client.telemetry.emit_runtime(RuntimeEvent::new(
                        RuntimeLevel::Warn,
                        RuntimeKind::Carrier,
                        format!("QUIC carrier stream open failed: {error}"),
                    ));
                    return Err(error);
                }
            };
            let pending_quic_auth = pending_auth.is_some();
            let version = session.version;
            Ok(PhysicalLane {
                reader: Some(Box::pin(reader)),
                writer: Some(Box::pin(writer)),
                pending_auth,
                pending_quic_auth,
                _link: None,
                _latency: None,
                _quic: Some(session),
                version,
            })
        }
    }
}

pub(super) async fn prepare_lanes(
    client: Arc<PortalClient>,
    route: ResolvedRoute,
    flow_id: u32,
) -> Result<Vec<PhysicalLane>> {
    if !route.split() {
        return Ok(vec![
            open_lane(client, route.uplink, flow_id, MuxDirection::Up).await?,
        ]);
    }

    let (uplink, downlink) = tokio::join!(
        open_lane(client.clone(), route.uplink, flow_id, MuxDirection::Up,),
        open_lane(client, route.downlink, flow_id, MuxDirection::Down),
    );
    match (uplink, downlink) {
        (Ok(uplink), Ok(downlink)) if uplink.version == downlink.version => {
            Ok(vec![uplink, downlink])
        }
        (Ok(uplink), Ok(downlink)) => Err(anyhow!(
            "split carriers negotiated different protocol versions: uplink={}, downlink={}",
            uplink.version,
            downlink.version,
        )),
        (Err(error), Ok(downlink)) => {
            drop(downlink);
            Err(error)
        }
        (Ok(uplink), Err(error)) => {
            drop(uplink);
            Err(error)
        }
        (Err(uplink), Err(downlink)) => Err(anyhow!(
            "both {} route lanes failed before commit: uplink: {uplink:#}; downlink: {downlink:#}",
            route.label(),
        )),
    }
}

pub(super) async fn prepare_with_fallback<T, F, Fut>(
    client: &Arc<PortalClient>,
    initial_lease: FlowLease,
    plan: RoutePlan,
    prepare: F,
) -> std::result::Result<(T, FlowLease, ResolvedRoute), OpenFlowError>
where
    F: FnMut(u32, ResolvedRoute) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    prepare_with_fallback_timeout(client, initial_lease, plan, mix_fallback_timeout(), prepare)
        .await
}

async fn prepare_with_fallback_timeout<T, F, Fut>(
    client: &Arc<PortalClient>,
    initial_lease: FlowLease,
    plan: RoutePlan,
    primary_timeout: Duration,
    mut prepare: F,
) -> std::result::Result<(T, FlowLease, ResolvedRoute), OpenFlowError>
where
    F: FnMut(u32, ResolvedRoute) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let initial_id = initial_lease.id();
    let primary = if plan.fallback.is_some() {
        timeout(primary_timeout, prepare(initial_id, plan.primary))
            .await
            .unwrap_or_else(|_| {
                Err(anyhow!(
                    "route {} preparation timed out after {}",
                    plan.primary.label(),
                    humantime::format_duration(primary_timeout),
                ))
            })
    } else {
        prepare(initial_id, plan.primary).await
    };
    match primary {
        Ok(prepared) => Ok((prepared, initial_lease, plan.primary)),
        Err(primary_error) => {
            let Some(fallback) = plan.fallback else {
                return Err(OpenFlowError::Transport(primary_error));
            };
            client.telemetry.emit_runtime(RuntimeEvent::new(
                RuntimeLevel::Warn,
                RuntimeKind::Carrier,
                format!(
                    "route {} failed before commit; retrying {}: {primary_error:#}",
                    plan.primary.label(),
                    fallback.label(),
                ),
            ));
            drop(initial_lease);
            let fallback_lease = client.flow_ids.allocate().map_err(|error| {
                OpenFlowError::Protocol(anyhow!(
                    "route {} failed before commit: {primary_error:#}; failed to allocate fallback flow ID: {error:#}",
                    plan.primary.label(),
                ))
            })?;
            let fallback_id = fallback_lease.id();
            match prepare(fallback_id, fallback).await {
                Ok(prepared) => Ok((prepared, fallback_lease, fallback)),
                Err(fallback_error) => Err(OpenFlowError::Transport(anyhow!(
                    "route {} failed before commit: {primary_error:#}; fallback route {} failed before commit: {fallback_error:#}",
                    plan.primary.label(),
                    fallback.label(),
                ))),
            }
        }
    }
}

pub(super) async fn write_open_request(
    writer: &mut BoxWriter,
    pending_auth: Option<AuthFrame>,
    header: FlowHeader,
    target: &Target,
) -> Result<()> {
    header.validate()?;
    let flow = write_flow_header(header);
    let mut request = [0u8; AUTH_FRAME_LEN + FLOW_HEADER_LEN + TARGET_MAX_ENCODED_LEN];
    let auth_len = if let Some(auth) = pending_auth {
        request[..AUTH_FRAME_LEN].copy_from_slice(&auth);
        AUTH_FRAME_LEN
    } else {
        0
    };
    request[auth_len..auth_len + FLOW_HEADER_LEN].copy_from_slice(&flow);
    let target_offset = auth_len + FLOW_HEADER_LEN;
    let target_len = encode_target_into(target, &mut request[target_offset..])?;
    timeout(handshake_timeout(), async {
        writer
            .write_all(&request[..target_offset + target_len])
            .await?;
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("vector::flow::write_open_request: request write timeout"))?
    .context("vector::flow::write_open_request: failed to write request")?;
    Ok(())
}

pub(super) async fn write_header(
    writer: &mut BoxWriter,
    pending_auth: Option<AuthFrame>,
    header: FlowHeader,
) -> Result<()> {
    header.validate()?;
    let flow = write_flow_header(header);
    let mut request = [0u8; AUTH_FRAME_LEN + FLOW_HEADER_LEN];
    let auth_len = if let Some(auth) = pending_auth {
        request[..AUTH_FRAME_LEN].copy_from_slice(&auth);
        AUTH_FRAME_LEN
    } else {
        0
    };
    request[auth_len..auth_len + FLOW_HEADER_LEN].copy_from_slice(&flow);
    timeout(handshake_timeout(), async {
        writer
            .write_all(&request[..auth_len + FLOW_HEADER_LEN])
            .await?;
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("vector::flow::write_header: flow header write timeout"))?
    .context("vector::flow::write_header: failed to write flow header")?;
    Ok(())
}

pub(super) async fn read_ready(reader: &mut BoxReader) -> std::result::Result<(), SetupResult> {
    read_ready_with_timeout(reader, flow_setup_timeout()).await
}

async fn read_ready_with_timeout(
    reader: &mut BoxReader,
    setup_timeout: Duration,
) -> std::result::Result<(), SetupResult> {
    let result = timeout(setup_timeout, read_flow_result(reader))
        .await
        .map_err(|_| SetupResult::InternalError)
        .and_then(|result| result.map_err(|_| SetupResult::InternalError))?;
    match result {
        FlowResult::Ready => Ok(()),
        FlowResult::Reject(error) => Err(error.into()),
    }
}

pub(super) fn to_target(address: &SocksAddress) -> Result<Target> {
    match address {
        SocksAddress::Ip(address) => Target::ip(*address),
        SocksAddress::Domain(host, port) => Target::domain(host.clone(), *port),
    }
}

pub(super) fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::TlsTcp => "TCP",
        Carrier::Quic => "UDP",
    }
}

pub(super) const fn configured_carrier(mode: CarrierMode) -> Option<Carrier> {
    match mode {
        CarrierMode::Tcp => Some(Carrier::TlsTcp),
        CarrierMode::Udp => Some(Carrier::Quic),
        CarrierMode::Mix => None,
    }
}

pub(super) const fn configured_carrier_name(mode: CarrierMode) -> &'static str {
    match mode {
        CarrierMode::Tcp => "TCP",
        CarrierMode::Udp => "UDP",
        CarrierMode::Mix => "MIX",
    }
}

pub(super) fn carrier_counter(
    vector: &VectorInner,
    carrier: Carrier,
    uplink: bool,
) -> &std::sync::atomic::AtomicU64 {
    match (carrier, uplink) {
        (Carrier::TlsTcp, true) => &vector.stats.up_tcp,
        (Carrier::Quic, true) => &vector.stats.up_udp,
        (Carrier::TlsTcp, false) => &vector.stats.down_tcp,
        (Carrier::Quic, false) => &vector.stats.down_udp,
    }
}

#[derive(Debug)]
pub(crate) enum OpenFlowError {
    Setup(SetupResult),
    Transport(anyhow::Error),
    Protocol(anyhow::Error),
}

impl OpenFlowError {
    pub(super) fn socks_reply(&self) -> u8 {
        match self {
            Self::Setup(SetupResult::InvalidRequest | SetupResult::FlowLimit) => {
                REPLY_CONNECTION_NOT_ALLOWED
            }
            Self::Setup(SetupResult::DialFailed) => REPLY_HOST_UNREACHABLE,
            Self::Setup(SetupResult::PairTimeout) => REPLY_TTL_EXPIRED,
            Self::Setup(_) => REPLY_GENERAL_FAILURE,
            Self::Transport(_) => REPLY_NETWORK_UNREACHABLE,
            Self::Protocol(_) => REPLY_GENERAL_FAILURE,
        }
    }

    pub(super) fn access_outcome(&self) -> AccessOutcome {
        match self {
            Self::Setup(SetupResult::InvalidRequest | SetupResult::FlowLimit) => {
                AccessOutcome::Rejected
            }
            Self::Setup(SetupResult::PairTimeout) => AccessOutcome::Timeout,
            Self::Setup(_) | Self::Transport(_) | Self::Protocol(_) => {
                access_error_outcome(&self.to_string())
            }
        }
    }

    pub(crate) fn setup_result(&self) -> Option<SetupResult> {
        match self {
            Self::Setup(result) => Some(*result),
            Self::Transport(_) | Self::Protocol(_) => None,
        }
    }
}

fn access_error_outcome(error: &str) -> AccessOutcome {
    if error.to_ascii_lowercase().contains("timeout") {
        AccessOutcome::Timeout
    } else {
        AccessOutcome::Error
    }
}

impl std::fmt::Display for OpenFlowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(result) => write!(formatter, "flow setup rejected: {}", result.as_str()),
            Self::Transport(error) | Self::Protocol(error) => error.fmt(formatter),
        }
    }
}

pub(super) struct SessionGuard {
    stats: Arc<crate::transport::Stats>,
    udp: bool,
}

impl SessionGuard {
    pub(super) fn new(stats: Arc<crate::transport::Stats>, udp: bool) -> Self {
        Self { stats, udp }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stats.done_session(self.udp);
    }
}

#[cfg(test)]
#[path = "../tests/vector/flow.rs"]
mod tests;
