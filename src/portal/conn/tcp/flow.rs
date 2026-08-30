// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated TLS lane parsing and handoff to the shared pairing layer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::portal::PortalInner;
use crate::portal::pairing::{BoxReader, BoxWriter, LinkGuard, SessionKey};
use crate::protocol::{
    Carrier, FlowErrorCode, FlowKind, FlowResult, FlowRole, read_flow_header, read_request,
    write_flow_result,
};

const FLOW_REJECT_TIMEOUT: Duration = Duration::from_secs(1);

#[allow(clippy::too_many_arguments)]
pub(super) async fn process_flow<R, W>(
    portal: Arc<PortalInner>,
    recv: R,
    mut send: W,
    session_id: SessionKey,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    shutdown: CancellationToken,
    flow_timeout: Duration,
    mut link_guard: Option<LinkGuard>,
    expected_flow_id: Option<u32>,
) where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let mut recv = BufReader::new(recv);
    let header = match tokio::select! {
        result = timeout(flow_timeout, read_flow_header(&mut recv)) => Some(result),
        _ = shutdown.cancelled() => None,
    } {
        Some(Ok(Ok(header))) => header,
        Some(Err(_)) | None => return,
        Some(Ok(Err(err))) => {
            portal.logger.debug(format_args!(
                "portal::conn::tcp: invalid flow header: {err}"
            ));
            return;
        }
    };
    if expected_flow_id.is_some_and(|flow_id| flow_id != header.flow_id) {
        portal.logger.debug(format_args!(
            "portal::conn::tcp: mux/header flow ID mismatch"
        ));
        return;
    }
    if let Err(err) = header.validate_on(Carrier::TlsTcp) {
        portal
            .logger
            .debug(format_args!("portal::conn::tcp: carrier mismatch: {err}"));
        reject_invalid(&portal, session_id, header.role, header.flow_id, &mut send).await;
        return;
    }
    let target = if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
        match tokio::select! {
            result = timeout(portal.runtime.handshake_timeout, read_request(&mut recv)) => Some(result),
            _ = shutdown.cancelled() => None,
            _ = portal.drain.cancelled() => None,
        } {
            Some(Ok(Ok(target))) => Some(target),
            _ => {
                reject_invalid(&portal, session_id, header.role, header.flow_id, &mut send).await;
                return;
            }
        }
    } else {
        None
    };
    let path = crate::portal::pairing::LinkPath {
        version: session_id.version,
        peer: peer.to_string(),
        local: local.map_or_else(|| portal.endpoint_addr.clone(), |value| value.to_string()),
    };
    let link = crate::portal::pairing::LinkHalf::tcp(path);

    match header.kind {
        FlowKind::Tcp => {
            let (reader, writer, liveness) = match header.role {
                FlowRole::Open => (Some(box_reader(recv, link_guard.take())), None, None),
                FlowRole::Attach => (
                    None,
                    Some(box_writer(send, link_guard.take())),
                    Some(Box::pin(recv) as BoxReader),
                ),
                FlowRole::Duplex => (
                    Some(Box::pin(recv) as BoxReader),
                    Some(box_writer(send, link_guard.take())),
                    None,
                ),
            };
            match portal
                .pairing
                .submit_tcp(session_id, header, target, link, reader, writer, liveness)
                .await
            {
                Ok(Some(paired)) => {
                    let relay = super::super::relay::relay_paired_tcp(portal.clone(), paired);
                    if let Some(relay) = portal.relay_tasks.spawn_or_return(relay) {
                        relay.await;
                    }
                }
                Ok(None) => {}
                Err(err) => portal
                    .logger
                    .debug(format_args!("portal::conn::tcp: TCP flow rejected: {err}")),
            }
        }
        FlowKind::Udp => {
            let half = match header.role {
                FlowRole::Open => crate::portal::pairing::UdpHalf::Uplink {
                    uplink: crate::portal::pairing::UdpUp::TlsTcp(box_reader(
                        recv,
                        link_guard.take(),
                    )),
                },
                FlowRole::Attach => crate::portal::pairing::UdpHalf::Downlink(
                    crate::portal::pairing::UdpDown::TlsTcp {
                        writer: box_writer(send, link_guard.take()),
                        liveness: Some(Box::pin(recv)),
                    },
                ),
                FlowRole::Duplex => crate::portal::pairing::UdpHalf::Duplex {
                    uplink: crate::portal::pairing::UdpUp::TlsTcp(Box::pin(recv)),
                    downlink: crate::portal::pairing::UdpDown::TlsTcp {
                        writer: box_writer(send, link_guard.take()),
                        liveness: None,
                    },
                },
            };
            match portal
                .pairing
                .submit_udp(session_id, header, target, link, half)
                .await
            {
                Ok(Some(paired)) => {
                    let relay = super::super::relay::relay_paired_udp(portal.clone(), paired);
                    if let Some(relay) = portal.relay_tasks.spawn_or_return(relay) {
                        relay.await;
                    }
                }
                Ok(None) => {}
                Err(err) => portal
                    .logger
                    .debug(format_args!("portal::conn::tcp: UDP flow rejected: {err}")),
            }
        }
    }
}

fn box_reader<R>(reader: R, guard: Option<LinkGuard>) -> BoxReader
where
    R: AsyncRead + Send + Unpin + 'static,
{
    match guard {
        Some(guard) => crate::portal::pairing::guarded_reader(reader, guard),
        None => Box::pin(reader),
    }
}

fn box_writer<W>(writer: W, guard: Option<LinkGuard>) -> BoxWriter
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    match guard {
        Some(guard) => crate::portal::pairing::guarded_writer(writer, guard),
        None => Box::pin(writer),
    }
}

async fn reject_invalid<W: AsyncWrite + Unpin>(
    portal: &Arc<PortalInner>,
    session_id: SessionKey,
    role: FlowRole,
    flow_id: u32,
    writer: &mut W,
) {
    if role == FlowRole::Open {
        portal
            .pairing
            .reject_flow_setup(session_id, flow_id, FlowErrorCode::InvalidRequest)
            .await;
        return;
    }
    let write = async {
        let _ = write_flow_result(writer, FlowResult::Reject(FlowErrorCode::InvalidRequest)).await;
        let _ = writer.shutdown().await;
    };
    let _ = timeout(FLOW_REJECT_TIMEOUT, write).await;
}
