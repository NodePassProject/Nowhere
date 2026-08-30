// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC connection handling and dispatch.

mod auth;
mod relay;
mod session;
mod tcp;

pub(in crate::portal) use self::session::DatagramReadyRequest;
pub(in crate::portal) use self::session::QueuedDatagram;

use std::sync::Arc;

use quinn::crypto::rustls::HandshakeData;
use quinn::{Connection, Incoming, VarInt};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use self::auth::{
    AuthenticationOutcome, authenticate_connection, authentication_deadline,
    authentication_failure_close,
};
pub(super) use self::tcp::handle_tcp_incoming;
use super::PortalInner;
use super::admission::UnauthenticatedGuard;
use crate::common::rate_limit_bytes_per_second;
use crate::protocol::ProtocolVersion;
use crate::telemetry::{RuntimeEvent, RuntimeKind, RuntimeLevel};

pub(super) async fn handle_incoming(
    portal: Arc<PortalInner>,
    incoming: Incoming,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
) {
    let conn = match tokio::select! {
        biased;
        _ = shutdown.cancelled() => return,
        _ = portal.drain.cancelled() => return,
        result = timeout(portal.runtime.handshake_timeout, incoming) => result,
    } {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            portal.telemetry.emit_runtime(RuntimeEvent::new(
                RuntimeLevel::Warn,
                RuntimeKind::Carrier,
                format!("QUIC TLS handshake failed: {err}"),
            ));
            portal.logger.debug(format_args!(
                "portal::conn::handle_incoming: QUIC TLS handshake failed: {err}"
            ));
            return;
        }
        // Handshake timeouts are expected for abandoned or hostile clients.
        // Keep them silent to avoid log amplification.
        Err(_) => return,
    };
    let version = match conn
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| ProtocolVersion::from_alpn(data.protocol.as_deref()).ok())
    {
        Some(version) => version,
        None => {
            conn.close(VarInt::from_u32(1), b"unsupported protocol");
            portal.logger.debug(format_args!(
                "portal::conn::handle_incoming: invalid negotiated QUIC protocol"
            ));
            return;
        }
    };
    handle_connection(portal, conn, version, admission, shutdown).await;
}

/// Runs authentication and then dispatches accepted streams/datagrams.
async fn handle_connection(
    portal: Arc<PortalInner>,
    conn: Connection,
    version: ProtocolVersion,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
) {
    let auth_deadline = authentication_deadline(portal.runtime.handshake_timeout);
    let authenticated = match authenticate_connection(
        portal.clone(),
        conn.clone(),
        version,
        auth_deadline,
        &shutdown,
    )
    .await
    {
        AuthenticationOutcome::Success(authenticated) => authenticated,
        AuthenticationOutcome::Failure(err) => {
            let (code, reason) = authentication_failure_close();
            conn.close(code, reason);
            drop(admission);
            portal.telemetry.emit_runtime(
                RuntimeEvent::new(
                    RuntimeLevel::Warn,
                    RuntimeKind::Authentication,
                    format!("QUIC authentication failed: {err}"),
                )
                .with_client(conn.remote_address().to_string()),
            );
            portal.logger.error(format_args!(
                "portal::conn::handle_connection: authentication failed: {err}"
            ));
            return;
        }
        AuthenticationOutcome::Shutdown => return,
    };
    if portal.drain.is_cancelled() {
        conn.close(VarInt::from_u32(0), b"");
        drop(admission);
        return;
    }
    // Once auth succeeds, expand the conservative pre-auth limits to the normal
    // data-plane limits and release the admission slot.
    let flow_control = match crate::transport::quic_flow_control() {
        Ok(value) => value,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::handle_connection: invalid QUIC memory profile: {err}"
            ));
            conn.close(VarInt::from_u32(0), b"");
            drop(admission);
            return;
        }
    };
    conn.set_receive_window(VarInt::from_u32(flow_control.connection_receive_window));
    conn.set_max_concurrent_bi_streams(VarInt::from_u32(
        portal.runtime.quic_bidi_stream_capacity(),
    ));
    drop(admission);
    let session = authenticated.session;
    let link_replaced = CancellationToken::new();
    let link_guard = portal
        .pairing
        .register_quic_link(
            session.session_key,
            portal.stats.clone(),
            link_replaced.clone(),
        )
        .await;
    session.set_quic_generation(link_guard.quic_generation());
    let _link_guard = link_guard;
    portal.telemetry.emit_runtime(
        RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Carrier,
            "QUIC carrier connected",
        )
        .with_client(conn.remote_address().to_string()),
    );

    let etar_bps = rate_limit_bytes_per_second(portal.etar_limit);
    if etar_bps > 0 {
        portal.logger.debug(format_args!(
            "portal::conn::handle_connection: enabled TX rate limiter at {etar_bps} Bps"
        ));
    }

    let datagram_task = tokio::spawn(session.clone().datagram_loop(shutdown.clone()));
    let first_session = session.clone();
    let first_tasks = portal.connection_tasks.clone();
    first_tasks.spawn(async move {
        first_session
            .handle_first_stream(authenticated.first_send, authenticated.first_recv)
            .await;
    });

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = link_replaced.cancelled() => {
                portal.telemetry.emit_runtime(
                    RuntimeEvent::new(
                        RuntimeLevel::Warn,
                        RuntimeKind::Carrier,
                        "QUIC carrier replaced",
                    )
                    .with_client(conn.remote_address().to_string()),
                );
                portal.logger.debug(format_args!(
                    "portal::conn::handle_connection: authenticated QUIC carrier replaced"
                ));
                break;
            },
            stream = conn.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        let session = session.clone();
                        let tasks = portal.connection_tasks.clone();
                        tasks.spawn(async move {
                            session.handle_stream(send, recv).await;
                        });
                    }
                    Err(err) => {
                        if !shutdown.is_cancelled() {
                            portal.telemetry.emit_runtime(RuntimeEvent::new(
                                RuntimeLevel::Warn,
                                RuntimeKind::Carrier,
                                format!("QUIC carrier stream loop closed: {err}"),
                            ));
                            portal.logger.debug(format_args!("portal::conn::handle_connection: bidirectional stream accept loop closed: {err}"));
                        }
                        break;
                    }
                }
            }
        }
    }

    session.close();
    datagram_task.abort();
    let _ = datagram_task.await;
    portal.telemetry.emit_runtime(
        RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Carrier,
            "QUIC carrier disconnected",
        )
        .with_client(conn.remote_address().to_string()),
    );
    conn.close(VarInt::from_u32(0), b"");
}

#[cfg(test)]
#[path = "../tests/portal/conn.rs"]
mod tests;
