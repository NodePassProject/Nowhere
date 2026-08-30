// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS/TCP ingress for dedicated lanes or the optional shared Mux.

mod flow;

use std::io::Cursor;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use socket2::SockRef;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::common::MUX_MARKER;
use crate::mux::{MUX_IDLE_TIMEOUT, MuxConfig, MuxHandle};
use crate::portal::PortalInner;
use crate::portal::admission::UnauthenticatedGuard;
use crate::portal::pairing::SessionKey;
use crate::protocol::{AuthTransport, ProtocolVersion, read_auth_frame};
use crate::telemetry::{RuntimeEvent, RuntimeKind, RuntimeLevel};

use self::flow::process_flow;
use super::auth::{authentication_deadline, wait_for_auth_deadline};

// Dedicated TLS lanes may authenticate before the FlowHeader is available.
// Keep a finite bootstrap window long enough for 1.7 Vector's 30-second warm
// lane behavior. This is a protocol deadline, not a configurable connection
// pool: Portal does not create, replenish, or retain idle lanes itself.
pub(in crate::portal) const AUTHENTICATED_LANE_BOOTSTRAP_TIMEOUT: Duration =
    Duration::from_secs(40);

pub(in crate::portal) async fn handle_tcp_incoming(
    portal: Arc<PortalInner>,
    stream: TcpStream,
    peer: SocketAddr,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
) {
    handle_tcp_incoming_with_bootstrap_timeout(
        portal,
        stream,
        peer,
        admission,
        shutdown,
        AUTHENTICATED_LANE_BOOTSTRAP_TIMEOUT,
    )
    .await;
}

pub(super) async fn handle_tcp_incoming_with_bootstrap_timeout(
    portal: Arc<PortalInner>,
    stream: TcpStream,
    peer: SocketAddr,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
    bootstrap_timeout: Duration,
) {
    handle_tcp_incoming_with_timeouts(
        portal,
        stream,
        peer,
        admission,
        shutdown,
        bootstrap_timeout,
        MUX_IDLE_TIMEOUT,
    )
    .await;
}

pub(super) async fn handle_tcp_incoming_with_timeouts(
    portal: Arc<PortalInner>,
    stream: TcpStream,
    peer: SocketAddr,
    admission: UnauthenticatedGuard,
    shutdown: CancellationToken,
    bootstrap_timeout: Duration,
    mux_idle_timeout: Duration,
) {
    if let Err(err) = stream.set_nodelay(true) {
        portal
            .logger
            .debug(format_args!("portal::conn::tcp: TCP_NODELAY failed: {err}"));
    }
    let local = stream.local_addr().ok();
    let acceptor = TlsAcceptor::from(portal.tls_server_config.clone());
    let tls_stream = match tokio::select! {
        biased;
        _ = shutdown.cancelled() => return,
        _ = portal.drain.cancelled() => return,
        result = timeout(portal.runtime.handshake_timeout, acceptor.accept(stream)) => result,
    } {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            let level = if matches!(
                err.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) {
                "client disconnected"
            } else {
                "handshake failed"
            };
            portal
                .logger
                .debug(format_args!("portal::conn::tcp: TLS {level}: {err}"));
            return;
        }
        Err(_) => return,
    };
    let auth_deadline = authentication_deadline(portal.runtime.handshake_timeout);
    let mut tls_stream = tls_stream;
    let version = match ProtocolVersion::from_alpn(tls_stream.get_ref().1.alpn_protocol()) {
        Ok(version) => version,
        Err(err) => {
            portal.logger.debug(format_args!(
                "portal::conn::tcp: invalid negotiated protocol: {err}"
            ));
            return;
        }
    };
    let mut exporter = [0u8; 32];
    if let Err(err) = tls_stream.get_ref().1.export_keying_material(
        &mut exporter,
        b"EXPORTER-Nowhere-Auth",
        Some(&[]),
    ) {
        portal.logger.debug(format_args!(
            "portal::conn::tcp: TLS exporter failed: {err}"
        ));
        return;
    }
    let auth = tokio::select! {
        _ = shutdown.cancelled() => return,
        _ = portal.drain.cancelled() => return,
        result = timeout_at(auth_deadline, read_auth_frame(
            &mut tls_stream,
            portal.credentials.auth_key,
            AuthTransport::TlsTcp,
            &exporter,
        )) => result,
    };
    let session_id = match auth {
        Ok(Ok(session_id)) => {
            drop(admission);
            session_id
        }
        Ok(Err(err)) => {
            if !wait_for_auth_deadline(auth_deadline, &shutdown, &portal.drain).await {
                return;
            }
            drop(tls_stream);
            drop(admission);
            portal.telemetry.emit_runtime(
                RuntimeEvent::new(
                    RuntimeLevel::Warn,
                    RuntimeKind::Authentication,
                    format!("TLS/TCP authentication failed: {err}"),
                )
                .with_client(peer.to_string()),
            );
            return;
        }
        Err(_) => return,
    };
    let session_key = SessionKey::new(version, session_id);
    if let Err(err) = SockRef::from(tls_stream.get_ref().0).set_keepalive(true) {
        portal.logger.debug(format_args!(
            "portal::conn::tcp: TCP keepalive failed: {err}"
        ));
        return;
    }

    let first = match tokio::select! {
        _ = shutdown.cancelled() => return,
        _ = portal.drain.cancelled() => return,
        result = timeout(bootstrap_timeout, tls_stream.read_u8()) => result,
    } {
        Ok(Ok(first)) => first,
        _ => return,
    };
    let flow_timeout = portal.runtime.handshake_timeout;
    if first == MUX_MARKER {
        handle_mux(
            portal,
            tls_stream,
            session_key,
            peer,
            local,
            shutdown,
            mux_idle_timeout,
        )
        .await;
        return;
    }

    let link_guard = portal
        .pairing
        .register_tcp_link(session_key, portal.stats.clone());
    let (recv, send) = tokio::io::split(tls_stream);
    process_flow(
        portal,
        Cursor::new([first]).chain(recv),
        send,
        session_key,
        peer,
        local,
        shutdown,
        flow_timeout,
        Some(link_guard),
        None,
    )
    .await;
}

async fn handle_mux(
    portal: Arc<PortalInner>,
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    session_key: SessionKey,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    shutdown: CancellationToken,
    idle_timeout: Duration,
) {
    let flow_timeout = portal.runtime.handshake_timeout;
    let (mux, mut incoming) = match MuxHandle::start(tls_stream, MuxConfig::default()) {
        Ok(value) => value,
        Err(err) => {
            portal
                .logger
                .debug(format_args!("portal::conn::tcp: invalid mux limits: {err}"));
            return;
        }
    };
    let _link_guard = portal
        .pairing
        .register_tcp_link(session_key, portal.stats.clone());
    portal.telemetry.emit_runtime(
        RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Carrier,
            "TLS mux carrier connected",
        )
        .with_client(peer.to_string()),
    );
    let mut flow_tasks = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = portal.drain.cancelled() => break,
            accepted = incoming.accept() => accepted,
            _ = flow_tasks.join_next(), if !flow_tasks.is_empty() => continue,
            idle = mux.idle_for(idle_timeout) => {
                if idle && mux.active_streams() != 0 {
                    continue;
                }
                break;
            },
        };
        let Ok(Some(stream)) = accepted else { break };
        let expected_flow_id = stream.flow_id();
        let (recv, send) = stream.into_split();
        let portal = portal.clone();
        let shutdown = shutdown.clone();
        flow_tasks.spawn(async move {
            process_flow(
                portal,
                recv,
                send,
                session_key,
                peer,
                local,
                shutdown,
                flow_timeout,
                None,
                Some(expected_flow_id),
            )
            .await;
        });
    }
    flow_tasks.abort_all();
    while flow_tasks.join_next().await.is_some() {}
    mux.close();
    portal.telemetry.emit_runtime(
        RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Carrier,
            "TLS mux carrier disconnected",
        )
        .with_client(peer.to_string()),
    );
}
