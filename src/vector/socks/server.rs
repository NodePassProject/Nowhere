// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 TCP listener, CONNECT dispatch, and UDP associations.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{Context, Result, anyhow};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::common::socks::{
    COMMAND_BIND, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, REPLY_ADDRESS_NOT_SUPPORTED,
    REPLY_COMMAND_NOT_SUPPORTED, REPLY_CONNECTION_NOT_ALLOWED, REPLY_SUCCEEDED, SocksAddress,
    authenticate, decode_udp_packet, encode_udp_packet_into, read_request, write_reply,
};
use crate::common::{bind_udp_addrs, handshake_timeout, udp_idle_timeout};
use crate::telemetry::{
    AccessOutcome, AccessSpan, AccessStart, RuntimeEvent, RuntimeKind, RuntimeLevel,
    TrafficProtocol, now_unix_ms,
};

use super::super::VectorInner;
use super::super::flow::{
    carrier_name, configured_carrier, configured_carrier_name, open_tcp, relay_tcp, to_target,
};
use super::super::udp_flow::{UdpTunnel, open_udp};

#[path = "server/udp.rs"]
mod udp;

#[cfg(test)]
use self::udp::{accept_udp_source, validate_udp_source_request};
use self::udp::{run_udp_association, start_access};
const TCP_LISTEN_BACKLOG: i32 = 1024;
const SOCKS_UDP_PACKET_MAX: usize = u16::MAX as usize + 3 + 1 + 1 + 255 + 2;

pub(in crate::vector) fn listen(host: &str, port: u16) -> Result<Vec<TcpListener>> {
    bind_udp_addrs(host, port)?
        .into_iter()
        .map(listen_one)
        .collect()
}

fn listen_one(address: SocketAddr) -> Result<TcpListener> {
    let socket = if address.is_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(true)?;
        socket
    } else {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?
    };
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(TCP_LISTEN_BACKLOG)?;
    TcpListener::from_std(std::net::TcpListener::from(socket))
        .with_context(|| format!("vector::socks::listen: failed to listen on {address}"))
}

pub(in crate::vector) async fn serve_listener(
    vector: Arc<VectorInner>,
    listener: TcpListener,
    shutdown: CancellationToken,
) {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let Ok(admission) = vector.socks_admission.clone().try_acquire_owned() else {
                        vector.telemetry.emit_runtime(
                            RuntimeEvent::new(
                                RuntimeLevel::Warn,
                                RuntimeKind::Listener,
                                "SOCKS client limit exceeded",
                            )
                            .with_client(peer.to_string()),
                        );
                        drop(stream);
                        continue;
                    };
                    let vector = vector.clone();
                    let shutdown = shutdown.clone();
                    clients.spawn(async move {
                        let _admission = admission;
                        if let Err(error) = handle_client(vector.clone(), stream, peer, shutdown).await {
                            vector.logger.debug(format_args!(
                                "vector::socks::handle_client: {peer}: {error}"
                            ));
                        }
                    });
                }
                Err(error) => {
                    vector.telemetry.emit_runtime(RuntimeEvent::new(
                        RuntimeLevel::Error,
                        RuntimeKind::Listener,
                        format!("SOCKS accept failed: {error}"),
                    ));
                    vector.logger.error(format_args!(
                        "vector::socks::serve_listener: accept failed: {error}"
                    ));
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            },
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    while clients.join_next().await.is_some() {}
}

async fn handle_client(
    vector: Arc<VectorInner>,
    mut stream: TcpStream,
    peer: SocketAddr,
    shutdown: CancellationToken,
) -> Result<()> {
    let request = tokio::time::timeout(handshake_timeout(), async {
        let credentials = vector
            .config
            .socks
            .credentials
            .as_ref()
            .map(|value| value.as_pair());
        authenticate(&mut stream, credentials).await?;
        read_request(&mut stream).await
    })
    .await;
    let request = match request {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            vector.telemetry.emit_runtime(
                RuntimeEvent::new(
                    RuntimeLevel::Warn,
                    RuntimeKind::Authentication,
                    format!("SOCKS5 handshake failed: {error}"),
                )
                .with_client(peer.to_string()),
            );
            return Err(error);
        }
        Err(_) => {
            vector.telemetry.emit_runtime(
                RuntimeEvent::new(
                    RuntimeLevel::Warn,
                    RuntimeKind::Authentication,
                    "SOCKS5 handshake timed out",
                )
                .with_client(peer.to_string()),
            );
            return Err(anyhow!("SOCKS5 handshake timeout"));
        }
    };
    match request.command {
        COMMAND_CONNECT => {
            if request.address.port() == 0 {
                write_reply(
                    &mut stream,
                    REPLY_ADDRESS_NOT_SUPPORTED,
                    &SocksAddress::unspecified(),
                )
                .await?;
                return Ok(());
            }
            let access = start_access(
                &vector,
                TrafficProtocol::Tcp,
                Some(peer.to_string()),
                &request.address,
            );
            let target = to_target(&request.address)?;
            match open_tcp(vector.client.clone(), &target, 0).await {
                Ok(tunnel) => {
                    let reply = tunnel.socks_reply();
                    write_reply(&mut stream, reply, &SocksAddress::unspecified()).await?;
                    tokio::select! {
                        result = relay_tcp(vector, stream, tunnel, peer, &request.address, access) => result,
                        _ = shutdown.cancelled() => Ok(()),
                    }
                }
                Err(error) => {
                    access.finish(error.access_outcome(), Some(error.to_string()));
                    write_reply(
                        &mut stream,
                        error.socks_reply(),
                        &SocksAddress::unspecified(),
                    )
                    .await?;
                    Err(anyhow!("CONNECT {} failed: {error}", request.address))
                }
            }
        }
        COMMAND_UDP_ASSOCIATE => {
            run_udp_association(vector, stream, peer, request.address, shutdown).await
        }
        COMMAND_BIND => {
            write_reply(
                &mut stream,
                REPLY_COMMAND_NOT_SUPPORTED,
                &SocksAddress::unspecified(),
            )
            .await
        }
        _ => {
            write_reply(
                &mut stream,
                REPLY_COMMAND_NOT_SUPPORTED,
                &SocksAddress::unspecified(),
            )
            .await
        }
    }
}

#[cfg(test)]
#[path = "../../tests/vector/socks_server.rs"]
mod tests;
