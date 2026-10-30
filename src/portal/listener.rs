// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC endpoint and TCP listener setup plus accept loops.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Endpoint, IdleTimeout, ServerConfig, VarInt, default_runtime};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio::time::Duration;

use crate::transport::{
    MorphKeys, configure_morph_mtu, morph_endpoint_config, transport_flow_control,
    wrap_morph_udp_socket,
};

const QUIC_PRE_AUTH_RECEIVE_WINDOW: u32 = 64 * 1024;
const QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const QUIC_DATAGRAM_SEND_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const QUIC_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const TCP_LISTEN_BACKLOG: i32 = 1024;

pub(super) fn listen_endpoint(
    server_config: ServerConfig,
    addr: SocketAddr,
    morph_keys: Option<MorphKeys>,
) -> Result<Endpoint> {
    let socket = bind_quic_socket(addr)
        .with_context(|| format!("portal::listen_endpoint: failed to bind UDP socket: {addr}"))?;
    let runtime = default_runtime()
        .ok_or_else(|| anyhow::anyhow!("portal::listen_endpoint: no async runtime found"))?;
    let socket = runtime
        .wrap_udp_socket(socket)
        .context("portal::listen_endpoint: failed to initialize UDP runtime socket")?;
    let morph_enabled = morph_keys.is_some();
    let socket = wrap_morph_udp_socket(socket, morph_keys, crate::transport::UdpRole::Server)?;
    Endpoint::new_with_abstract_socket(
        morph_endpoint_config(morph_enabled)?,
        Some(server_config),
        socket,
        runtime,
    )
    .with_context(|| format!("portal::listen_endpoint: failed to listen for QUIC on {addr}"))
}

fn bind_quic_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = if addr.is_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket
    } else {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?
    };
    let _ = socket.set_send_buffer_size(QUIC_SOCKET_BUFFER_SIZE);
    let _ = socket.set_recv_buffer_size(QUIC_SOCKET_BUFFER_SIZE);
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

pub(super) fn listen_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let socket = if addr.is_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(true)?;
        socket
    } else {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?
    };
    crate::common::configure_tcp_listener(&socket)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(TCP_LISTEN_BACKLOG)?;
    let listener = std::net::TcpListener::from(socket);
    TcpListener::from_std(listener)
        .with_context(|| format!("portal::listen_tcp: failed to listen for TLS/TCP on {addr}"))
}

pub(super) fn configure_transport(
    server_config: &mut quinn::ServerConfig,
    udp_idle_timeout: Duration,
    keep_alive_interval: Option<Duration>,
    morph_enabled: bool,
) -> Result<()> {
    let flow_control = transport_flow_control()?;
    let transport = Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
        anyhow::anyhow!("portal::configure_transport: server transport already shared")
    })?;
    transport.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER_SIZE));
    transport.datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_SIZE);
    transport.stream_receive_window(VarInt::from_u32(flow_control.stream_receive_window));
    transport.receive_window(VarInt::from_u32(QUIC_PRE_AUTH_RECEIVE_WINDOW));
    transport.send_window(flow_control.send_window);
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.max_idle_timeout(Some(IdleTimeout::try_from(udp_idle_timeout)?));
    transport.keep_alive_interval(keep_alive_interval);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    configure_morph_mtu(transport, morph_enabled);

    Ok(())
}

#[cfg(test)]
#[path = "../tests/portal/listener.rs"]
mod socket_tests;
