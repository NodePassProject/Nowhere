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
use crate::common::{bind_udp_addrs, env_int, handshake_timeout, udp_idle_timeout};

use super::super::VectorInner;
use super::super::flow::{carrier_name, open_tcp, relay_tcp};
use super::super::udp_flow::{UdpTunnel, open_udp};
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
    .await
    .map_err(|_| anyhow!("SOCKS5 handshake timeout"))??;
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
            match open_tcp(vector.clone(), &request.address).await {
                Ok(tunnel) => {
                    let reply = tunnel.socks_reply();
                    write_reply(&mut stream, reply, &SocksAddress::unspecified()).await?;
                    tokio::select! {
                        result = relay_tcp(vector, stream, tunnel, peer, &request.address) => result,
                        _ = shutdown.cancelled() => Ok(()),
                    }
                }
                Err(error) => {
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

async fn run_udp_association(
    vector: Arc<VectorInner>,
    mut control: TcpStream,
    control_peer: SocketAddr,
    requested: SocksAddress,
    shutdown: CancellationToken,
) -> Result<()> {
    let requested_port =
        validate_udp_source_request(&requested, control_peer.ip()).map_err(|error| {
            vector.logger.debug(format_args!(
                "vector::socks::run_udp_association: source rejected: {error}"
            ));
            error
        });
    let requested_port = match requested_port {
        Ok(port) => port,
        Err(error) => {
            write_reply(
                &mut control,
                REPLY_CONNECTION_NOT_ALLOWED,
                &SocksAddress::unspecified(),
            )
            .await?;
            return Err(error);
        }
    };
    let local_ip = control.local_addr()?.ip();
    let bind = SocketAddr::new(
        if local_ip.is_unspecified() {
            match control_peer.ip() {
                IpAddr::V4(_) => IpAddr::from([0, 0, 0, 0]),
                IpAddr::V6(_) => IpAddr::from([0u16; 8]),
            }
        } else {
            local_ip
        },
        0,
    );
    let udp = Arc::new(UdpSocket::bind(bind).await?);
    let mut advertised = udp.local_addr()?;
    if advertised.ip().is_unspecified() && !local_ip.is_unspecified() {
        advertised.set_ip(local_ip);
    }
    write_reply(&mut control, REPLY_SUCCEEDED, &SocksAddress::Ip(advertised)).await?;

    let association_shutdown = shutdown.child_token();
    let client_endpoint = Arc::new(StdMutex::new(
        requested_port.map(|port| SocketAddr::new(control_peer.ip(), port)),
    ));
    let max_flows = env_int("NOW_QUIC_MAX_UDP_FLOWS", 256).clamp(1, 256) as usize;
    let mut flows: HashMap<SocksAddress, mpsc::Sender<QueuedLocalPacket>> =
        HashMap::with_capacity(max_flows.min(64));
    let mut tasks = JoinSet::new();
    let mut packet = vec![0u8; SOCKS_UDP_PACKET_MAX];
    let mut control_byte = [0u8; 1];

    let outcome = loop {
        tokio::select! {
            _ = association_shutdown.cancelled() => break Ok(()),
            result = control.read(&mut control_byte) => {
                match result {
                    Ok(0) => break Ok(()),
                    Ok(_) => break Err(anyhow!("unexpected UDP ASSOCIATE control data")),
                    Err(error) => break Err(error.into()),
                }
            }
            received = udp.recv_from(&mut packet) => {
                let (size, source) = match received {
                    Ok(received) => received,
                    Err(error) => break Err(error.into()),
                };
                if source.ip() != control_peer.ip() {
                    continue;
                }
                let Ok((target, fragment, payload)) = decode_udp_packet(&packet[..size]) else {
                    continue;
                };
                if fragment != 0 || target.port() == 0 {
                    continue;
                }
                if !accept_udp_source(&client_endpoint, control_peer.ip(), source) {
                    continue;
                }
                let Ok(permit) = vector
                    .local_udp_budget
                    .clone()
                    .try_acquire_many_owned(payload.len().max(1) as u32)
                else {
                    continue;
                };
                let mut payload = QueuedLocalPacket {
                    payload: payload.to_vec(),
                    _permit: permit,
                };
                if let Some(sender) = flows.get(&target) {
                    match sender.try_send(payload) {
                        Ok(()) | Err(TrySendError::Full(_)) => continue,
                        Err(TrySendError::Closed(returned)) => payload = returned,
                    }
                    flows.remove(&target);
                }
                if flows.len() >= max_flows {
                    continue;
                }
                let (sender, receiver) = mpsc::channel(64);
                if sender.try_send(payload).is_err() {
                    continue;
                }
                flows.insert(target.clone(), sender);
                tasks.spawn(open_and_relay_udp_target(
                    vector.clone(),
                    udp.clone(),
                    client_endpoint.clone(),
                    target,
                    receiver,
                    association_shutdown.clone(),
                ));
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {
                flows.retain(|_, sender| !sender.is_closed());
            }
        }
    };
    association_shutdown.cancel();
    flows.clear();
    while tasks.join_next().await.is_some() {}
    outcome
}

async fn open_and_relay_udp_target(
    vector: Arc<VectorInner>,
    socket: Arc<UdpSocket>,
    client_endpoint: Arc<StdMutex<Option<SocketAddr>>>,
    target: SocksAddress,
    outbound: mpsc::Receiver<QueuedLocalPacket>,
    shutdown: CancellationToken,
) {
    let tunnel = tokio::select! {
        _ = shutdown.cancelled() => return,
        result = open_udp(vector.clone(), &target) => match result {
            Ok(tunnel) => tunnel,
            Err(error) => {
                vector.logger.debug(format_args!(
                    "vector::socks::open_and_relay_udp_target: target {target} failed: {error}"
                ));
                return;
            }
        },
    };
    relay_udp_target(
        vector,
        socket,
        client_endpoint,
        target,
        tunnel,
        outbound,
        shutdown,
    )
    .await;
}

fn validate_udp_source_request(requested: &SocksAddress, peer_ip: IpAddr) -> Result<Option<u16>> {
    match requested {
        SocksAddress::Ip(address) => {
            if !address.ip().is_unspecified() && address.ip() != peer_ip {
                return Err(anyhow!("UDP source IP differs from control peer"));
            }
            Ok((address.port() != 0).then_some(address.port()))
        }
        SocksAddress::Domain(_, _) => Err(anyhow!("domain UDP source constraint unsupported")),
    }
}

fn accept_udp_source(
    endpoint: &StdMutex<Option<SocketAddr>>,
    peer_ip: IpAddr,
    source: SocketAddr,
) -> bool {
    if source.ip() != peer_ip {
        return false;
    }
    let mut endpoint = endpoint.lock().unwrap_or_else(|lock| lock.into_inner());
    match *endpoint {
        Some(expected) => expected == source,
        None => {
            *endpoint = Some(source);
            true
        }
    }
}

async fn relay_udp_target(
    vector: Arc<VectorInner>,
    socket: Arc<UdpSocket>,
    client_endpoint: Arc<StdMutex<Option<SocketAddr>>>,
    target: SocksAddress,
    mut tunnel: UdpTunnel,
    mut outbound: mpsc::Receiver<QueuedLocalPacket>,
    shutdown: CancellationToken,
) {
    let mut inbound = Vec::with_capacity(u16::MAX as usize);
    let mut local_packet = vector.buffers.get_udp_buffer();
    local_packet.clear();
    let source = client_endpoint
        .lock()
        .unwrap_or_else(|lock| lock.into_inner())
        .map_or_else(|| "<unknown>".to_owned(), |endpoint| endpoint.to_string());
    vector.logger.debug(format_args!(
        "vector::socks::relay_udp_target: transfer starting: UP[{}] {source} -> {} -> {} -> {target} | DOWN[{}] {target} -> {} -> {} -> {source}",
        carrier_name(tunnel.uplink),
        vector.config.socks.endpoint(),
        vector.config.portal_endpoint(),
        carrier_name(tunnel.downlink),
        vector.config.portal_endpoint(),
        vector.config.socks.endpoint(),
    ));
    let idle = tokio::time::sleep_until(Instant::now() + udp_idle_timeout());
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = &mut idle => break,
            payload = outbound.recv() => {
                let Some(payload) = payload else { break; };
                let sent = tokio::select! {
                    _ = shutdown.cancelled() => None,
                    _ = &mut idle => None,
                    result = async {
                        if let Some(rate) = &vector.rate_limiter {
                            rate.wait_read(payload.payload.len() as i64).await;
                        }
                        tunnel.send(&payload.payload).await
                    } => Some(result),
                };
                if !matches!(sent, Some(Ok(()))) { break; }
                idle.as_mut().reset(Instant::now() + udp_idle_timeout());
            }
            received = tunnel.recv_into(&mut inbound) => {
                let Ok(Some(packet)) = received else { break; };
                let size = packet.len();
                let endpoint = *client_endpoint.lock().unwrap_or_else(|lock| lock.into_inner());
                let Some(endpoint) = endpoint else { continue; };
                if encode_udp_packet_into(&mut local_packet, &target, packet.payload(&inbound)).is_err() {
                    continue;
                }
                let sent = tokio::select! {
                    _ = shutdown.cancelled() => None,
                    _ = &mut idle => None,
                    result = async {
                        if let Some(rate) = &vector.rate_limiter {
                            rate.wait_write(size as i64).await;
                        }
                        socket.send_to(&local_packet, endpoint).await
                    } => Some(result),
                };
                if !matches!(sent, Some(Ok(_))) { break; }
                idle.as_mut().reset(Instant::now() + udp_idle_timeout());
            }
        }
    }
    tunnel.close().await;
    vector.logger.debug(format_args!(
        "vector::socks::relay_udp_target: transfer complete: target={target}"
    ));
}

struct QueuedLocalPacket {
    payload: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
#[path = "../../tests/vector/socks_server.rs"]
mod tests;
