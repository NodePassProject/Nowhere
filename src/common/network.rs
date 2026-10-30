// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Network binding and outbound dial helpers.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::{TcpSocket, TcpStream, UdpSocket, lookup_host};

use super::{AddressFamily, CarrierEndpoint, DialPolicy};

pub(crate) fn configure_tcp_listener(socket: &socket2::Socket) -> std::io::Result<()> {
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;

        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, setsockopt,
        };

        let enabled = 1i32;
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&enabled as *const i32).cast(),
                std::mem::size_of_val(&enabled) as i32,
            )
        };
        if result == SOCKET_ERROR {
            return Err(std::io::Error::from_raw_os_error(unsafe {
                WSAGetLastError()
            }));
        }
    }
    Ok(())
}

pub(crate) fn resolve_bind_addrs(host: &str, endpoint: CarrierEndpoint) -> Result<Vec<SocketAddr>> {
    let mut addrs = if host == "*" || host.is_empty() {
        match endpoint.family {
            AddressFamily::Any => vec![
                SocketAddr::from(([0, 0, 0, 0], endpoint.port)),
                SocketAddr::from(([0u16; 8], endpoint.port)),
            ],
            AddressFamily::V4 => vec![SocketAddr::from(([0, 0, 0, 0], endpoint.port))],
            AddressFamily::V6 => vec![SocketAddr::from(([0u16; 8], endpoint.port))],
        }
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        if endpoint.family.accepts(ip) {
            vec![SocketAddr::new(ip, endpoint.port)]
        } else {
            Vec::new()
        }
    } else {
        let joined = format!("{host}:{}", endpoint.port);
        joined
            .to_socket_addrs()
            .with_context(|| format!("failed to resolve listen address: {joined}"))?
            .filter(|addr| endpoint.family.accepts(addr.ip()))
            .collect()
    };
    addrs.sort_unstable();
    addrs.dedup();
    if addrs.is_empty() {
        return Err(anyhow!("no matching listen address resolved for {host}"));
    }
    Ok(addrs)
}

pub fn bind_udp_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if host.is_empty() {
        return Ok(vec![
            SocketAddr::from(([0, 0, 0, 0], port)),
            SocketAddr::from(([0u16; 8], port)),
        ]);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let joined = format!("{host}:{port}");
    let addr = joined
        .to_socket_addrs()
        .with_context(|| {
            format!("common::util::bind_udp_addrs: failed to resolve listen address: {joined}")
        })?
        .next()
        .ok_or_else(|| {
            anyhow!("common::util::bind_udp_addrs: no listen address resolved: {joined}")
        })?;
    Ok(vec![addr])
}

pub(crate) async fn dial_tcp_with_policy(
    policy: &DialPolicy,
    target: &str,
    timeout: Duration,
    family: AddressFamily,
) -> Result<TcpStream> {
    let connect = async {
        let addrs = lookup_host(target).await.with_context(|| {
            format!("common::util::dial_tcp_from_local_ip: failed to resolve target: {target}")
        })?;

        connect_tcp_candidates(policy, filter_addrs_for_family(addrs, policy, family)).await
    };

    tokio::time::timeout(timeout, connect)
        .await
        .context("common::util::dial_tcp_from_local_ip: dial timeout")?
}

pub(crate) async fn dial_udp_with_policy(
    policy: &DialPolicy,
    target: &str,
    timeout: Duration,
) -> Result<UdpSocket> {
    let connect = async {
        let addrs = lookup_host(target).await.with_context(|| {
            format!("common::util::dial_udp_from_local_ip: failed to resolve target: {target}")
        })?;

        connect_udp_candidates(
            policy,
            filter_addrs_for_family(addrs, policy, AddressFamily::Any),
        )
        .await
    };

    tokio::time::timeout(timeout, connect)
        .await
        .context("common::util::dial_udp_from_local_ip: dial timeout")?
}

async fn connect_tcp_candidates(
    policy: &DialPolicy,
    addresses: Vec<SocketAddr>,
) -> Result<TcpStream> {
    let mut last_err = None;
    for address in addresses {
        match connect_tcp_addr(policy.local_ip(address.ip())?, address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_err = Some(error),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("common::util::dial_tcp_from_local_ip: no target address matches configured address family")))
}

async fn connect_udp_candidates(
    policy: &DialPolicy,
    addresses: Vec<SocketAddr>,
) -> Result<UdpSocket> {
    let mut last_err = None;
    for address in addresses {
        match connect_udp_addr(policy.local_ip(address.ip())?, address).await {
            Ok(socket) => return Ok(socket),
            Err(error) => last_err = Some(error),
        }
    }
    Err(last_err
        .unwrap_or_else(|| anyhow!("common::util::dial_udp_from_local_ip: no target address")))
}

pub(crate) fn filter_addrs_for_family(
    addrs: impl Iterator<Item = SocketAddr>,
    policy: &DialPolicy,
    family: AddressFamily,
) -> Vec<SocketAddr> {
    addrs
        .filter(|addr| policy.accepts(addr.ip()) && family.accepts(addr.ip()))
        .collect()
}

pub(super) async fn connect_tcp_addr(
    local_ip: Option<IpAddr>,
    target: SocketAddr,
) -> Result<TcpStream> {
    if let Some(ip) = local_ip {
        let socket = if target.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .context("common::util::connect_tcp_addr: failed to create TCP socket")?;
        socket.bind(SocketAddr::new(ip, 0)).with_context(|| {
            format!("common::util::connect_tcp_addr: failed to bind local IP: {ip}")
        })?;
        socket.connect(target).await.with_context(|| {
            format!("common::util::connect_tcp_addr: failed to dial from local IP: {ip}")
        })
    } else {
        TcpStream::connect(target)
            .await
            .with_context(|| "common::util::connect_tcp_addr: failed to dial target")
    }
}

pub(super) async fn connect_udp_addr(
    local_ip: Option<IpAddr>,
    target: SocketAddr,
) -> Result<UdpSocket> {
    let bind_addr = match local_ip {
        Some(ip) => SocketAddr::new(ip, 0),
        None if target.is_ipv4() => SocketAddr::from(([0, 0, 0, 0], 0)),
        None => SocketAddr::from(([0u16; 8], 0)),
    };
    let socket = UdpSocket::bind(bind_addr).await.with_context(|| {
        format!("common::util::connect_udp_addr: failed to bind UDP socket: {bind_addr}")
    })?;
    socket.connect(target).await.with_context(|| {
        format!("common::util::connect_udp_addr: failed to connect UDP socket: {target}")
    })?;
    Ok(socket)
}

#[cfg(test)]
#[path = "../tests/common/network.rs"]
mod tests;

pub(crate) fn is_normal_close(error: &anyhow::Error) -> bool {
    fn closed(error: &(dyn std::error::Error + 'static)) -> bool {
        if let Some(error) = error.downcast_ref::<quinn::ConnectionError>() {
            return matches!(error, quinn::ConnectionError::LocallyClosed)
                || matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 0u32.into());
        }
        if let Some(error) = error.downcast_ref::<std::io::Error>() {
            return error.get_ref().is_some_and(|error| closed(error));
        }
        if let Some(error) = error.downcast_ref::<quinn::ReadError>() {
            return matches!(error, quinn::ReadError::ConnectionLost(error) if closed(error));
        }
        if let Some(error) = error.downcast_ref::<quinn::WriteError>() {
            return matches!(error, quinn::WriteError::ConnectionLost(error) if closed(error));
        }
        error.is::<crate::vector::OpenFlowError>()
            && matches!(
                error.downcast_ref::<crate::vector::OpenFlowError>(),
                Some(crate::vector::OpenFlowError::Cancelled)
            )
    }
    error.chain().any(closed)
}
