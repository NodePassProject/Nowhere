// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Payload-oriented direct and SOCKS5 UDP socket facade.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::ops::Range;

use anyhow::{Context, Result, bail};
use tokio::net::{TcpStream, UdpSocket};

use super::protocol::parse_udp_header;

/// UDP socket facade that preserves payload-only send/receive semantics.
pub(crate) enum OutboundUdpSocket {
    Direct(UdpSocket),
    Socks(SocksUdpAssociation),
}

impl OutboundUdpSocket {
    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Direct(socket) => socket.local_addr(),
            Self::Socks(association) => association.socket.local_addr(),
        }
    }

    pub(crate) async fn send(&self, payload: &[u8], packet: &mut Vec<u8>) -> Result<usize> {
        match self {
            Self::Direct(socket) => socket.send(payload).await.map_err(Into::into),
            Self::Socks(association) => association.send(payload, packet).await,
        }
    }

    pub(crate) async fn recv(&self, buffer: &mut [u8]) -> Result<Range<usize>> {
        match self {
            Self::Direct(socket) => socket
                .recv(buffer)
                .await
                .map(|size| 0..size)
                .map_err(Into::into),
            Self::Socks(association) => association.recv(buffer).await,
        }
    }
}

pub(crate) struct SocksUdpAssociation {
    pub(super) control: TcpStream,
    pub(super) socket: UdpSocket,
    pub(super) target_header: Vec<u8>,
}

impl SocksUdpAssociation {
    async fn send(&self, payload: &[u8], packet: &mut Vec<u8>) -> Result<usize> {
        packet.clear();
        packet.reserve(self.target_header.len() + payload.len());
        packet.extend_from_slice(&self.target_header);
        packet.extend_from_slice(payload);
        let sent = self
            .socket
            .send(packet)
            .await
            .context("common::socks::SocksUdpAssociation::send: failed to write relay")?;
        if sent != packet.len() {
            bail!("common::socks::SocksUdpAssociation::send: partial UDP datagram");
        }
        Ok(payload.len())
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<Range<usize>> {
        loop {
            let size = tokio::select! {
                result = self.socket.recv(buffer) => result.context(
                    "common::socks::SocksUdpAssociation::recv: failed to read relay",
                )?,
                result = self.control.readable() => {
                    result.context(
                        "common::socks::SocksUdpAssociation::recv: failed to poll control connection",
                    )?;
                    let mut byte = [0u8; 1];
                    match self.control.try_read(&mut byte) {
                        Ok(0) => bail!(
                            "common::socks::SocksUdpAssociation::recv: control connection closed"
                        ),
                        Ok(_) => bail!(
                            "common::socks::SocksUdpAssociation::recv: unexpected control data"
                        ),
                        Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                        Err(err) => return Err(err).context(
                            "common::socks::SocksUdpAssociation::recv: failed to read control connection",
                        ),
                    }
                }
            };
            let (header_len, fragment) = parse_udp_header(&buffer[..size])?;
            if fragment != 0 {
                continue;
            }
            return Ok(header_len..size);
        }
    }
}
