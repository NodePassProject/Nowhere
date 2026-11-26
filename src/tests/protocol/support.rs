// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Protocol helpers shared by internal tests.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::Target;

pub(crate) fn encode_udp_data(flow_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > super::datagram::UDP_PACKET_MAX {
        bail!("protocol::test_support::encode_udp_data: payload too large");
    }
    let header = super::datagram::encode_udp_data_header(flow_id)?;
    let mut output = Vec::with_capacity(super::datagram::UDP_HEADER_LEN + payload.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    Ok(output)
}

pub(crate) fn encode_udp_data_fragments(
    flow_id: u32,
    packet_id: u32,
    payload: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>> {
    if max_datagram_size < super::datagram::UDP_HEADER_LEN {
        bail!("protocol::test_support::encode_udp_data_fragments: datagram limit too small");
    }
    if payload.len() <= max_datagram_size - super::datagram::UDP_HEADER_LEN {
        return Ok(vec![encode_udp_data(flow_id, payload)?]);
    }
    Ok(
        super::datagram::encode_udp_fragments(flow_id, packet_id, payload, max_datagram_size)?
            .collect(),
    )
}

pub(crate) fn encode_target(target: &Target) -> Result<Vec<u8>> {
    let mut output = vec![0; target.encoded_len()?];
    let written = super::request::encode_target_into(target, &mut output)?;
    debug_assert_eq!(written, output.len());
    Ok(output)
}

pub(crate) async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    target: &Target,
) -> Result<()> {
    let mut encoded = [0; super::TARGET_MAX_ENCODED_LEN];
    let encoded_len = super::request::encode_target_into(target, &mut encoded)?;
    writer
        .write_all(&encoded[..encoded_len])
        .await
        .context("protocol::test_support::write_request: failed to write target")
}

pub(crate) fn write_request_frame(target: &Target) -> Result<Vec<u8>> {
    encode_target(target)
}

impl Target {
    pub(crate) const fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    pub(crate) const fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Ip(address) => Some(*address),
            Self::Domain { .. } => None,
        }
    }

    pub(crate) fn domain_name(&self) -> Option<&str> {
        match self {
            Self::Ip(_) => None,
            Self::Domain { host, .. } => Some(host),
        }
    }

    pub(crate) const fn ip_addr(&self) -> Option<std::net::IpAddr> {
        match self {
            Self::Ip(address) => Some(address.ip()),
            Self::Domain { .. } => None,
        }
    }
}

pub(crate) fn encode_udp_packet(payload: &[u8]) -> Result<Vec<u8>> {
    let header = super::uot::encode_udp_packet_header(payload.len())?;
    let mut output = Vec::with_capacity(header.len() + payload.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    Ok(output)
}

pub(crate) async fn read_udp_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>> {
    let mut payload = Vec::new();
    let Some(payload_len) = read_udp_packet_into(reader, &mut payload).await? else {
        return Ok(None);
    };
    debug_assert_eq!(payload_len, payload.len());
    Ok(Some(payload))
}

pub(crate) async fn read_udp_packet_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    payload: &mut Vec<u8>,
) -> Result<Option<usize>> {
    let mut first = [0; 1];
    let count = reader
        .read(&mut first)
        .await
        .context("protocol::uot::read_udp_packet: failed to read packet length")?;
    if count == 0 {
        payload.clear();
        return Ok(None);
    }

    let mut second = [0; 1];
    reader
        .read_exact(&mut second)
        .await
        .context("protocol::uot::read_udp_packet: truncated packet length")?;
    let payload_len = u16::from_be_bytes([first[0], second[0]]) as usize;
    payload.resize(payload_len, 0);
    reader
        .read_exact(payload)
        .await
        .context("protocol::uot::read_udp_packet: truncated packet payload")?;
    Ok(Some(payload_len))
}
