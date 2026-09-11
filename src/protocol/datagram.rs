// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Minimal QUIC DATAGRAM codec and bounded fragment reassembly.

use anyhow::{Result, bail};
use bytes::Bytes;

use super::FlowId;

/// Unfragmented DATA frame type in the high two bits.
pub const UDP_FRAME_DATA: u8 = 0;
/// Fragmented DATA frame type in the high two bits.
pub const UDP_FRAME_FRAGMENT: u8 = 1;
/// Flow CLOSE frame type in the high two bits.
pub const UDP_FRAME_CLOSE: u8 = 2;
/// Common unfragmented/CLOSE header length.
pub const UDP_HEADER_LEN: usize = 4;
/// Fragment header length.
pub const UDP_FRAGMENT_HEADER_LEN: usize = 12;
/// Largest UDP payload representable by the protocol.
pub const UDP_PACKET_MAX: usize = u16::MAX as usize;

const FRAME_TYPE_SHIFT: u32 = 30;
const FRAME_TYPE_MASK: u32 = 0b11 << FRAME_TYPE_SHIFT;

/// Fragment metadata parameterized by borrowed or owned payload storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpFragment<P> {
    /// Packet identifier scoped to the active reassembly window of one flow.
    pub packet_id: u32,
    /// Zero-based fragment index.
    pub fragment_index: u8,
    /// Total fragment count, always in 2..=255.
    pub fragment_count: u8,
    /// Original UDP packet length.
    pub total_len: u16,
    /// Fragment payload.
    pub payload: P,
}

/// Borrowed fragment view returned by the allocation-free decoder.
pub type BorrowedUdpFragment<'a> = UdpFragment<&'a [u8]>;
/// Owned fragment backed by a zero-copy slice of a QUIC DATAGRAM.
pub type OwnedUdpFragment = UdpFragment<Bytes>;

/// One decoded QUIC DATAGRAM frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpFrame<'a> {
    /// One complete UDP packet, including a legal zero-length packet.
    Data { flow_id: FlowId, payload: &'a [u8] },
    /// One fragment of a larger UDP packet.
    Fragment {
        flow_id: FlowId,
        fragment: BorrowedUdpFragment<'a>,
    },
    /// Immediate flow resource release.
    Close { flow_id: FlowId },
}

/// Owned decoded frame retaining the original QUIC DATAGRAM allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedUdpFrame {
    Data {
        flow_id: FlowId,
        payload: Bytes,
    },
    Fragment {
        flow_id: FlowId,
        fragment: OwnedUdpFragment,
    },
    Close {
        flow_id: FlowId,
    },
}

/// Encodes an unfragmented DATA header on the stack.
pub fn encode_udp_data_header(flow_id: FlowId) -> Result<[u8; UDP_HEADER_LEN]> {
    encode_base_header(UDP_FRAME_DATA, flow_id)
}

/// Encodes a CLOSE frame on the stack.
pub fn encode_udp_close(flow_id: FlowId) -> Result<[u8; UDP_HEADER_LEN]> {
    encode_base_header(UDP_FRAME_CLOSE, flow_id)
}

/// Encodes a validated fragment header on the stack.
pub fn encode_udp_fragment_header(
    flow_id: FlowId,
    packet_id: u32,
    fragment_index: u8,
    fragment_count: u8,
    total_len: u16,
) -> Result<[u8; UDP_FRAGMENT_HEADER_LEN]> {
    validate_flow_id(flow_id, "encode_udp_fragment_header")?;
    validate_packet_id(packet_id, "encode_udp_fragment_header")?;
    validate_fragment_metadata(
        fragment_index,
        fragment_count,
        total_len,
        "encode_udp_fragment_header",
    )?;
    let mut output = [0; UDP_FRAGMENT_HEADER_LEN];
    output[..4].copy_from_slice(&encode_base_word(UDP_FRAME_FRAGMENT, flow_id)?.to_be_bytes());
    output[4..8].copy_from_slice(&packet_id.to_be_bytes());
    output[8] = fragment_index;
    output[9] = fragment_count;
    output[10..12].copy_from_slice(&total_len.to_be_bytes());
    Ok(output)
}

/// Encodes one unfragmented DATA frame.
pub fn encode_udp_data(flow_id: FlowId, payload: &[u8]) -> Result<Vec<u8>> {
    validate_udp_payload(payload, "encode_udp_data")?;
    let header = encode_udp_data_header(flow_id)?;
    let mut output = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    Ok(output)
}

/// Encodes either one minimal DATA frame or the required FRAGMENT frames.
pub fn encode_udp_data_fragments(
    flow_id: FlowId,
    packet_id: u32,
    payload: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>> {
    validate_flow_id(flow_id, "encode_udp_data_fragments")?;
    validate_udp_payload(payload, "encode_udp_data_fragments")?;
    if max_datagram_size < UDP_HEADER_LEN {
        bail!(
            "protocol::datagram::encode_udp_data_fragments: DATAGRAM limit {max_datagram_size} smaller than header {UDP_HEADER_LEN}"
        );
    }
    if payload.len() <= max_datagram_size - UDP_HEADER_LEN {
        return Ok(vec![encode_udp_data(flow_id, payload)?]);
    }

    Ok(encode_udp_fragments(flow_id, packet_id, payload, max_datagram_size)?.collect())
}

/// Validates a fragmented packet once and then materializes one DATAGRAM at a
/// time. Dropping the iterator stops all remaining allocation and copying.
pub fn encode_udp_fragments(
    flow_id: FlowId,
    packet_id: u32,
    payload: &[u8],
    max_datagram_size: usize,
) -> Result<UdpFragments<'_>> {
    validate_flow_id(flow_id, "encode_udp_fragments")?;
    validate_packet_id(packet_id, "encode_udp_fragments")?;
    validate_udp_payload(payload, "encode_udp_fragments")?;
    if max_datagram_size >= UDP_HEADER_LEN && payload.len() <= max_datagram_size - UDP_HEADER_LEN {
        bail!("protocol::datagram::encode_udp_fragments: packet must use unfragmented DATA");
    }
    let fragment_payload_max = max_datagram_size
        .checked_sub(UDP_FRAGMENT_HEADER_LEN)
        .filter(|capacity| *capacity != 0)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "protocol::datagram::encode_udp_fragments: DATAGRAM limit {max_datagram_size} has no fragment payload capacity"
            )
        })?;
    let fragment_count = payload.len().div_ceil(fragment_payload_max);
    if !(2..=u8::MAX as usize).contains(&fragment_count) {
        bail!("protocol::datagram::encode_udp_fragments: invalid fragment count: {fragment_count}");
    }
    Ok(UdpFragments {
        flow_id,
        packet_id,
        payload,
        fragment_payload_max,
        fragment_count: fragment_count as u8,
        next: 0,
    })
}

/// Lazy sequence produced by [`encode_udp_fragments`].
pub struct UdpFragments<'a> {
    flow_id: FlowId,
    packet_id: u32,
    payload: &'a [u8],
    fragment_payload_max: usize,
    fragment_count: u8,
    next: u8,
}

impl Iterator for UdpFragments<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.fragment_count {
            return None;
        }
        let fragment_index = self.next;
        self.next += 1;
        let start = fragment_index as usize * self.fragment_payload_max;
        let end = self.payload.len().min(start + self.fragment_payload_max);
        let fragment_payload = &self.payload[start..end];
        let header = encode_udp_fragment_header(
            self.flow_id,
            self.packet_id,
            fragment_index,
            self.fragment_count,
            self.payload.len() as u16,
        )
        .expect("fragment plan was validated at construction");
        let mut frame = Vec::with_capacity(UDP_FRAGMENT_HEADER_LEN + fragment_payload.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(fragment_payload);
        Some(frame)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.fragment_count - self.next) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for UdpFragments<'_> {}

/// Decodes one complete QUIC DATAGRAM without allocating.
pub fn decode_udp_frame(input: &[u8]) -> Result<UdpFrame<'_>> {
    if input.len() < UDP_HEADER_LEN {
        bail!("protocol::datagram::decode_udp_frame: short header");
    }
    let base = u32::from_be_bytes(input[..4].try_into().expect("fixed base header"));
    let frame_type = (base & FRAME_TYPE_MASK) >> FRAME_TYPE_SHIFT;
    let flow_id = base & super::MAX_FLOW_ID;
    validate_flow_id(flow_id, "decode_udp_frame")?;

    match frame_type {
        value if value == UDP_FRAME_DATA as u32 => {
            let payload = &input[UDP_HEADER_LEN..];
            validate_udp_payload(payload, "decode_udp_frame")?;
            Ok(UdpFrame::Data { flow_id, payload })
        }
        value if value == UDP_FRAME_FRAGMENT as u32 => decode_fragment(input, flow_id),
        value if value == UDP_FRAME_CLOSE as u32 => {
            if input.len() != UDP_HEADER_LEN {
                bail!("protocol::datagram::decode_udp_frame: CLOSE payload");
            }
            Ok(UdpFrame::Close { flow_id })
        }
        value => bail!("protocol::datagram::decode_udp_frame: invalid frame type: {value}"),
    }
}

/// Decodes a Quinn-owned DATAGRAM and slices its payload without copying.
pub fn decode_udp_frame_owned(input: Bytes) -> Result<OwnedUdpFrame> {
    match decode_udp_frame(&input)? {
        UdpFrame::Data { flow_id, .. } => Ok(OwnedUdpFrame::Data {
            flow_id,
            payload: input.slice(UDP_HEADER_LEN..),
        }),
        UdpFrame::Fragment { flow_id, fragment } => {
            let fragment = OwnedUdpFragment {
                packet_id: fragment.packet_id,
                fragment_index: fragment.fragment_index,
                fragment_count: fragment.fragment_count,
                total_len: fragment.total_len,
                payload: input.slice(UDP_FRAGMENT_HEADER_LEN..),
            };
            Ok(OwnedUdpFrame::Fragment { flow_id, fragment })
        }
        UdpFrame::Close { flow_id } => Ok(OwnedUdpFrame::Close { flow_id }),
    }
}

fn decode_fragment(input: &[u8], flow_id: FlowId) -> Result<UdpFrame<'_>> {
    if input.len() < UDP_FRAGMENT_HEADER_LEN {
        bail!("protocol::datagram::decode_udp_frame: short fragment header");
    }
    let packet_id = u32::from_be_bytes(input[4..8].try_into().expect("fixed packet id"));
    validate_packet_id(packet_id, "decode_udp_frame")?;
    let fragment_index = input[8];
    let fragment_count = input[9];
    let total_len = u16::from_be_bytes([input[10], input[11]]);
    validate_fragment_metadata(
        fragment_index,
        fragment_count,
        total_len,
        "decode_udp_frame",
    )?;
    let payload = &input[UDP_FRAGMENT_HEADER_LEN..];
    if payload.is_empty()
        || payload.len().saturating_add(fragment_count as usize - 1) > total_len as usize
    {
        bail!("protocol::datagram::decode_udp_frame: invalid fragment payload length");
    }
    Ok(UdpFrame::Fragment {
        flow_id,
        fragment: UdpFragment {
            packet_id,
            fragment_index,
            fragment_count,
            total_len,
            payload,
        },
    })
}

fn encode_base_header(frame_type: u8, flow_id: FlowId) -> Result<[u8; UDP_HEADER_LEN]> {
    Ok(encode_base_word(frame_type, flow_id)?.to_be_bytes())
}

fn encode_base_word(frame_type: u8, flow_id: FlowId) -> Result<u32> {
    validate_flow_id(flow_id, "encode_base_header")?;
    if frame_type > UDP_FRAME_CLOSE {
        bail!("protocol::datagram::encode_base_header: invalid frame type");
    }
    Ok((u32::from(frame_type) << FRAME_TYPE_SHIFT) | flow_id)
}

fn validate_flow_id(flow_id: FlowId, operation: &str) -> Result<()> {
    if flow_id == 0 || flow_id > super::MAX_FLOW_ID {
        bail!("protocol::datagram::{operation}: flow id out of range");
    }
    Ok(())
}

fn validate_packet_id(packet_id: u32, operation: &str) -> Result<()> {
    if packet_id == 0 {
        bail!("protocol::datagram::{operation}: zero packet id");
    }
    Ok(())
}

fn validate_udp_payload(payload: &[u8], operation: &str) -> Result<()> {
    if payload.len() > UDP_PACKET_MAX {
        bail!(
            "protocol::datagram::{operation}: UDP payload too large: {}",
            payload.len()
        );
    }
    Ok(())
}

fn validate_fragment_metadata(
    fragment_index: u8,
    fragment_count: u8,
    total_len: u16,
    operation: &str,
) -> Result<()> {
    if fragment_count < 2 || fragment_index >= fragment_count {
        bail!("protocol::datagram::{operation}: invalid fragment index or count");
    }
    if total_len == 0 {
        bail!("protocol::datagram::{operation}: zero fragmented packet length");
    }
    if total_len < fragment_count as u16 {
        bail!("protocol::datagram::{operation}: total length smaller than fragment count");
    }
    Ok(())
}

mod reassembly;

pub use self::reassembly::{
    DatagramReassembler, ReassemblyConfig, ReassemblyDropReason, ReassemblyOutcome,
};

#[cfg(test)]
#[path = "../tests/protocol/datagram.rs"]
mod tests;
