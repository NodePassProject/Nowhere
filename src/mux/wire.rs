// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::error::Error;
use std::fmt;

pub(super) type FlowId = u32;
pub(super) const HEADER_LEN: usize = 8;

pub(super) const FLAG_SYN: u8 = 0x01;
pub(super) const FLAG_FIN: u8 = 0x02;
pub(super) const FLAG_RST: u8 = 0x04;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum FrameKind {
    Stream = 0x01,
    Window = 0x02,
}

impl TryFrom<u8> for FrameKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Stream),
            0x02 => Ok(Self::Window),
            _ => Err(WireError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrameHeader {
    pub kind: FrameKind,
    pub flags: u8,
    pub value: u16,
    pub flow_id: FlowId,
}

impl FrameHeader {
    pub fn stream(flow_id: FlowId, flags: u8, payload_len: usize) -> Result<Self, WireError> {
        Self::new(FrameKind::Stream, flags, payload_len, flow_id)
    }

    pub fn window(flow_id: FlowId, credit: usize) -> Result<Self, WireError> {
        Self::new(FrameKind::Window, 0, credit, flow_id)
    }

    fn new(kind: FrameKind, flags: u8, value: usize, flow_id: FlowId) -> Result<Self, WireError> {
        let value = u16::try_from(value).map_err(|_| WireError::ValueTooLarge)?;
        let header = Self {
            kind,
            flags,
            value,
            flow_id,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(self) -> Result<(), WireError> {
        match self.kind {
            FrameKind::Stream => {
                if self.flow_id == 0 {
                    return Err(WireError::InvalidFlowId);
                }
                if self.flags & !(FLAG_SYN | FLAG_FIN | FLAG_RST) != 0 {
                    return Err(WireError::ReservedFlags);
                }
                if self.flags & FLAG_RST != 0 && (self.flags != FLAG_RST || self.value != 0) {
                    return Err(WireError::InvalidReset);
                }
                if self.flags & FLAG_SYN != 0 && self.flags != FLAG_SYN {
                    return Err(WireError::InvalidOpen);
                }
            }
            FrameKind::Window => {
                if self.flags != 0 {
                    return Err(WireError::ReservedFlags);
                }
                if self.value == 0 {
                    return Err(WireError::InvalidWindow);
                }
            }
        }
        Ok(())
    }
}

pub(super) fn encode_header(header: FrameHeader) -> Result<[u8; HEADER_LEN], WireError> {
    header.validate()?;
    let mut output = [0; HEADER_LEN];
    output[0] = header.kind as u8;
    output[1] = header.flags;
    output[2..4].copy_from_slice(&header.value.to_be_bytes());
    output[4..8].copy_from_slice(&header.flow_id.to_be_bytes());
    Ok(output)
}

pub(super) fn decode_header(input: &[u8]) -> Result<FrameHeader, WireError> {
    if input.len() != HEADER_LEN {
        return Err(WireError::InvalidHeaderLength(input.len()));
    }
    let header = FrameHeader {
        kind: FrameKind::try_from(input[0])?,
        flags: input[1],
        value: u16::from_be_bytes([input[2], input[3]]),
        flow_id: u32::from_be_bytes(input[4..8].try_into().expect("fixed flow ID")),
    };
    header.validate()?;
    Ok(header)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WireError {
    InvalidHeaderLength(usize),
    UnknownKind(u8),
    ValueTooLarge,
    ReservedFlags,
    InvalidFlowId,
    InvalidWindow,
    InvalidReset,
    InvalidOpen,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderLength(length) => {
                write!(formatter, "invalid header length: {length}")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown frame kind: {kind}"),
            Self::ValueTooLarge => formatter.write_str("frame value exceeds u16"),
            Self::ReservedFlags => formatter.write_str("reserved frame flags are non-zero"),
            Self::InvalidFlowId => formatter.write_str("invalid zero flow ID"),
            Self::InvalidWindow => formatter.write_str("window credit must be non-zero"),
            Self::InvalidReset => {
                formatter.write_str("RST must be the only flag and carry no data")
            }
            Self::InvalidOpen => formatter.write_str("SYN must be an isolated open frame"),
        }
    }
}

impl Error for WireError {}

#[cfg(test)]
#[path = "../tests/mux/wire.rs"]
mod tests;
