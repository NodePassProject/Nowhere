// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::error::Error;
use std::fmt;

pub(super) type FlowId = u32;
pub(super) const HEADER_LEN: usize = 8;

pub(super) const CLOSE_FIN: u8 = 0;
pub(super) const CLOSE_RESET: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum FrameKind {
    Open = 0x01,
    Data = 0x02,
    Window = 0x03,
    Close = 0x04,
}

impl TryFrom<u8> for FrameKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Open),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Window),
            0x04 => Ok(Self::Close),
            _ => Err(WireError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrameHeader {
    pub kind: FrameKind,
    pub code: u8,
    pub value: u16,
    pub flow_id: FlowId,
}

impl FrameHeader {
    pub fn open(flow_id: FlowId, window_extension: usize) -> Result<Self, WireError> {
        Self::new(FrameKind::Open, 0, window_extension, flow_id)
    }

    pub fn data(flow_id: FlowId, payload_len: usize) -> Result<Self, WireError> {
        Self::new(FrameKind::Data, 0, payload_len, flow_id)
    }

    pub fn window(flow_id: FlowId, credit: usize) -> Result<Self, WireError> {
        Self::new(FrameKind::Window, 0, credit, flow_id)
    }

    pub fn close(flow_id: FlowId, code: u8) -> Result<Self, WireError> {
        Self::new(FrameKind::Close, code, 0, flow_id)
    }

    fn new(kind: FrameKind, code: u8, value: usize, flow_id: FlowId) -> Result<Self, WireError> {
        let value = u16::try_from(value).map_err(|_| WireError::ValueTooLarge)?;
        let header = Self {
            kind,
            code,
            value,
            flow_id,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(self) -> Result<(), WireError> {
        match self.kind {
            FrameKind::Open => {
                require_flow(self.flow_id)?;
                if self.code != 0 {
                    return Err(WireError::ReservedCode);
                }
            }
            FrameKind::Data => {
                require_flow(self.flow_id)?;
                if self.code != 0 {
                    return Err(WireError::ReservedCode);
                }
                if self.value == 0 {
                    return Err(WireError::InvalidData);
                }
            }
            FrameKind::Window => {
                if self.code != 0 {
                    return Err(WireError::ReservedCode);
                }
                if self.value == 0 {
                    return Err(WireError::InvalidWindow);
                }
            }
            FrameKind::Close => {
                require_flow(self.flow_id)?;
                if self.code > CLOSE_RESET || self.value != 0 {
                    return Err(WireError::InvalidClose);
                }
            }
        }
        Ok(())
    }
}

fn require_flow(flow_id: FlowId) -> Result<(), WireError> {
    if flow_id == 0 {
        Err(WireError::InvalidFlowId)
    } else {
        Ok(())
    }
}

pub(super) fn encode_header(header: FrameHeader) -> Result<[u8; HEADER_LEN], WireError> {
    header.validate()?;
    let mut output = [0; HEADER_LEN];
    output[0] = header.kind as u8;
    output[1] = header.code;
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
        code: input[1],
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
    ReservedCode,
    InvalidFlowId,
    InvalidData,
    InvalidWindow,
    InvalidClose,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderLength(length) => {
                write!(formatter, "invalid header length: {length}")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown frame kind: {kind}"),
            Self::ValueTooLarge => formatter.write_str("frame value exceeds u16"),
            Self::ReservedCode => formatter.write_str("reserved frame code is non-zero"),
            Self::InvalidFlowId => formatter.write_str("invalid zero flow ID"),
            Self::InvalidData => formatter.write_str("DATA payload must be non-empty"),
            Self::InvalidWindow => formatter.write_str("WINDOW credit must be non-zero"),
            Self::InvalidClose => formatter.write_str("invalid CLOSE code or value"),
        }
    }
}

impl Error for WireError {}

#[cfg(test)]
#[path = "../tests/mux/wire.rs"]
mod tests;
