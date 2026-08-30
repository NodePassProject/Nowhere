// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Data-plane protocol version negotiated through TLS ALPN.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// ALPN used by Nowhere 1.x peers with their default configuration.
pub const V1_ALPN: &[u8] = b"now/1";
/// Fixed ALPN for Nowhere 2.x peers.
pub const V2_ALPN: &[u8] = b"nw2";
/// Supported ALPNs in server-preference order.
pub const SUPPORTED_ALPNS: [&[u8]; 2] = [V2_ALPN, V1_ALPN];

/// Data-plane protocol version selected for one authenticated carrier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolVersion {
    V1,
    V2,
}

impl ProtocolVersion {
    /// Classifies an ALPN selected by TLS or QUIC.
    pub fn from_alpn(alpn: Option<&[u8]>) -> Result<Self> {
        match alpn {
            Some(V2_ALPN) => Ok(Self::V2),
            Some(V1_ALPN) => Ok(Self::V1),
            Some(_) => bail!("protocol::ProtocolVersion: unsupported negotiated ALPN"),
            None => bail!("protocol::ProtocolVersion: peer did not negotiate ALPN"),
        }
    }

    /// Stable short label used by local telemetry and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
#[path = "../tests/protocol/version.rs"]
mod tests;
