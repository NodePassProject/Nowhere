// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared QUIC flow-control budgets for every protocol version and Mux setting.

use anyhow::{Result, bail};

const MIB: u32 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuicFlowControl {
    pub(crate) stream_receive_window: u32,
    pub(crate) connection_receive_window: u32,
    pub(crate) send_window: u64,
}

impl QuicFlowControl {
    const MEMORY: Self = Self::new(4, 8, 8);
    const BALANCED: Self = Self::new(8, 16, 16);
    const THROUGHPUT: Self = Self::new(16, 32, 32);

    const fn new(stream_mib: u32, connection_mib: u32, send_mib: u64) -> Self {
        Self {
            stream_receive_window: stream_mib * MIB,
            connection_receive_window: connection_mib * MIB,
            send_window: send_mib * MIB as u64,
        }
    }
}

/// Reads the process-wide QUIC flow-control profile.
///
/// The throughput profile preserves the established high-BDP values; memory
/// and balanced remain available through the environment override.
pub(crate) fn quic_flow_control() -> Result<QuicFlowControl> {
    parse_quic_profile(std::env::var("NOW_QUIC_MEMORY_PROFILE").ok().as_deref())
}

fn parse_quic_profile(value: Option<&str>) -> Result<QuicFlowControl> {
    match value.unwrap_or("throughput") {
        "memory" => Ok(QuicFlowControl::MEMORY),
        "balanced" => Ok(QuicFlowControl::BALANCED),
        "throughput" => Ok(QuicFlowControl::THROUGHPUT),
        _ => bail!("NOW_QUIC_MEMORY_PROFILE must be memory, balanced, or throughput"),
    }
}

#[cfg(test)]
#[path = "../tests/transport/quic.rs"]
mod tests;
