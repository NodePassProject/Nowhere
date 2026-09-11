// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Network-mode parsing for TCP, UDP, or mixed service.

use std::fmt;

/// Portal listener mode derived from declared carrier endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkMode {
    Mix,
    Tcp,
    Udp,
}

impl NetworkMode {
    pub(super) fn from_carriers(tcp: bool, udp: bool) -> Self {
        match (tcp, udp) {
            (true, true) => Self::Mix,
            (true, false) => Self::Tcp,
            (false, true) => Self::Udp,
            (false, false) => unreachable!("endpoint parser requires at least one carrier"),
        }
    }

    /// Returns whether this mode should accept TLS/TCP connections.
    pub(super) fn listens_tcp(self) -> bool {
        matches!(self, Self::Mix | Self::Tcp)
    }

    /// Returns whether this mode should accept QUIC/UDP connections.
    pub(super) fn listens_udp(self) -> bool {
        matches!(self, Self::Mix | Self::Udp)
    }

    /// Returns the numeric mode reported in checkpoint events.
    pub(super) fn checkpoint_value(self) -> u8 {
        match self {
            Self::Mix => 0,
            Self::Tcp => 1,
            Self::Udp => 2,
        }
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mix => formatter.write_str("mix"),
            Self::Tcp => formatter.write_str("tcp"),
            Self::Udp => formatter.write_str("udp"),
        }
    }
}
