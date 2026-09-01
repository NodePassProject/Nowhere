// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Stateless per-flow resolution from configured carrier policy to wire carriers.

use crate::protocol::{Carrier, FlowId, SessionId};

use super::config::CarrierMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolvedRoute {
    pub(super) uplink: Carrier,
    pub(super) downlink: Carrier,
}

impl ResolvedRoute {
    pub(super) const fn split(self) -> bool {
        self.uplink as u8 != self.downlink as u8
    }

    pub(super) fn label(self) -> &'static str {
        match (self.uplink, self.downlink) {
            (Carrier::TlsTcp, Carrier::TlsTcp) => "TT",
            (Carrier::TlsTcp, Carrier::Quic) => "TQ",
            (Carrier::Quic, Carrier::TlsTcp) => "QT",
            (Carrier::Quic, Carrier::Quic) => "QQ",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RoutePlan {
    pub(super) primary: ResolvedRoute,
    pub(super) fallback: Option<ResolvedRoute>,
}

pub(super) fn seed_from_session(session_id: SessionId) -> u64 {
    let low = u64::from_le_bytes(session_id[..8].try_into().expect("session ID low half"));
    let high = u64::from_le_bytes(session_id[8..].try_into().expect("session ID high half"));
    low ^ high.rotate_left(32)
}

pub(super) fn plan_route(
    up: CarrierMode,
    down: CarrierMode,
    seed: u64,
    flow_id: FlowId,
) -> RoutePlan {
    if !up.is_mix() && !down.is_mix() {
        return RoutePlan {
            primary: resolve_with_choice(up, down, false),
            fallback: None,
        };
    }
    let choose_quic = splitmix64(seed ^ u64::from(flow_id)) & 1 != 0;
    RoutePlan {
        primary: resolve_with_choice(up, down, choose_quic),
        fallback: Some(resolve_with_choice(up, down, !choose_quic)),
    }
}

fn resolve_with_choice(up: CarrierMode, down: CarrierMode, choose_quic: bool) -> ResolvedRoute {
    let selected = if choose_quic {
        Carrier::Quic
    } else {
        Carrier::TlsTcp
    };
    let fixed = |mode| match mode {
        CarrierMode::Tcp => Carrier::TlsTcp,
        CarrierMode::Udp => Carrier::Quic,
        CarrierMode::Mix => selected,
    };
    ResolvedRoute {
        uplink: fixed(up),
        downlink: fixed(down),
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
#[path = "../tests/vector/route.rs"]
mod tests;
