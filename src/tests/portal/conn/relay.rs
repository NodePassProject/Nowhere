// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Relay path and lifecycle wording tests.

use super::*;

fn symmetric_exchange_path(
    carrier: Carrier,
    peer: &str,
    local: &str,
    target_local: &str,
    target: &str,
) -> String {
    format!(
        "UP[{}] {peer} -> {local} -> {target_local} -> {target} | DOWN[{}] {target} -> {target_local} -> {local} -> {peer}",
        carrier_name(carrier),
        carrier_name(carrier),
    )
}

#[test]
fn paired_path_contains_both_carriers_and_both_client_links() {
    let uplink = LinkPath {
        version: crate::protocol::ProtocolVersion::V2,
        peer: "198.51.100.1:1000".into(),
        local: "192.0.2.1:2077".into(),
    };
    let downlink = LinkPath {
        version: crate::protocol::ProtocolVersion::V2,
        peer: "[2001:db8::2]:2000".into(),
        local: "[2001:db8::1]:2077".into(),
    };
    assert_eq!(
        paired_exchange_path(
            Carrier::TlsTcp,
            &uplink,
            "192.0.2.1:3000",
            "target.test:443",
            Carrier::Quic,
            &downlink,
        ),
        "UP[TCP] 198.51.100.1:1000 -> 192.0.2.1:2077 -> 192.0.2.1:3000 -> target.test:443 | DOWN[UDP] target.test:443 -> 192.0.2.1:3000 -> [2001:db8::1]:2077 -> [2001:db8::2]:2000"
    );
}

#[test]
fn symmetric_path_uses_the_same_carrier_prefix() {
    assert_eq!(
        symmetric_exchange_path(
            Carrier::Quic,
            "198.51.100.1:1000",
            "192.0.2.1:2077",
            "192.0.2.1:3000",
            "target.test:443",
        ),
        "UP[UDP] 198.51.100.1:1000 -> 192.0.2.1:2077 -> 192.0.2.1:3000 -> target.test:443 | DOWN[UDP] target.test:443 -> 192.0.2.1:3000 -> 192.0.2.1:2077 -> 198.51.100.1:1000"
    );
}

#[test]
fn lifecycle_terms_match_transport_contract() {
    assert_eq!(TCP_EXCHANGE_STARTING, "exchange starting");
    assert_eq!(TCP_EXCHANGE_COMPLETE, "exchange complete");
    assert_eq!(UDP_TRANSFER_STARTING, "transfer starting");
    assert_eq!(UDP_TRANSFER_COMPLETE, "transfer complete");
}
