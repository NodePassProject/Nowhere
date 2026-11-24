// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared QUIC flow-control budgets tests.

use super::*;

#[test]
fn profiles_select_expected_window_budgets() {
    for (name, connection_mib, send_mib) in [
        ("memory", 16, 8),
        ("balanced", 16, 16),
        ("throughput", 32, 32),
    ] {
        let profile = parse_transport_profile(Some(name)).unwrap();
        assert_eq!(profile.stream_receive_window, 4 * MIB, "{name}");
        assert_eq!(
            profile.connection_receive_window,
            connection_mib * MIB,
            "{name}"
        );
        assert_eq!(profile.send_window, send_mib * u64::from(MIB), "{name}");
    }
}

#[test]
fn throughput_is_the_default_profile() {
    assert_eq!(
        parse_transport_profile(None).unwrap(),
        TransportFlowControl::THROUGHPUT
    );
}

#[test]
fn rejects_unknown_profiles() {
    assert!(parse_transport_profile(Some("tiny")).is_err());
}
