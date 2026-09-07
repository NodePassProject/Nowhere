// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

#[test]
fn profiles_keep_streams_within_connection_limits() {
    for profile in [
        parse_transport_profile(Some("memory")).unwrap(),
        parse_transport_profile(Some("balanced")).unwrap(),
        parse_transport_profile(Some("throughput")).unwrap(),
    ] {
        assert!(profile.stream_receive_window <= profile.connection_receive_window);
        assert!(u64::from(profile.connection_receive_window) <= profile.send_window * 2);
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
