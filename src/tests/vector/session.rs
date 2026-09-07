// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

#[test]
fn transport_flow_control_matches_authenticated_portal_capacity() {
    let flow_control = crate::transport::transport_flow_control().unwrap();
    assert!(flow_control.stream_receive_window <= flow_control.connection_receive_window);
    assert!(flow_control.send_window >= u64::from(flow_control.stream_receive_window));
}
