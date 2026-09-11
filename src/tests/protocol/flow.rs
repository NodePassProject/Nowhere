// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::io::AsyncReadExt;

use super::*;

#[test]
fn fixed_vectors_pack_flags_and_network_order_id() {
    assert_eq!(
        encode_flow_header(FlowHeader {
            role: FlowRole::Duplex,
            flow_id: 0x0102_0304,
            kind: FlowKind::Tcp,
            uplink: Carrier::TlsTcp,
            downlink: Carrier::TlsTcp,
            hops: 0,
        })
        .unwrap(),
        [0x00, 1, 2, 3, 4]
    );
    assert_eq!(
        encode_flow_header(FlowHeader {
            role: FlowRole::Open,
            flow_id: 0x1122_3344,
            kind: FlowKind::Udp,
            uplink: Carrier::Quic,
            downlink: Carrier::TlsTcp,
            hops: 0,
        })
        .unwrap(),
        [0x0d, 0x11, 0x22, 0x33, 0x44]
    );
    assert_eq!(
        encode_flow_header(FlowHeader {
            role: FlowRole::Attach,
            flow_id: 7,
            kind: FlowKind::Udp,
            uplink: Carrier::TlsTcp,
            downlink: Carrier::Quic,
            hops: 0,
        })
        .unwrap(),
        [0x16, 0, 0, 0, 7]
    );
}

#[test]
fn every_valid_role_kind_and_carrier_combination_round_trips() {
    for kind in [FlowKind::Tcp, FlowKind::Udp] {
        for carrier in [Carrier::TlsTcp, Carrier::Quic] {
            round_trip(FlowHeader {
                role: FlowRole::Duplex,
                flow_id: 1,
                kind,
                uplink: carrier,
                downlink: carrier,
                hops: MAX_PORTAL_HOPS,
            });
        }
        for role in [FlowRole::Open, FlowRole::Attach] {
            round_trip(FlowHeader {
                role,
                flow_id: MAX_FLOW_ID,
                kind,
                uplink: Carrier::TlsTcp,
                downlink: Carrier::Quic,
                hops: 3,
            });
            round_trip(FlowHeader {
                role,
                flow_id: 2,
                kind,
                uplink: Carrier::Quic,
                downlink: Carrier::TlsTcp,
                hops: 6,
            });
        }
    }
}

#[test]
fn semantic_validation_rejects_out_of_range_ids_and_duplex_carrier_conflicts() {
    let duplex = FlowHeader {
        role: FlowRole::Duplex,
        flow_id: 1,
        kind: FlowKind::Tcp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
        hops: 0,
    };
    assert!(encode_flow_header(duplex).is_err());

    let split = FlowHeader {
        role: FlowRole::Open,
        flow_id: 1,
        kind: FlowKind::Udp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::TlsTcp,
        hops: 0,
    };
    assert!(encode_flow_header(split).is_ok());

    let zero = FlowHeader {
        role: FlowRole::Duplex,
        flow_id: 0,
        kind: FlowKind::Tcp,
        uplink: Carrier::Quic,
        downlink: Carrier::Quic,
        hops: 0,
    };
    assert!(encode_flow_header(zero).is_err());

    assert!(
        encode_flow_header(FlowHeader {
            flow_id: MAX_FLOW_ID + 1,
            ..zero
        })
        .is_err()
    );
}

#[test]
fn current_lane_must_match_the_role_direction() {
    let open = FlowHeader {
        role: FlowRole::Open,
        flow_id: 1,
        kind: FlowKind::Tcp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
        hops: 0,
    };
    assert!(open.validate_on(Carrier::TlsTcp).is_ok());
    assert!(open.validate_on(Carrier::Quic).is_err());

    let attach = FlowHeader {
        role: FlowRole::Attach,
        ..open
    };
    assert!(attach.validate_on(Carrier::Quic).is_ok());
    assert!(attach.validate_on(Carrier::TlsTcp).is_err());
    assert!(open.carries_target());
    assert!(!attach.carries_target());
}

#[test]
fn decoder_rejects_invalid_ids_lengths_and_semantics() {
    for input in [&[][..], &[0; 4], &[0; 6]] {
        assert!(decode_flow_header(input).is_err());
    }
    assert!(decode_flow_header(&[0, 0, 0, 0, 0]).is_err());
    for id in [MAX_FLOW_ID + 1, u32::MAX] {
        let mut bytes = [0; FLOW_HEADER_LEN];
        bytes[1..].copy_from_slice(&id.to_be_bytes());
        assert!(decode_flow_header(&bytes).is_err());
    }

    let valid = [0, 0, 0, 0, 1];
    let mut invalid_role = valid;
    invalid_role[0] = 3;
    assert!(decode_flow_header(&invalid_role).is_err());

    let mut bad_duplex = valid;
    bad_duplex[0] = 0x10;
    assert!(decode_flow_header(&bad_duplex).is_err());
}

#[tokio::test]
async fn async_reader_consumes_only_five_bytes() {
    let header = FlowHeader {
        role: FlowRole::Duplex,
        flow_id: 9,
        kind: FlowKind::Udp,
        uplink: Carrier::Quic,
        downlink: Carrier::Quic,
        hops: 7,
    };
    let mut input = encode_flow_header(header).unwrap().to_vec();
    input.extend_from_slice(b"payload");
    let mut input = input.as_slice();
    assert_eq!(read_flow_header(&mut input).await.unwrap(), header);
    let mut payload = Vec::new();
    input.read_to_end(&mut payload).await.unwrap();
    assert_eq!(payload, b"payload");
}

#[test]
fn all_hop_budgets_fit_the_packed_header_budget() {
    for hops in 0..=MAX_PORTAL_HOPS {
        let header = FlowHeader {
            role: FlowRole::Duplex,
            flow_id: 42,
            kind: FlowKind::Tcp,
            uplink: Carrier::TlsTcp,
            downlink: Carrier::TlsTcp,
            hops,
        };
        let encoded = encode_flow_header(header).unwrap();
        assert_eq!(encoded[0] >> 5, hops);
        assert_eq!(decode_flow_header(&encoded).unwrap(), header);
    }
}

fn round_trip(header: FlowHeader) {
    let encoded = encode_flow_header(header).unwrap();
    assert_eq!(encoded.len(), FLOW_HEADER_LEN);
    assert_eq!(decode_flow_header(&encoded).unwrap(), header);
}

#[test]
fn both_public_encoders_reject_invalid_ids() {
    for flow_id in [0, MAX_FLOW_ID + 1, u32::MAX] {
        let header = FlowHeader {
            role: FlowRole::Duplex,
            flow_id,
            kind: FlowKind::Tcp,
            uplink: Carrier::TlsTcp,
            downlink: Carrier::TlsTcp,
            hops: 0,
        };
        assert!(write_flow_header(header).is_err());
        assert!(encode_flow_header(header).is_err());
    }
}
