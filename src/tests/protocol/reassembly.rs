// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded fragment reassembly, ownership, expiry, and eviction tests.

use crate::protocol::MAX_FLOW_ID;
use crate::protocol::datagram::{OwnedUdpFrame, decode_udp_frame_owned};
use crate::protocol::test_support::encode_udp_data_fragments;

use super::*;

#[test]
fn invalid_reassembly_id_cannot_reserve_resources() {
    let mut reassembler = DatagramReassembler::<()>::new(ReassemblyConfig::default());
    let fragment = OwnedUdpFragment {
        packet_id: 1,
        fragment_index: 0,
        fragment_count: 2,
        total_len: 2,
        payload: Bytes::from_static(b"a"),
    };
    for id in [0, MAX_FLOW_ID + 1, u32::MAX] {
        assert!(matches!(
            reassembler.push_with(id, fragment.clone(), Instant::now(), |_| panic!(
                "invalid ID reserved resources"
            )),
            ReassemblyOutcome::Dropped(_)
        ));
        assert_eq!(reassembler.slot_count(), 0);
        assert_eq!(reassembler.reserved_bytes(), 0);
    }
}

#[test]
fn reassembler_completes_out_of_order_and_ignores_identical_duplicates() {
    let frames = encode_udp_data_fragments(3, 4, &[0x33; 100], 64).unwrap();
    let now = Instant::now();
    let mut reassembler = DatagramReassembler::default();
    let last_source = Bytes::from(frames[1].clone());
    let last_source_owner = last_source.clone();
    let (_, last) = owned_fragment(last_source);
    let last_payload_ptr = last.payload.as_ptr();
    assert_eq!(
        reassembler.push(3, last.clone(), now),
        ReassemblyOutcome::Pending {
            evicted_partial: false
        }
    );
    let retained = reassembler
        .slots
        .values()
        .next()
        .and_then(|slot| slot.fragments[1].as_ref())
        .expect("last fragment retained");
    assert_eq!(retained.as_ptr(), last_payload_ptr);
    drop(last_source_owner);
    assert_eq!(
        reassembler.push(3, last, now),
        ReassemblyOutcome::Pending {
            evicted_partial: false
        }
    );
    let (_, first) = owned_fragment(Bytes::from(frames[0].clone()));
    let ReassemblyOutcome::Complete { payload, .. } = reassembler.push(3, first, now) else {
        panic!("expected complete packet");
    };
    assert_eq!(payload.as_ref(), vec![0x33; 100]);
    assert_eq!(reassembler.slot_count(), 0);
    assert_eq!(reassembler.reserved_bytes(), 0);
}

#[test]
fn reassembler_drops_conflicting_duplicate_and_metadata_for_the_whole_packet() {
    let now = Instant::now();
    let original = OwnedUdpFragment {
        packet_id: 7,
        fragment_index: 0,
        fragment_count: 2,
        total_len: 2,
        payload: Bytes::from_static(b"a"),
    };
    let mut reassembler = DatagramReassembler::default();
    assert!(matches!(
        reassembler.push(1, original.clone(), now),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(
        reassembler.push(
            1,
            OwnedUdpFragment {
                payload: Bytes::from_static(b"b"),
                ..original.clone()
            },
            now
        ),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::DuplicateConflict)
    );
    assert_eq!(reassembler.slot_count(), 0);

    assert!(matches!(
        reassembler.push(1, original.clone(), now),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(
        reassembler.push(
            1,
            OwnedUdpFragment {
                fragment_count: 3,
                total_len: 3,
                ..original
            },
            now
        ),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::MetadataConflict)
    );
    assert_eq!(reassembler.slot_count(), 0);
}

#[test]
fn reassembler_enforces_declared_length_byte_budget_slot_cap_timeout_and_flow_removal() {
    let now = Instant::now();
    let config = ReassemblyConfig {
        max_slots: 1,
        max_bytes: 4,
        ttl: Duration::from_secs(1),
    };
    let first = OwnedUdpFragment {
        packet_id: 1,
        fragment_index: 0,
        fragment_count: 2,
        total_len: 4,
        payload: Bytes::from_static(b"aa"),
    };
    let mut reassembler = DatagramReassembler::<()>::new(config);
    assert!(matches!(
        reassembler.push(1, first.clone(), now),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(reassembler.reserved_bytes(), 4);

    let second_flow = OwnedUdpFragment {
        packet_id: 2,
        ..first.clone()
    };
    assert_eq!(
        reassembler.push(2, second_flow, now + Duration::from_millis(1)),
        ReassemblyOutcome::Pending {
            evicted_partial: true
        }
    );
    assert_eq!(reassembler.slot_count(), 1);
    reassembler.remove_flow(2);
    assert_eq!(reassembler.reserved_bytes(), 0);

    let too_large = OwnedUdpFragment {
        total_len: 5,
        ..first.clone()
    };
    assert_eq!(
        reassembler.push(3, too_large, now),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::ByteLimit)
    );

    assert!(matches!(
        reassembler.push(1, first, now),
        ReassemblyOutcome::Pending { .. }
    ));
    assert!(reassembler.expire(now + Duration::from_secs(2)));
    assert_eq!(reassembler.slot_count(), 0);
}

#[test]
fn reassembler_rejects_inconsistent_final_length() {
    let now = Instant::now();
    let first = OwnedUdpFragment {
        packet_id: 9,
        fragment_index: 0,
        fragment_count: 2,
        total_len: 3,
        payload: Bytes::from_static(b"a"),
    };
    let second = OwnedUdpFragment {
        fragment_index: 1,
        payload: Bytes::from_static(b"b"),
        ..first.clone()
    };
    let mut reassembler = DatagramReassembler::default();
    assert!(matches!(
        reassembler.push(1, first, now),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(
        reassembler.push(1, second, now),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::InvalidLength)
    );
}

#[test]
fn reassembler_rejects_forged_metadata_without_panicking() {
    let now = Instant::now();
    let mut reassembler = DatagramReassembler::default();
    for (flow_id, fragment) in [
        (
            0,
            OwnedUdpFragment {
                packet_id: 1,
                fragment_index: 0,
                fragment_count: 2,
                total_len: 2,
                payload: Bytes::from_static(b"a"),
            },
        ),
        (
            1,
            OwnedUdpFragment {
                packet_id: 0,
                fragment_index: 0,
                fragment_count: 2,
                total_len: 2,
                payload: Bytes::from_static(b"a"),
            },
        ),
        (
            1,
            OwnedUdpFragment {
                packet_id: 1,
                fragment_index: 2,
                fragment_count: 2,
                total_len: 2,
                payload: Bytes::from_static(b"a"),
            },
        ),
        (
            1,
            OwnedUdpFragment {
                packet_id: 1,
                fragment_index: 0,
                fragment_count: 0,
                total_len: 0,
                payload: Bytes::new(),
            },
        ),
    ] {
        assert_eq!(
            reassembler.push(flow_id, fragment, now),
            ReassemblyOutcome::Dropped(ReassemblyDropReason::InvalidLength)
        );
    }
}

fn owned_fragment(frame: Bytes) -> (FlowId, OwnedUdpFragment) {
    let OwnedUdpFrame::Fragment { flow_id, fragment } = decode_udp_frame_owned(frame).unwrap()
    else {
        panic!("expected owned fragment");
    };
    (flow_id, fragment)
}
