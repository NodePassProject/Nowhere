// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal reservation adapter tests for the shared UDP reassembler.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::protocol::{
    DatagramReassembler, OwnedUdpFragment, ReassemblyConfig, ReassemblyDropReason,
    ReassemblyOutcome,
};
use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::*;

fn fragment(
    packet_id: u32,
    fragment_index: u8,
    fragment_count: u8,
    total_len: u16,
    payload: &'static [u8],
) -> OwnedUdpFragment {
    OwnedUdpFragment {
        packet_id,
        fragment_index,
        fragment_count,
        total_len,
        payload: Bytes::from_static(payload),
    }
}

fn reassembler() -> DatagramReassembler<OwnedSemaphorePermit> {
    DatagramReassembler::new(ReassemblyConfig::default())
}

fn push(
    reassembler: &mut DatagramReassembler<OwnedSemaphorePermit>,
    flow_id: u32,
    fragment: OwnedUdpFragment,
    now: Instant,
    budget: &Arc<Semaphore>,
) -> ReassemblyOutcome<OwnedSemaphorePermit> {
    let budget = budget.clone();
    reassembler.push_with(flow_id, fragment, now, move |packet_len| {
        reserve_packet_budget(budget, usize::from(packet_len))
    })
}

#[test]
fn partial_reservation_moves_to_complete_datagram_until_drop() {
    let budget = Arc::new(Semaphore::new(32));
    let now = Instant::now();
    let mut reassembler = reassembler();

    assert!(matches!(
        push(
            &mut reassembler,
            7,
            fragment(1, 1, 2, 6, b"def"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(budget.available_permits(), 26);

    let (payload, reservation) = match push(
        &mut reassembler,
        7,
        fragment(1, 0, 2, 6, b"abc"),
        now,
        &budget,
    ) {
        ReassemblyOutcome::Complete {
            payload,
            reservation,
            ..
        } => (payload, reservation),
        _ => panic!("packet should complete"),
    };
    assert_eq!(payload, b"abcdef"[..]);
    assert_eq!(budget.available_permits(), 26);

    let datagram = QueuedDatagram::new(payload, reservation);
    assert_eq!(datagram.payload, b"abcdef"[..]);
    assert_eq!(budget.available_permits(), 26);
    drop(datagram);
    assert_eq!(budget.available_permits(), 32);
}

#[test]
fn empty_unfragmented_packet_holds_one_budget_unit() {
    let budget = Arc::new(Semaphore::new(1));
    let permit = reserve_packet_budget(budget.clone(), 0).unwrap();
    let datagram = QueuedDatagram::new(Bytes::new(), permit);
    assert!(datagram.payload.is_empty());
    assert_eq!(budget.available_permits(), 0);
    drop(datagram);
    assert_eq!(budget.available_permits(), 1);
}

#[test]
fn packet_budget_rejects_new_slot_without_leaking_permits() {
    let budget = Arc::new(Semaphore::new(5));
    let mut reassembler = reassembler();
    assert!(matches!(
        push(
            &mut reassembler,
            9,
            fragment(3, 0, 2, 6, b"abc"),
            Instant::now(),
            &budget,
        ),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::ByteLimit)
    ));
    assert_eq!(reassembler.slot_count(), 0);
    assert_eq!(budget.available_permits(), 5);
}

#[test]
fn failed_replacement_admission_preserves_the_existing_partial_packet() {
    let budget = Arc::new(Semaphore::new(6));
    let now = Instant::now();
    let mut reassembler = DatagramReassembler::new(ReassemblyConfig {
        max_slots: 1,
        max_bytes: 12,
        ..ReassemblyConfig::default()
    });
    assert!(matches!(
        push(
            &mut reassembler,
            9,
            fragment(3, 0, 2, 6, b"abc"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(budget.available_permits(), 0);

    assert!(matches!(
        push(
            &mut reassembler,
            10,
            fragment(4, 0, 2, 6, b"xyz"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::ByteLimit)
    ));
    assert_eq!(reassembler.slot_count(), 1);
    assert_eq!(reassembler.reserved_bytes(), 6);

    let (payload, reservation) = match push(
        &mut reassembler,
        9,
        fragment(3, 1, 2, 6, b"def"),
        now,
        &budget,
    ) {
        ReassemblyOutcome::Complete {
            payload,
            reservation,
            ..
        } => (payload, reservation),
        _ => panic!("existing partial packet must survive failed replacement admission"),
    };
    assert_eq!(payload, b"abcdef"[..]);
    drop(reservation);
    assert_eq!(budget.available_permits(), 6);
}

#[test]
fn remove_flow_releases_only_that_flows_partial_reservations() {
    let budget = Arc::new(Semaphore::new(20));
    let now = Instant::now();
    let mut reassembler = reassembler();
    for (flow_id, packet_id) in [(10, 1), (11, 2)] {
        assert!(matches!(
            push(
                &mut reassembler,
                flow_id,
                fragment(packet_id, 0, 2, 6, b"abc"),
                now,
                &budget,
            ),
            ReassemblyOutcome::Pending { .. }
        ));
    }
    assert_eq!(budget.available_permits(), 8);

    reassembler.remove_flow(10);
    assert_eq!(budget.available_permits(), 14);

    let (payload, reservation) = match push(
        &mut reassembler,
        11,
        fragment(2, 1, 2, 6, b"def"),
        now,
        &budget,
    ) {
        ReassemblyOutcome::Complete {
            payload,
            reservation,
            ..
        } => (payload, reservation),
        _ => panic!("unremoved flow should still complete"),
    };
    let datagram = QueuedDatagram::new(payload, reservation);
    assert_eq!(datagram.payload, b"abcdef"[..]);
    assert_eq!(budget.available_permits(), 14);
    drop(datagram);
    assert_eq!(budget.available_permits(), 20);
}

#[test]
fn expiry_releases_partial_reservation_after_exact_ttl_boundary() {
    let budget = Arc::new(Semaphore::new(8));
    let ttl = Duration::from_secs(10);
    let now = Instant::now();
    let mut reassembler = DatagramReassembler::new(ReassemblyConfig {
        ttl,
        ..ReassemblyConfig::default()
    });
    assert!(matches!(
        push(
            &mut reassembler,
            12,
            fragment(3, 0, 2, 6, b"abc"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(budget.available_permits(), 2);

    assert!(!reassembler.expire(now + ttl));
    assert_eq!(budget.available_permits(), 2);

    assert!(reassembler.expire(now + ttl + Duration::from_nanos(1)));
    assert_eq!(budget.available_permits(), 8);
}

#[test]
fn conflicting_duplicate_releases_partial_reservation() {
    let budget = Arc::new(Semaphore::new(6));
    let now = Instant::now();
    let mut reassembler = reassembler();
    assert!(matches!(
        push(
            &mut reassembler,
            13,
            fragment(4, 0, 2, 6, b"abc"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(budget.available_permits(), 0);
    assert!(matches!(
        push(
            &mut reassembler,
            13,
            fragment(4, 0, 2, 6, b"xyz"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::DuplicateConflict)
    ));
    assert_eq!(reassembler.slot_count(), 0);
    assert_eq!(budget.available_permits(), 6);
}

#[test]
fn conflicting_metadata_releases_partial_reservation() {
    let budget = Arc::new(Semaphore::new(8));
    let now = Instant::now();
    let mut reassembler = reassembler();
    assert!(matches!(
        push(
            &mut reassembler,
            15,
            fragment(9, 0, 2, 6, b"abc"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Pending { .. }
    ));
    assert_eq!(budget.available_permits(), 2);
    assert!(matches!(
        push(
            &mut reassembler,
            15,
            fragment(9, 1, 2, 8, b"def"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::MetadataConflict)
    ));
    assert_eq!(reassembler.slot_count(), 0);
    assert_eq!(budget.available_permits(), 8);
}

#[test]
fn invalid_cumulative_length_releases_partial_reservation() {
    let budget = Arc::new(Semaphore::new(6));
    let now = Instant::now();
    let mut reassembler = reassembler();
    for fragment_index in 0..2 {
        assert!(matches!(
            push(
                &mut reassembler,
                14,
                fragment(5, fragment_index, 3, 6, b"abc"),
                now,
                &budget,
            ),
            ReassemblyOutcome::Pending { .. }
        ));
    }
    assert_eq!(budget.available_permits(), 0);
    assert!(matches!(
        push(
            &mut reassembler,
            14,
            fragment(5, 2, 3, 6, b"abc"),
            now,
            &budget,
        ),
        ReassemblyOutcome::Dropped(ReassemblyDropReason::InvalidLength)
    ));
    assert_eq!(reassembler.slot_count(), 0);
    assert_eq!(budget.available_permits(), 6);
}
