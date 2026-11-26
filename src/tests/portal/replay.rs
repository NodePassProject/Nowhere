// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Replay window reference-model, FIFO collision, concurrency and fixed-memory regressions.

use std::collections::HashSet;
use std::sync::{Arc, Barrier};

use super::*;

fn authentication(identity: u64, counter: u64) -> AuthenticatedPrelude {
    AuthenticatedPrelude { identity, counter }
}

#[test]
fn first_duplicate_out_of_order_and_invalid_counters() {
    let replay = ReplayProtection::new();
    assert!(!replay.precheck(authentication(1, 0)));
    assert!(!replay.commit(authentication(1, 0)));
    assert!(!replay.commit(authentication(1, 1 << 48)));
    assert!(replay.precheck(authentication(1, 100)));
    assert!(replay.state.lock().unwrap().entries.is_empty());
    assert!(replay.commit(authentication(1, 100)));
    assert_eq!(replay.state.lock().unwrap().entries.len(), 1);
    assert!(!replay.precheck(authentication(1, 100)));
    assert!(!replay.commit(authentication(1, 100)));
    assert!(replay.commit(authentication(1, 99)));
    assert!(replay.commit(authentication(1, 101)));
    assert!(!replay.commit(authentication(1, 99)));
    assert!(replay.commit(authentication(0, 1)));
    assert!(!replay.commit(authentication(0, 1)));
}

#[test]
fn every_word_and_window_shift_matches_reference_model() {
    for advance in [1, 2, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 100_000] {
        let replay = ReplayProtection::new();
        for counter in [1024, 1023, 961, 960, 959, 897, 896, 1] {
            assert!(replay.commit(authentication(1, counter)));
        }
        assert!(replay.commit(authentication(1, 1024 + advance)));
        for counter in (1..1024 + advance).rev().take(1100) {
            let used = [1024, 1023, 961, 960, 959, 897, 896, 1].contains(&counter);
            let expected = 1024 + advance - counter < WINDOW as u64 && !used;
            assert_eq!(
                replay.precheck(authentication(1, counter)),
                expected,
                "advance={advance},counter={counter}"
            );
            assert_eq!(replay.commit(authentication(1, counter)), expected);
        }
    }
}

#[test]
fn every_window_advance_matches_individual_bit_reference() {
    let bitmap =
        std::array::from_fn(|index| 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(index as u64 + 1) | 1);
    for advance in 1..=WINDOW * 2 {
        let mut entry = Entry {
            identity: 1,
            highest: (1 << 48) - 1 - (WINDOW * 2) as u64,
            bitmap,
            next: EMPTY,
        };
        let counter = entry.highest + advance as u64;
        entry.mark(counter);
        assert_eq!(entry.highest, counter);
        for offset in 0..WINDOW {
            let expected = offset == 0
                || (offset >= advance
                    && bitmap[(offset - advance) / 64] & (1 << ((offset - advance) % 64)) != 0);
            assert_eq!(entry.accepts(counter - offset as u64), !expected);
        }
        assert!(!entry.accepts(counter - WINDOW as u64));
    }
}

#[test]
fn deterministic_random_sequence_matches_set_reference() {
    let replay = ReplayProtection::new();
    let mut highest = 0;
    let mut used = HashSet::new();
    let mut random = 0x0fed_cba9_8765_4321u64;
    for _ in 0..50_000 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let counter = match random & 7 {
            0 => highest + 1 + (random >> 32) % 2048,
            1 => highest.saturating_sub(1024),
            2 => highest.saturating_sub(1023),
            _ => highest.saturating_sub((random >> 32) % 1200),
        };
        let expected = counter != 0
            && (counter > highest
                || (highest - counter < WINDOW as u64 && !used.contains(&counter)));
        assert_eq!(replay.precheck(authentication(42, counter)), expected);
        assert_eq!(replay.commit(authentication(42, counter)), expected);
        if expected {
            highest = highest.max(counter);
            used.insert(counter);
            used.retain(|counter| highest - counter < WINDOW as u64);
        }
    }
}

#[test]
fn capacity_fifo_and_repeated_rotation_keep_storage_fixed() {
    let replay = ReplayProtection::new();
    let (entries, capacity, buckets) = {
        let state = replay.state.lock().unwrap();
        assert!(state.entries.is_empty());
        assert!(state.entries.capacity() >= CAPACITY);
        (
            state.entries.as_ptr(),
            state.entries.capacity(),
            state.buckets.as_ptr(),
        )
    };
    for identity in 0..(CAPACITY - 1) as u64 {
        assert!(replay.commit(authentication(identity, 1)));
    }
    assert_eq!(replay.state.lock().unwrap().entries.len(), CAPACITY - 1);
    assert!(replay.commit(authentication((CAPACITY - 1) as u64, 1)));
    {
        let state = replay.state.lock().unwrap();
        assert_eq!(state.entries.len(), CAPACITY);
        assert_eq!(state.oldest, 0);
    }
    assert!(replay.commit(authentication(0, 2)));
    assert!(replay.commit(authentication(CAPACITY as u64, 1)));
    assert!(replay.precheck(authentication(0, 1)));
    assert!(!replay.precheck(authentication(1, 1)));
    assert!(replay.commit(authentication(0, 1)));
    assert!(replay.precheck(authentication(1, 1)));
    for identity in CAPACITY as u64 + 1..CAPACITY as u64 * 5 {
        assert!(replay.commit(authentication(identity, 1)));
    }
    let state = replay.state.lock().unwrap();
    assert_eq!(state.entries.len(), CAPACITY);
    assert_eq!(state.entries.capacity(), capacity);
    assert_eq!(state.buckets.len(), BUCKETS);
    assert_eq!(entries, state.entries.as_ptr());
    assert_eq!(buckets, state.buckets.as_ptr());
    for identity in CAPACITY as u64 * 4..CAPACITY as u64 * 5 {
        assert!(state.find(identity).is_some());
    }
}

#[test]
fn collisions_preserve_links_when_fifo_removes_middle_and_tail() {
    let replay = ReplayProtection::new();
    let colliding: Vec<_> = {
        let state = replay.state.lock().unwrap();
        (0..)
            .filter(|&identity| state.bucket(identity) == 0)
            .take(4)
            .collect()
    };
    for &identity in &colliding {
        assert!(replay.commit(authentication(identity, 1)));
    }
    {
        let mut state = replay.state.lock().unwrap();
        state.remove(1);
        state.remove(0);
        state.remove(3);
        assert!(state.find(colliding[1]).is_none());
        assert!(state.find(colliding[0]).is_none());
        assert!(state.find(colliding[3]).is_none());
        assert_eq!(state.find(colliding[2]), Some(2));
    }
}

#[test]
fn fifo_replacement_in_the_same_bucket_reuses_the_slot_without_a_self_link() {
    let replay = ReplayProtection::new();
    let (replacement, other_identities) = {
        let state = replay.state.lock().unwrap();
        let bucket = state.bucket(0);
        let replacement = (1..)
            .find(|&identity| state.bucket(identity) == bucket)
            .unwrap();
        let other_identities: Vec<_> = (1..)
            .filter(|&identity| state.bucket(identity) != bucket)
            .take(CAPACITY - 1)
            .collect();
        (replacement, other_identities)
    };
    assert!(replay.commit(authentication(0, 1)));
    for identity in other_identities {
        assert!(replay.commit(authentication(identity, 1)));
    }
    assert!(replay.commit(authentication(replacement, 1)));
    {
        let state = replay.state.lock().unwrap();
        assert_eq!(state.entries[0].next, EMPTY);
        assert_eq!(state.find(replacement), Some(0));
    }
    assert!(replay.precheck(authentication(0, 1)));
    assert!(!replay.commit(authentication(replacement, 1)));
}

#[test]
fn concurrent_duplicate_commit_has_exactly_one_winner_after_readonly_prechecks() {
    let replay = Arc::new(ReplayProtection::new());
    let barrier = Arc::new(Barrier::new(32));
    let workers: Vec<_> = (0..32)
        .map(|_| {
            let replay = replay.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                assert!(replay.precheck(authentication(1, 1)));
                barrier.wait();
                replay.commit(authentication(1, 1))
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn concurrent_out_of_order_window_accepts_each_counter_once() {
    let replay = Arc::new(ReplayProtection::new());
    assert!(replay.commit(authentication(7, 1024)));
    let workers: Vec<_> = (0..16)
        .map(|worker| {
            let replay = replay.clone();
            std::thread::spawn(move || {
                for counter in (1 + worker..1024).step_by(16) {
                    assert!(replay.commit(authentication(7, counter)));
                    assert!(!replay.commit(authentication(7, counter)));
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        replay.state.lock().unwrap().entries[0].bitmap,
        [u64::MAX; 16]
    );
}

#[test]
fn maximum_counter_and_new_instance_reset() {
    let maximum = (1 << 48) - 1;
    let replay = ReplayProtection::new();
    assert!(replay.commit(authentication(1, maximum)));
    assert!(replay.commit(authentication(1, maximum - 1023)));
    assert!(!replay.commit(authentication(1, maximum - 1024)));
    assert!(!replay.commit(authentication(1, maximum)));
    assert!(ReplayProtection::new().commit(authentication(1, maximum)));
}

#[test]
fn poisoned_state_fails_closed() {
    let replay = Arc::new(ReplayProtection::new());
    let worker = replay.clone();
    let _ = std::thread::spawn(move || {
        let _guard = worker.state.lock().unwrap();
        panic!("test poison");
    })
    .join();
    assert!(!replay.precheck(authentication(1, 1)));
    assert!(!replay.commit(authentication(1, 1)));
}

#[test]
fn commit_rechecks_stale_precheck_after_window_advance_or_eviction() {
    let replay = ReplayProtection::new();
    let first = authentication(0, 1);
    assert!(replay.precheck(first));
    assert!(replay.commit(authentication(0, 1025)));
    assert!(!replay.commit(first));
    for identity in 1..=CAPACITY as u64 {
        assert!(replay.commit(authentication(identity, 1)));
    }
    assert!(replay.commit(first));
    assert!(!replay.commit(first));
}
