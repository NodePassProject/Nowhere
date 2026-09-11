// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded, timeout-aware UDP fragment reassembly.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use super::{FlowId, OwnedUdpFragment, validate_fragment_metadata};

/// Resource limits for application-layer UDP fragment reassembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReassemblyConfig {
    pub max_slots: usize,
    pub max_bytes: usize,
    pub ttl: Duration,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_slots: 64,
            max_bytes: 1024 * 1024,
            ttl: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyDropReason {
    MetadataConflict,
    DuplicateConflict,
    ByteLimit,
    InvalidLength,
}

impl ReassemblyDropReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataConflict => "conflicting UDP fragment metadata",
            Self::DuplicateConflict => "conflicting duplicate UDP fragment",
            Self::ByteLimit => "UDP reassembly resource limit reached",
            Self::InvalidLength => "invalid UDP fragment length",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReassemblyOutcome<R = ()> {
    Pending {
        evicted_partial: bool,
    },
    Complete {
        payload: Bytes,
        reservation: R,
        evicted_partial: bool,
    },
    Dropped(ReassemblyDropReason),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ReassemblyKey {
    flow_id: FlowId,
    packet_id: u32,
}

pub(super) struct ReassemblySlot<R> {
    created_at: Instant,
    fragment_count: u8,
    total_len: u16,
    pub(super) fragments: Vec<Option<Bytes>>,
    received: usize,
    retained: usize,
    reservation: R,
}

/// Bounded, timeout-aware fragment reassembler.
pub struct DatagramReassembler<R = ()> {
    config: ReassemblyConfig,
    pub(super) slots: HashMap<ReassemblyKey, ReassemblySlot<R>>,
    reserved_bytes: usize,
    next_expiry: Option<Instant>,
}

impl<R> DatagramReassembler<R> {
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            config,
            slots: HashMap::new(),
            reserved_bytes: 0,
            next_expiry: None,
        }
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    pub fn remove_flow(&mut self, flow_id: FlowId) {
        let removed: usize = self
            .slots
            .iter()
            .filter(|(key, _)| key.flow_id == flow_id)
            .map(|(_, slot)| slot.total_len as usize)
            .sum();
        self.slots.retain(|key, _| key.flow_id != flow_id);
        self.reserved_bytes = self.reserved_bytes.saturating_sub(removed);
        if self.slots.is_empty() {
            self.next_expiry = None;
        }
    }

    /// Releases every partial packet and any caller-owned reservations.
    pub fn clear(&mut self) {
        self.slots.clear();
        self.reserved_bytes = 0;
        self.next_expiry = None;
    }

    pub fn expire(&mut self, now: Instant) -> bool {
        let Some(next_expiry) = self.next_expiry else {
            return false;
        };
        // Slots remain valid through the exact TTL boundary.
        if now <= next_expiry {
            return false;
        }
        let before = self.slots.len();
        let mut released = 0usize;
        self.slots.retain(|_, slot| {
            let keep = now.saturating_duration_since(slot.created_at) <= self.config.ttl;
            if !keep {
                released = released.saturating_add(slot.total_len as usize);
            }
            keep
        });
        self.reserved_bytes = self.reserved_bytes.saturating_sub(released);
        self.next_expiry = self
            .slots
            .values()
            .filter_map(|slot| slot.created_at.checked_add(self.config.ttl))
            .min();
        self.slots.len() != before
    }

    /// Retains a zero-copy fragment slice and reserves any caller-owned
    /// resource exactly once when a new packet slot is created.
    pub fn push_with<F>(
        &mut self,
        flow_id: FlowId,
        fragment: OwnedUdpFragment,
        now: Instant,
        reserve: F,
    ) -> ReassemblyOutcome<R>
    where
        F: FnOnce(u16) -> Option<R>,
    {
        if flow_id == 0
            || flow_id > crate::protocol::MAX_FLOW_ID
            || fragment.packet_id == 0
            || validate_fragment_metadata(
                fragment.fragment_index,
                fragment.fragment_count,
                fragment.total_len,
                "reassembly",
            )
            .is_err()
            || fragment.payload.is_empty()
            || fragment
                .payload
                .len()
                .saturating_add(fragment.fragment_count as usize - 1)
                > fragment.total_len as usize
        {
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::InvalidLength);
        }
        let key = ReassemblyKey {
            flow_id,
            packet_id: fragment.packet_id,
        };
        let mut evicted_partial = self.expire(now);

        if let Some(slot) = self.slots.get_mut(&key) {
            if slot.fragment_count != fragment.fragment_count
                || slot.total_len != fragment.total_len
            {
                self.remove_slot(&key);
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::MetadataConflict);
            }

            let index = fragment.fragment_index as usize;
            if let Some(existing) = &slot.fragments[index] {
                if existing != &fragment.payload {
                    self.remove_slot(&key);
                    return ReassemblyOutcome::Dropped(ReassemblyDropReason::DuplicateConflict);
                }
                return ReassemblyOutcome::Pending { evicted_partial };
            }

            let retained = slot.retained.saturating_add(fragment.payload.len());
            if retained > slot.total_len as usize {
                self.remove_slot(&key);
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::InvalidLength);
            }
            slot.fragments[index] = Some(fragment.payload);
            slot.received += 1;
            slot.retained = retained;
            if slot.received < slot.fragment_count as usize {
                return ReassemblyOutcome::Pending { evicted_partial };
            }

            let slot = self.remove_slot(&key).expect("complete slot exists");
            if slot.retained != slot.total_len as usize {
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::InvalidLength);
            }
            let mut payload = BytesMut::with_capacity(slot.total_len as usize);
            for fragment in slot.fragments {
                let Some(fragment) = fragment else {
                    return ReassemblyOutcome::Dropped(ReassemblyDropReason::InvalidLength);
                };
                payload.extend_from_slice(&fragment);
            }
            return ReassemblyOutcome::Complete {
                payload: payload.freeze(),
                reservation: slot.reservation,
                evicted_partial,
            };
        }

        if self.config.max_slots == 0 || fragment.total_len as usize > self.config.max_bytes {
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::ByteLimit);
        }
        let oldest = if self.slots.len() >= self.config.max_slots {
            self.slots
                .iter()
                .min_by_key(|(_, slot)| slot.created_at)
                .map(|(key, _)| *key)
        } else {
            None
        };
        let replaced_bytes = oldest
            .and_then(|key| self.slots.get(&key))
            .map_or(0, |slot| slot.total_len as usize);
        if self
            .reserved_bytes
            .saturating_sub(replaced_bytes)
            .saturating_add(fragment.total_len as usize)
            > self.config.max_bytes
        {
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::ByteLimit);
        }
        // External admission is fallible. Reserve before evicting so a failed
        // replacement cannot discard an otherwise valid partial packet.
        let Some(reservation) = reserve(fragment.total_len) else {
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::ByteLimit);
        };
        if let Some(oldest) = oldest {
            self.remove_slot(&oldest);
            evicted_partial = true;
        }
        self.reserved_bytes += fragment.total_len as usize;
        let expiry = now.checked_add(self.config.ttl).unwrap_or(now);
        self.next_expiry = Some(
            self.next_expiry
                .map_or(expiry, |current| current.min(expiry)),
        );
        let mut fragments = vec![None; fragment.fragment_count as usize];
        let retained = fragment.payload.len();
        fragments[fragment.fragment_index as usize] = Some(fragment.payload);
        self.slots.insert(
            key,
            ReassemblySlot {
                created_at: now,
                fragment_count: fragment.fragment_count,
                total_len: fragment.total_len,
                fragments,
                received: 1,
                retained,
                reservation,
            },
        );
        ReassemblyOutcome::Pending { evicted_partial }
    }

    fn remove_slot(&mut self, key: &ReassemblyKey) -> Option<ReassemblySlot<R>> {
        let slot = self.slots.remove(key)?;
        self.reserved_bytes = self.reserved_bytes.saturating_sub(slot.total_len as usize);
        if self.slots.is_empty() {
            self.next_expiry = None;
        }
        Some(slot)
    }
}

impl DatagramReassembler<()> {
    /// Retains a fragment when no external resource reservation is required.
    pub fn push(
        &mut self,
        flow_id: FlowId,
        fragment: OwnedUdpFragment,
        now: Instant,
    ) -> ReassemblyOutcome {
        self.push_with(flow_id, fragment, now, |_| Some(()))
    }
}

impl Default for DatagramReassembler<()> {
    fn default() -> Self {
        Self::new(ReassemblyConfig::default())
    }
}
