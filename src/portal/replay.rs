// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Fixed-capacity FIFO identity registry and atomic TCP prelude replay windows.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::Mutex;

use crate::transport::AuthenticatedPrelude;

const CAPACITY: usize = 16_384;
const BUCKETS: usize = CAPACITY * 2;
const EMPTY: u32 = u32::MAX;
const WINDOW: usize = 1024;

struct Entry {
    identity: u64,
    highest: u64,
    bitmap: [u64; WINDOW / 64],
    next: u32,
}

struct ReplayState {
    entries: Vec<Entry>,
    buckets: Box<[u32]>,
    hash: RandomState,
    oldest: usize,
}

pub(super) struct ReplayProtection {
    state: Mutex<ReplayState>,
}

impl ReplayProtection {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(ReplayState {
                entries: Vec::with_capacity(CAPACITY),
                buckets: vec![EMPTY; BUCKETS].into_boxed_slice(),
                hash: RandomState::new(),
                oldest: 0,
            }),
        }
    }

    pub(super) fn precheck(&self, authentication: AuthenticatedPrelude) -> bool {
        if !authentication.is_valid() {
            return false;
        }
        let Ok(state) = self.state.lock() else {
            return false;
        };
        state
            .find(authentication.identity)
            .is_none_or(|index| state.entries[index].accepts(authentication.counter))
    }

    pub(super) fn commit(&self, authentication: AuthenticatedPrelude) -> bool {
        if !authentication.is_valid() {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if let Some(index) = state.find(authentication.identity) {
            let entry = &mut state.entries[index];
            if !entry.accepts(authentication.counter) {
                return false;
            }
            entry.mark(authentication.counter);
            return true;
        }
        let len = state.entries.len();
        let index = if len < CAPACITY {
            len
        } else {
            let index = state.oldest;
            state.remove(index);
            state.oldest = (index + 1) % CAPACITY;
            index
        };
        let bucket = state.bucket(authentication.identity);
        let mut entry = Entry {
            identity: authentication.identity,
            highest: authentication.counter,
            bitmap: [0; WINDOW / 64],
            next: state.buckets[bucket],
        };
        entry.bitmap[0] = 1;
        if index == len {
            state.entries.push(entry);
        } else {
            state.entries[index] = entry;
        }
        state.buckets[bucket] = index as u32;
        true
    }
}

impl ReplayState {
    fn bucket(&self, identity: u64) -> usize {
        self.hash.hash_one(identity) as usize & (BUCKETS - 1)
    }

    fn find(&self, identity: u64) -> Option<usize> {
        let mut index = self.buckets[self.bucket(identity)];
        while index != EMPTY {
            let entry = &self.entries[index as usize];
            if entry.identity == identity {
                return Some(index as usize);
            }
            index = entry.next;
        }
        None
    }

    fn remove(&mut self, index: usize) {
        let bucket = self.bucket(self.entries[index].identity);
        let mut current = self.buckets[bucket];
        let mut previous = None;
        while current as usize != index {
            previous = Some(current as usize);
            current = self.entries[current as usize].next;
        }
        let next = self.entries[index].next;
        if let Some(previous) = previous {
            self.entries[previous].next = next;
        } else {
            self.buckets[bucket] = next;
        }
    }
}

impl Entry {
    fn accepts(&self, counter: u64) -> bool {
        if counter > self.highest {
            return true;
        }
        let distance = self.highest - counter;
        distance < WINDOW as u64
            && self.bitmap[distance as usize / 64] & (1 << (distance % 64)) == 0
    }

    fn mark(&mut self, counter: u64) {
        if counter > self.highest {
            let distance = counter - self.highest;
            if distance >= WINDOW as u64 {
                self.bitmap.fill(0);
            } else {
                let words = distance as usize / 64;
                let bits = distance as usize % 64;
                for index in (0..self.bitmap.len()).rev() {
                    self.bitmap[index] = if index < words {
                        0
                    } else {
                        let mut value = self.bitmap[index - words] << bits;
                        if bits != 0 && index > words {
                            value |= self.bitmap[index - words - 1] >> (64 - bits);
                        }
                        value
                    };
                }
            }
            self.highest = counter;
        }
        let distance = (self.highest - counter) as usize;
        self.bitmap[distance / 64] |= 1 << (distance % 64);
    }
}

#[cfg(test)]
#[path = "../tests/portal/replay.rs"]
mod tests;
