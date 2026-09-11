// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Collision-free allocation within the shared 30-bit flow identifier space.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};

use crate::protocol::{FlowId, MAX_FLOW_ID};

#[derive(Debug)]
pub(super) struct FlowIdAllocator {
    next: AtomicU32,
    active: Mutex<HashSet<FlowId>>,
}

impl FlowIdAllocator {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU32::new(1),
            active: Mutex::new(HashSet::new()),
        })
    }

    pub(super) fn allocate(self: &Arc<Self>) -> Result<FlowLease> {
        self.allocate_with_limit(MAX_FLOW_ID)
    }

    fn allocate_with_limit(self: &Arc<Self>, max_id: FlowId) -> Result<FlowLease> {
        let mut active = self.active.lock().unwrap_or_else(|lock| lock.into_inner());
        if active.len() == max_id as usize {
            bail!("vector::flow_id: flow identifier space exhausted");
        }
        for _ in 0..=active.len() {
            let id = self
                .next
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                    Some(if id >= max_id { 1 } else { id + 1 })
                })
                .unwrap_or_else(|id| id);
            if id != 0 && active.insert(id) {
                return Ok(FlowLease {
                    id,
                    allocator: self.clone(),
                });
            }
        }
        bail!("vector::flow_id: no reusable flow identifier available")
    }

    fn release(&self, id: FlowId) {
        self.active
            .lock()
            .unwrap_or_else(|lock| lock.into_inner())
            .remove(&id);
    }
}

#[derive(Debug)]
pub(super) struct FlowLease {
    id: FlowId,
    allocator: Arc<FlowIdAllocator>,
}

impl FlowLease {
    pub(super) fn id(&self) -> FlowId {
        self.id
    }
}

impl Drop for FlowLease {
    fn drop(&mut self) {
        self.allocator.release(self.id);
    }
}

#[cfg(test)]
#[path = "../tests/vector/flow_id.rs"]
mod tests;
