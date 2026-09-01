// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Collision-free `u32` flow identifier allocation.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};

use crate::protocol::FlowId;

#[derive(Debug)]
pub(super) struct FlowIdAllocator {
    next: AtomicU32,
    active: Mutex<HashSet<FlowId>>,
    limit: usize,
}

impl FlowIdAllocator {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU32::new(1),
            active: Mutex::new(HashSet::with_capacity(limit.min(4_096))),
            limit,
        })
    }

    pub(super) fn allocate(self: &Arc<Self>) -> Result<FlowLease> {
        let mut active = self.active.lock().unwrap_or_else(|lock| lock.into_inner());
        if active.len() >= self.limit {
            bail!("vector::flow_id: active flow limit reached");
        }
        for _ in 0..=self.limit {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            let id = if id == 0 {
                self.next.fetch_add(1, Ordering::Relaxed)
            } else {
                id
            };
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
