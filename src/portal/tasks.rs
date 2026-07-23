// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded-shutdown tracking for detached live-flow tasks.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, oneshot};
use tokio::task::AbortHandle;

const READY_GATE_CLOSED: usize = 1usize << (usize::BITS - 1);
const READY_GATE_COUNT: usize = READY_GATE_CLOSED - 1;

/// Lock-free linearization gate for committing v1 READY results.
#[derive(Default)]
pub(super) struct ReadyGate {
    state: AtomicUsize,
}

impl ReadyGate {
    /// Reserves a READY commit that linearizes before shutdown admission closes.
    pub(super) fn try_enter(&self) -> Option<ReadyPermit<'_>> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & READY_GATE_CLOSED != 0 || state & READY_GATE_COUNT == READY_GATE_COUNT {
                return None;
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ReadyPermit { gate: self }),
                Err(current) => state = current,
            }
        }
    }

    /// Prevents all commits that did not already reserve a permit.
    pub(super) fn close(&self) {
        self.state.fetch_or(READY_GATE_CLOSED, Ordering::AcqRel);
    }
}

pub(super) struct ReadyPermit<'a> {
    gate: &'a ReadyGate,
}

impl Drop for ReadyPermit<'_> {
    fn drop(&mut self) {
        self.gate.state.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
pub(super) struct FlowTaskTracker {
    state: Mutex<TrackerState>,
    next_id: AtomicU64,
    active: AtomicUsize,
    idle: Notify,
}

#[derive(Default)]
struct TrackerState {
    closed: bool,
    handles: HashMap<u64, AbortHandle>,
}

impl FlowTaskTracker {
    pub(super) fn spawn<F>(self: &Arc<Self>, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_or_return(future).is_none()
    }

    /// Spawns while admission is open, or returns ownership to the caller so
    /// it can complete protocol cleanup instead of silently dropping a flow.
    pub(super) fn spawn_or_return<F>(self: &Arc<Self>, future: F) -> Option<F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = self.state.lock().expect("flow task tracker poisoned");
        if state.closed {
            return Some(future);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::AcqRel);
        let (registered, registration) = oneshot::channel();
        let tracker = self.clone();
        // Capture the guard in the task future itself. If Tokio aborts the task
        // before its first poll, dropping that future still balances `active`.
        let completion = CompletionGuard { tracker, id };
        let task = tokio::spawn(async move {
            let _completion = completion;
            let _ = registration.await;
            future.await;
        });
        let abort_handle = task.abort_handle();
        drop(task);
        state.handles.insert(id, abort_handle);
        drop(state);
        let _ = registered.send(());
        None
    }

    pub(super) fn close(&self) {
        let mut state = self.state.lock().expect("flow task tracker poisoned");
        state.closed = true;
        if self.active.load(Ordering::Acquire) == 0 {
            self.idle.notify_waiters();
        }
    }

    pub(super) fn abort_all(&self) {
        let state = self.state.lock().expect("flow task tracker poisoned");
        for handle in state.handles.values() {
            handle.abort();
        }
    }

    pub(super) async fn wait(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    fn done(&self, id: u64) {
        self.state
            .lock()
            .expect("flow task tracker poisoned")
            .handles
            .remove(&id);
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }
}

struct CompletionGuard {
    tracker: Arc<FlowTaskTracker>,
    id: u64,
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.tracker.done(self.id);
    }
}

#[cfg(test)]
#[path = "../tests/portal/tasks.rs"]
mod tests;
