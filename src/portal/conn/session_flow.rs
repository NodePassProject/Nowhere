// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP flow state and response forwarding for QUIC sessions.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::common::{udp_dial_timeout, udp_idle_timeout};
use crate::protocol::{Carrier, frame_payload_bytes};

use super::super::relay::{UDP_TRANSFER_COMPLETE, UDP_TRANSFER_STARTING, symmetric_exchange_path};
use super::PortalSession;

const UDP_FLOW_QUEUE_DATAGRAMS: usize = 64;

/// Key that scopes a UDP flow to both client flow ID and target address.
#[derive(Clone, Debug, Eq)]
pub(super) struct UdpFlowKey {
    flow_id: u64,
    target: String,
}

impl UdpFlowKey {
    /// Creates a UDP flow key.
    pub(super) fn new(flow_id: u64, target: impl Into<String>) -> Self {
        Self {
            flow_id,
            target: target.into(),
        }
    }

    pub(super) fn target(&self) -> &str {
        &self.target
    }
}

impl PartialEq for UdpFlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.flow_id == other.flow_id && self.target == other.target
    }
}

impl Hash for UdpFlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.flow_id.hash(state);
        self.target.hash(state);
    }
}

/// One queued client datagram and its share of the connection memory budget.
pub(in crate::portal) struct QueuedDatagram {
    pub(in crate::portal) payload: Bytes,
    _budget: OwnedSemaphorePermit,
}

impl QueuedDatagram {
    pub(in crate::portal) fn new(payload: Bytes, budget: OwnedSemaphorePermit) -> Self {
        Self {
            payload,
            _budget: budget,
        }
    }
}

/// Queue and cancellation state for one proxied UDP flow.
pub(super) struct PortalUdpFlow {
    session: Weak<PortalSession>,
    key: UdpFlowKey,
    sender: mpsc::Sender<QueuedDatagram>,
    closed: AtomicBool,
    cancel: CancellationToken,
}

impl PortalUdpFlow {
    /// Creates a pending UDP flow before target dialing begins.
    pub(super) fn new(
        session: Weak<PortalSession>,
        key: UdpFlowKey,
    ) -> (Self, mpsc::Receiver<QueuedDatagram>) {
        let (sender, receiver) = mpsc::channel(UDP_FLOW_QUEUE_DATAGRAMS);
        (
            Self {
                session,
                key,
                sender,
                closed: AtomicBool::new(false),
                cancel: CancellationToken::new(),
            },
            receiver,
        )
    }

    /// Returns whether this flow has begun closing.
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Enqueues without waiting; overload drops the new datagram.
    pub(super) fn enqueue(&self, datagram: QueuedDatagram) -> bool {
        if self.is_closed() {
            return false;
        }
        self.sender.try_send(datagram).is_ok()
    }

    /// Dials the target, then owns both directions and idle expiry for this flow.
    pub(super) async fn run(
        self: Arc<Self>,
        mut receiver: mpsc::Receiver<QueuedDatagram>,
        response_header: Vec<u8>,
    ) {
        let Some(session) = self.session.upgrade() else {
            return;
        };
        let socket = tokio::select! {
            _ = self.cancel.cancelled() => return,
            result = session.portal.outbound.dial_udp(self.key.target(), udp_dial_timeout()) => {
                match result {
                    Ok(socket) => socket,
                    Err(err) => {
                        session.portal.logger.error(format_args!(
                            "portal::conn::udp_flow: failed to dial target {}: {err}",
                            self.key.target()
                        ));
                        self.close().await;
                        return;
                    }
                }
            }
        };
        if session.portal.logger.debug_enabled() {
            let target_local = socket
                .local_addr()
                .map(|address| address.to_string())
                .unwrap_or_else(|_| "<unknown>".to_string());
            let path = session.link_path();
            session.portal.logger.debug(format_args!(
                "portal::conn::udp_flow: {}: {}",
                UDP_TRANSFER_STARTING,
                symmetric_exchange_path(
                    Carrier::Udp,
                    &path.peer,
                    &path.local,
                    &target_local,
                    self.key.target(),
                )
            ));
        }
        let mut buf = session.portal.buffers.get_udp_buffer();
        let mut target_packet = Vec::new();
        let idle_sleep = tokio::time::sleep_until(Instant::now() + udp_idle_timeout());
        tokio::pin!(idle_sleep);

        let complete_reason = loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break "cancelled".to_string(),
                datagram = receiver.recv() => {
                    let Some(datagram) = datagram else {
                        break "request channel closed".to_string();
                    };
                    idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                    if let Some(limiter) = &session.portal.rate_limiter {
                        limiter.wait_read(datagram.payload.len() as i64).await;
                    }
                    if self.is_closed() {
                        break "closed".to_string();
                    }
                    match socket.send(&datagram.payload, &mut target_packet).await {
                        Ok(n) => {
                            session.portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                            session.portal.stats.up_udp.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(err) => {
                            session.portal.logger.error(format_args!(
                                "portal::conn::udp_flow: failed to write target {}: {err}",
                                self.key.target()
                            ));
                            break format!("target write error: {err}");
                        }
                    }
                }
                read = socket.recv(&mut buf) => {
                    let payload = match read {
                        Ok(range) => &buf[range],
                        Err(err) => {
                            if self.is_closed() {
                                break "closed".to_string();
                            }
                            break format!("target read error: {err}");
                        }
                    };
                    if payload.is_empty() {
                        continue;
                    }
                    idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                    let n = payload.len();
                    let frame = frame_payload_bytes(&response_header, payload);
                    if let Some(limiter) = &session.portal.rate_limiter {
                        limiter.wait_write(n as i64).await;
                    }
                    if self.is_closed() {
                        break "closed".to_string();
                    }
                    match session.conn.send_datagram(frame) {
                        Ok(()) => {
                            session.portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                            session.portal.stats.down_udp.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(err) => {
                            break format!("client write error: {err}");
                        }
                    }
                }
                _ = &mut idle_sleep => {
                    break "idle timeout".to_string();
                }
            }
        };
        self.close().await;
        session.portal.logger.debug(format_args!(
            "portal::conn::udp_flow: {}: {complete_reason}",
            UDP_TRANSFER_COMPLETE
        ));
    }

    /// Closes the flow, removes it from the session map, and updates counters.
    pub(super) async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancel.cancel();

        if let Some(session) = self.session.upgrade() {
            let mut guard = session.udp_flows.lock().await;
            if guard
                .get(&self.key)
                .is_some_and(|flow| std::ptr::eq(flow.as_ref(), self))
            {
                guard.remove(&self.key);
            }
            session.portal.stats.done_session(true);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/portal/conn/session_flow.rs"]
mod tests;
