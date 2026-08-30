// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC DATAGRAM dispatch for UDP packets after reliable flow setup.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::protocol::{OwnedUdpFragment, OwnedUdpFrame, ReassemblyOutcome, decode_udp_frame_owned};

use super::flow::reserve_packet_budget;
use super::{DatagramReadyRequest, PortalSession, QueuedDatagram};

impl PortalSession {
    /// Consumes pending and live QUIC datagrams for this authenticated session.
    pub(in crate::portal::conn) async fn datagram_loop(
        self: Arc<Self>,
        shutdown: CancellationToken,
    ) {
        let Some(mut ready_requests) = self.take_udp_ready_requests().await else {
            return;
        };
        let mut cleanup = tokio::time::interval(std::time::Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let data = tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = cleanup.tick() => {
                    if self.udp_reassembler
                        .lock()
                        .unwrap_or_else(|lock| lock.into_inner())
                        .expire(std::time::Instant::now())
                    {
                        self.warn_udp_drop("incomplete UDP packet expired");
                    }
                    continue;
                }
                request = ready_requests.recv() => {
                    let Some(request) = request else {
                        return;
                    };
                    self.commit_udp_ready(request, &shutdown).await;
                    continue;
                }
                datagram = self.conn.read_datagram() => match datagram {
                    Ok(data) => data,
                    Err(err) => {
                        if !shutdown.is_cancelled() {
                            self.portal.logger.debug(format_args!("portal::conn::datagram_loop: receive closed: {err}"));
                        }
                        return;
                    }
                }
            };
            self.handle_datagram(data).await;
        }
    }

    async fn commit_udp_ready(
        self: &Arc<Self>,
        request: DatagramReadyRequest,
        shutdown: &CancellationToken,
    ) {
        let waker = Waker::noop();
        let deadline = tokio::time::Instant::now() + self.portal.runtime.handshake_timeout;
        let mut drained = 0usize;
        loop {
            let polled = {
                let read = self.conn.read_datagram();
                tokio::pin!(read);
                let mut context = Context::from_waker(waker);
                std::future::Future::poll(read.as_mut(), &mut context)
            };
            match polled {
                Poll::Ready(Ok(data)) => {
                    self.handle_datagram(data).await;
                    drained += 1;
                    if shutdown.is_cancelled() || tokio::time::Instant::now() >= deadline {
                        let _ = request.acknowledge.send(false);
                        return;
                    }
                    if drained.is_multiple_of(1_024) {
                        tokio::task::yield_now().await;
                    }
                }
                Poll::Ready(Err(_)) => {
                    let _ = request.acknowledge.send(false);
                    return;
                }
                Poll::Pending => {
                    let _ = request.acknowledge.send(true);
                    return;
                }
            }
        }
    }

    async fn handle_datagram(self: &Arc<Self>, data: Bytes) {
        match decode_udp_frame_owned(data) {
            Ok(OwnedUdpFrame::Data { flow_id, payload }) => {
                self.handle_unfragmented_udp(flow_id, payload);
            }
            Ok(OwnedUdpFrame::Fragment { flow_id, fragment }) => {
                self.handle_udp_fragment(flow_id, fragment);
            }
            Ok(OwnedUdpFrame::Close { flow_id }) => self.close_udp_flow(flow_id).await,
            Err(err) => self.portal.logger.debug(format_args!(
                "portal::conn::datagram_loop: invalid UDP frame: {err}"
            )),
        }
    }

    fn handle_unfragmented_udp(&self, flow_id: u32, payload: Bytes) {
        let flows = self
            .udp_flows
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let Some(state) = flows.get(&flow_id) else {
            self.warn_udp_drop("DATA for unknown UDP flow");
            return;
        };
        if !state.ready.load(Ordering::Acquire) {
            self.warn_udp_drop("DATA before UDP flow READY");
            return;
        }
        let Some(permit) = reserve_packet_budget(self.udp_queue_budget.clone(), payload.len())
        else {
            self.warn_udp_drop("connection queue byte limit reached");
            return;
        };
        self.enqueue_udp(&state.sender, QueuedDatagram::new(payload, permit));
    }

    fn handle_udp_fragment(&self, flow_id: u32, fragment: OwnedUdpFragment) {
        // Every dual-state operation takes flows before reassembly. Keeping
        // both guards through enqueue prevents close/remove races from
        // resurrecting a partial or complete packet.
        let flows = self
            .udp_flows
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let Some(state) = flows.get(&flow_id) else {
            self.warn_udp_drop("DATA for unknown UDP flow");
            return;
        };
        if !state.ready.load(Ordering::Acquire) {
            self.warn_udp_drop("DATA before UDP flow READY");
            return;
        }
        let mut reassembler = self
            .udp_reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let outcome = reassembler.push_with(flow_id, fragment, std::time::Instant::now(), |len| {
            reserve_packet_budget(self.udp_queue_budget.clone(), usize::from(len))
        });
        match outcome {
            ReassemblyOutcome::Pending { evicted_partial } => {
                if evicted_partial {
                    self.warn_udp_drop("incomplete UDP packet evicted");
                }
            }
            ReassemblyOutcome::Dropped(reason) => self.warn_udp_drop(reason.as_str()),
            ReassemblyOutcome::Complete {
                payload,
                reservation,
                evicted_partial,
            } => {
                if evicted_partial {
                    self.warn_udp_drop("incomplete UDP packet evicted");
                }
                self.enqueue_udp(&state.sender, QueuedDatagram::new(payload, reservation));
            }
        }
    }

    async fn close_udp_flow(&self, flow_id: u32) {
        self.remove_udp_uplink(flow_id);
        self.portal
            .pairing
            .cancel_udp(self.session_key, flow_id)
            .await;
    }

    fn enqueue_udp(
        &self,
        sender: &tokio::sync::mpsc::Sender<QueuedDatagram>,
        datagram: QueuedDatagram,
    ) -> bool {
        if sender.try_send(datagram).is_err() {
            self.warn_udp_drop("per-flow datagram queue is full");
            return false;
        }
        true
    }

    fn warn_udp_drop(&self, reason: &str) {
        if !self.udp_overload_logged.swap(true, Ordering::AcqRel) {
            self.portal.logger.warn(format_args!(
                "portal::conn::datagram_loop: dropping UDP datagrams for {}: {reason}",
                self.conn.remote_address()
            ));
        }
    }
}
