// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pairing registry state types.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use quinn::Connection;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::protocol::{FlowKind, ProtocolVersion, SessionId, Target};

pub(in crate::portal) type BoxReader = Pin<Box<dyn AsyncRead + Send>>;
pub(in crate::portal) type BoxWriter = Pin<Box<dyn AsyncWrite + Send>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::portal) struct SessionKey {
    pub(in crate::portal) version: ProtocolVersion,
    pub(in crate::portal) id: SessionId,
}

impl SessionKey {
    pub(in crate::portal) const fn new(version: ProtocolVersion, id: SessionId) -> Self {
        Self { version, id }
    }
}

impl From<SessionId> for SessionKey {
    fn from(id: SessionId) -> Self {
        Self::new(ProtocolVersion::V2, id)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::portal) struct FlowKey {
    pub(in crate::portal) session_id: SessionKey,
    pub(in crate::portal) flow_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::portal) struct Metadata {
    pub(in crate::portal) kind: FlowKind,
    pub(in crate::portal) uplink: crate::protocol::Carrier,
    pub(in crate::portal) downlink: crate::protocol::Carrier,
    pub(in crate::portal) hops: u8,
}

pub(in crate::portal) struct PendingTcp {
    pub(in crate::portal) epoch: u64,
    pub(in crate::portal) metadata: Metadata,
    /// Active QUIC generation when this split flow first became pending.
    pub(in crate::portal) quic_snapshot: Option<u64>,
    pub(in crate::portal) target: Option<Target>,
    pub(in crate::portal) uplink: Option<BoxReader>,
    pub(in crate::portal) downlink: Option<BoxWriter>,
    pub(in crate::portal) downlink_liveness: Option<BoxReader>,
    pub(in crate::portal) uplink_path: Option<LinkPath>,
    pub(in crate::portal) downlink_path: Option<LinkPath>,
    pub(in crate::portal) uplink_generation: Option<u64>,
    pub(in crate::portal) downlink_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::portal) struct LinkPath {
    pub(in crate::portal) version: ProtocolVersion,
    pub(in crate::portal) peer: String,
    pub(in crate::portal) local: String,
}

pub(in crate::portal) struct LinkHalf {
    pub(in crate::portal) path: LinkPath,
    pub(in crate::portal) quic_generation: Option<u64>,
}

impl LinkHalf {
    pub(in crate::portal) fn tcp(path: LinkPath) -> Self {
        Self {
            path,
            quic_generation: None,
        }
    }

    pub(in crate::portal) fn quic(path: LinkPath, generation: u64) -> Self {
        Self {
            path,
            quic_generation: Some(generation),
        }
    }
}

pub(in crate::portal) enum UdpUp {
    TlsTcp(BoxReader),
    Quic(QuicUdpReceiver),
}

pub(in crate::portal) struct QuicUdpReceiver {
    receiver: mpsc::Receiver<crate::portal::conn::QueuedDatagram>,
    ready: Arc<AtomicBool>,
    ready_requests: Option<mpsc::Sender<crate::portal::conn::DatagramReadyRequest>>,
    on_drop: Option<Box<dyn FnOnce() + Send>>,
}

impl QuicUdpReceiver {
    pub(in crate::portal) fn new(
        receiver: mpsc::Receiver<crate::portal::conn::QueuedDatagram>,
        ready: Arc<AtomicBool>,
        ready_requests: mpsc::Sender<crate::portal::conn::DatagramReadyRequest>,
        on_drop: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            receiver,
            ready,
            ready_requests: Some(ready_requests),
            on_drop: Some(Box::new(on_drop)),
        }
    }

    /// Drains the session DATAGRAM queue while this flow still rejects DATA.
    pub(in crate::portal) async fn prepare_ready(&mut self) -> bool {
        let Some(requests) = &self.ready_requests else {
            return true;
        };
        let (acknowledge, response) = oneshot::channel();
        if requests
            .send(crate::portal::conn::DatagramReadyRequest { acknowledge })
            .await
            .is_err()
        {
            return false;
        }
        response.await.unwrap_or(false)
    }

    /// Opens the DATA path immediately after READY has been queued on the
    /// selected downlink. There is deliberately no await between those events.
    pub(in crate::portal) fn activate(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub(in crate::portal) async fn recv(&mut self) -> Option<bytes::Bytes> {
        self.receiver.recv().await.map(|datagram| datagram.payload)
    }
}

#[cfg(test)]
#[path = "../../tests/portal/pairing_state.rs"]
mod tests;

impl Drop for QuicUdpReceiver {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

pub(in crate::portal) enum UdpDown {
    TlsTcp {
        writer: BoxWriter,
        liveness: Option<BoxReader>,
    },
    Quic {
        control: BoxWriter,
        conn: Connection,
    },
}

pub(in crate::portal) enum UdpHalf {
    Uplink { uplink: UdpUp },
    Downlink(UdpDown),
    Duplex { uplink: UdpUp, downlink: UdpDown },
}

pub(in crate::portal) struct PendingUdp {
    pub(in crate::portal) epoch: u64,
    pub(in crate::portal) metadata: Metadata,
    /// Active QUIC generation when this split flow first became pending.
    pub(in crate::portal) quic_snapshot: Option<u64>,
    pub(in crate::portal) target: Option<Target>,
    pub(in crate::portal) uplink: Option<UdpUp>,
    pub(in crate::portal) downlink: Option<UdpDown>,
    pub(in crate::portal) flow_permit: Option<Arc<OwnedSemaphorePermit>>,
    pub(in crate::portal) uplink_path: Option<LinkPath>,
    pub(in crate::portal) downlink_path: Option<LinkPath>,
    pub(in crate::portal) uplink_generation: Option<u64>,
    pub(in crate::portal) downlink_generation: Option<u64>,
}

pub(in crate::portal) struct PairedUdp {
    pub(in crate::portal) flow_id: u32,
    pub(in crate::portal) target: Target,
    pub(in crate::portal) uplink: UdpUp,
    pub(in crate::portal) downlink: UdpDown,
    pub(in crate::portal) uplink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) downlink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) hops: u8,
    pub(in crate::portal) uplink_path: LinkPath,
    pub(in crate::portal) downlink_path: LinkPath,
    pub(in crate::portal) _flow_lease: FlowLease,
}

pub(in crate::portal) struct PairedTcp {
    pub(in crate::portal) flow_id: u32,
    pub(in crate::portal) target: Target,
    pub(in crate::portal) uplink: BoxReader,
    pub(in crate::portal) downlink: BoxWriter,
    pub(in crate::portal) downlink_liveness: Option<BoxReader>,
    pub(in crate::portal) uplink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) downlink_carrier: crate::protocol::Carrier,
    pub(in crate::portal) hops: u8,
    pub(in crate::portal) uplink_path: LinkPath,
    pub(in crate::portal) downlink_path: LinkPath,
    pub(in crate::portal) _flow_lease: FlowLease,
}

pub(in crate::portal) struct LinkCounts {
    pub(in crate::portal) tcp: usize,
    pub(in crate::portal) udp: Option<ActiveQuic>,
    pub(in crate::portal) udp_flow_budget: Arc<Semaphore>,
}

impl LinkCounts {
    pub(in crate::portal) fn new(max_udp_flows: usize) -> Self {
        Self {
            tcp: 0,
            udp: None,
            udp_flow_budget: Arc::new(Semaphore::new(max_udp_flows)),
        }
    }
}

pub(in crate::portal) struct ActiveQuic {
    pub(in crate::portal) generation: u64,
    pub(in crate::portal) replacement: tokio_util::sync::CancellationToken,
}

pub(in crate::portal) struct FlowClaim {
    pub(in crate::portal) epoch: u64,
    pub(in crate::portal) metadata: Metadata,
    pub(in crate::portal) target: Option<Target>,
    pub(in crate::portal) active: bool,
    pub(in crate::portal) cancel: CancellationToken,
    pub(in crate::portal) quic_generations: Vec<u64>,
}

pub(in crate::portal) struct FlowLease {
    pub(in crate::portal) registry: std::sync::Weak<super::PairingRegistry>,
    pub(in crate::portal) key: FlowKey,
    pub(in crate::portal) epoch: u64,
    pub(in crate::portal) cancel: CancellationToken,
    pub(in crate::portal) _udp_permit: Option<Arc<OwnedSemaphorePermit>>,
}

impl FlowLease {
    pub(in crate::portal) fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

impl Drop for FlowLease {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.finish_flow(self.key, self.epoch);
        }
    }
}
