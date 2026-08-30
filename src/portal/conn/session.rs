// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC session state for reliable flow setup and UDP DATAGRAM traffic.

#[path = "session_datagram.rs"]
mod datagram;
#[path = "session_flow.rs"]
mod flow;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::timeout;

use crate::protocol::{
    Carrier, DatagramReassembler, FlowErrorCode, FlowKind, FlowResult, FlowRole, ReassemblyConfig,
    read_flow_header, read_request, write_flow_result,
};

pub(in crate::portal) use self::flow::QueuedDatagram;
use crate::portal::PortalInner;
use crate::portal::pairing::SessionKey;

const FLOW_REJECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const UDP_REASSEMBLY_SLOTS: usize = 64;
const UDP_REASSEMBLY_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// Per-authenticated QUIC connection state.
pub(super) struct PortalSession {
    portal: Arc<PortalInner>,
    conn: Connection,
    pub(super) session_key: SessionKey,
    quic_generation: AtomicU64,
    udp_flows: StdMutex<HashMap<u32, UdpState>>,
    udp_reassembler: StdMutex<DatagramReassembler<OwnedSemaphorePermit>>,
    udp_ready_tx: mpsc::Sender<DatagramReadyRequest>,
    udp_ready_rx: Mutex<Option<mpsc::Receiver<DatagramReadyRequest>>>,
    udp_queue_budget: Arc<Semaphore>,
    udp_overload_logged: AtomicBool,
    closed: AtomicBool,
}

pub(super) struct UdpState {
    pub(super) sender: mpsc::Sender<QueuedDatagram>,
    pub(super) ready: Arc<AtomicBool>,
}

pub(in crate::portal) struct DatagramReadyRequest {
    pub(in crate::portal) acknowledge: oneshot::Sender<bool>,
}

impl PortalSession {
    fn link_path(&self) -> crate::portal::pairing::LinkPath {
        crate::portal::pairing::LinkPath {
            version: self.session_key.version,
            peer: self.conn.remote_address().to_string(),
            local: self.conn.local_ip().map_or_else(
                || self.portal.endpoint_addr.clone(),
                |ip| std::net::SocketAddr::new(ip, self.portal.listen_port).to_string(),
            ),
        }
    }

    /// Creates session state for one authenticated QUIC connection.
    pub(super) fn new(portal: Arc<PortalInner>, conn: Connection, session_key: SessionKey) -> Self {
        let (udp_ready_tx, udp_ready_rx) = mpsc::channel(64);
        let udp_reassembly_config = ReassemblyConfig {
            max_slots: UDP_REASSEMBLY_SLOTS,
            max_bytes: portal.udp_flow_limits.queue_bytes,
            ttl: UDP_REASSEMBLY_TTL,
        };
        Self {
            udp_queue_budget: Arc::new(Semaphore::new(portal.udp_flow_limits.queue_bytes)),
            portal,
            conn,
            session_key,
            quic_generation: AtomicU64::new(0),
            udp_flows: StdMutex::new(HashMap::new()),
            udp_reassembler: StdMutex::new(DatagramReassembler::new(udp_reassembly_config)),
            udp_ready_tx,
            udp_ready_rx: Mutex::new(Some(udp_ready_rx)),
            udp_overload_logged: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    pub(super) fn set_quic_generation(&self, generation: u64) {
        self.quic_generation.store(generation, Ordering::Release);
    }

    pub(super) fn quic_generation(&self) -> u64 {
        self.quic_generation.load(Ordering::Acquire)
    }

    /// Handles one reliable QUIC flow-control stream.
    pub(super) async fn handle_stream(self: Arc<Self>, send: SendStream, recv: RecvStream) {
        self.handle_buffered_stream(send, BufReader::new(recv))
            .await;
    }

    /// Continues parsing the first bidi stream after its 32-byte auth prefix.
    /// Ending that stream after authentication alone remains a valid warm
    /// carrier; any trailing bytes start the first flow immediately.
    pub(super) async fn handle_first_stream(
        self: Arc<Self>,
        mut send: SendStream,
        recv: RecvStream,
    ) {
        let mut recv = BufReader::new(recv);
        match timeout(self.portal.runtime.handshake_timeout, recv.fill_buf()).await {
            Ok(Ok([])) => {
                let _ = send.finish();
                return;
            }
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                self.portal.logger.debug(format_args!(
                    "portal::conn::handle_first_stream: failed to inspect flow bytes: {err}"
                ));
                return;
            }
            Err(_) => return,
        }
        self.handle_buffered_stream(send, recv).await;
    }

    async fn handle_buffered_stream(
        self: Arc<Self>,
        mut send: SendStream,
        mut recv: BufReader<RecvStream>,
    ) {
        let header = match timeout(
            self.portal.runtime.handshake_timeout,
            read_flow_header(&mut recv),
        )
        .await
        {
            Ok(Ok(header)) => header,
            Ok(Err(err)) => {
                self.portal.logger.debug(format_args!(
                    "portal::conn::handle_stream: invalid flow header: {err}"
                ));
                return;
            }
            Err(_) => return,
        };
        if let Err(err) = header.validate_on(Carrier::Quic) {
            self.portal.logger.debug(format_args!(
                "portal::conn::handle_stream: carrier mismatch: {err}"
            ));
            if header.role == FlowRole::Open {
                self.portal
                    .pairing
                    .reject_flow_setup(
                        self.session_key,
                        header.flow_id,
                        FlowErrorCode::InvalidRequest,
                    )
                    .await;
            } else {
                reject_quic_control(&mut send, FlowErrorCode::InvalidRequest).await;
            }
            return;
        }
        let target = if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
            match tokio::select! {
                result = timeout(
                    self.portal.runtime.handshake_timeout,
                    read_request(&mut recv),
                ) => result,
                _ = self.portal.drain.cancelled() => {
                    if header.role == FlowRole::Open {
                        self.portal
                            .pairing
                            .reject_flow_setup(
                                self.session_key,
                                header.flow_id,
                                FlowErrorCode::FlowLimit,
                            )
                            .await;
                    } else {
                        reject_quic_control(&mut send, FlowErrorCode::FlowLimit).await;
                    }
                    return;
                }
            } {
                Ok(Ok(target)) => Some(target),
                _ => {
                    if header.role == FlowRole::Open {
                        self.portal
                            .pairing
                            .reject_flow_setup(
                                self.session_key,
                                header.flow_id,
                                FlowErrorCode::InvalidRequest,
                            )
                            .await;
                    } else if header.role == FlowRole::Duplex {
                        reject_quic_control(&mut send, FlowErrorCode::InvalidRequest).await;
                    }
                    return;
                }
            }
        } else {
            None
        };
        let link = crate::portal::pairing::LinkHalf::quic(self.link_path(), self.quic_generation());

        match header.kind {
            FlowKind::Tcp => {
                let (reader, writer) = match header.role {
                    FlowRole::Open => (Some(Box::pin(recv) as _), None),
                    FlowRole::Attach => (None, Some(Box::pin(send) as _)),
                    FlowRole::Duplex => (Some(Box::pin(recv) as _), Some(Box::pin(send) as _)),
                };
                match self
                    .portal
                    .pairing
                    .submit_tcp(self.session_key, header, target, link, reader, writer, None)
                    .await
                {
                    Ok(Some(paired)) => {
                        let relay = super::relay::relay_paired_tcp(self.portal.clone(), paired);
                        if let Some(relay) = self.portal.relay_tasks.spawn_or_return(relay) {
                            relay.await;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => self.portal.logger.debug(format_args!(
                        "portal::conn::handle_stream: TCP flow rejected: {err}"
                    )),
                }
            }
            FlowKind::Udp => {
                let half = match header.role {
                    FlowRole::Open => {
                        let Some(receiver) = self.install_udp_uplink(header.flow_id) else {
                            self.portal
                                .pairing
                                .reject_flow_setup(
                                    self.session_key,
                                    header.flow_id,
                                    FlowErrorCode::MetadataConflict,
                                )
                                .await;
                            return;
                        };
                        crate::portal::pairing::UdpHalf::Uplink {
                            uplink: crate::portal::pairing::UdpUp::Quic(receiver),
                        }
                    }
                    FlowRole::Attach => crate::portal::pairing::UdpHalf::Downlink(
                        crate::portal::pairing::UdpDown::Quic {
                            control: Box::pin(send),
                            conn: self.conn.clone(),
                        },
                    ),
                    FlowRole::Duplex => {
                        let Some(receiver) = self.install_udp_uplink(header.flow_id) else {
                            reject_quic_control(&mut send, FlowErrorCode::MetadataConflict).await;
                            return;
                        };
                        crate::portal::pairing::UdpHalf::Duplex {
                            uplink: crate::portal::pairing::UdpUp::Quic(receiver),
                            downlink: crate::portal::pairing::UdpDown::Quic {
                                control: Box::pin(send),
                                conn: self.conn.clone(),
                            },
                        }
                    }
                };
                match self
                    .portal
                    .pairing
                    .submit_udp(self.session_key, header, target, link, half)
                    .await
                {
                    Ok(Some(paired)) => {
                        let relay = super::relay::relay_paired_udp(self.portal.clone(), paired);
                        if let Some(relay) = self.portal.relay_tasks.spawn_or_return(relay) {
                            relay.await;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
                            self.remove_udp_uplink(header.flow_id);
                        }
                        self.portal.logger.debug(format_args!(
                            "portal::conn::handle_stream: UDP flow rejected: {err}"
                        ));
                    }
                }
            }
        }
    }

    fn install_udp_uplink(
        self: &Arc<Self>,
        flow_id: u32,
    ) -> Option<crate::portal::pairing::QuicUdpReceiver> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let (sender, receiver) = mpsc::channel(64);
        let ready = Arc::new(AtomicBool::new(false));
        let mut flows = self
            .udp_flows
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        if self.closed.load(Ordering::Acquire) || flows.contains_key(&flow_id) {
            return None;
        }
        flows.insert(
            flow_id,
            UdpState {
                sender,
                ready: ready.clone(),
            },
        );
        drop(flows);
        let weak_session = Arc::downgrade(self);
        Some(crate::portal::pairing::QuicUdpReceiver::new(
            receiver,
            ready,
            self.udp_ready_tx.clone(),
            move || {
                let Some(session) = weak_session.upgrade() else {
                    return;
                };
                session.remove_udp_uplink(flow_id);
            },
        ))
    }

    pub(super) fn remove_udp_uplink(&self, flow_id: u32) {
        let mut flows = self
            .udp_flows
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let mut reassembler = self
            .udp_reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        if let Some(state) = flows.remove(&flow_id) {
            state.ready.store(false, Ordering::Release);
        }
        reassembler.remove_flow(flow_id);
    }

    pub(super) async fn take_udp_ready_requests(
        &self,
    ) -> Option<mpsc::Receiver<DatagramReadyRequest>> {
        self.udp_ready_rx.lock().await.take()
    }

    /// Closes all UDP flows owned by the session exactly once.
    pub(super) fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut flows = self
            .udp_flows
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let mut reassembler = self
            .udp_reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        for state in flows.values() {
            state.ready.store(false, Ordering::Release);
        }
        flows.clear();
        reassembler.clear();
    }
}

async fn reject_quic_control(send: &mut SendStream, code: FlowErrorCode) {
    let write = async {
        let _ = write_flow_result(send, FlowResult::Reject(code)).await;
        let _ = send.shutdown().await;
    };
    let _ = timeout(FLOW_REJECT_TIMEOUT, write).await;
}
