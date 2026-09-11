// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot, watch};

use self::driver::closed;
use self::wire::{FlowId, FrameHeader};

mod driver;
mod handle;
mod stream;
mod wire;

pub(crate) const FRAME_BYTES: usize = 32 * 1024;
const MIB: usize = 1024 * 1024;
const BASE_STREAM_WINDOW_BYTES: usize = 4 * MIB;
const BASE_CONNECTION_WINDOW_BYTES: usize = 8 * MIB;
const MAX_STREAM_WINDOW_BYTES: usize = 16 * MIB;
const MAX_CONNECTION_WINDOW_BYTES: usize = 32 * MIB;
const CREDIT_UNIT_BYTES: usize = 1024;
const WINDOW_UPDATE_DIVISOR: usize = 8;
const ACTIVE_STREAM_RESOURCE_LIMIT: usize = 4096;
pub(crate) const MUX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MuxConfig {
    pub stream_window_bytes: usize,
    pub connection_window_bytes: usize,
    pub active_stream_limit: usize,
    pub outbound_frames: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self::from_flow_control(crate::transport::transport_flow_control().unwrap_or(
            crate::transport::TransportFlowControl {
                stream_receive_window: MAX_STREAM_WINDOW_BYTES as u32,
                connection_receive_window: MAX_CONNECTION_WINDOW_BYTES as u32,
                send_window: MAX_CONNECTION_WINDOW_BYTES as u64,
            },
        ))
    }
}

impl MuxConfig {
    pub(crate) fn from_flow_control(profile: crate::transport::TransportFlowControl) -> Self {
        Self {
            stream_window_bytes: profile.stream_receive_window as usize,
            connection_window_bytes: profile.connection_receive_window as usize,
            active_stream_limit: ACTIVE_STREAM_RESOURCE_LIMIT,
            outbound_frames: 512,
        }
    }
    fn validate(self) -> io::Result<Self> {
        if self.stream_window_bytes < BASE_STREAM_WINDOW_BYTES
            || self.stream_window_bytes > MAX_STREAM_WINDOW_BYTES
            || self.connection_window_bytes < BASE_CONNECTION_WINDOW_BYTES
            || self.connection_window_bytes > MAX_CONNECTION_WINDOW_BYTES
            || !self.stream_window_bytes.is_multiple_of(CREDIT_UNIT_BYTES)
            || !self
                .connection_window_bytes
                .is_multiple_of(CREDIT_UNIT_BYTES)
            || self.connection_window_bytes < self.stream_window_bytes
            || self.active_stream_limit == 0
            || self.outbound_frames == 0
            || self.connection_window_bytes > Semaphore::MAX_PERMITS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid mux limits",
            ));
        }
        Ok(self)
    }
}

pub(crate) struct MuxStream {
    reader: FlowReader,
    writer: FlowWriter,
}

pub(crate) struct MuxChunk {
    payload: Bytes,
    _credit: Option<ReceiveCredit>,
}

struct ReceiveCredit {
    shared: Arc<Shared>,
    flow_id: FlowId,
    charge: usize,
}

pub(crate) struct FlowReader {
    shared: Arc<Shared>,
    flow_id: FlowId,
    receiver: mpsc::UnboundedReceiver<Inbound>,
    current: Option<(Bytes, usize, usize)>,
    eof: bool,
}

pub(crate) struct FlowWriter {
    shared: Arc<Shared>,
    flow_id: FlowId,
    pending: Option<WriteFuture>,
    pending_action: Option<ActionFuture>,
    closed: bool,
}

#[derive(Clone)]
pub(crate) struct MuxHandle {
    shared: Arc<Shared>,
}

pub(crate) struct Incoming {
    receiver: mpsc::Receiver<MuxStream>,
}

type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;
type ActionFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct Shared {
    config: MuxConfig,
    flows: Mutex<HashMap<FlowId, FlowState>>,
    connection_send_credit: Arc<Semaphore>,
    connection_send_peak: AtomicUsize,
    connection_receive_credit: Mutex<usize>,
    pending_connection_credit: AtomicUsize,
    ready_flows: Mutex<VecDeque<FlowId>>,
    data_tx: mpsc::Sender<Outbound>,
    terminal_tx: mpsc::Sender<FlowId>,
    control_notify: Notify,
    incoming_tx: mpsc::Sender<MuxStream>,
    active_streams_tx: watch::Sender<usize>,
    closed: AtomicBool,
    closed_notify: tokio_util::sync::CancellationToken,
    #[cfg(test)]
    borrowed_write_copies: AtomicUsize,
}

struct FlowState {
    inbound: mpsc::UnboundedSender<Inbound>,
    send_credit: Arc<Semaphore>,
    send_slot: Arc<Semaphore>,
    receive_credit: usize,
    pending_receive_credit: usize,
    window_queued: bool,
    local_parts: u8,
    remote_fin: bool,
}

enum Inbound {
    Data { payload: Bytes, charge: usize },
    Fin,
    Reset,
}

enum Outbound {
    Data {
        header: FrameHeader,
        payload: MuxChunk,
        _slot: tokio::sync::OwnedSemaphorePermit,
    },
    Control(FrameHeader),
    Flush(oneshot::Sender<io::Result<()>>),
}

impl MuxChunk {
    pub(crate) fn from_bytes(payload: Bytes) -> Self {
        Self {
            payload,
            _credit: None,
        }
    }

    fn received(payload: Bytes, shared: Arc<Shared>, flow_id: FlowId, charge: usize) -> Self {
        Self {
            payload,
            _credit: Some(ReceiveCredit {
                shared,
                flow_id,
                charge,
            }),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.payload.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

impl AsRef<[u8]> for MuxChunk {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}

impl Drop for ReceiveCredit {
    fn drop(&mut self) {
        self.shared.release_receive(self.flow_id, self.charge);
    }
}

impl Shared {
    fn insert_flow(
        self: &Arc<Self>,
        flow_id: FlowId,
        advertise_window: bool,
    ) -> io::Result<MuxStream> {
        if flow_id == 0 || flow_id > crate::protocol::MAX_FLOW_ID {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flow ID is outside the 30-bit range",
            ));
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        // DATA is bounded separately by byte credit. OPEN must have its own
        // admission ceiling because it allocates flow metadata without DATA.
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut flows = self.flows.lock().expect("mux flow lock");
        if self.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        if flows.contains_key(&flow_id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "mux flow already exists",
            ));
        }
        if flows.len() >= self.config.active_stream_limit {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "mux active-stream resource limit reached",
            ));
        }
        let send_credit = Arc::new(Semaphore::new(credit_units(BASE_STREAM_WINDOW_BYTES)));
        let initial_credit = if advertise_window {
            credit_units(
                self.config
                    .stream_window_bytes
                    .saturating_sub(BASE_STREAM_WINDOW_BYTES),
            )
        } else {
            0
        };
        flows.insert(
            flow_id,
            FlowState {
                inbound: sender,
                send_credit,
                send_slot: Arc::new(Semaphore::new(1)),
                receive_credit: credit_units(self.config.stream_window_bytes),
                pending_receive_credit: initial_credit,
                window_queued: advertise_window && initial_credit != 0,
                local_parts: 2,
                remote_fin: false,
            },
        );
        let active_streams = flows.len();
        self.active_streams_tx.send_replace(active_streams);
        drop(flows);
        if advertise_window && initial_credit != 0 {
            self.ready_flows
                .lock()
                .expect("mux ready-flow lock")
                .push_back(flow_id);
            self.control_notify.notify_one();
        }
        Ok(MuxStream {
            reader: FlowReader {
                shared: self.clone(),
                flow_id,
                receiver,
                current: None,
                eof: false,
            },
            writer: FlowWriter {
                shared: self.clone(),
                flow_id,
                pending: None,
                pending_action: None,
                closed: false,
            },
        })
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut flows = self.flows.lock().expect("mux flow lock");
        for flow in flows.values() {
            flow.send_credit.close();
            flow.send_slot.close();
        }
        flows.clear();
        self.active_streams_tx.send_replace(0);
        drop(flows);
        self.connection_send_credit.close();
        self.closed_notify.cancel();
    }

    fn send_credit(&self, flow_id: FlowId) -> io::Result<Arc<Semaphore>> {
        self.flows
            .lock()
            .expect("mux flow lock")
            .get(&flow_id)
            .map(|flow| flow.send_credit.clone())
            .ok_or_else(closed)
    }

    fn remove_flow(&self, flow_id: FlowId) -> Option<FlowState> {
        let mut flows = self.flows.lock().expect("mux flow lock");
        let removed = flows.remove(&flow_id);
        if let Some(flow) = &removed {
            flow.send_credit.close();
            flow.send_slot.close();
        }
        let active_streams = flows.len();
        self.active_streams_tx.send_replace(active_streams);
        drop(flows);
        removed
    }

    fn admit_receive(
        &self,
        flow_id: FlowId,
        charge: usize,
    ) -> io::Result<mpsc::UnboundedSender<Inbound>> {
        let mut connection = self
            .connection_receive_credit
            .lock()
            .expect("mux credit lock");
        let mut flows = self.flows.lock().expect("mux flow lock");
        let flow = flows.get_mut(&flow_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "frame for unknown mux flow")
        })?;
        if flow.remote_fin {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DATA received after mux FIN",
            ));
        }
        if flow.receive_credit < charge || *connection < charge {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer exceeded mux window",
            ));
        }
        flow.receive_credit -= charge;
        *connection -= charge;
        Ok(flow.inbound.clone())
    }

    fn release_receive(&self, flow_id: FlowId, charge: usize) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let (flow_ready, flow_notify) = {
            let mut connection = self
                .connection_receive_credit
                .lock()
                .expect("mux credit lock");
            *connection = connection
                .saturating_add(charge)
                .min(credit_units(self.config.connection_window_bytes));
            if let Some(flow) = self.flows.lock().expect("mux flow lock").get_mut(&flow_id) {
                flow.receive_credit = flow
                    .receive_credit
                    .saturating_add(charge)
                    .min(credit_units(self.config.stream_window_bytes));
                flow.pending_receive_credit = flow.pending_receive_credit.saturating_add(charge);
                let ready = if flow.window_queued {
                    false
                } else {
                    flow.window_queued = true;
                    true
                };
                let threshold =
                    credit_units(self.config.stream_window_bytes / WINDOW_UPDATE_DIVISOR)
                        .min(u16::MAX as usize);
                (ready, flow.pending_receive_credit >= threshold)
            } else {
                (false, false)
            }
        };
        if flow_ready {
            self.ready_flows
                .lock()
                .expect("mux ready-flow lock")
                .push_back(flow_id);
        }
        let previous = self
            .pending_connection_credit
            .fetch_add(charge, Ordering::AcqRel);
        let threshold = credit_units(self.config.connection_window_bytes / WINDOW_UPDATE_DIVISOR)
            .min(u16::MAX as usize);
        if flow_notify || previous.saturating_add(charge) >= threshold {
            self.control_notify.notify_one();
        }
    }

    fn release_part(&self, flow_id: FlowId) {
        let mut flows = self.flows.lock().expect("mux flow lock");
        let Some(flow) = flows.get_mut(&flow_id) else {
            return;
        };
        let flush_credit = flow.pending_receive_credit != 0;
        flow.local_parts = flow.local_parts.saturating_sub(1);
        if flow.local_parts == 0 {
            flows.remove(&flow_id);
        }
        let active_streams = flows.len();
        self.active_streams_tx.send_replace(active_streams);
        drop(flows);
        if flush_credit {
            self.control_notify.notify_one();
        }
    }
}

fn credit_units(bytes: usize) -> usize {
    bytes.div_ceil(CREDIT_UNIT_BYTES)
}

#[cfg(test)]
#[path = "../tests/mux/runtime.rs"]
mod tests;
