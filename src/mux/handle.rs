// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Public Mux handle lifecycle and logical-stream admission.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, Semaphore, mpsc, watch};

use super::driver::{closed, frame_open, run_reader, run_terminals, run_writer};
use super::{Incoming, MuxConfig, MuxHandle, MuxStream, Outbound, Shared};

impl MuxHandle {
    pub(crate) fn start<T>(io: T, config: MuxConfig) -> io::Result<(Self, Incoming)>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let config = config.validate()?;
        let (data_tx, data_rx) = mpsc::channel(config.outbound_frames);
        let (terminal_tx, terminal_rx) = mpsc::unbounded_channel();
        let (incoming_tx, incoming_rx) = mpsc::channel(config.active_stream_limit);
        let (active_streams_tx, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            config,
            flows: Mutex::new(HashMap::new()),
            connection_send_credit: Arc::new(Semaphore::new(super::credit_units(
                super::BASE_CONNECTION_WINDOW_BYTES,
            ))),
            connection_send_peak: AtomicUsize::new(super::credit_units(
                super::BASE_CONNECTION_WINDOW_BYTES,
            )),
            connection_receive_credit: Mutex::new(super::credit_units(
                config.connection_window_bytes,
            )),
            pending_connection_credit: AtomicUsize::new(super::credit_units(
                config
                    .connection_window_bytes
                    .saturating_sub(super::BASE_CONNECTION_WINDOW_BYTES),
            )),
            ready_flows: Mutex::new(VecDeque::new()),
            data_tx,
            terminal_tx,
            control_notify: Notify::new(),
            incoming_tx,
            active_streams_tx,
            closed: AtomicBool::new(false),
            closed_notify: tokio_util::sync::CancellationToken::new(),
            #[cfg(test)]
            borrowed_write_copies: AtomicUsize::new(0),
        });
        let (reader, writer) = tokio::io::split(io);
        tokio::spawn(run_reader(reader, shared.clone()));
        tokio::spawn(run_writer(writer, shared.clone(), data_rx));
        tokio::spawn(run_terminals(shared.clone(), terminal_rx));
        if config.connection_window_bytes > super::BASE_CONNECTION_WINDOW_BYTES {
            shared.control_notify.notify_one();
        }
        Ok((
            Self { shared },
            Incoming {
                receiver: incoming_rx,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) async fn open_stream(&self, flow_id: super::FlowId) -> io::Result<MuxStream> {
        let stream = self.prepare_stream(flow_id)?;
        self.open_prepared(stream).await
    }

    pub(crate) fn prepare_stream(&self, flow_id: super::FlowId) -> io::Result<MuxStream> {
        self.shared.insert_flow(flow_id, false)
    }

    pub(crate) async fn open_prepared(&self, stream: MuxStream) -> io::Result<MuxStream> {
        let flow_id = stream.flow_id();
        self.shared
            .data_tx
            .send(Outbound::Control(frame_open(
                flow_id,
                self.shared.config.stream_window_bytes,
            )?))
            .await
            .map_err(|_| closed())?;
        Ok(stream)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    pub(crate) fn active_streams(&self) -> usize {
        self.shared.flows.lock().expect("mux flow lock").len()
    }

    pub(crate) fn pressure(&self) -> usize {
        let available = self.shared.connection_send_credit.available_permits();
        let peak = self.shared.connection_send_peak.load(Ordering::Relaxed);
        let receive = *self
            .shared
            .connection_receive_credit
            .lock()
            .expect("mux credit lock");
        let receive_peak = super::credit_units(self.shared.config.connection_window_bytes);
        let queue = self.shared.config.outbound_frames;
        // Fixed-point occupancy; no per-frame timestamps or flow scans.
        let occupancy =
            |free: usize, total: usize| total.saturating_sub(free) * 1024 / total.max(1);
        occupancy(available, peak)
            .max(occupancy(receive, receive_peak))
            .max(occupancy(self.shared.data_tx.capacity(), queue))
    }

    #[cfg(test)]
    pub(crate) fn borrowed_write_copies(&self) -> usize {
        self.shared.borrowed_write_copies.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn reset_borrowed_write_copies(&self) {
        self.shared
            .borrowed_write_copies
            .store(0, Ordering::Relaxed);
    }

    pub(crate) fn close(&self) {
        self.shared.close();
    }

    #[cfg(test)]
    pub(crate) fn same_carrier(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    pub(crate) async fn idle_for(&self, duration: Duration) -> bool {
        let mut active = self.shared.active_streams_tx.subscribe();
        loop {
            if self.is_closed() {
                return false;
            }
            if *active.borrow_and_update() != 0 {
                if active.changed().await.is_err() {
                    return false;
                }
                continue;
            }
            tokio::select! {
                _ = tokio::time::sleep(duration) => {
                    if *active.borrow() == 0 && !self.is_closed() {
                        return true;
                    }
                }
                changed = active.changed() => {
                    if changed.is_err() {
                        return false;
                    }
                }
            }
        }
    }

    pub(crate) async fn closed(&self) {
        if self.is_closed() {
            return;
        }
        self.shared.closed_notify.cancelled().await;
    }
}

impl Incoming {
    pub(crate) async fn accept(&mut self) -> io::Result<Option<MuxStream>> {
        Ok(self.receiver.recv().await)
    }
}
