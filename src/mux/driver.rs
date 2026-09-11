// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{self, IoSlice};
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::wire::{
    CLOSE_FIN, FlowId, FrameHeader, FrameKind, HEADER_LEN, decode_header, encode_header,
};
use super::{Inbound, MuxChunk, Outbound, Shared};

pub(super) async fn send_data(
    shared: Arc<Shared>,
    flow_id: FlowId,
    payload: MuxChunk,
) -> io::Result<()> {
    let charge = frame_charge(payload.len());
    let (flow_credit, slot) = {
        let flows = shared.flows.lock().expect("mux flow lock");
        let flow = flows.get(&flow_id).ok_or_else(closed)?;
        (flow.send_credit.clone(), flow.send_slot.clone())
    };
    let slot = slot.acquire_owned().await.map_err(|_| closed())?;
    let flow = flow_credit
        .acquire_many_owned(charge as u32)
        .await
        .map_err(|_| closed())?;
    let connection = shared
        .connection_send_credit
        .clone()
        .acquire_many_owned(charge as u32)
        .await
        .map_err(|_| closed())?;
    shared
        .data_tx
        .send(Outbound::Data {
            header: frame_data(flow_id, payload.len())?,
            payload,
            _slot: slot,
        })
        .await
        .map_err(|_| closed())?;
    flow.forget();
    connection.forget();
    Ok(())
}

pub(super) async fn run_reader<R: AsyncRead + Unpin>(mut reader: R, shared: Arc<Shared>) {
    let operation = async {
        let mut data_frames = 0_u8;
        loop {
            if shared.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
            let mut encoded = [0; HEADER_LEN];
            tokio::select! {
                _ = shared.closed_notify.cancelled() => return Ok(()),
                result = reader.read_exact(&mut encoded) => { result?; }
            }
            let header = decode_header(&encoded).map_err(invalid)?;
            let payload_len = match header.kind {
                FrameKind::Data => header.value as usize,
                FrameKind::Open | FrameKind::Window | FrameKind::Fin | FrameKind::Reset => 0,
            };
            let mut payload = vec![0; payload_len];
            if payload_len != 0 {
                tokio::select! {
                    _ = shared.closed_notify.cancelled() => return Ok(()),
                    result = reader.read_exact(&mut payload) => { result?; }
                }
            }
            match header.kind {
                FrameKind::Open => receive_open(&shared, header).await?,
                FrameKind::Data => receive_data(&shared, header, Bytes::from(payload)).await?,
                FrameKind::Window => receive_window(&shared, header)?,
                FrameKind::Fin | FrameKind::Reset => receive_close(&shared, header).await,
            }
            if payload_len != 0 {
                data_frames = data_frames.wrapping_add(1);
                if data_frames == 32 {
                    data_frames = 0;
                    tokio::task::yield_now().await;
                }
            }
        }
    };
    let result: io::Result<()> = tokio::select! {
        biased;
        _ = shared.closed_notify.cancelled() => return,
        result = operation => result,
    };
    if result.is_err() {
        shared.close();
    }
}

async fn receive_open(shared: &Arc<Shared>, header: FrameHeader) -> io::Result<()> {
    let stream = shared.insert_flow(header.flow_id, true)?;
    let extra_credit = header.value as usize;
    if extra_credit != 0 {
        let credit = shared.send_credit(header.flow_id)?;
        if credit.available_permits().saturating_add(extra_credit)
            > super::credit_units(super::MAX_STREAM_WINDOW_BYTES)
        {
            return Err(invalid("stream window overflow"));
        }
        credit.add_permits(extra_credit);
    }
    shared.incoming_tx.send(stream).map_err(|_| closed())
}

async fn receive_data(shared: &Arc<Shared>, header: FrameHeader, payload: Bytes) -> io::Result<()> {
    let charge = frame_charge(payload.len());
    let inbound = shared.admit_receive(header.flow_id, charge)?;
    if inbound.send(Inbound::Data { payload, charge }).is_err() {
        // The local read half may be abandoned while its writer is still
        // live. Return credit for discarded bytes without killing other flows.
        shared.release_receive(header.flow_id, charge);
    }
    Ok(())
}

async fn receive_close(shared: &Shared, header: FrameHeader) {
    if header.kind == FrameKind::Reset {
        if let Some(flow) = shared.remove_flow(header.flow_id) {
            let _ = flow.inbound.send(Inbound::Reset);
        }
        return;
    }
    let inbound = {
        let mut flows = shared.flows.lock().expect("mux flow lock");
        flows.get_mut(&header.flow_id).and_then(|flow| {
            if flow.remote_fin {
                None
            } else {
                flow.remote_fin = true;
                Some(flow.inbound.clone())
            }
        })
    };
    if let Some(inbound) = inbound {
        let _ = inbound.send(Inbound::Fin);
    }
}

fn receive_window(shared: &Shared, header: FrameHeader) -> io::Result<()> {
    let credit = header.value as usize;
    if header.flow_id == 0 {
        if shared
            .connection_send_credit
            .available_permits()
            .saturating_add(credit)
            > super::credit_units(super::MAX_CONNECTION_WINDOW_BYTES)
        {
            return Err(invalid("connection window overflow"));
        }
        shared.connection_send_credit.add_permits(credit);
        shared.connection_send_peak.fetch_max(
            shared.connection_send_credit.available_permits(),
            std::sync::atomic::Ordering::Relaxed,
        );
        return Ok(());
    }
    let mut flows = shared.flows.lock().expect("mux flow lock");
    let Some(flow) = flows.get_mut(&header.flow_id) else {
        return Ok(());
    };
    if flow.send_credit.available_permits().saturating_add(credit)
        > super::credit_units(super::MAX_STREAM_WINDOW_BYTES)
    {
        return Err(invalid("stream window overflow"));
    }
    flow.send_credit.add_permits(credit);
    Ok(())
}

pub(super) async fn run_terminals(
    shared: Arc<Shared>,
    mut terminal_rx: mpsc::UnboundedReceiver<FlowId>,
) {
    loop {
        if shared.closed.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let flow_id = tokio::select! {
            _ = shared.closed_notify.cancelled() => return,
            flow_id = terminal_rx.recv() => flow_id,
        };
        let Some(flow_id) = flow_id else { return };
        let Ok(header) = frame_close(flow_id, CLOSE_FIN) else {
            continue;
        };
        let sent = tokio::select! {
            _ = shared.closed_notify.cancelled() => return,
            sent = shared.data_tx.send(Outbound::Control(header)) => sent,
        };
        if sent.is_err() {
            return;
        }
    }
}

pub(super) async fn run_writer<W: AsyncWrite + Unpin>(
    mut writer: W,
    shared: Arc<Shared>,
    mut data_rx: mpsc::Receiver<Outbound>,
) {
    let mut control = Vec::with_capacity(HEADER_LEN * 64);
    let mut headers = Vec::with_capacity(HEADER_LEN * 256);
    let mut pending_item = None;
    let operation = async {
        loop {
            if shared.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
            let item = if let Some(item) = pending_item.take() {
                Some(item)
            } else {
                tokio::select! {
                    biased;
                    _ = shared.closed_notify.cancelled() => return Ok(()),
                    _ = shared.control_notify.notified() => {
                        write_pending_windows(&mut writer, &shared, &mut control).await?;
                        continue;
                    }
                    item = data_rx.recv() => item,
                }
            };
            let Some(item) = item else { return Ok(()) };
            match item {
                Outbound::Flush(done) => {
                    let result = writer.flush().await;
                    let failed = result.is_err();
                    let _ = done.send(result);
                    if failed {
                        return Err(closed());
                    }
                }
                Outbound::Control(header) => {
                    headers.clear();
                    headers.extend_from_slice(&encode_header(header).map_err(invalid)?);
                    while headers.len() < HEADER_LEN * 256 {
                        let Ok(next) = data_rx.try_recv() else { break };
                        match next {
                            Outbound::Control(header) => {
                                headers.extend_from_slice(&encode_header(header).map_err(invalid)?);
                            }
                            next => {
                                pending_item = Some(next);
                                break;
                            }
                        }
                    }
                    writer.write_all(&headers).await?;
                    writer.flush().await?;
                }
                Outbound::Data {
                    header,
                    payload,
                    _slot,
                } => {
                    let header = encode_header(header).map_err(invalid)?;
                    write_frame_vectored(&mut writer, &header, payload.as_ref()).await?;
                    drop(_slot);
                }
            }
        }
    };
    let result: io::Result<()> = tokio::select! {
        biased;
        _ = shared.closed_notify.cancelled() => return,
        result = operation => result,
    };
    if result.is_err() {
        shared.close();
    }
}

async fn write_frame_vectored<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &[u8; HEADER_LEN],
    payload: &[u8],
) -> io::Result<()> {
    let mut header_offset = 0;
    let mut payload_offset = 0;
    while header_offset != header.len() || payload_offset != payload.len() {
        let written = if header_offset != header.len() {
            writer
                .write_vectored(&[
                    IoSlice::new(&header[header_offset..]),
                    IoSlice::new(&payload[payload_offset..]),
                ])
                .await?
        } else {
            writer.write(&payload[payload_offset..]).await?
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write mux frame",
            ));
        }
        let header_remaining = header.len() - header_offset;
        if written <= header_remaining {
            header_offset += written;
        } else {
            header_offset = header.len();
            payload_offset += written - header_remaining;
        }
    }
    Ok(())
}

async fn write_pending_windows<W: AsyncWrite + Unpin>(
    writer: &mut W,
    shared: &Shared,
    encoded: &mut Vec<u8>,
) -> io::Result<()> {
    encoded.clear();
    let connection = shared
        .pending_connection_credit
        .swap(0, std::sync::atomic::Ordering::AcqRel);
    let ready = shared
        .ready_flows
        .lock()
        .expect("mux ready-flow lock")
        .drain(..)
        .collect::<Vec<_>>();
    let flows = {
        let mut flows = shared.flows.lock().expect("mux flow lock");
        ready
            .into_iter()
            .filter_map(|flow_id| {
                let flow = flows.get_mut(&flow_id)?;
                let credit = std::mem::take(&mut flow.pending_receive_credit);
                flow.window_queued = false;
                (credit != 0).then_some((flow_id, credit))
            })
            .collect::<Vec<_>>()
    };
    append_windows(encoded, 0, connection)?;
    for (flow_id, credit) in flows {
        append_windows(encoded, flow_id, credit)?;
    }
    if !encoded.is_empty() {
        writer.write_all(encoded).await?;
        writer.flush().await?;
    }
    Ok(())
}

fn append_windows(encoded: &mut Vec<u8>, flow_id: FlowId, mut credit: usize) -> io::Result<()> {
    while credit != 0 {
        let delta = credit.min(u16::MAX as usize);
        let header = FrameHeader::window(flow_id, delta).map_err(invalid)?;
        encoded.extend_from_slice(&encode_header(header).map_err(invalid)?);
        credit -= delta;
    }
    Ok(())
}

fn frame_charge(payload: usize) -> usize {
    super::credit_units(payload)
}

pub(super) fn frame_open(flow_id: FlowId, receive_window_bytes: usize) -> io::Result<FrameHeader> {
    let extra = receive_window_bytes.saturating_sub(super::BASE_STREAM_WINDOW_BYTES);
    FrameHeader::open(flow_id, super::credit_units(extra)).map_err(invalid)
}

pub(super) fn frame_data(flow_id: FlowId, length: usize) -> io::Result<FrameHeader> {
    FrameHeader::data(flow_id, length).map_err(invalid)
}

pub(super) fn frame_close(flow_id: FlowId, code: u8) -> io::Result<FrameHeader> {
    FrameHeader::close(flow_id, code).map_err(invalid)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(super) fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "mux carrier is closed")
}
