// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::io;
use std::io::IoSlice;
use std::sync::Arc;

use super::wire::{
    FLAG_FIN, FLAG_RST, FLAG_SYN, FlowId, FrameHeader, FrameKind, HEADER_LEN, decode_header,
    encode_header,
};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::{Inbound, MuxChunk, Outbound, Shared};

pub(super) async fn send_data(
    shared: Arc<Shared>,
    flow_id: FlowId,
    payload: MuxChunk,
) -> io::Result<()> {
    let charge = frame_charge(payload.len());
    let flow_credit = shared.send_credit(flow_id)?;
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
        .send(Outbound {
            header: frame_stream(flow_id, 0, payload.len())?,
            payload,
            flushed: None,
        })
        .await
        .map_err(|_| closed())?;
    flow.forget();
    connection.forget();
    Ok(())
}

pub(super) async fn run_reader<R: AsyncRead + Unpin>(mut reader: R, shared: Arc<Shared>) {
    let result: io::Result<()> = async {
        let mut data_frames = 0_u8;
        loop {
            if shared.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
            let mut encoded = [0; HEADER_LEN];
            tokio::select! {
                _ = shared.closed_notify.notified() => return Ok(()),
                result = reader.read_exact(&mut encoded) => { result?; }
            }
            let header = decode_header(&encoded).map_err(invalid)?;
            let payload_len = match header.kind {
                FrameKind::Stream if header.flags & FLAG_SYN == 0 => header.value as usize,
                FrameKind::Stream | FrameKind::Window => 0,
            };
            let mut payload = vec![0; payload_len];
            if !payload.is_empty() {
                tokio::select! {
                    _ = shared.closed_notify.notified() => return Ok(()),
                    result = reader.read_exact(&mut payload) => { result?; }
                }
            }
            match header.kind {
                FrameKind::Stream => receive_stream(&shared, header, Bytes::from(payload)).await?,
                FrameKind::Window => receive_window(&shared, header)?,
            }
            if payload_len != 0 {
                data_frames = data_frames.wrapping_add(1);
                if data_frames == 32 {
                    data_frames = 0;
                    tokio::task::yield_now().await;
                }
            }
        }
    }
    .await;
    if result.is_err() {
        shared.close();
    }
}

async fn receive_stream(
    shared: &Arc<Shared>,
    header: FrameHeader,
    payload: Bytes,
) -> io::Result<()> {
    if header.flags & FLAG_SYN != 0 {
        let terminal_permit = shared.reserve_terminal().await?;
        let stream = shared.insert_flow(header.flow_id, terminal_permit, true)?;
        let extra_credit = header.value as usize;
        if extra_credit != 0 {
            let credit = shared.send_credit(header.flow_id)?;
            if credit.available_permits().saturating_add(extra_credit)
                > super::credit_units(super::MAX_STREAM_WINDOW_BYTES)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream window overflow",
                ));
            }
            credit.add_permits(extra_credit);
        }
        shared
            .incoming_tx
            .send(stream)
            .await
            .map_err(|_| closed())?;
    }
    if header.flags & FLAG_RST != 0 {
        let flow = shared.remove_flow(header.flow_id);
        if let Some(flow) = flow {
            let _ = flow.inbound.send(Inbound::Reset).await;
        }
        return Ok(());
    }
    if !payload.is_empty() {
        let charge = frame_charge(payload.len());
        let inbound = shared.admit_receive(header.flow_id, charge)?;
        inbound
            .send(Inbound::Data { payload, charge })
            .await
            .map_err(|_| closed())?;
    }
    if header.flags & FLAG_FIN != 0 {
        let inbound = shared
            .flows
            .lock()
            .expect("mux flow lock")
            .get(&header.flow_id)
            .map(|flow| flow.inbound.clone());
        if let Some(inbound) = inbound {
            let _ = inbound.send(Inbound::Fin).await;
        }
    }
    Ok(())
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connection window overflow",
            ));
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
        // Flow-close frames and their final credit updates can cross on the
        // full-duplex carrier. A late stream-local WINDOW has no authority to
        // change connection credit and is safe to ignore.
        return Ok(());
    };
    if flow.send_credit.available_permits().saturating_add(credit)
        > super::credit_units(super::MAX_STREAM_WINDOW_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stream window overflow",
        ));
    }
    flow.send_credit.add_permits(credit);
    Ok(())
}

pub(super) async fn run_terminals(shared: Arc<Shared>, mut terminal_rx: mpsc::Receiver<FlowId>) {
    loop {
        if shared.closed.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let flow_id = tokio::select! {
            _ = shared.closed_notify.notified() => return,
            flow_id = terminal_rx.recv() => flow_id,
        };
        let Some(flow_id) = flow_id else { return };
        let Ok(header) = frame_stream(flow_id, FLAG_FIN, 0) else {
            continue;
        };
        let sent = tokio::select! {
            _ = shared.closed_notify.notified() => return,
            sent = shared.data_tx.send(Outbound {
                header,
                payload: MuxChunk::empty(),
                flushed: None,
            }) => sent,
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
    let mut control = Vec::with_capacity(8 * 64);
    let mut headers = Vec::with_capacity(8 * 256);
    let mut pending_item = None;
    let result: io::Result<()> = async {
        loop {
            if shared.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(());
            }
            let item = if let Some(item) = pending_item.take() {
                Some(item)
            } else {
                tokio::select! {
                    biased;
                    _ = shared.closed_notify.notified() => return Ok(()),
                    _ = shared.control_notify.notified() => {
                        write_pending_windows(&mut writer, &shared, &mut control).await?;
                        continue;
                    }
                    item = data_rx.recv() => item,
                }
            };
            let Some(item) = item else { return Ok(()) };
            if item.flushed.is_some() && item.payload.is_empty() && item.header.flags == 0 {
                let result = writer.flush().await;
                if let Some(done) = item.flushed {
                    let _ = done.send(result);
                }
                continue;
            }
            if item.flushed.is_none() && item.payload.is_empty() {
                headers.clear();
                headers.extend_from_slice(&encode_header(item.header).map_err(invalid)?);
                while headers.len() < 8 * 256 {
                    let Ok(next) = data_rx.try_recv() else { break };
                    if next.flushed.is_none() && next.payload.is_empty() {
                        headers.extend_from_slice(&encode_header(next.header).map_err(invalid)?);
                    } else {
                        pending_item = Some(next);
                        break;
                    }
                }
                writer.write_all(&headers).await?;
                writer.flush().await?;
                continue;
            }
            let header = encode_header(item.header).map_err(invalid)?;
            write_frame_vectored(&mut writer, &header, item.payload.as_ref()).await?;
        }
    }
    .await;
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
            let buffers = [
                IoSlice::new(&header[header_offset..]),
                IoSlice::new(&payload[payload_offset..]),
            ];
            writer.write_vectored(&buffers).await?
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
    FrameHeader::stream(flow_id, FLAG_SYN, super::credit_units(extra)).map_err(invalid)
}

pub(super) fn frame_stream(flow_id: FlowId, flags: u8, length: usize) -> io::Result<FrameHeader> {
    FrameHeader::stream(flow_id, flags, length).map_err(invalid)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(super) fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "mux carrier is closed")
}
