// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Typed UoT and QUIC DATAGRAM relay for split or duplex UDP flows.

use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::common::{UdpDatagramSend, send_quic_udp_packet};
use crate::portal::PortalInner;
use crate::portal::pairing::{PairedUdp, UdpDown, UdpUp};
use crate::protocol::{
    Carrier, FlowErrorCode, FlowResult, encode_udp_close, read_udp_packet_into, write_flow_result,
    write_udp_packet,
};
use crate::telemetry::{AccessOutcome, AccessStart, TrafficProtocol, now_unix_ms};

use super::{
    SessionGuard, UDP_TRANSFER_COMPLETE, UDP_TRANSFER_STARTING, access_exchange_path,
    paired_exchange_path,
};

const FLOW_RESULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const FLOW_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Relays one UDP flow through independently selected upload and download carriers.
pub(in crate::portal) async fn relay_paired_udp(portal: Arc<PortalInner>, paired: PairedUdp) {
    let PairedUdp {
        flow_id,
        target,
        mut uplink,
        mut downlink,
        uplink_carrier,
        downlink_carrier,
        hops,
        uplink_path,
        downlink_path,
        _flow_lease,
    } = paired;
    let target_addr = target.to_string();
    let access = portal.telemetry.start_access(|| AccessStart {
        id: 0,
        timestamp_ms: now_unix_ms(),
        protocol: TrafficProtocol::Udp,
        wire_version: Some(uplink_path.version),
        flow_id: Some(flow_id.into()),
        session_tag: None,
        client: Some(uplink_path.peer.clone()),
        path_peers: vec![uplink_path.peer.clone(), downlink_path.peer.clone()],
        target: target_addr.clone(),
        initial_uplink: Some(uplink_carrier),
        initial_downlink: Some(downlink_carrier),
        path: Some(access_exchange_path(
            uplink_carrier,
            &uplink_path,
            &target_addr,
            downlink_carrier,
            &downlink_path,
        )),
    });
    let cancel = _flow_lease.cancellation_token();
    let dial = tokio::select! {
        biased;
        _ = cancel.cancelled() => UdpTargetDial::Cancelled,
        _ = portal.drain.cancelled() => UdpTargetDial::Draining,
        result = portal.outbound.dial_udp_target(&target, hops, portal.runtime.udp_dial_timeout) => {
            match result {
                Ok(socket) => UdpTargetDial::Connected(socket),
                Err(error) => UdpTargetDial::Failed(error),
            }
        },
    };
    let mut socket = match dial {
        UdpTargetDial::Connected(socket) => socket,
        UdpTargetDial::Cancelled => {
            let _ = send_udp_result_bounded(
                &mut downlink,
                FlowResult::Reject(FlowErrorCode::SessionReplaced),
            )
            .await;
            access.finish(AccessOutcome::Cancelled, None);
            return;
        }
        UdpTargetDial::Draining => {
            let _ = send_udp_result_bounded(
                &mut downlink,
                FlowResult::Reject(FlowErrorCode::FlowLimit),
            )
            .await;
            access.finish(AccessOutcome::Rejected, Some("portal draining".to_owned()));
            return;
        }
        UdpTargetDial::Failed(err) => {
            let code = if cancel.is_cancelled() {
                FlowErrorCode::SessionReplaced
            } else if portal.drain.is_cancelled() {
                FlowErrorCode::FlowLimit
            } else if let Some(result) = err.setup_result() {
                FlowErrorCode::try_from(result).unwrap_or(FlowErrorCode::InternalError)
            } else {
                FlowErrorCode::DialFailed
            };
            let _ = send_udp_result_bounded(&mut downlink, FlowResult::Reject(code)).await;
            portal.logger.debug(format_args!(
                "portal::conn::relay_paired_udp: target dial failed: {err}"
            ));
            let error = err.to_string();
            access.finish(error_outcome(&error), Some(error));
            return;
        }
    };
    if let UdpUp::Quic(receiver) = &mut uplink {
        let preparation = tokio::select! {
            biased;
            _ = cancel.cancelled() => Preparation::Cancelled,
            _ = portal.drain.cancelled() => Preparation::Draining,
            prepared = receiver.prepare_ready() => Preparation::Prepared(prepared),
        };
        match preparation {
            Preparation::Prepared(true) => {}
            Preparation::Cancelled => {
                let _ = send_udp_result_bounded(
                    &mut downlink,
                    FlowResult::Reject(FlowErrorCode::SessionReplaced),
                )
                .await;
                access.finish(AccessOutcome::Cancelled, None);
                return;
            }
            Preparation::Draining => {
                let _ = send_udp_result_bounded(
                    &mut downlink,
                    FlowResult::Reject(FlowErrorCode::FlowLimit),
                )
                .await;
                access.finish(AccessOutcome::Rejected, Some("portal draining".to_owned()));
                return;
            }
            Preparation::Prepared(false) => {
                let _ = send_udp_result_bounded(
                    &mut downlink,
                    FlowResult::Reject(FlowErrorCode::InternalError),
                )
                .await;
                access.finish(
                    AccessOutcome::Error,
                    Some("QUIC datagram route preparation failed".to_owned()),
                );
                return;
            }
        }
    }
    match commit_udp_ready(&cancel, &portal.ready_gate, &mut downlink).await {
        Ok(true) => {
            // READY is now queued on the authoritative downlink. Activate the
            // DATAGRAM route synchronously before the peer can observe it and
            // return its first packet.
            if let UdpUp::Quic(receiver) = &uplink {
                receiver.activate();
            }
        }
        Ok(false) => {
            access.finish(
                AccessOutcome::Rejected,
                Some("flow setup rejected".to_owned()),
            );
            return;
        }
        Err(error) => {
            access.finish(AccessOutcome::Error, Some(error.to_string()));
            return;
        }
    }
    if portal.logger.debug_enabled() {
        let target_local = socket.local_label();
        portal.logger.debug(format_args!(
            "portal::conn::relay_paired_udp: {}: {}",
            UDP_TRANSFER_STARTING,
            paired_exchange_path(
                uplink_carrier,
                &uplink_path,
                &target_local,
                &target_addr,
                downlink_carrier,
                &downlink_path,
            )
        ));
    }
    portal.stats.add_session(true);
    let _done = SessionGuard::new(portal.clone(), true);
    let mut packet_id = 1u32;
    let mut target_buf = portal.buffers.get_udp_buffer();
    let mut target_packet = Vec::new();
    let mut uot_packet = Vec::new();
    let mut downlink_liveness = match &mut downlink {
        UdpDown::TlsTcp { liveness, .. } => liveness.take(),
        UdpDown::Quic { .. } => None,
    };
    let idle_sleep = tokio::time::sleep_until(Instant::now() + portal.runtime.udp_idle_timeout);
    tokio::pin!(idle_sleep);
    let activity = Notify::new();
    let mut downlink_frame_incomplete = false;
    let completion = {
        let (mut target_send, mut target_recv) = socket.split_mut();
        let uplink_pipeline = async {
            loop {
                let n = match &mut uplink {
                    UdpUp::TlsTcp(reader) => {
                        let Some(length) = read_udp_packet_into(reader, &mut uot_packet).await?
                        else {
                            return anyhow::Ok(());
                        };
                        if let Some(limiter) = &portal.rate_limiter {
                            limiter.wait_read(length as i64).await;
                        }
                        target_send
                            .send(&uot_packet[..length], &mut target_packet)
                            .await?
                    }
                    UdpUp::Quic(receiver) => {
                        let Some(payload) = receiver.recv().await else {
                            return anyhow::Ok(());
                        };
                        if let Some(limiter) = &portal.rate_limiter {
                            limiter.wait_read(payload.len() as i64).await;
                        }
                        target_send.send(&payload, &mut target_packet).await?
                    }
                };
                access.add_upload(n as u64);
                portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                match uplink_carrier {
                    Carrier::TlsTcp => &portal.stats.up_tcp,
                    Carrier::Quic => &portal.stats.up_udp,
                }
                .fetch_add(n as u64, Ordering::Relaxed);
                activity.notify_one();
            }
        };
        let downlink_pipeline = async {
            loop {
                let packet = match target_recv.recv(&mut target_buf).await {
                    Ok(Some(packet)) => packet,
                    Ok(None) => return Ok(()),
                    Err(err) => return Err::<(), anyhow::Error>(err),
                };
                let payload = packet.payload(&target_buf);
                let n = payload.len();
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_write(n as i64).await;
                }
                downlink_frame_incomplete = true;
                let outcome =
                    send_paired_udp(&mut downlink, flow_id, &mut packet_id, payload).await;
                let outcome = match outcome {
                    Ok(outcome) => {
                        downlink_frame_incomplete = false;
                        outcome
                    }
                    Err(err) => return Err::<(), anyhow::Error>(err),
                };
                match outcome {
                    UdpDatagramSend::Sent => {
                        access.add_download(n as u64);
                        portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                        match downlink_carrier {
                            Carrier::TlsTcp => &portal.stats.down_tcp,
                            Carrier::Quic => &portal.stats.down_udp,
                        }
                        .fetch_add(n as u64, Ordering::Relaxed);
                    }
                    UdpDatagramSend::DroppedTooLarge => {}
                }
                activity.notify_one();
            }
        };
        tokio::pin!(uplink_pipeline);
        tokio::pin!(downlink_pipeline);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break UdpCompletion::Cancelled,
                _ = async {
                    if let Some(liveness) = &mut downlink_liveness {
                        let mut byte = [0u8; 1];
                        let _ = liveness.read(&mut byte).await;
                    } else {
                        pending::<()>().await;
                    }
                } => break UdpCompletion::Success("downlink closed"),
                result = &mut uplink_pipeline => break match result {
                    Ok(()) => UdpCompletion::Success("uplink closed"),
                    Err(err) => UdpCompletion::Error(format!("uplink or target write error: {err}")),
                },
                result = &mut downlink_pipeline => break match result {
                    Ok(()) => UdpCompletion::Success("downlink closed"),
                    Err(err) => UdpCompletion::Error(format!("target read or downlink write error: {err}")),
                },
                _ = activity.notified() => {
                    idle_sleep
                        .as_mut()
                        .reset(Instant::now() + portal.runtime.udp_idle_timeout);
                }
                _ = &mut idle_sleep => break UdpCompletion::Timeout,
            }
        }
    };
    socket.close().await;
    finish_udp_downlink(&mut downlink, flow_id, downlink_frame_incomplete).await;
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_udp: {}: {}",
        UDP_TRANSFER_COMPLETE,
        completion.reason(),
    ));
    match completion {
        UdpCompletion::Success(_) => access.finish(AccessOutcome::Success, None),
        UdpCompletion::Cancelled => access.finish(AccessOutcome::Cancelled, None),
        UdpCompletion::Timeout => {
            access.finish(AccessOutcome::Timeout, Some("idle timeout".to_owned()));
        }
        UdpCompletion::Error(error) => {
            let outcome = error_outcome(&error);
            access.finish(outcome, Some(error));
        }
    }
}

enum UdpTargetDial<T> {
    Connected(T),
    Cancelled,
    Draining,
    Failed(crate::portal::outbound::OutboundError),
}

enum Preparation {
    Prepared(bool),
    Cancelled,
    Draining,
}

enum UdpCompletion {
    Success(&'static str),
    Cancelled,
    Timeout,
    Error(String),
}

impl UdpCompletion {
    fn reason(&self) -> &str {
        match self {
            Self::Success(reason) => reason,
            Self::Cancelled => "cancelled",
            Self::Timeout => "idle timeout",
            Self::Error(error) => error,
        }
    }
}

fn error_outcome(error: &str) -> AccessOutcome {
    if error.to_ascii_lowercase().contains("timeout") {
        AccessOutcome::Timeout
    } else {
        AccessOutcome::Error
    }
}

async fn send_udp_result(downlink: &mut UdpDown, result: FlowResult) -> anyhow::Result<()> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            write_flow_result(writer, result).await?;
            if matches!(result, FlowResult::Reject(_)) {
                writer.shutdown().await?;
            }
        }
        UdpDown::Quic { control, .. } => {
            send_quic_control_result(control, result).await?;
        }
    }
    Ok(())
}

async fn send_quic_control_result(
    control: &mut crate::portal::pairing::BoxWriter,
    result: FlowResult,
) -> anyhow::Result<()> {
    write_flow_result(control, result).await?;
    control.shutdown().await?;
    Ok(())
}

/// Commits the single setup result. As with TCP, cancellation is sampled only
/// before READY starts so a partially written READY is never followed by a
/// second control result.
async fn commit_udp_ready(
    cancel: &tokio_util::sync::CancellationToken,
    ready_gate: &crate::portal::tasks::ReadyGate,
    downlink: &mut UdpDown,
) -> anyhow::Result<bool> {
    if cancel.is_cancelled() {
        send_udp_result_bounded(downlink, FlowResult::Reject(FlowErrorCode::SessionReplaced))
            .await?;
        return Ok(false);
    }
    let Some(_ready_permit) = ready_gate.try_enter() else {
        send_udp_result_bounded(downlink, FlowResult::Reject(FlowErrorCode::FlowLimit)).await?;
        return Ok(false);
    };
    if cancel.is_cancelled() {
        send_udp_result_bounded(downlink, FlowResult::Reject(FlowErrorCode::SessionReplaced))
            .await?;
        return Ok(false);
    }
    send_udp_result_bounded(downlink, FlowResult::Ready).await?;
    Ok(true)
}

async fn send_udp_result_bounded(downlink: &mut UdpDown, result: FlowResult) -> anyhow::Result<()> {
    tokio::time::timeout(FLOW_RESULT_TIMEOUT, send_udp_result(downlink, result))
        .await
        .map_err(|_| anyhow::anyhow!("flow result write timeout"))?
}

async fn send_paired_udp(
    downlink: &mut UdpDown,
    flow_id: u32,
    packet_id: &mut u32,
    payload: &[u8],
) -> anyhow::Result<UdpDatagramSend> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            write_udp_packet(writer, payload).await?;
            Ok(UdpDatagramSend::Sent)
        }
        UdpDown::Quic { conn, .. } => send_quic_udp_packet(conn, flow_id, packet_id, payload).await,
    }
}

async fn send_udp_close(downlink: &mut UdpDown, flow_id: u32) -> anyhow::Result<()> {
    match downlink {
        UdpDown::TlsTcp { writer, .. } => {
            writer.shutdown().await?;
        }
        UdpDown::Quic { conn, .. } => {
            conn.send_datagram_wait(Bytes::copy_from_slice(&encode_udp_close(flow_id)?))
                .await?;
        }
    }
    Ok(())
}

async fn finish_udp_downlink(downlink: &mut UdpDown, flow_id: u32, frame_incomplete: bool) {
    // A cancelled write_all may have emitted only a prefix of a UoT DATA
    // frame. Appending CLOSE would corrupt the stream; each UoT flow owns its
    // connection, so EOF is the only safe termination in that case. QUIC
    // DATAGRAM frames are atomic and can still receive an advisory CLOSE.
    if frame_incomplete && matches!(&*downlink, UdpDown::TlsTcp { .. }) {
        return;
    }
    let _ = tokio::time::timeout(FLOW_CLOSE_TIMEOUT, send_udp_close(downlink, flow_id)).await;
}

#[cfg(test)]
#[path = "../../tests/portal/conn/relay_uot.rs"]
mod tests;
