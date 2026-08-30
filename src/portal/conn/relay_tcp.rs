// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP target dialing and split/duplex stream relay.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::portal::PortalInner;
use crate::portal::pairing::PairedTcp;
use crate::protocol::{FlowErrorCode, FlowResult, write_flow_result};
use crate::telemetry::{AccessOutcome, AccessStart, TrafficProtocol, now_unix_ms};

use super::stream::relay_stream;
use super::{
    SessionGuard, TCP_EXCHANGE_COMPLETE, TCP_EXCHANGE_STARTING, access_exchange_path,
    paired_exchange_path,
};

const FLOW_RESULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Relays a TCP target through independently selected upload and download halves.
pub(in crate::portal) async fn relay_paired_tcp(portal: Arc<PortalInner>, paired: PairedTcp) {
    let PairedTcp {
        flow_id,
        target,
        uplink: mut client_read,
        downlink: mut client_write,
        downlink_liveness,
        uplink_carrier: uplink,
        downlink_carrier: downlink,
        hops,
        uplink_path,
        downlink_path,
        _flow_lease,
    } = paired;
    let target_addr = target.to_string();
    let access = portal.telemetry.start_access(|| AccessStart {
        id: 0,
        timestamp_ms: now_unix_ms(),
        protocol: TrafficProtocol::Tcp,
        wire_version: Some(uplink_path.version),
        flow_id: Some(flow_id.into()),
        session_tag: None,
        client: Some(uplink_path.peer.clone()),
        path_peers: vec![uplink_path.peer.clone(), downlink_path.peer.clone()],
        target: target_addr.clone(),
        initial_uplink: Some(uplink),
        initial_downlink: Some(downlink),
        path: Some(access_exchange_path(
            uplink,
            &uplink_path,
            &target_addr,
            downlink,
            &downlink_path,
        )),
    });
    let cancel = _flow_lease.cancellation_token();
    let dial = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            TargetDial::Cancelled
        },
        _ = portal.drain.cancelled() => {
            TargetDial::Draining
        },
        result = portal.outbound.dial_tcp_target(&target, hops, portal.runtime.tcp_dial_timeout) => {
            match result {
                Ok(conn) => TargetDial::Connected(conn),
                Err(error) => TargetDial::Failed(error),
            }
        },
    };
    let target_conn = match dial {
        TargetDial::Connected(conn) => conn,
        TargetDial::Cancelled => {
            let _ = write_flow_result_bounded(
                &mut client_write,
                FlowResult::Reject(FlowErrorCode::SessionReplaced),
                true,
            )
            .await;
            access.finish(AccessOutcome::Cancelled, None);
            return;
        }
        TargetDial::Draining => {
            let _ = write_flow_result_bounded(
                &mut client_write,
                FlowResult::Reject(FlowErrorCode::FlowLimit),
                true,
            )
            .await;
            access.finish(AccessOutcome::Rejected, Some("portal draining".to_owned()));
            return;
        }
        TargetDial::Failed(err) => {
            let code = if cancel.is_cancelled() {
                FlowErrorCode::SessionReplaced
            } else if portal.drain.is_cancelled() {
                FlowErrorCode::FlowLimit
            } else if let Some(result) = err.setup_result() {
                FlowErrorCode::try_from(result).unwrap_or(FlowErrorCode::InternalError)
            } else {
                FlowErrorCode::DialFailed
            };
            let _ =
                write_flow_result_bounded(&mut client_write, FlowResult::Reject(code), true).await;
            portal.logger.debug(format_args!(
                "portal::conn::relay_paired_tcp: target dial failed: {err}"
            ));
            let error = err.to_string();
            access.finish(error_outcome(&error), Some(error));
            return;
        }
    };
    match commit_ready(&cancel, &portal.ready_gate, &mut client_write).await {
        Ok(true) => {}
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
    portal.stats.add_session(false);
    let _done = SessionGuard::new(portal.clone(), false);
    if portal.logger.debug_enabled() {
        let target_local = target_conn.local_label();
        portal.logger.debug(format_args!(
            "portal::conn::relay_paired_tcp: {}: {}",
            TCP_EXCHANGE_STARTING,
            paired_exchange_path(
                uplink,
                &uplink_path,
                &target_local,
                &target_addr,
                downlink,
                &downlink_path,
            )
        ));
    }

    let (target_read, target_write, _target_guard) = target_conn.into_parts();
    let completion = {
        let relay = relay_stream(
            portal.clone(),
            &mut client_read,
            &mut client_write,
            (target_read, target_write),
            (
                portal.buffers.get_tcp_buffer(),
                portal.buffers.get_tcp_buffer(),
            ),
            Some((uplink, downlink)),
            &access,
        );
        tokio::pin!(relay);
        if let Some(mut liveness) = downlink_liveness {
            let mut byte = [0u8; 1];
            tokio::select! {
                result = &mut relay => RelayCompletion::Relay(result),
                _ = cancel.cancelled() => RelayCompletion::Cancelled,
                _ = liveness.read(&mut byte) => RelayCompletion::DownlinkClosed,
            }
        } else {
            tokio::select! {
                result = &mut relay => RelayCompletion::Relay(result),
                _ = cancel.cancelled() => RelayCompletion::Cancelled,
            }
        }
    };
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_tcp: {}: {}",
        TCP_EXCHANGE_COMPLETE,
        match &completion {
            RelayCompletion::Relay(Ok(())) => "EOF".to_string(),
            RelayCompletion::Relay(Err(err)) => err.to_string(),
            RelayCompletion::Cancelled | RelayCompletion::DownlinkClosed => {
                "cancelled".to_string()
            }
        }
    ));
    match completion {
        RelayCompletion::Relay(Ok(())) | RelayCompletion::DownlinkClosed => {
            access.finish(AccessOutcome::Success, None);
        }
        RelayCompletion::Relay(Err(error)) => {
            let error = error.to_string();
            access.finish(error_outcome(&error), Some(error));
        }
        RelayCompletion::Cancelled => access.finish(AccessOutcome::Cancelled, None),
    }
}

enum TargetDial<T> {
    Connected(T),
    Cancelled,
    Draining,
    Failed(crate::portal::outbound::OutboundError),
}

enum RelayCompletion {
    Relay(anyhow::Result<()>),
    Cancelled,
    DownlinkClosed,
}

fn error_outcome(error: &str) -> AccessOutcome {
    if error.to_ascii_lowercase().contains("timeout") {
        AccessOutcome::Timeout
    } else {
        AccessOutcome::Error
    }
}

/// Commits the single setup result. Cancellation is sampled before the READY
/// write starts; after that point READY owns the writer and must finish without
/// a competing REJECT that could corrupt a partially written frame.
async fn commit_ready(
    cancel: &tokio_util::sync::CancellationToken,
    ready_gate: &crate::portal::tasks::ReadyGate,
    writer: &mut crate::portal::pairing::BoxWriter,
) -> anyhow::Result<bool> {
    if cancel.is_cancelled() {
        write_flow_result_bounded(
            writer,
            FlowResult::Reject(FlowErrorCode::SessionReplaced),
            true,
        )
        .await?;
        return Ok(false);
    }
    let Some(_ready_permit) = ready_gate.try_enter() else {
        write_flow_result_bounded(writer, FlowResult::Reject(FlowErrorCode::FlowLimit), true)
            .await?;
        return Ok(false);
    };
    if cancel.is_cancelled() {
        write_flow_result_bounded(
            writer,
            FlowResult::Reject(FlowErrorCode::SessionReplaced),
            true,
        )
        .await?;
        return Ok(false);
    }
    write_flow_result_bounded(writer, FlowResult::Ready, false).await?;
    Ok(true)
}

async fn write_flow_result_bounded(
    writer: &mut crate::portal::pairing::BoxWriter,
    result: FlowResult,
    finish: bool,
) -> anyhow::Result<()> {
    tokio::time::timeout(FLOW_RESULT_TIMEOUT, async {
        write_flow_result(writer, result).await?;
        if finish {
            writer.shutdown().await?;
        }
        anyhow::Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("flow result write timeout"))?
}

#[cfg(test)]
#[path = "../../tests/portal/conn/relay_tcp.rs"]
mod tests;
