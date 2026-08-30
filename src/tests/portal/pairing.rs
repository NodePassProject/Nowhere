// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pairing registry tests.

use super::*;
use crate::protocol::{
    Carrier, FlowKind, FlowResult, FlowRole, SESSION_ID_LEN, SessionId, Target, encode_flow_result,
    read_flow_result,
};
use crate::transport::Stats;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

impl PairingRegistry {
    fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }
}

fn registry(max_udp_flows: usize, timeout: Duration) -> Arc<PairingRegistry> {
    Arc::new(PairingRegistry {
        tcp: Mutex::new(HashMap::new()),
        udp: Mutex::new(HashMap::new()),
        links: StdMutex::new(HashMap::new()),
        claims: StdMutex::new(HashMap::new()),
        rejections: StdMutex::new(HashMap::new()),
        accepting: AtomicBool::new(true),
        next_quic_generation: AtomicU64::new(1),
        next_epoch: AtomicU64::new(1),
        max_pending: 16,
        timeout,
        max_tcp_flows: 16,
        max_udp_flows,
    })
}

fn header(
    role: FlowRole,
    flow_id: u32,
    kind: FlowKind,
    uplink: Carrier,
    downlink: Carrier,
) -> FlowHeader {
    FlowHeader {
        role,
        flow_id,
        kind,
        uplink,
        downlink,
        hops: 0,
    }
}

fn target(value: &str) -> Target {
    value.parse().unwrap()
}

fn path(label: &str) -> LinkPath {
    LinkPath {
        version: crate::protocol::ProtocolVersion::V2,
        peer: format!("{label}.client:1234"),
        local: "portal.test:2077".into(),
    }
}

fn tcp_half(label: &str) -> LinkHalf {
    LinkHalf::tcp(path(label))
}

fn quic_half(label: &str, generation: u64) -> LinkHalf {
    LinkHalf::quic(path(label), generation)
}

fn available_udp_permits(registry: &PairingRegistry, session_id: SessionId) -> usize {
    registry
        .links
        .lock()
        .expect("link registry poisoned")
        .get(&session_id.into())
        .expect("registered session")
        .udp_flow_budget
        .available_permits()
}

struct PendingWriter;

trait PairingResultExt<T> {
    fn unwrap_pairing_error(self) -> PairingError;
}

impl<T> PairingResultExt<T> for Result<T, PairingError> {
    fn unwrap_pairing_error(self) -> PairingError {
        match self {
            Ok(_) => panic!("pairing operation unexpectedly succeeded"),
            Err(error) => error,
        }
    }
}

impl AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

#[path = "pairing/lifecycle.rs"]
mod lifecycle;
#[path = "pairing/rejection.rs"]
mod rejection;
#[path = "pairing/replacement.rs"]
mod replacement;
#[path = "pairing/udp.rs"]
mod udp;
#[path = "pairing/version.rs"]
mod version;
