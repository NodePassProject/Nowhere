// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pairing registry tests.

use super::*;
use crate::protocol::{
    Carrier, FlowKind, FlowResult, FlowRole, SESSION_ID_LEN, Target, encode_flow_result,
    read_flow_result,
};
use crate::transport::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

impl PairingRegistry {
    fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }
}

fn registry(timeout: Duration) -> Arc<PairingRegistry> {
    Arc::new(PairingRegistry::new(timeout))
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
        peer: format!("{label}.client:1234"),
        local: "portal.test:2000".into(),
    }
}

fn tcp_half(label: &str) -> LinkHalf {
    LinkHalf::tcp(path(label))
}

fn quic_half(label: &str, generation: u64) -> LinkHalf {
    LinkHalf::quic(path(label), generation)
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
