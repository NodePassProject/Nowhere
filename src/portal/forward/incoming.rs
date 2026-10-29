// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Incoming flow headers, setup results, and transport-specific tunnel handles.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{FlowKind, FlowResult, SetupResult, Target};
use crate::transport::{QuicConnection, Stats};
use crate::vector::{BoxReader, BoxWriter, TcpTunnelGuard, UdpTunnel};

pub(crate) enum Incoming {
    Tls {
        reader: BoxReader,
        writer: BoxWriter,
        guard: TcpTunnelGuard,
    },
    Quic {
        recv: quinn::RecvStream,
        send: quinn::SendStream,
        connection: Arc<QuicConnection>,
    },
}

impl Incoming {
    pub(super) async fn request(
        &mut self,
        started: Option<FlowKind>,
    ) -> Result<Option<(FlowKind, Target)>> {
        match self {
            Self::Tls { reader, .. } => {
                let kind = if let Some(kind) = started {
                    kind
                } else if let Some(kind) = crate::protocol::read_flow_start(reader).await? {
                    kind
                } else {
                    return Ok(None);
                };
                Ok(Some((kind, crate::protocol::read_request(reader).await?)))
            }
            Self::Quic { recv, .. } => {
                let kind = if let Some(kind) = started {
                    kind
                } else if let Some(kind) = crate::protocol::read_flow_start(recv).await? {
                    kind
                } else {
                    return Ok(None);
                };
                Ok(Some((kind, crate::protocol::read_request(recv).await?)))
            }
        }
    }

    pub(super) async fn result(&mut self, result: SetupResult) -> Result<()> {
        async fn write<W: tokio::io::AsyncWrite + Unpin>(
            writer: &mut W,
            result: SetupResult,
        ) -> Result<()> {
            crate::protocol::write_flow_result(writer, FlowResult::from(result)).await?;
            writer.flush().await?;
            if result != SetupResult::Ready {
                writer.shutdown().await?;
            }
            Ok(())
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            match self {
                Self::Tls { writer, .. } => write(writer, result).await,
                Self::Quic { send, .. } => write(send, result).await,
            }
        })
        .await
        .context("SetupResult write timeout")?
    }

    pub(super) async fn closed(&mut self) -> Result<()> {
        let mut byte = [0];
        let count = match self {
            Self::Tls { reader, .. } => reader.read(&mut byte).await?,
            Self::Quic { recv, send, .. } => {
                tokio::select! {
                    count = tokio::io::AsyncReadExt::read(recv, &mut byte) => count?,
                    _ = send.stopped() => 0,
                }
            }
        };
        if count != 0 {
            anyhow::bail!("target payload arrived before READY");
        }
        Ok(())
    }

    pub(super) fn into_tcp(self) -> (BoxReader, BoxWriter, TcpTunnelGuard) {
        match self {
            Self::Tls {
                reader,
                writer,
                guard,
            } => (reader, writer, guard),
            Self::Quic { recv, send, .. } => (
                Box::pin(recv),
                Box::pin(send),
                TcpTunnelGuard { _flow: None },
            ),
        }
    }

    pub(super) fn into_udp(
        self,
        stats: Arc<Stats>,
        handshake_timeout: Duration,
        pending: Option<(
            crate::transport::UdpRoute,
            tokio::sync::mpsc::Receiver<crate::common::BudgetedDatagram>,
        )>,
    ) -> Result<UdpTunnel> {
        let tunnel = match self {
            Self::Tls {
                reader,
                writer,
                guard,
            } => UdpTunnel::stream(reader, writer, guard, stats, false, handshake_timeout),
            Self::Quic {
                recv,
                send,
                connection,
            } => {
                let id = connection.flow_id(u64::from(send.id()))?;
                let (route, datagrams) = match pending {
                    Some(route) => route,
                    None => connection.register(id)?,
                };
                UdpTunnel::quic(route, datagrams, send, recv, stats, false)
            }
        };
        Ok(tunnel)
    }
}
