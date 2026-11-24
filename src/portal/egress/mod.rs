// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Unified FIFO ownership and outbound TCP/UDP setup for registered Egress carriers.

mod registry;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OwnedSemaphorePermit;

use crate::protocol::{Carrier, FlowKind, SetupResult, Target};
use crate::transport::{MorphTcpStream, QuicConnection, Stats};
use crate::vector::{BoxReader, BoxWriter, TcpTunnel, TcpTunnelGuard, UdpTunnel};

use self::registry::Selected;

pub(crate) use self::registry::EgressRegistry;

pub(super) type TlsStream = tokio_rustls::server::TlsStream<MorphTcpStream<tokio::net::TcpStream>>;

pub(super) struct TlsConnection {
    pub(super) stream: TlsStream,
    pub(super) permit: OwnedSemaphorePermit,
}

struct PermitIo<T> {
    io: T,
    _permit: Arc<OwnedSemaphorePermit>,
}

impl<T: AsyncRead + Unpin> AsyncRead for PermitIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PermitIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl TlsConnection {
    fn into_parts(self) -> (BoxReader, BoxWriter) {
        let permit = Arc::new(self.permit);
        let (reader, writer) = tokio::io::split(self.stream);
        (
            Box::pin(PermitIo {
                io: reader,
                _permit: permit.clone(),
            }),
            Box::pin(PermitIo {
                io: writer,
                _permit: permit,
            }),
        )
    }
}

pub(crate) async fn open_tcp(registry: &EgressRegistry, target: &Target) -> Result<TcpTunnel> {
    match registry.claim().await? {
        Selected::Quic(q) => {
            let (send, recv) = open(q, FlowKind::Tcp, target).await?;
            Ok(TcpTunnel::new(
                Box::pin(recv),
                Box::pin(send),
                Carrier::Quic,
                TcpTunnelGuard { _flow: None },
            ))
        }
        Selected::Tls(receiver) => {
            let (mut reader, mut writer) = receiver
                .await
                .context("Egress TLS claim cancelled")?
                .into_parts();
            crate::vector::client::write_start(&mut writer, FlowKind::Tcp, target).await?;
            crate::vector::client::read_ready(&mut reader).await?;
            Ok(TcpTunnel::new(
                reader,
                writer,
                Carrier::TlsTcp,
                TcpTunnelGuard { _flow: None },
            ))
        }
    }
}

pub(crate) async fn open_udp(
    registry: &EgressRegistry,
    target: &Target,
    stats: Arc<Stats>,
    handshake_timeout: Duration,
) -> Result<UdpTunnel> {
    match registry.claim().await? {
        Selected::Quic(q) => {
            let (mut send, mut recv) = q.connection.open_bi().await?;
            let id = q.flow_id(u64::from(send.id()))?;
            let (route, datagrams) = q.register(id)?;
            write_request(&mut send, FlowKind::Udp, target).await?;
            ready(&mut recv).await?;
            let tunnel = UdpTunnel::quic(route, datagrams, send, recv, stats, false);
            tunnel.activate();
            Ok(tunnel)
        }
        Selected::Tls(receiver) => {
            let (mut reader, mut writer) = receiver
                .await
                .context("Egress TLS claim cancelled")?
                .into_parts();
            crate::vector::client::write_start(&mut writer, FlowKind::Udp, target).await?;
            crate::vector::client::read_ready(&mut reader).await?;
            Ok(UdpTunnel::stream(
                reader,
                writer,
                TcpTunnelGuard { _flow: None },
                stats,
                false,
                handshake_timeout,
            ))
        }
    }
}

async fn open(
    q: Arc<QuicConnection>,
    kind: FlowKind,
    target: &Target,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = q.connection.open_bi().await?;
    q.flow_id(u64::from(send.id()))?;
    write_request(&mut send, kind, target).await?;
    ready(&mut recv).await?;
    Ok((send, recv))
}

async fn write_request(
    send: &mut quinn::SendStream,
    kind: FlowKind,
    target: &Target,
) -> Result<()> {
    let mut bytes = [0; crate::protocol::TARGET_MAX_ENCODED_LEN + 1];
    let size = crate::protocol::encode_flow_request_into(kind, target, &mut bytes)?;
    send.write_all(&bytes[..size]).await?;
    Ok(())
}

async fn ready(recv: &mut quinn::RecvStream) -> Result<()> {
    let result = tokio::time::timeout(
        crate::common::flow_setup_timeout(),
        crate::protocol::read_flow_result(recv),
    )
    .await
    .context("Egress setup timeout")??;
    let result = SetupResult::from(result);
    if result != SetupResult::Ready {
        return Err(crate::vector::OpenFlowError::Setup(result).into());
    }
    Ok(())
}
