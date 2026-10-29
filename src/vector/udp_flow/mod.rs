// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP tunnel handles, transport framing, payload ownership, and traffic accounting.

mod framing;
mod io;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::common::BudgetedDatagram;
use crate::protocol::{FlowKind, Target};
use crate::transport::{QuicConnection, Stats, UdpRoute};

use self::framing::UotReadState;
use super::PortalClient;
use super::flow::{BoxReader, BoxWriter, FlowGuard, OpenFlowError, TcpTunnelGuard};

pub(crate) use self::io::ReceivedUdpPacket;

pub(crate) struct UdpTunnel {
    sender: UdpTunnelSender,
    receiver: UdpTunnelReceiver,
    _guard: TcpTunnelGuard,
    _flow: Option<FlowGuard>,
    _route: Option<UdpRoute>,
    cancel: CancellationToken,
}

pub(crate) struct UdpTunnelSender {
    transport: UdpSendTransport,
    stats: Arc<Stats>,
    account: bool,
    cancel: CancellationToken,
}

pub(crate) struct UdpTunnelReceiver {
    transport: UdpReceiveTransport,
    stats: Arc<Stats>,
    account: bool,
    cancel: CancellationToken,
}

enum UdpSendTransport {
    Stream {
        writer: BoxWriter,
        handshake_timeout: Duration,
    },
    Quic {
        connection: Arc<QuicConnection>,
        id: u32,
        packet_id: u32,
    },
}

enum UdpReceiveTransport {
    Stream {
        reader: BoxReader,
        framing: UotReadState,
    },
    Quic(mpsc::Receiver<BudgetedDatagram>),
}

impl UdpTunnel {
    pub(crate) fn stream(
        reader: BoxReader,
        writer: BoxWriter,
        guard: TcpTunnelGuard,
        stats: Arc<Stats>,
        account: bool,
        handshake_timeout: Duration,
    ) -> Self {
        let cancel = CancellationToken::new();
        let flow = if account {
            stats.add_flow(true);
            Some(FlowGuard::new(stats.clone(), true))
        } else {
            None
        };
        Self {
            sender: UdpTunnelSender {
                transport: UdpSendTransport::Stream {
                    writer,
                    handshake_timeout,
                },
                stats: stats.clone(),
                account,
                cancel: cancel.clone(),
            },
            receiver: UdpTunnelReceiver {
                transport: UdpReceiveTransport::Stream {
                    reader,
                    framing: UotReadState::default(),
                },
                stats,
                account,
                cancel: cancel.clone(),
            },
            _guard: guard,
            _flow: flow,
            _route: None,
            cancel,
        }
    }

    pub(crate) fn quic(
        route: UdpRoute,
        datagrams: mpsc::Receiver<BudgetedDatagram>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        stats: Arc<Stats>,
        account: bool,
    ) -> Self {
        let cancel = route.cancel.clone();
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut byte = [0];
            tokio::select! {_ = task_cancel.cancelled() => {}, _ = recv.read(&mut byte) => {}, _ = send.stopped() => {}}
            task_cancel.cancel();
            let _ = send.finish();
            let _ = recv.stop(0u32.into());
        });
        let quic = route.connection.clone();
        let id = route.id;
        let flow = if account {
            stats.add_flow(true);
            Some(FlowGuard::new(stats.clone(), true))
        } else {
            None
        };
        Self {
            sender: UdpTunnelSender {
                transport: UdpSendTransport::Quic {
                    connection: quic,
                    id,
                    packet_id: 1,
                },
                stats: stats.clone(),
                account,
                cancel: cancel.clone(),
            },
            receiver: UdpTunnelReceiver {
                transport: UdpReceiveTransport::Quic(datagrams),
                stats,
                account,
                cancel: cancel.clone(),
            },
            _guard: TcpTunnelGuard { _flow: None },
            _flow: flow,
            _route: Some(route),
            cancel,
        }
    }

    pub(crate) fn activate(&self) {
        if let Some(route) = &self._route {
            route.activate();
        }
    }

    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<bool> {
        self.sender.send(payload).await
    }

    pub(crate) async fn recv_into(
        &mut self,
        payload: &mut Vec<u8>,
    ) -> Result<Option<ReceivedUdpPacket>> {
        self.receiver.recv_into(payload).await
    }

    pub(crate) fn split_mut(&mut self) -> (&mut UdpTunnelSender, &mut UdpTunnelReceiver) {
        (&mut self.sender, &mut self.receiver)
    }

    pub(crate) async fn close(&mut self) {
        self.cancel.cancel();
        match &mut self.sender.transport {
            UdpSendTransport::Stream {
                writer,
                handshake_timeout,
            } => {
                let _ = tokio::time::timeout(*handshake_timeout, writer.shutdown()).await;
            }
            UdpSendTransport::Quic { connection, id, .. } => {
                connection.remove(*id);
                if let Ok(bytes) = crate::protocol::encode_udp_close(*id) {
                    let _ = connection
                        .connection
                        .send_datagram(Bytes::copy_from_slice(&bytes));
                }
            }
        }
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub(crate) async fn open_udp(
    client: Arc<PortalClient>,
    target: &Target,
) -> std::result::Result<UdpTunnel, OpenFlowError> {
    if client.config.net == super::config::CarrierMode::Tcp {
        let (reader, writer, guard) = client.open_tls_flow(FlowKind::Udp, target).await?;
        Ok(UdpTunnel::stream(
            reader,
            writer,
            guard,
            client.stats.clone(),
            client.account_stats,
            client.config.handshake_timeout,
        ))
    } else {
        let flow = client.open_quic_flow(FlowKind::Udp, target).await?;
        let (route, datagrams) = flow.udp.expect("UDP Flow route");
        let tunnel = UdpTunnel::quic(
            route,
            datagrams,
            flow.send,
            flow.recv,
            client.stats.clone(),
            client.account_stats,
        );
        tunnel.activate();
        Ok(tunnel)
    }
}

#[cfg(test)]
#[path = "../../tests/vector/udp_flow/mod.rs"]
mod tests;
