// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP packet ownership, transport I/O, and byte accounting.

use std::ops::Range;
use std::sync::atomic::Ordering;

use anyhow::{Result, bail};

use crate::common::{BudgetedDatagram, UdpDatagramSend};
use crate::protocol::write_udp_packet;

use super::{UdpReceiveTransport, UdpSendTransport, UdpTunnelReceiver, UdpTunnelSender};

impl UdpTunnelSender {
    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<bool> {
        if self.cancel.is_cancelled() {
            bail!("UDP Flow closed");
        }
        let sent = match &mut self.transport {
            UdpSendTransport::Stream { writer, .. } => {
                write_udp_packet(writer, payload).await?;
                true
            }
            UdpSendTransport::Quic {
                connection,
                id,
                packet_id,
            } => {
                crate::common::send_quic_udp_packet(&connection.connection, *id, packet_id, payload)
                    .await?
                    == UdpDatagramSend::Sent
            }
        };
        if sent && self.account {
            self.stats
                .udp_upload_bytes
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
        Ok(sent)
    }
}

impl UdpTunnelReceiver {
    pub(crate) async fn recv_into(
        &mut self,
        payload: &mut Vec<u8>,
    ) -> Result<Option<ReceivedUdpPacket>> {
        let packet = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Ok(None),
            packet = async {
                match &mut self.transport {
                    UdpReceiveTransport::Stream { reader, framing } => {
                        Ok::<_, anyhow::Error>(framing.read_packet(reader, payload).await?
                            .map(|size| ReceivedUdpPacket::Buffered(0..size)))
                    }
                    UdpReceiveTransport::Quic(datagrams) => {
                        Ok(datagrams.recv().await.map(ReceivedUdpPacket::Owned))
                    }
                }
            } => packet,
        }?;
        if let Some(packet) = &packet
            && self.account
        {
            self.stats
                .udp_download_bytes
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
        }
        Ok(packet)
    }
}

pub(crate) enum ReceivedUdpPacket {
    Buffered(Range<usize>),
    Owned(BudgetedDatagram),
}

impl ReceivedUdpPacket {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Buffered(range) => range.len(),
            Self::Owned(bytes) => bytes.payload.len(),
        }
    }

    pub(crate) fn payload<'a>(&'a self, buffer: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Buffered(range) => &buffer[range.clone()],
            Self::Owned(bytes) => &bytes.payload,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/vector/udp_flow/io.rs"]
mod tests;
