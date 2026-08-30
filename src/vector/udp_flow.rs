// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Target-scoped UDP flow setup and packet transport.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::common::{UdpDatagramSend, handshake_timeout};
use crate::protocol::{
    Carrier, FlowHeader, FlowKind, FlowRole, ProtocolVersion, Target, write_udp_packet,
};

use super::PortalClient;
use super::config::CarrierMode;
use super::flow::{
    BoxReader, BoxWriter, OpenFlowError, PhysicalLane, SessionGuard, carrier, open_lane,
    read_ready, write_header, write_open_request,
};
use super::flow_id::FlowLease;
use super::session::{MuxDirection, QueuedDatagram, QuicSession};
pub(crate) struct UdpTunnel {
    flow_id: u32,
    quic: Option<Arc<QuicSession>>,
    pub(super) uplink: Carrier,
    pub(super) downlink: Carrier,
    version: ProtocolVersion,
    sender: UdpTunnelSender,
    receiver: UdpTunnelReceiver,
    _lanes: Vec<PhysicalLane>,
    _lease: Option<FlowLease>,
    _session: Option<SessionGuard>,
    _flow_permit: Option<OwnedSemaphorePermit>,
}

impl UdpTunnel {
    pub(crate) fn carriers(&self) -> (Carrier, Carrier) {
        (self.uplink, self.downlink)
    }
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.version
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
        self.sender.close().await;
        if let Some(quic) = &self.quic {
            quic.close_udp(self.flow_id);
        }
    }
}

pub(crate) struct UdpTunnelSender {
    flow_id: u32,
    writer: Option<BoxWriter>,
    quic: Option<Arc<QuicSession>>,
    packet_id: u32,
    uplink: Carrier,
    client: Arc<PortalClient>,
}

impl UdpTunnelSender {
    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<bool> {
        let delivered = if let Some(writer) = &mut self.writer {
            write_udp_packet(writer, payload).await?;
            true
        } else if let Some(quic) = &self.quic {
            quic_datagram_delivered(
                quic.send_udp(self.flow_id, &mut self.packet_id, payload)
                    .await?,
            )
        } else {
            bail!("vector::udp_flow::UdpTunnel::send: no uplink carrier");
        };
        if !delivered {
            return Ok(false);
        }
        if self.client.account_stats {
            self.client
                .stats
                .udp_rx
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            client_carrier_counter(&self.client, self.uplink, true)
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
        Ok(true)
    }

    async fn close(&mut self) {
        if let Some(writer) = &mut self.writer {
            let _ = timeout(handshake_timeout(), writer.shutdown()).await;
        }
    }
}

pub(crate) struct UdpTunnelReceiver {
    reader: Option<BoxReader>,
    down_datagrams: Option<mpsc::Receiver<QueuedDatagram>>,
    uot_read: UotReadState,
    downlink: Carrier,
    client: Arc<PortalClient>,
}

impl UdpTunnelReceiver {
    pub(crate) async fn recv_into(
        &mut self,
        payload: &mut Vec<u8>,
    ) -> Result<Option<ReceivedUdpPacket>> {
        let packet = if let Some(reader) = &mut self.reader {
            let Some(size) = self.uot_read.read_packet(reader, payload).await? else {
                return Ok(None);
            };
            ReceivedUdpPacket::Buffered(size)
        } else if let Some(receiver) = &mut self.down_datagrams {
            let Some(packet) = receiver.recv().await else {
                return Ok(None);
            };
            ReceivedUdpPacket::Owned(packet.payload)
        } else {
            bail!("vector::udp_flow::UdpTunnel::recv: no downlink carrier");
        };
        let size = packet.len();
        if self.client.account_stats {
            self.client
                .stats
                .udp_tx
                .fetch_add(size as u64, Ordering::Relaxed);
            client_carrier_counter(&self.client, self.downlink, false)
                .fetch_add(size as u64, Ordering::Relaxed);
        }
        Ok(Some(packet))
    }
}

fn quic_datagram_delivered(outcome: UdpDatagramSend) -> bool {
    outcome == UdpDatagramSend::Sent
}

/// A UoT packet already in the reusable read buffer, or an owned zero-copy
/// slice received from Quinn.
pub(crate) enum ReceivedUdpPacket {
    Buffered(usize),
    Owned(Bytes),
}

impl ReceivedUdpPacket {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Buffered(size) => *size,
            Self::Owned(payload) => payload.len(),
        }
    }

    pub(crate) fn payload<'a>(&'a self, buffered: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Buffered(size) => &buffered[..*size],
            Self::Owned(payload) => payload,
        }
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        if let Some(quic) = &self.quic {
            quic.remove_udp(self.flow_id);
        }
    }
}

pub(crate) async fn open_udp(
    client: Arc<PortalClient>,
    target: &Target,
    hops: u8,
) -> std::result::Result<UdpTunnel, OpenFlowError> {
    let flow_permit = client
        .udp_flow_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| OpenFlowError::Setup(crate::protocol::SetupResult::FlowLimit))?;
    let lease = client
        .flow_ids
        .allocate()
        .map_err(OpenFlowError::Protocol)?;
    let flow_id = lease.id();
    let uplink = carrier(client.config.up);
    let downlink = carrier(client.config.down);

    let split_lanes = uplink != downlink;
    let mut lanes = if !split_lanes {
        vec![
            open_lane(client.clone(), client.config.up, flow_id, MuxDirection::Up)
                .await
                .map_err(OpenFlowError::Transport)?,
        ]
    } else {
        let (uplink_lane, downlink_lane) = tokio::join!(
            open_lane(client.clone(), client.config.up, flow_id, MuxDirection::Up,),
            open_lane(
                client.clone(),
                client.config.down,
                flow_id,
                MuxDirection::Down,
            ),
        );
        vec![
            uplink_lane.map_err(OpenFlowError::Transport)?,
            downlink_lane.map_err(OpenFlowError::Transport)?,
        ]
    };

    let quic = lanes.iter().find_map(|lane| lane._quic.clone());
    let version = lanes[0].version;
    if lanes.iter().any(|lane| lane.version != version) {
        return Err(OpenFlowError::Protocol(anyhow::anyhow!(
            "vector::udp_flow::open_udp: split carriers negotiated different protocol versions"
        )));
    }
    let mut down_datagrams = if client.config.down == CarrierMode::Udp {
        Some(
            quic.as_ref()
                .expect("QUIC downlink has session")
                .register_udp(flow_id)
                .map_err(OpenFlowError::Transport)?,
        )
    } else {
        None
    };

    if let Err(error) = setup_udp_lanes(
        &client,
        &mut lanes,
        flow_id,
        uplink,
        downlink,
        split_lanes,
        target,
        hops,
    )
    .await
    {
        if let Some(quic) = &quic {
            quic.remove_udp(flow_id);
        }
        return Err(error);
    }
    if down_datagrams.is_some()
        && let Err(error) = quic
            .as_ref()
            .expect("QUIC downlink has session")
            .activate_udp(flow_id)
    {
        if let Some(quic) = &quic {
            quic.remove_udp(flow_id);
        }
        return Err(OpenFlowError::Transport(error));
    }

    let writer = if client.config.up == CarrierMode::Tcp {
        Some(lanes[0].take_writer())
    } else {
        None
    };
    let down_index = usize::from(split_lanes);
    let reader = if client.config.down == CarrierMode::Tcp {
        Some(lanes[down_index].take_reader())
    } else {
        None
    };
    if client.account_stats {
        client.stats.add_session(true);
    }
    Ok(UdpTunnel {
        flow_id,
        uplink,
        downlink,
        version,
        sender: UdpTunnelSender {
            flow_id,
            writer,
            quic: quic.clone(),
            packet_id: 1,
            uplink,
            client: client.clone(),
        },
        receiver: UdpTunnelReceiver {
            reader,
            down_datagrams: down_datagrams.take(),
            uot_read: UotReadState::default(),
            downlink,
            client: client.clone(),
        },
        quic,
        _session: client
            .account_stats
            .then(|| SessionGuard::new(client.stats.clone(), true)),
        _flow_permit: Some(flow_permit),
        _lanes: lanes,
        _lease: Some(lease),
    })
}

#[derive(Default)]
struct UotReadState {
    header: [u8; 2],
    header_read: usize,
    payload_len: Option<usize>,
    payload_read: usize,
}

impl UotReadState {
    /// Reads incrementally so cancelling an in-progress downlink read to send
    /// an uplink packet cannot lose UoT framing bytes.
    async fn read_packet(
        &mut self,
        reader: &mut BoxReader,
        payload: &mut Vec<u8>,
    ) -> Result<Option<usize>> {
        while self.header_read != self.header.len() {
            let read = reader
                .read(&mut self.header[self.header_read..])
                .await
                .context("vector::udp_flow::UotReadState: failed to read packet length")?;
            if read == 0 {
                if self.header_read == 0 {
                    payload.clear();
                    return Ok(None);
                }
                bail!("vector::udp_flow::UotReadState: truncated packet length");
            }
            self.header_read += read;
        }

        let payload_len = *self
            .payload_len
            .get_or_insert_with(|| u16::from_be_bytes(self.header) as usize);
        payload.resize(payload_len, 0);
        while self.payload_read != payload_len {
            let read = reader
                .read(&mut payload[self.payload_read..])
                .await
                .context("vector::udp_flow::UotReadState: failed to read packet payload")?;
            if read == 0 {
                bail!("vector::udp_flow::UotReadState: truncated packet payload");
            }
            self.payload_read += read;
        }

        self.header_read = 0;
        self.payload_len = None;
        self.payload_read = 0;
        Ok(Some(payload_len))
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "setup keeps the wire header fields and lane shape explicit"
)]
async fn setup_udp_lanes(
    client: &PortalClient,
    lanes: &mut [PhysicalLane],
    flow_id: u32,
    uplink: Carrier,
    downlink: Carrier,
    split_lanes: bool,
    target: &crate::protocol::Target,
    hops: u8,
) -> std::result::Result<(), OpenFlowError> {
    let open = FlowHeader {
        role: if split_lanes {
            FlowRole::Open
        } else {
            FlowRole::Duplex
        },
        flow_id,
        kind: FlowKind::Udp,
        uplink,
        downlink,
        hops,
    };
    let pending_auth = lanes[0].take_pending_auth();
    write_open_request(
        lanes[0].writer.as_mut().expect("uplink writer"),
        pending_auth,
        open,
        target,
    )
    .await
    .map_err(OpenFlowError::Transport)?;
    lanes[0].mark_auth_sent();
    if split_lanes {
        let pending_auth = lanes[1].take_pending_auth();
        write_header(
            lanes[1].writer.as_mut().expect("downlink writer"),
            pending_auth,
            FlowHeader {
                role: FlowRole::Attach,
                ..open
            },
        )
        .await
        .map_err(OpenFlowError::Transport)?;
        lanes[1].mark_auth_sent();
    }
    if client.config.up == CarrierMode::Udp {
        timeout(
            handshake_timeout(),
            lanes[0]
                .writer
                .as_mut()
                .expect("QUIC uplink control")
                .shutdown(),
        )
        .await
        .map_err(|_| {
            OpenFlowError::Transport(anyhow::anyhow!(
                "vector::udp_flow::setup_udp_lanes: uplink shutdown timeout"
            ))
        })?
        .map_err(|error| OpenFlowError::Transport(error.into()))?;
    }
    let down_index = usize::from(split_lanes);
    if client.config.down == CarrierMode::Udp && down_index != 0 {
        timeout(
            handshake_timeout(),
            lanes[down_index]
                .writer
                .as_mut()
                .expect("QUIC downlink control")
                .shutdown(),
        )
        .await
        .map_err(|_| {
            OpenFlowError::Transport(anyhow::anyhow!(
                "vector::udp_flow::setup_udp_lanes: downlink shutdown timeout"
            ))
        })?
        .map_err(|error| OpenFlowError::Transport(error.into()))?;
    }
    read_ready(lanes[down_index].reader.as_mut().expect("downlink reader"))
        .await
        .map_err(OpenFlowError::Setup)
}

fn client_carrier_counter(
    client: &PortalClient,
    carrier: Carrier,
    uplink: bool,
) -> &std::sync::atomic::AtomicU64 {
    match (carrier, uplink) {
        (Carrier::TlsTcp, true) => &client.stats.up_tcp,
        (Carrier::Quic, true) => &client.stats.up_udp,
        (Carrier::TlsTcp, false) => &client.stats.down_tcp,
        (Carrier::Quic, false) => &client.stats.down_udp,
    }
}

#[cfg(test)]
#[path = "../tests/vector/udp_flow.rs"]
mod tests;
