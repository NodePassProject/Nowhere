// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP target dialing and whole-datagram relay across stream and QUIC transports.

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::common::OutboundUdpSocket;
use crate::portal::egress;
use crate::protocol::{SetupResult, Target};
use crate::vector::UdpTunnel;

use super::{ActiveFlow, Forwarder, Incoming, Outlet};

impl Forwarder {
    pub(super) async fn udp(
        &self,
        mut incoming: Incoming,
        target: &Target,
        cancel: CancellationToken,
    ) -> Result<()> {
        let dial = async {
            match &self.outbound {
                Outlet::Network(dialer) => dialer
                    .dial_udp_target(target, self.runtime.udp_dial_timeout)
                    .await
                    .map(UdpTarget::Network),
                Outlet::Egress(registry) => tokio::time::timeout(
                    crate::common::flow_setup_timeout(),
                    egress::open_udp(
                        registry,
                        target,
                        self.stats.clone(),
                        self.runtime.handshake_timeout,
                    ),
                )
                .await
                .context("Egress UDP setup timeout")?
                .map(UdpTarget::Tunnel),
            }
        };
        let target = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = self.shutdown.cancelled() => return Ok(()),
            closed = incoming.closed() => { closed?; return Ok(()); },
            result = dial => result,
        };
        let mut target = match target {
            Ok(target) => target,
            Err(error) => {
                let _ = incoming
                    .result(
                        error
                            .downcast_ref::<crate::vector::OpenFlowError>()
                            .and_then(|e| e.setup_result())
                            .unwrap_or(SetupResult::DialFailed),
                    )
                    .await;
                return Err(error);
            }
        };
        if let Incoming::Quic { connection, .. } = &incoming
            && connection.connection.max_datagram_size().is_none()
        {
            incoming.result(SetupResult::InternalError).await?;
            return Err(crate::vector::OpenFlowError::Setup(SetupResult::InternalError).into());
        }
        let pending = match &incoming {
            Incoming::Quic {
                connection, send, ..
            } => {
                let id = connection.flow_id(u64::from(send.id()))?;
                Some(connection.register(id)?)
            }
            _ => None,
        };
        incoming.result(SetupResult::Ready).await?;
        let mut input =
            incoming.into_udp(self.stats.clone(), self.runtime.handshake_timeout, pending)?;
        input.activate();
        let _active = ActiveFlow::new(self.stats.clone(), true);
        let input_cancel = input.cancellation();
        let target_cancel = match &target {
            UdpTarget::Tunnel(tunnel) => tunnel.cancellation(),
            _ => CancellationToken::new(),
        };
        let mut target_buffer = Vec::new();
        let result = relay_udp(
            self,
            &mut input,
            &mut target,
            cancel,
            input_cancel,
            target_cancel,
            &mut target_buffer,
        )
        .await;
        input.close().await;
        if let UdpTarget::Tunnel(tunnel) = &mut target {
            tunnel.close().await;
        }
        result
    }
}

enum UdpTarget {
    Network(OutboundUdpSocket),
    Tunnel(UdpTunnel),
}

enum TargetSender<'a> {
    Network(&'a OutboundUdpSocket),
    Tunnel(&'a mut crate::vector::UdpTunnelSender),
}

enum TargetReceiver<'a> {
    Network(&'a OutboundUdpSocket),
    Tunnel(&'a mut crate::vector::UdpTunnelReceiver),
}

impl UdpTarget {
    fn split_mut(&mut self) -> (TargetSender<'_>, TargetReceiver<'_>) {
        match self {
            Self::Network(socket) => (
                TargetSender::Network(socket),
                TargetReceiver::Network(socket),
            ),
            Self::Tunnel(tunnel) => {
                let (s, r) = tunnel.split_mut();
                (TargetSender::Tunnel(s), TargetReceiver::Tunnel(r))
            }
        }
    }
}

impl TargetSender<'_> {
    async fn send(&mut self, payload: &[u8], scratch: &mut Vec<u8>) -> Result<bool> {
        match self {
            Self::Network(socket) => Ok(socket.send(payload, scratch).await? == payload.len()),
            Self::Tunnel(sender) => sender.send(payload).await,
        }
    }
}

impl TargetReceiver<'_> {
    async fn recv(
        &mut self,
        buffer: &mut Vec<u8>,
    ) -> Result<Option<crate::vector::ReceivedUdpPacket>> {
        match self {
            Self::Network(socket) => {
                *buffer = Vec::new();
                *buffer = socket.recv().await?;
                Ok(Some(crate::vector::ReceivedUdpPacket::Buffered(
                    0..buffer.len(),
                )))
            }
            Self::Tunnel(receiver) => receiver.recv_into(buffer).await,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_udp(
    forward: &Forwarder,
    input: &mut UdpTunnel,
    target: &mut UdpTarget,
    cancel: CancellationToken,
    input_cancel: CancellationToken,
    target_cancel: CancellationToken,
    target_buffer: &mut Vec<u8>,
) -> Result<()> {
    let (send, recv) = input.split_mut();
    let (mut target_send, mut target_recv) = target.split_mut();
    let activity = tokio::sync::Notify::new();
    let mut input_buffer = Vec::new();
    let mut scratch = Vec::new();
    let upload = async {
        loop {
            let Some(packet) = recv.recv_into(&mut input_buffer).await? else {
                return Ok::<_, anyhow::Error>(());
            };
            let payload = packet.payload(&input_buffer);
            if let Some(rate) = &forward.rate {
                rate.wait_read(payload.len() as i64).await;
            }
            if target_send.send(payload, &mut scratch).await? {
                forward
                    .stats
                    .udp_upload_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            activity.notify_one();
        }
    };
    let download = async {
        loop {
            let Some(packet) = target_recv.recv(target_buffer).await? else {
                return Ok::<_, anyhow::Error>(());
            };
            let payload = packet.payload(target_buffer);
            if let Some(rate) = &forward.rate {
                rate.wait_write(payload.len() as i64).await;
            }
            if send.send(payload).await? {
                forward
                    .stats
                    .udp_download_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            activity.notify_one();
        }
    };
    tokio::pin!(upload);
    tokio::pin!(download);
    let idle = tokio::time::sleep(forward.runtime.udp_idle_timeout);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = forward.shutdown.cancelled() => return Ok(()),
            _ = input_cancel.cancelled() => return Ok(()),
            _ = target_cancel.cancelled() => return Ok(()),
            result = &mut upload => return result,
            result = &mut download => return result,
            _ = activity.notified() => idle.as_mut().reset(
                tokio::time::Instant::now() + forward.runtime.udp_idle_timeout,
            ),
            _ = &mut idle => return Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/portal/forward/udp.rs"]
mod tests;
