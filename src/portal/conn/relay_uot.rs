// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-TCP relay loop for UoT clients.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use crate::common::{handshake_timeout, udp_dial_timeout, udp_idle_timeout};
use crate::portal::PortalInner;
use crate::portal::pairing::PairedUdp;
use crate::protocol::{
    Carrier, DATAGRAM_UDP_COMPACT_CLOSE, DATAGRAM_UDP_DATA, DATAGRAM_UDP_OPEN_ACK,
    encode_udp_compact, read_uot_packet, read_uot_setup_target, write_uot_packet,
};

use super::{
    SessionGuard, UDP_TRANSFER_COMPLETE, UDP_TRANSFER_STARTING, paired_exchange_path,
    symmetric_exchange_path,
};

/// Relays UDP packets through a length-prefixed TCP stream after UoT setup.
pub(in crate::portal::conn) async fn relay_udp_over_tcp_target<R, W>(
    portal: Arc<PortalInner>,
    client_read: &mut R,
    client_write: &mut W,
    peer: String,
    local: String,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let target_addr = match timeout(handshake_timeout(), read_uot_setup_target(client_read)).await {
        Ok(Ok(target)) => target,
        Ok(Err(err)) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to read setup target: {err}"
            ));
            return;
        }
        Err(_) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to read setup target: deadline elapsed"
            ));
            return;
        }
    };

    let socket = match portal
        .outbound
        .dial_udp(&target_addr, udp_dial_timeout())
        .await
    {
        Ok(socket) => socket,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_udp_over_tcp_target: failed to dial target: {err}"
            ));
            return;
        }
    };
    if portal.logger.debug_enabled() {
        let target_local = socket
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        portal.logger.debug(format_args!(
            "portal::conn::relay_udp_over_tcp_target: {}: {}",
            UDP_TRANSFER_STARTING,
            symmetric_exchange_path(Carrier::Tcp, &peer, &local, &target_local, &target_addr)
        ));
    }

    portal.stats.add_session(true);
    let _done = SessionGuard::new(portal.clone(), true);
    let mut target_buf = portal.buffers.get_udp_buffer();
    let mut target_packet = Vec::new();
    let idle_sleep = tokio::time::sleep_until(Instant::now() + udp_idle_timeout());
    tokio::pin!(idle_sleep);

    let complete_reason = loop {
        // UoT is connection-oriented, so the idle timer is based on traffic in
        // either direction rather than target socket lifetime alone.
        tokio::select! {
            packet = read_uot_packet(client_read) => {
                let payload = match packet {
                    Ok(Some(payload)) => payload,
                    Ok(None) => break "client EOF".to_string(),
                    Err(err) => break format!("client frame error: {err}"),
                };
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_read(payload.len() as i64).await;
                }
                match socket.send(&payload, &mut target_packet).await {
                    Ok(n) => {
                        portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                        portal.stats.up_tcp.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(err) => {
                        portal.logger.error(format_args!(
                            "portal::conn::relay_udp_over_tcp_target: failed to write target: {err}"
                        ));
                        break format!("target write error: {err}");
                    }
                }
            }
            read = socket.recv(&mut target_buf) => {
                let payload = match read {
                    Ok(range) => &target_buf[range],
                    Err(err) => break format!("target read error: {err}"),
                };
                let n = payload.len();
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_write(n as i64).await;
                }
                if let Err(err) = write_uot_packet(client_write, payload).await {
                    break format!("client write error: {err}");
                }
                portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                portal.stats.down_tcp.fetch_add(n as u64, Ordering::Relaxed);
            }
            _ = &mut idle_sleep => {
                break "idle timeout".to_string();
            }
        }
    };
    portal.logger.debug(format_args!(
        "portal::conn::relay_udp_over_tcp_target: {}: {complete_reason}",
        UDP_TRANSFER_COMPLETE
    ));
}

/// Relays one UDP flow through independently selected upload and download carriers.
pub(in crate::portal) async fn relay_paired_udp(portal: Arc<PortalInner>, paired: PairedUdp) {
    let PairedUdp {
        flow_id,
        target: target_addr,
        mut uplink,
        mut downlink,
        uplink_carrier,
        downlink_carrier,
        uplink_path,
        downlink_path,
        compact_ack,
    } = paired;
    let socket = match portal
        .outbound
        .dial_udp(&target_addr, udp_dial_timeout())
        .await
    {
        Ok(socket) => socket,
        Err(err) => {
            portal.logger.error(format_args!(
                "portal::conn::relay_paired_udp: failed to dial target {target_addr}: {err}"
            ));
            return;
        }
    };
    if portal.logger.debug_enabled() {
        let target_local = socket
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
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
    let mut ack_sent = false;
    let mut target_buf = portal.buffers.get_udp_buffer();
    let mut target_packet = Vec::new();
    let idle_sleep = tokio::time::sleep_until(Instant::now() + udp_idle_timeout());
    tokio::pin!(idle_sleep);
    let complete_reason = loop {
        tokio::select! {
            packet = read_paired_udp(&mut uplink) => {
                let payload = match packet {
                    Ok(Some(payload)) => payload,
                    Ok(None) => break "uplink EOF".to_string(),
                    Err(err) => break format!("uplink error: {err}"),
                };
                if payload.is_empty() { continue; }
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_read(payload.len() as i64).await;
                }
                match socket.send(&payload, &mut target_packet).await {
                    Ok(n) => {
                        if !ack_sent {
                            if let Err(err) =
                                send_udp_ack(&mut downlink, flow_id, compact_ack.as_ref()).await
                            {
                                break format!("client ACK write error: {err}");
                            }
                            ack_sent = true;
                        }
                        portal.stats.udp_rx.fetch_add(n as u64, Ordering::Relaxed);
                        match uplink_carrier {
                            Carrier::Tcp => &portal.stats.up_tcp,
                            Carrier::Udp => &portal.stats.up_udp,
                        }.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(err) => break format!("target write error: {err}"),
                }
            }
            read = socket.recv(&mut target_buf) => {
                let payload = match read {
                    Ok(range) => &target_buf[range],
                    Err(err) => break format!("target read error: {err}"),
                };
                if payload.is_empty() { continue; }
                let n = payload.len();
                idle_sleep.as_mut().reset(Instant::now() + udp_idle_timeout());
                if let Some(limiter) = &portal.rate_limiter {
                    limiter.wait_write(n as i64).await;
                }
                if let Err(err) = send_paired_udp(&mut downlink, flow_id, payload).await {
                    break format!("client write error: {err}");
                }
                portal.stats.udp_tx.fetch_add(n as u64, Ordering::Relaxed);
                match downlink_carrier {
                    Carrier::Tcp => &portal.stats.down_tcp,
                    Carrier::Udp => &portal.stats.down_udp,
                }.fetch_add(n as u64, Ordering::Relaxed);
            }
            _ = &mut idle_sleep => break "idle timeout".to_string(),
        }
    };
    if let Err(err) = send_udp_close(&mut downlink, flow_id).await {
        portal.logger.debug(format_args!(
            "portal::conn::relay_paired_udp: failed to send CLOSE: {err}"
        ));
    }
    portal.logger.debug(format_args!(
        "portal::conn::relay_paired_udp: {}: {complete_reason}",
        UDP_TRANSFER_COMPLETE
    ));
}

async fn read_paired_udp(
    uplink: &mut crate::portal::pairing::UdpUp,
) -> anyhow::Result<Option<Bytes>> {
    match uplink {
        crate::portal::pairing::UdpUp::Tcp(reader) => {
            Ok(read_uot_packet(reader).await?.map(Bytes::from))
        }
        crate::portal::pairing::UdpUp::Quic(receiver) => Ok(receiver.recv().await),
    }
}

async fn send_udp_ack(
    downlink: &mut crate::portal::pairing::UdpDown,
    flow_id: u64,
    compact_ack: Option<&crate::portal::pairing::CompactAck>,
) -> anyhow::Result<()> {
    match downlink {
        crate::portal::pairing::UdpDown::Tcp(writer) => {
            writer.write_all(&[0, 0]).await?;
        }
        crate::portal::pairing::UdpDown::Quic(conn) => {
            if compact_ack.is_none() {
                let frame = encode_udp_compact(DATAGRAM_UDP_OPEN_ACK, flow_id, &[])?;
                conn.send_datagram(bytes::Bytes::from(frame))?;
            }
        }
    }
    if let Some(ack) = compact_ack {
        let frame = encode_udp_compact(DATAGRAM_UDP_OPEN_ACK, flow_id, &[])?;
        ack.conn.send_datagram(bytes::Bytes::from(frame))?;
        ack.acked.store(true, Ordering::Release);
    }
    Ok(())
}

async fn send_paired_udp(
    downlink: &mut crate::portal::pairing::UdpDown,
    flow_id: u64,
    payload: &[u8],
) -> anyhow::Result<()> {
    match downlink {
        crate::portal::pairing::UdpDown::Tcp(writer) => {
            write_uot_packet(writer, payload).await?;
        }
        crate::portal::pairing::UdpDown::Quic(conn) => {
            let frame = encode_udp_compact(DATAGRAM_UDP_DATA, flow_id, payload)?;
            conn.send_datagram(bytes::Bytes::from(frame))?;
        }
    }
    Ok(())
}

async fn send_udp_close(
    downlink: &mut crate::portal::pairing::UdpDown,
    flow_id: u64,
) -> anyhow::Result<()> {
    match downlink {
        crate::portal::pairing::UdpDown::Tcp(writer) => {
            writer.write_all(&[0, 0]).await?;
        }
        crate::portal::pairing::UdpDown::Quic(conn) => {
            let frame = encode_udp_compact(DATAGRAM_UDP_COMPACT_CLOSE, flow_id, &[])?;
            conn.send_datagram(bytes::Bytes::from(frame))?;
        }
    }
    Ok(())
}
