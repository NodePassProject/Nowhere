// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP tunnel lifecycle, stream I/O, and traffic accounting tests.

use std::sync::atomic::Ordering;

use crate::protocol::write_udp_packet;

use super::*;

#[tokio::test]
async fn stream_tunnel_reuses_receive_buffer_and_accounts_only_completed_packets() {
    let stats = Arc::new(Stats::default());
    let (stream, mut peer) = tokio::io::duplex(64);
    let (reader, writer) = tokio::io::split(stream);
    let mut tunnel = UdpTunnel::stream(
        Box::pin(reader),
        Box::pin(writer),
        TcpTunnelGuard { _flow: None },
        stats.clone(),
        true,
        std::time::Duration::from_secs(1),
    );
    let mut buffer = Vec::with_capacity(64);
    let pointer = buffer.as_ptr();
    for payload in [b"payload".as_slice(), b"", b"next"] {
        write_udp_packet(&mut peer, payload).await.unwrap();
        let packet = tunnel.recv_into(&mut buffer).await.unwrap().unwrap();
        assert_eq!(packet.payload(&buffer), payload);
        assert_eq!(buffer.as_ptr(), pointer);
        assert!(tunnel.send(payload).await.unwrap());
        assert_eq!(
            crate::protocol::read_udp_packet(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            payload
        );
    }
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 1);
    assert_eq!(stats.udp_upload_bytes.load(Ordering::Relaxed), 11);
    assert_eq!(stats.udp_download_bytes.load(Ordering::Relaxed), 11);
    tunnel.close().await;
    assert!(tunnel.recv_into(&mut buffer).await.unwrap().is_none());
    assert!(tunnel.send(b"closed").await.is_err());
    tunnel.close().await;
    drop(tunnel);
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn dropping_a_stream_tunnel_cancels_it_and_releases_the_active_count() {
    let stats = Arc::new(Stats::default());
    let (stream, _peer) = tokio::io::duplex(64);
    let (reader, writer) = tokio::io::split(stream);
    let tunnel = UdpTunnel::stream(
        Box::pin(reader),
        Box::pin(writer),
        TcpTunnelGuard { _flow: None },
        stats.clone(),
        true,
        std::time::Duration::from_secs(1),
    );
    let cancellation = tunnel.cancellation();
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 1);
    drop(tunnel);
    assert!(cancellation.is_cancelled());
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 0);
}

struct PendingShutdown;

impl tokio::io::AsyncWrite for PendingShutdown {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

#[tokio::test]
async fn stream_close_uses_its_saved_handshake_timeout() {
    let mut tunnel = UdpTunnel::stream(
        Box::pin(tokio::io::empty()),
        Box::pin(PendingShutdown),
        TcpTunnelGuard { _flow: None },
        Arc::new(Stats::default()),
        false,
        Duration::from_millis(50),
    );
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(1), tunnel.close())
        .await
        .expect("UDP close ignored its saved budget");
    assert!(started.elapsed() >= Duration::from_millis(50));
    assert!(tunnel.cancellation().is_cancelled());
}
