// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP/TLS portal connection tests.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger, MUX_MARKER};
use crate::portal::Portal;
use crate::portal::conn::tcp::{
    AUTHENTICATED_LANE_BOOTSTRAP_TIMEOUT, handle_tcp_incoming_with_bootstrap_timeout,
    handle_tcp_incoming_with_timeouts,
};
use crate::protocol::{
    Carrier, FlowHeader, FlowKind, FlowResult, FlowRole, encode_udp_packet, read_flow_result,
    read_udp_packet, write_flow_header, write_request_frame,
};

use super::super::*;
use super::support::{
    TestSocksAuth, connect_test_tls, connect_test_tls_with_alpns, spawn_test_socks5_tcp,
    spawn_test_socks5_udp, test_target, tls_auth_frame,
};

fn duplex_setup(flow_id: u32, kind: FlowKind, target: &str) -> Vec<u8> {
    let mut setup = write_flow_header(FlowHeader {
        role: FlowRole::Duplex,
        flow_id,
        kind,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::TlsTcp,
        hops: 0,
    })
    .unwrap()
    .to_vec();
    setup.extend_from_slice(&write_request_frame(&test_target(target)).unwrap());
    setup
}

#[tokio::test]
async fn portal_rejects_client_hello_without_nw2() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, peer) = listener.accept().await.unwrap();
            let admission = portal_inner
                .unauthenticated_admission
                .try_acquire(peer.ip())
                .unwrap();
            handle_tcp_incoming(
                portal_inner.clone(),
                stream,
                peer,
                admission,
                child_shutdown.clone(),
            )
            .await;
        }
    });

    for alpns in [vec![b"now/1".to_vec()], vec![b"private/2".to_vec()], vec![]] {
        assert!(
            connect_test_tls_with_alpns(listen_addr, alpns)
                .await
                .is_err()
        );
    }
    shutdown.cancel();
    server_task.await.unwrap();
}

#[tokio::test]
async fn portal_accepts_delayed_dedicated_flow_header() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;

    let auth = tls_auth_frame(&portal, &tls, [7; 16]);
    tls.write_all(&auth).await.unwrap();
    sleep(Duration::from_millis(150)).await;

    let mut request = duplex_setup(1, FlowKind::Tcp, &target.to_string());
    request.extend_from_slice(b"ping");
    tls.write_all(&request).await.unwrap();

    assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tls.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"pong");

    shutdown.cancel();
    let _ = tls.shutdown().await;
    echo_task.await.unwrap();
    server_task.await.unwrap();
}

#[test]
fn authenticated_lane_window_covers_vector_1_7_warm_lane_ttl() {
    assert!(AUTHENTICATED_LANE_BOOTSTRAP_TIMEOUT > Duration::from_secs(30));
}

#[tokio::test]
async fn tls_tcp_relays_through_socks5_connect() {
    let (socks_addr, socks_task) = spawn_test_socks5_tcp(TestSocksAuth::None, "target.test").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1:2000?log=none&net=tcp&socks={socks_addr}"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut request = tls_auth_frame(&portal, &tls, [21; 16]).to_vec();
    request.extend_from_slice(&duplex_setup(2, FlowKind::Tcp, "target.test:443"));
    request.extend_from_slice(b"ping");
    tls.write_all(&request).await.unwrap();

    assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tls.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"pong");

    let _ = tls.shutdown().await;
    shutdown.cancel();
    socks_task.await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn tls_tcp_uot_relays_udp_and_counts_logical_udp() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut request = [0u8; 4];
        let (n, peer) = target.recv_from(&mut request).await.unwrap();
        assert_eq!(&request[..n], b"ping");
        target.send_to(b"pong", peer).await.unwrap();
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut bootstrap = tls_auth_frame(&portal, &tls, [13; 16]).to_vec();
    bootstrap.extend_from_slice(&duplex_setup(3, FlowKind::Udp, &target_addr.to_string()));
    bootstrap.extend_from_slice(&encode_udp_packet(b"ping").unwrap());
    tls.write_all(&bootstrap).await.unwrap();

    assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);
    let response = timeout(Duration::from_secs(3), read_udp_packet(&mut tls))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, b"pong".to_vec());
    assert_eq!(portal.inner.stats.udp_active.load(Ordering::Relaxed), 1);
    assert_eq!(portal.inner.stats.udp_rx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.udp_tx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.tcp_active.load(Ordering::Relaxed), 0);

    let _ = tls.shutdown().await;
    shutdown.cancel();
    echo_task.await.unwrap();
    server_task.await.unwrap();
    timeout(Duration::from_secs(1), async {
        while portal.inner.stats.udp_active.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(portal.inner.stats.udp_active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn tls_tcp_uot_relays_through_authenticated_socks5_udp() {
    let (socks_addr, socks_task) =
        spawn_test_socks5_udp(TestSocksAuth::Password("user", "pass"), "dns.test").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1:2000?log=none&net=tcp&socks=user:pass@{socks_addr}"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut bootstrap = tls_auth_frame(&portal, &tls, [22; 16]).to_vec();
    bootstrap.extend_from_slice(&duplex_setup(4, FlowKind::Udp, "dns.test:53"));
    bootstrap.extend_from_slice(&encode_udp_packet(b"ping").unwrap());
    tls.write_all(&bootstrap).await.unwrap();

    assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);
    let response = timeout(Duration::from_secs(3), read_udp_packet(&mut tls))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, b"pong".to_vec());
    assert_eq!(portal.inner.stats.udp_rx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.udp_tx.load(Ordering::Relaxed), 4);

    let _ = tls.shutdown().await;
    shutdown.cancel();
    socks_task.await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn tls_tcp_auth_failure_waits_for_deadline_without_application_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut auth = tls_auth_frame(&portal, &tls, [11; 16]);
    auth[0] ^= 0xff;
    let started = Instant::now();
    tls.write_all(&auth).await.unwrap();

    let mut response = [0u8; 1];
    let read = timeout(Duration::from_secs(7), tls.read(&mut response))
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(4), "elapsed: {elapsed:?}");
    assert!(elapsed <= Duration::from_secs(6) + Duration::from_millis(500));
    assert!(!matches!(read, Ok(length) if length != 0));

    server_task.await.unwrap();
    shutdown.cancel();
}

#[tokio::test]
async fn tls_tcp_flow_header_timeout_closes_unused_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming_with_bootstrap_timeout(
            portal_inner,
            stream,
            peer,
            admission,
            child_shutdown,
            Duration::from_millis(100),
        )
        .await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let auth = tls_auth_frame(&portal, &tls, [8; 16]);
    tls.write_all(&auth).await.unwrap();

    timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    shutdown.cancel();
    let _ = tls.shutdown().await;
}

#[tokio::test]
async fn tls_mux_carrier_closes_after_becoming_fully_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming_with_timeouts(
            portal_inner,
            stream,
            peer,
            admission,
            child_shutdown,
            Duration::from_secs(1),
            Duration::from_millis(100),
        )
        .await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut bootstrap = tls_auth_frame(&portal, &tls, [23; 16]).to_vec();
    bootstrap.push(MUX_MARKER);
    tls.write_all(&bootstrap).await.unwrap();
    tls.flush().await.unwrap();

    timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    let mut window = [0_u8; 7];
    tls.read_exact(&mut window).await.unwrap();
    assert_eq!(window[0], 0x03);
    assert_eq!(&window[3..], &[0, 0, 0, 0]);
    let mut byte = [0_u8; 1];
    let read = tls.read(&mut byte).await;
    assert!(
        matches!(read, Ok(0))
            || matches!(read, Err(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    assert_eq!(portal.inner.stats.link_tcp.load(Ordering::Relaxed), 0);
    shutdown.cancel();
}

#[tokio::test]
async fn tls_tcp_coalesced_auth_and_flow_bootstrap_relays() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut bootstrap = tls_auth_frame(&portal, &tls, [10; 16]).to_vec();
    bootstrap.extend_from_slice(&duplex_setup(10, FlowKind::Tcp, &target.to_string()));
    bootstrap.extend_from_slice(b"ping");
    tls.write_all(&bootstrap).await.unwrap();

    assert_eq!(read_flow_result(&mut tls).await.unwrap(), FlowResult::Ready);
    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tls.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"pong");
    let _ = tls.shutdown().await;
    shutdown.cancel();
    echo_task.await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn tls_tcp_carrier_mismatch_returns_invalid_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();
        handle_tcp_incoming(portal_inner, stream, peer, admission, child_shutdown).await;
    });

    let mut tls = connect_test_tls(listen_addr).await;
    let mut bootstrap = tls_auth_frame(&portal, &tls, [11; 16]).to_vec();
    bootstrap.extend_from_slice(
        &write_flow_header(FlowHeader {
            role: FlowRole::Duplex,
            flow_id: 11,
            kind: FlowKind::Tcp,
            uplink: Carrier::Quic,
            downlink: Carrier::Quic,
            hops: 0,
        })
        .unwrap(),
    );
    tls.write_all(&bootstrap).await.unwrap();

    assert_eq!(
        read_flow_result(&mut tls).await.unwrap(),
        FlowResult::Reject(crate::protocol::FlowErrorCode::InvalidRequest)
    );
    let _ = tls.shutdown().await;
    shutdown.cancel();
    server_task.await.unwrap();
}

#[tokio::test]
async fn mismatched_open_leaves_invalid_request_for_later_attach() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2000?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            let admission = portal_inner
                .unauthenticated_admission
                .try_acquire(peer.ip())
                .unwrap();
            handle_tcp_incoming(
                portal_inner.clone(),
                stream,
                peer,
                admission,
                child_shutdown.clone(),
            )
            .await;
        }
    });

    let session_id = [12; 16];
    let open = FlowHeader {
        role: FlowRole::Open,
        flow_id: 12,
        kind: FlowKind::Tcp,
        uplink: Carrier::Quic,
        downlink: Carrier::TlsTcp,
        hops: 0,
    };
    let mut first = connect_test_tls(listen_addr).await;
    let mut bootstrap = tls_auth_frame(&portal, &first, session_id).to_vec();
    bootstrap.extend_from_slice(&write_flow_header(open).unwrap());
    first.write_all(&bootstrap).await.unwrap();
    let mut eof = [0u8; 1];
    match first.read(&mut eof).await {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        result => panic!("expected mismatched OPEN lane to close, got {result:?}"),
    }

    let mut second = connect_test_tls(listen_addr).await;
    let mut attach = tls_auth_frame(&portal, &second, session_id).to_vec();
    attach.extend_from_slice(
        &write_flow_header(FlowHeader {
            role: FlowRole::Attach,
            ..open
        })
        .unwrap(),
    );
    second.write_all(&attach).await.unwrap();
    assert_eq!(
        read_flow_result(&mut second).await.unwrap(),
        FlowResult::Reject(crate::protocol::FlowErrorCode::InvalidRequest)
    );

    let _ = second.shutdown().await;
    shutdown.cancel();
    server_task.await.unwrap();
}
