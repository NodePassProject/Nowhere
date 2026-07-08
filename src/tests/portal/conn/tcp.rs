// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP/TLS portal connection tests.

#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, BorrowedSocket, RawSocket};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger, handshake_timeout};
use crate::portal::Portal;
use crate::protocol::{
    Carrier, UOT_MAGIC_TARGET, read_uot_packet, write_auth_frame, write_request_frame,
    write_uot_packet_frame, write_uot_setup_frame,
};

use super::super::*;
use super::support::{
    TestSocksAuth, connect_test_tls, spawn_test_socks5_tcp, spawn_test_socks5_udp,
};

#[cfg(any(unix, windows))]
#[tokio::test]
async fn tcp_incoming_enables_nodelay_on_accepted_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let portal_inner = portal.inner.clone();
    let shutdown = CancellationToken::new();
    let child_shutdown = shutdown.clone();
    let (raw_socket_sender, raw_socket_receiver) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let raw_socket = raw_tcp_socket(&stream);
        assert!(!tcp_nodelay_for_raw_socket(raw_socket));
        raw_socket_sender.send(raw_socket).unwrap();
        let admission = portal_inner
            .unauthenticated_admission
            .try_acquire(peer.ip())
            .unwrap();

        handle_tcp_incoming_with_pool_ttl(
            portal_inner,
            stream,
            peer,
            admission,
            child_shutdown,
            Duration::from_millis(100),
        )
        .await;
    });

    let client = TcpStream::connect(listen_addr).await.unwrap();
    let raw_socket = raw_socket_receiver.await.unwrap();
    timeout(Duration::from_secs(1), async {
        while !tcp_nodelay_for_raw_socket(raw_socket) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    drop(client);
    shutdown.cancel();
    timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[cfg(unix)]
type RawTcpSocket = RawFd;

#[cfg(windows)]
type RawTcpSocket = RawSocket;

#[cfg(unix)]
fn raw_tcp_socket(stream: &TcpStream) -> RawTcpSocket {
    stream.as_raw_fd()
}

#[cfg(windows)]
fn raw_tcp_socket(stream: &TcpStream) -> RawTcpSocket {
    stream.as_raw_socket()
}

#[cfg(unix)]
fn tcp_nodelay_for_raw_socket(raw_socket: RawTcpSocket) -> bool {
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw_socket) };
    socket2::SockRef::from(&borrowed).tcp_nodelay().unwrap()
}

#[cfg(windows)]
fn tcp_nodelay_for_raw_socket(raw_socket: RawTcpSocket) -> bool {
    let borrowed = unsafe { BorrowedSocket::borrow_raw(raw_socket) };
    socket2::SockRef::from(&borrowed).tcp_nodelay().unwrap()
}

#[tokio::test]
async fn tls_tcp_relay_flushes_target_to_client_writes_before_target_eof() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let (release_target, wait_release) = oneshot::channel();
    let target_task = tokio::spawn(async move {
        let (mut target, _) = target_listener.accept().await.unwrap();
        target.write_all(b"chunk").await.unwrap();
        let _ = wait_release.await;
        let _ = target.shutdown().await;
    });

    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let mut client_read = tokio::io::empty();
    let (flushed, wait_flushed) = oneshot::channel();
    let mut client_write = FlushSignalWriter::new(flushed);

    let relay_task = tokio::spawn(async move {
        super::super::relay::relay_tcp_target(
            portal.inner,
            &mut client_read,
            &mut client_write,
            target_addr.to_string(),
            "127.0.0.1:1000".to_string(),
            "127.0.0.1:2077".to_string(),
            Carrier::Tcp,
        )
        .await;
    });

    let flushed = timeout(Duration::from_millis(250), wait_flushed)
        .await
        .expect("relay did not flush target_to_client write before target EOF")
        .unwrap();
    assert_eq!(flushed, b"chunk");

    let _ = release_target.send(());
    timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap();

    target_task.await.unwrap();
}

#[tokio::test]
async fn tls_tcp_pool_waits_beyond_handshake_timeout_then_relays() {
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
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
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

    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [7; 32],
    );
    tls.write_all(&auth).await.unwrap();

    timeout(Duration::from_secs(1), async {
        while portal.inner.pool_active.load(Ordering::Relaxed) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    tokio::time::sleep(handshake_timeout() + Duration::from_millis(100)).await;
    assert_eq!(portal.inner.pool_active.load(Ordering::Relaxed), 1);

    let mut request =
        write_request_frame(&target.to_string(), &portal.inner.credentials.protocol_spec).unwrap();
    request.extend_from_slice(b"ping");
    tls.write_all(&request).await.unwrap();

    let mut response = [0u8; 4];
    timeout(Duration::from_secs(3), tls.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"pong");
    assert_eq!(portal.inner.pool_active.load(Ordering::Relaxed), 0);

    shutdown.cancel();
    let _ = tls.shutdown().await;
    echo_task.await.unwrap();
    server_task.await.unwrap();
}

struct FlushSignalWriter {
    buffered: Vec<u8>,
    flushed: Option<oneshot::Sender<Vec<u8>>>,
}

impl FlushSignalWriter {
    fn new(flushed: oneshot::Sender<Vec<u8>>) -> Self {
        Self {
            buffered: Vec::new(),
            flushed: Some(flushed),
        }
    }
}

impl tokio::io::AsyncWrite for FlushSignalWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buffered.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(flushed) = self.flushed.take() {
            let buffered = std::mem::take(&mut self.buffered);
            let _ = flushed.send(buffered);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn tls_tcp_relays_through_socks5_connect() {
    let (socks_addr, socks_task) = spawn_test_socks5_tcp(TestSocksAuth::None, "target.test").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1:2077?log=none&net=tcp&socks={socks_addr}"
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
    let mut request = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [21; 32],
    );
    request.extend_from_slice(
        &write_request_frame("target.test:443", &portal.inner.credentials.protocol_spec).unwrap(),
    );
    request.extend_from_slice(b"ping");
    tls.write_all(&request).await.unwrap();

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
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
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
    let mut bootstrap = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [13; 32],
    );
    bootstrap.extend_from_slice(
        &write_request_frame(UOT_MAGIC_TARGET, &portal.inner.credentials.protocol_spec).unwrap(),
    );
    bootstrap.extend_from_slice(&write_uot_setup_frame(&target_addr.to_string()).unwrap());
    bootstrap.extend_from_slice(&write_uot_packet_frame(b"ping").unwrap());
    tls.write_all(&bootstrap).await.unwrap();

    let response = timeout(Duration::from_secs(3), read_uot_packet(&mut tls))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, b"pong");
    assert_eq!(portal.inner.stats.udp_active.load(Ordering::Relaxed), 1);
    assert_eq!(portal.inner.stats.udp_rx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.udp_tx.load(Ordering::Relaxed), 4);
    assert_eq!(portal.inner.stats.tcp_active.load(Ordering::Relaxed), 0);

    let _ = tls.shutdown().await;
    shutdown.cancel();
    echo_task.await.unwrap();
    server_task.await.unwrap();
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
            "portal://secret@127.0.0.1:2077?log=none&net=tcp&socks=user:pass@{socks_addr}"
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
    let mut bootstrap = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [22; 32],
    );
    bootstrap.extend_from_slice(
        &write_request_frame(UOT_MAGIC_TARGET, &portal.inner.credentials.protocol_spec).unwrap(),
    );
    bootstrap.extend_from_slice(&write_uot_setup_frame("dns.test:53").unwrap());
    bootstrap.extend_from_slice(&write_uot_packet_frame(b"ping").unwrap());
    tls.write_all(&bootstrap).await.unwrap();

    let response = timeout(Duration::from_secs(3), read_uot_packet(&mut tls))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, b"pong");
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
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
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
    let mut auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [11; 32],
    );
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
async fn tls_tcp_pool_ttl_closes_unused_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let portal = Portal::new(
        Url::parse("portal://secret@127.0.0.1:2077?log=none&net=tcp").unwrap(),
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
        handle_tcp_incoming_with_pool_ttl(
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
    let auth = write_auth_frame(
        portal.inner.credentials.key,
        &portal.inner.credentials.protocol_spec,
        [8; 32],
    );
    tls.write_all(&auth).await.unwrap();

    timeout(Duration::from_secs(1), async {
        while portal.inner.pool_active.load(Ordering::Relaxed) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(portal.inner.pool_active.load(Ordering::Relaxed), 0);

    shutdown.cancel();
    let _ = tls.shutdown().await;
}
