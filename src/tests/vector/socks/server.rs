// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 client admission, listener shutdown, and CONNECT setup cancellation tests.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use url::Url;

use crate::common::Logger;
use crate::vector::VectorRuntime as Vector;

use super::*;

#[test]
fn socks_client_resource_admission_is_process_wide_and_reusable() {
    let vector = Vector::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080")
            .unwrap(),
        Logger,
    )
    .unwrap();
    let limit = vector.inner.socks_client_admission.available_permits();
    let mut held = (0..limit)
        .map(|_| try_admit_client(&vector.inner).unwrap())
        .collect::<Vec<_>>();
    assert!(try_admit_client(&vector.inner).is_none());

    held.pop();
    assert!(try_admit_client(&vector.inner).is_some());
}

#[tokio::test]
async fn listener_shutdown_interrupts_idle_socks_handshake() {
    let vector = Vector::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:9?in=127.0.0.1:1080")
            .unwrap(),
        Logger,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let admission = vector.inner.socks_client_admission.clone();
    let full = admission.available_permits();
    let serving = tokio::spawn(serve_listener(
        vector.inner.clone(),
        listener,
        shutdown.clone(),
    ));
    let _client = TcpStream::connect(endpoint).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while admission.available_permits() == full {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    shutdown.cancel();

    tokio::time::timeout(Duration::from_millis(500), serving)
        .await
        .expect("listener stayed blocked on idle SOCKS handshake")
        .unwrap();
    assert_eq!(admission.available_permits(), full);
}

#[tokio::test]
async fn client_shutdown_interrupts_pending_connect_setup() {
    let portal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let portal_addr = portal.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let portal_task = tokio::spawn(async move {
        let (stream, _) = portal.accept().await.unwrap();
        let _ = accepted_tx.send(());
        let _stream = stream;
        std::future::pending::<()>().await;
    });
    let vector = Vector::new(
        Url::parse(&format!(
            "vector://0123456789abcdef0123456789abcdef@{portal_addr}?in=127.0.0.1:1080"
        ))
        .unwrap(),
        Logger,
    )
    .unwrap();
    let controls = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connecting = TcpStream::connect(controls.local_addr().unwrap());
    let (accepted, client) = tokio::join!(controls.accept(), connecting);
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let shutdown = CancellationToken::new();
    let handling = tokio::spawn(handle_client(
        vector.inner.clone(),
        server,
        peer,
        shutdown.clone(),
    ));
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    client
        .write_all(&[5, COMMAND_CONNECT, 0, 1, 192, 0, 2, 1, 0, 80])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), accepted_rx)
        .await
        .unwrap()
        .unwrap();

    shutdown.cancel();

    tokio::time::timeout(Duration::from_millis(500), handling)
        .await
        .expect("SOCKS client stayed blocked on Portal setup")
        .unwrap()
        .unwrap();
    portal_task.abort();
}

#[tokio::test]
async fn invalid_tcp_target_does_not_publish_access() {
    let vector = Vector::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080")
            .unwrap(),
        Logger,
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    let handling = tokio::spawn(handle_client(
        vector.inner.clone(),
        server,
        peer,
        CancellationToken::new(),
    ));
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    client
        .write_all(&[5, COMMAND_CONNECT, 0, 3, 4, b'-', b'b', b'a', b'd', 0, 80])
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handling)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn socks_handshake_uses_the_vector_instance_timeout() {
    let mut vector = Vector::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:9?in=127.0.0.1:1080&pin=0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
        Logger,
    ).unwrap();
    Arc::get_mut(&mut vector.inner)
        .unwrap()
        .config
        .portal
        .handshake_timeout = Duration::from_millis(50);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (accepted, client) = tokio::join!(
        listener.accept(),
        TcpStream::connect(listener.local_addr().unwrap())
    );
    let (server, peer) = accepted.unwrap();
    let _client = client.unwrap();
    let started = tokio::time::Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        handle_client(vector.inner.clone(), server, peer, CancellationToken::new()),
    )
    .await
    .expect("SOCKS handshake ignored the instance budget")
    .unwrap_err();
    assert!(error.to_string().contains("SOCKS5 handshake timeout"));
    assert!(started.elapsed() >= Duration::from_millis(50));
}

#[tokio::test]
async fn tcp_listener_binding_is_exclusive_and_restarts_after_graceful_close() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let listener = listen_one(address.parse().unwrap()).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let competitor = socket2::Socket::new(
            socket2::Domain::for_address(endpoint),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        if endpoint.is_ipv6() {
            competitor.set_only_v6(true).unwrap();
        }
        competitor.set_reuse_address(true).unwrap();
        assert!(competitor.bind(&endpoint.into()).is_err());
        drop(competitor);
        drop(listener);
        let listener = listen_one(endpoint).expect("idle listener did not immediately rebind");
        let mut client = tokio::net::TcpStream::connect(endpoint).await.unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            accepted.read_to_end(&mut request),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(request, b"request");
        accepted.write_all(b"reply").await.unwrap();
        accepted.shutdown().await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reply, b"reply");
        drop((client, accepted, listener));
        let restarted =
            listen_one(endpoint).expect("gracefully closed listener did not immediately rebind");
        drop(restarted);
    }
}

#[tokio::test]
async fn socks_ipv6_listener_is_v6_only_and_coexists_with_ipv4() {
    let listener = listen_one("[::]:0".parse().unwrap()).unwrap();
    let port = listener.local_addr().unwrap().port();
    assert!(socket2::SockRef::from(&listener).only_v6().unwrap());
    let ipv4 = listen_one(([0, 0, 0, 0], port).into()).unwrap();
    drop((listener, ipv4));
}
