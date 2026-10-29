// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Whole-operation setup deadlines and resource reclamation across carriers.

use tokio::io::AsyncReadExt;

use crate::transport::MorphTcpStream;

use super::*;

fn assert_elapsed(error: OpenFlowError) {
    let OpenFlowError::Transport(error) = error else {
        panic!("expected setup timeout, got {error}");
    };
    assert!(
        error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some(),
        "{error:#}"
    );
}

#[tokio::test]
async fn tls_tcp_and_udp_share_handshake_and_ready_budget() {
    for kind in [FlowKind::Tcp, FlowKind::Udp] {
        let url =
            url::Url::parse("portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000").unwrap();
        let (_, tls, _) = crate::common::new_server_configs_with_reload_interval(
            &url,
            Duration::from_secs(3600),
            Logger,
        )
        .unwrap();
        let pin = crate::tls_test_support::server_certificate_pin(&tls);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (config, credentials) = PortalClientConfig::from_probe_url(
            &url::Url::parse(&format!(
                "vector://0123456789abcdef0123456789abcdef@{}/tcp:{}?morph=0&pin={pin}",
                listener.local_addr().unwrap().ip(),
                listener.local_addr().unwrap().port(),
            ))
            .unwrap(),
        )
        .unwrap();
        let mut client = PortalClient::new(
            config,
            &credentials,
            4 * 1024 * 1024,
            Arc::new(Stats::default()),
            true,
            CancellationToken::new(),
        )
        .unwrap();
        Arc::get_mut(&mut client).unwrap().flow_setup_timeout = Duration::from_millis(600);
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            let (stream, _) = MorphTcpStream::accept_bootstrap(stream, None)
                .await
                .unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(tls)
                .accept(stream)
                .await
                .unwrap();
            let mut auth = [0; 16];
            stream.read_exact(&mut auth).await.unwrap();
            assert_eq!(
                crate::protocol::read_flow_start(&mut stream).await.unwrap(),
                Some(kind)
            );
            read_request(&mut stream).await.unwrap();
            let mut byte = [0];
            assert!(!matches!(stream.read(&mut byte).await, Ok(n) if n > 0));
        });
        let started = Instant::now();
        let target = Target::domain("example.com", 53).unwrap();
        let error = timeout(Duration::from_millis(850), async {
            if kind == FlowKind::Tcp {
                client.open_tcp(&target).await.err().unwrap()
            } else {
                crate::vector::udp_flow::open_udp(client.clone(), &target)
                    .await
                    .err()
                    .unwrap()
            }
        })
        .await
        .expect("setup restarted the budget after the handshake");
        assert_elapsed(error);
        assert!(started.elapsed() >= Duration::from_millis(600));
        timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client.stats.tcp_active.load(Ordering::Relaxed), 0);
        assert_eq!(client.stats.udp_active.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn first_quic_timeout_releases_connection_cache_lock_and_udp_route() {
    for kind in [FlowKind::Tcp, FlowKind::Udp] {
        let (endpoint, mut client) = quic_fixture();
        Arc::get_mut(&mut client).unwrap().flow_setup_timeout = Duration::from_millis(600);
        let opening = client.clone();
        let task = tokio::spawn(async move {
            opening
                .open_quic_flow(kind, &Target::domain("example.com", 53).unwrap())
                .await
        });
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let (_send, _recv, observed) = read_first_request(&connection, &client.credentials).await;
        assert_eq!(observed, kind);
        assert_elapsed(
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .err()
                .unwrap(),
        );
        assert!(client.quic.try_lock().unwrap().is_none());
        assert_eq!(client.stats.udp_active.load(Ordering::Relaxed), 0);
        timeout(Duration::from_secs(1), connection.closed())
            .await
            .unwrap();
        endpoint.close(0u32.into(), b"done");
    }
}

#[tokio::test]
async fn quic_lock_wait_and_reused_ready_share_one_budget_without_closing_active_flows() {
    let (endpoint, mut client) = quic_fixture();
    Arc::get_mut(&mut client).unwrap().flow_setup_timeout = Duration::from_millis(600);
    let peer_endpoint = endpoint.clone();
    let credentials = client.credentials.clone();
    let (ready, pending) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = peer_endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, recv, _) = read_first_request(&connection, &credentials).await;
        write_flow_result(&mut send, FlowResult::Ready)
            .await
            .unwrap();
        let (blocked_send, mut blocked_recv) = connection.accept_bi().await.unwrap();
        crate::protocol::read_flow_start(&mut blocked_recv)
            .await
            .unwrap();
        read_request(&mut blocked_recv).await.unwrap();
        ready.send(()).unwrap();
        let _ = blocked_recv.read_to_end(0).await;
        drop((blocked_send, blocked_recv));
        send.write_all(&[42]).await.unwrap();
        let (_send, mut recv_next) = connection.accept_bi().await.unwrap();
        assert_eq!(
            crate::protocol::read_flow_start(&mut recv_next)
                .await
                .unwrap(),
            Some(FlowKind::Udp)
        );
        read_request(&mut recv_next).await.unwrap();
        connection.closed().await;
        drop(recv);
    });
    let target = Target::domain("example.com", 53).unwrap();
    let mut active = client.open_quic_flow(FlowKind::Tcp, &target).await.unwrap();
    let state = client.quic.lock().await;
    let cached = state.as_ref().unwrap().1.clone();
    let opening = client.clone();
    let task = tokio::spawn(async move { opening.open_quic_flow(FlowKind::Udp, &target).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(state);
    pending.await.unwrap();
    let error = timeout(Duration::from_millis(550), task)
        .await
        .expect("lock waiting restarted the setup budget")
        .unwrap()
        .err()
        .unwrap();
    assert_elapsed(error);
    drop(
        cached
            .register(2)
            .expect("timed-out setup retained its UDP route"),
    );
    assert!(!cached.cancel.is_cancelled());
    assert!(Arc::ptr_eq(
        &client.quic.lock().await.as_ref().unwrap().1,
        &cached
    ));
    let mut byte = [0];
    active.recv.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, [42]);
    let opening = client.clone();
    let next = tokio::spawn(async move {
        opening
            .open_quic_flow(FlowKind::Udp, &Target::domain("example.com", 53).unwrap())
            .await
    });
    assert_elapsed(
        timeout(Duration::from_secs(1), next)
            .await
            .unwrap()
            .unwrap()
            .err()
            .unwrap(),
    );
    drop(
        cached
            .register(3)
            .expect("subsequent setup retained its UDP route"),
    );
    client.close(Instant::now() + Duration::from_secs(1)).await;
    peer.await.unwrap();
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn quic_setup_bounds_blocked_stream_credit_and_request_writes() {
    for (blocked_write, handshake_first) in [(false, false), (true, false), (false, true)] {
        timeout(Duration::from_secs(5), async {
            let (endpoint, mut client) = quic_fixture_with_transport(|transport| {
                if blocked_write {
                    transport.stream_receive_window(0u32.into());
                } else {
                    transport.max_concurrent_bidi_streams(0u32.into());
                }
            });
            let prepared = if handshake_first {
                let (connected, accepted) = tokio::join!(
                    connect_quic(&client.config, &client.tls),
                    async { endpoint.accept().await.unwrap().await.unwrap() },
                );
                let (local, connection) = connected.unwrap();
                let client = Arc::get_mut(&mut client).unwrap();
                client.config.handshake_timeout = Duration::from_millis(100);
                *client.quic.get_mut() = Some((
                    local,
                    QuicConnection::new(connection, false, client.udp_queue_bytes),
                ));
                Some(accepted)
            } else {
                Arc::get_mut(&mut client).unwrap().flow_setup_timeout = Duration::from_millis(400);
                None
            };
            let target = Target::domain("example.com", 53).unwrap();
            let opening = client.open_quic_flow(FlowKind::Udp, &target);
            tokio::pin!(opening);
            let connection = match prepared {
                Some(connection) => connection,
                None => tokio::select! {
                    result = &mut opening => panic!("setup ended before transport connected: {:?}", result.err()),
                    connection = async { endpoint.accept().await.unwrap().await.unwrap() } => connection,
                },
            };
            assert_elapsed(
                timeout(Duration::from_secs(1), &mut opening)
                    .await
                    .expect("blocked setup ignored its shorter budget")
                    .err()
                    .unwrap(),
            );
            assert_eq!(client.quic.try_lock().unwrap().is_some(), handshake_first);
            client.close(Instant::now() + Duration::from_secs(1)).await;
            connection.closed().await;
            endpoint.close(0u32.into(), b"done");
        })
        .await
        .expect("QUIC setup test exceeded its total deadline");
    }
}
