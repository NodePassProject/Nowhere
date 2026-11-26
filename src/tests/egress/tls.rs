// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Hydra growth, standby accounting, cooldown, and Egress-side TTL.

use std::time::Duration;

use socket2::SockRef;
use tokio::sync::mpsc;
use url::Url;

use crate::protocol::test_support::encode_target;

use super::*;

const KEY: &str = "0123456789abcdef0123456789abcdef";

type ServerTlsStream = tokio_rustls::server::TlsStream<MorphTcpStream<tokio::net::TcpStream>>;

async fn fake_portal() -> (
    Egress,
    mpsc::UnboundedReceiver<ServerTlsStream>,
    tokio::task::JoinHandle<()>,
) {
    fake_portal_with_morph(false).await
}

async fn fake_portal_with_morph(
    morph: bool,
) -> (
    Egress,
    mpsc::UnboundedReceiver<ServerTlsStream>,
    tokio::task::JoinHandle<()>,
) {
    let url = Url::parse(&format!("portal://{KEY}@127.0.0.1:2000?morph=0")).unwrap();
    let (_, tls, _) = crate::common::new_server_configs_with_reload_interval(
        &url,
        Duration::from_secs(3600),
        crate::common::Logger,
    )
    .unwrap();
    let pin = crate::tls_test_support::server_certificate_pin(&tls);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let egress = Egress::new(
        Url::parse(&format!(
            "egress://{KEY}@{}/tcp:{}?morph={}&pin={pin}",
            address.ip(),
            address.port(),
            u8::from(morph),
        ))
        .unwrap(),
        crate::common::Logger,
    )
    .unwrap();
    let keys = egress.config.morph_keys.clone();
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.clone());
            let tx = tx.clone();
            let keys = keys.clone();
            tokio::spawn(async move {
                let (stream, _) = MorphTcpStream::accept_bootstrap(stream, keys)
                    .await
                    .unwrap();
                if let Ok(mut stream) = acceptor.accept(stream).await {
                    let mut auth = [0; 16];
                    if stream.read_exact(&mut auth).await.is_ok()
                        && stream.write_all(&[0]).await.is_ok()
                        && stream.flush().await.is_ok()
                    {
                        let _ = tx.send(stream);
                    }
                }
            });
        }
    });
    (egress, rx, task)
}

async fn receive(rx: &mut mpsc::UnboundedReceiver<ServerTlsStream>) -> ServerTlsStream {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn tcp_keepalive_uses_fifteen_seconds_and_preserves_default_retries() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let socket = SockRef::from(&stream);
    assert!(!socket.keepalive().unwrap());
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    let retries = socket.tcp_keepalive_retries().unwrap();

    socket.set_tcp_keepalive(&tcp_keepalive()).unwrap();
    assert!(socket.keepalive().unwrap());
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        assert_eq!(
            socket.tcp_keepalive_time().unwrap(),
            Duration::from_secs(15)
        );
        assert_eq!(
            socket.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(15)
        );
        assert_eq!(socket.tcp_keepalive_retries().unwrap(), retries);
    }
}

#[tokio::test]
async fn tcp_keepalive_survives_standby_and_flow_start_with_and_without_morph() {
    for morph in [false, true] {
        let (egress, mut rx, server) = fake_portal_with_morph(morph).await;
        let task = tokio::spawn(pending_connection(
            egress.config.clone(),
            egress.tls.clone(),
            egress.credentials.egress_key,
            egress.forward.shutdown.clone(),
            Duration::from_secs(120),
        ));
        let mut peer = receive(&mut rx).await;
        peer.write_all(&[0]).await.unwrap();
        peer.flush().await.unwrap();
        let PendingResult::Started(mut stream, FlowKind::Tcp) =
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        else {
            panic!("expected a started TCP Flow");
        };
        let socket = SockRef::from(stream.get_ref().0.get_ref());
        assert!(socket.keepalive().unwrap());
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        {
            assert_eq!(
                socket.tcp_keepalive_time().unwrap(),
                Duration::from_secs(15)
            );
            assert_eq!(
                socket.tcp_keepalive_interval().unwrap(),
                Duration::from_secs(15)
            );
        }
        stream.write_all(b"flow").await.unwrap();
        stream.flush().await.unwrap();
        let mut payload = [0; 4];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload, b"flow");
        assert!(
            SockRef::from(stream.get_ref().0.get_ref())
                .keepalive()
                .unwrap()
        );
        server.abort();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
#[tokio::test]
async fn tcp_keepalive_configuration_error_stops_before_handshake() {
    let (egress, _rx, server) = fake_portal().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });
    let invalid = TcpKeepalive::new().with_retries(u32::MAX);
    let error = egress
        .tls
        .connect_tcp_with_keepalive(
            &address,
            &egress.config.dial_policy,
            crate::common::AddressFamily::Any,
            Some(&invalid),
        )
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("failed to configure TCP keepalive"));
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn growth_obeys_max_and_disconnects_only_reseed_when_empty() {
    let (mut egress, mut rx, server) = fake_portal().await;
    egress.tls_pool_max = 2;
    let shutdown = egress.forward.shutdown.clone();
    let task = tokio::spawn(async move { egress.maintain_tls().await });
    let mut seed = receive(&mut rx).await;
    seed.write_all(&[0]).await.unwrap();
    seed.flush().await.unwrap();
    let mut a = receive(&mut rx).await;
    let b = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    a.write_all(&[0]).await.unwrap();
    a.flush().await.unwrap();
    let c = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    drop(b);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    drop(c);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err()
    );
    let replacement = tokio::time::timeout(Duration::from_secs(4), rx.recv())
        .await
        .unwrap()
        .unwrap();
    drop(replacement);
    drop(seed);
    drop(a);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn egress_ttl_expires_standby() {
    let (egress, mut rx, server) = fake_portal().await;
    let ttl = Duration::from_millis(200);
    let started = Instant::now();
    let task = tokio::spawn(pending_connection(
        egress.config.clone(),
        egress.tls.clone(),
        egress.credentials.egress_key,
        egress.forward.shutdown.clone(),
        ttl,
    ));
    let _stream = receive(&mut rx).await;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        PendingResult::Expired
    ));
    assert!(started.elapsed() >= ttl);
    server.abort();
}

#[tokio::test]
async fn flow_start_wins_when_standby_ttl_is_also_ready() {
    let deadline = Instant::now() - Duration::from_secs(1);
    tokio::time::sleep_until(deadline).await;
    for raw in [0, 1, 0xfe, 0xff] {
        let kind = FlowKind::try_from(raw).unwrap();
        let bytes = [raw];
        let mut stream = bytes.as_slice();
        assert_eq!(
            wait_flow_start(&mut stream, &CancellationToken::new(), deadline)
                .await
                .unwrap(),
            Some(kind)
        );
    }
}

#[tokio::test]
async fn shutdown_keeps_priority_over_flow_start_and_standby_ttl() {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let mut stream = &[FlowKind::Tcp as u8][..];
    let error = wait_flow_start(
        &mut stream,
        &shutdown,
        Instant::now() - Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("shutting down"));
    assert_eq!(stream.len(), 1);
}

#[tokio::test]
async fn expired_standby_without_flow_start_expires_but_eof_still_fails() {
    let shutdown = CancellationToken::new();
    let deadline = Instant::now() - Duration::from_secs(1);
    tokio::time::sleep_until(deadline).await;
    let (mut stream, _peer) = tokio::io::duplex(1);
    assert_eq!(
        wait_flow_start(&mut stream, &shutdown, deadline)
            .await
            .unwrap(),
        None
    );
    let mut stream = &[][..];
    assert!(
        wait_flow_start(&mut stream, &shutdown, deadline)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn max_one_replaces_consumed_standby_without_exceeding_one() {
    let (mut egress, mut rx, server) = fake_portal().await;
    egress.tls_pool_max = 1;
    let ttl = Duration::from_millis(300);
    std::sync::Arc::get_mut(&mut egress.forward)
        .unwrap()
        .runtime
        .egress_tls_idle_ttl = ttl;
    let shutdown = egress.forward.shutdown.clone();
    let task = tokio::spawn(async move { egress.maintain_tls().await });
    let mut seed = receive(&mut rx).await;
    seed.write_all(&[0]).await.unwrap();
    seed.flush().await.unwrap();
    let replacement = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    tokio::time::sleep(ttl + Duration::from_millis(50)).await;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = crate::protocol::Target::Ip(target.local_addr().unwrap());
    seed.write_all(&encode_target(&address).unwrap())
        .await
        .unwrap();
    seed.flush().await.unwrap();
    let (_socket, _) = tokio::time::timeout(Duration::from_secs(2), target.accept())
        .await
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        crate::protocol::read_flow_result(&mut seed),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        crate::protocol::SetupResult::from(result),
        crate::protocol::SetupResult::Ready
    );
    drop(seed);
    drop(replacement);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn idle_growth_decays_to_a_single_seed() {
    let (mut egress, mut rx, server) = fake_portal().await;
    std::sync::Arc::get_mut(&mut egress.forward)
        .unwrap()
        .runtime
        .egress_tls_idle_ttl = Duration::from_millis(500);
    let shutdown = egress.forward.shutdown.clone();
    let task = tokio::spawn(async move { egress.maintain_tls().await });
    let mut initial = receive(&mut rx).await;
    initial.write_all(&[0]).await.unwrap();
    initial.flush().await.unwrap();
    let a = receive(&mut rx).await;
    let b = receive(&mut rx).await;

    let seed = receive(&mut rx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    drop(initial);
    drop(a);
    drop(b);
    drop(seed);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    server.abort();
}
