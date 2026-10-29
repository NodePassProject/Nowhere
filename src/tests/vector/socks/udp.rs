// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 UDP source validation, target admission, and association shutdown tests.

use std::sync::atomic::Ordering;
use std::time::Duration;

use url::Url;

use crate::common::Logger;
use crate::vector::VectorRuntime as Vector;

use super::*;

#[test]
fn source_request_rejects_other_ips_and_domains() {
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        validate_udp_source_request(&SocksAddress::Ip("127.0.0.2:1234".parse().unwrap()), peer,)
            .is_err()
    );
    assert!(
        validate_udp_source_request(&SocksAddress::Domain("localhost".into(), 1234), peer).is_err()
    );
}

#[test]
fn source_endpoint_locks_first_port() {
    let endpoint = StdMutex::new(None);
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1000".parse().unwrap()
    ));
    assert!(accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1000".parse().unwrap()
    ));
    assert!(!accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1001".parse().unwrap()
    ));
}

#[test]
fn udp_target_resource_admission_is_held_for_the_target_lifetime() {
    let vector = Vector::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080")
            .unwrap(),
        Logger,
    )
    .unwrap();
    let admission = &vector.inner.socks_udp_target_admission;
    let limit = admission.available_permits();
    let mut held = (0..limit)
        .map(|_| try_admit_udp_target(admission).unwrap())
        .collect::<Vec<_>>();
    assert!(try_admit_udp_target(admission).is_none());

    held.pop();
    assert!(try_admit_udp_target(admission).is_some());
}

#[tokio::test]
async fn pending_target_setup_does_not_block_control_shutdown() {
    let portal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let portal_addr = portal.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let portal_task = tokio::spawn(async move {
        let (stream, _) = portal.accept().await.unwrap();
        let _ = accepted_tx.send(());
        let _stream = stream;
        tokio::time::sleep(Duration::from_secs(10)).await;
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
    let association = tokio::spawn(run_udp_association(
        vector.inner.clone(),
        server,
        peer,
        SocksAddress::unspecified(),
        CancellationToken::new(),
    ));

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, REPLY_SUCCEEDED, 0, 1]);
    let udp_endpoint = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let local_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = Vec::new();
    encode_udp_packet_into(
        &mut packet,
        &SocksAddress::Ip("192.0.2.1:53".parse().unwrap()),
        b"request",
    )
    .unwrap();
    local_udp.send_to(&packet, udp_endpoint).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), accepted_rx)
        .await
        .unwrap()
        .unwrap();

    drop(client);
    tokio::time::timeout(Duration::from_millis(500), association)
        .await
        .expect("association stayed blocked on target setup")
        .unwrap()
        .unwrap();
    portal_task.abort();
}

async fn relay_finish(blocked_send: bool, cancel_carrier: bool) {
    let vector = Vector::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080")
            .unwrap(),
        Logger,
    )
    .unwrap();

    let target = SocksAddress::Ip("127.0.0.1:53".parse().unwrap());
    let (stream, peer) = tokio::io::duplex(1);
    let (reader, writer) = tokio::io::split(stream);
    let tunnel = UdpTunnel::stream(
        Box::pin(reader),
        Box::pin(writer),
        crate::vector::flow::TcpTunnelGuard { _flow: None },
        vector.inner.stats.clone(),
        true,
        vector.inner.config.handshake_timeout,
    );
    let cancel = tunnel.cancellation();
    let (sender, receiver) = mpsc::channel(1);
    if blocked_send {
        sender
            .send(QueuedLocalPacket {
                payload: vec![1; 128],
                _permit: vector
                    .inner
                    .local_udp_budget
                    .clone()
                    .acquire_many_owned(128)
                    .await
                    .unwrap(),
            })
            .await
            .unwrap();
    }
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let stats = vector.inner.stats.clone();
    let task = tokio::spawn(relay_udp_target(
        vector.inner,
        UdpClientSide {
            socket,
            endpoint: Arc::new(StdMutex::new(Some("127.0.0.1:10000".parse().unwrap()))),
            idle_timeout: if blocked_send {
                Duration::from_millis(200)
            } else {
                udp_idle_timeout()
            },
        },
        target,
        tunnel,
        receiver,
        CancellationToken::new(),
    ));
    tokio::task::yield_now().await;
    if blocked_send {
        assert!(!task.is_finished());
    } else if cancel_carrier {
        cancel.cancel();
    } else {
        drop(peer);
    }
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("UDP relay did not finish")
        .unwrap();
    assert_eq!(stats.udp_active.load(Ordering::Relaxed), 0);
    assert_eq!(stats.udp_upload_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(stats.udp_download_bytes.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn idle_timeout_during_udp_send_is_reported_as_timeout() {
    relay_finish(true, false).await;
}

#[tokio::test]
async fn cancelled_udp_carrier_is_not_reported_as_success() {
    relay_finish(false, true).await;
}

#[tokio::test]
async fn normal_udp_stream_eof_is_reported_as_success() {
    relay_finish(false, false).await;
}

#[tokio::test]
async fn invalid_udp_target_does_not_publish_access() {
    let vector = Vector::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080")
            .unwrap(),
        Logger,
    )
    .unwrap();

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (_sender, receiver) = mpsc::channel(1);
    let permit = try_admit_udp_target(&vector.inner.socks_udp_target_admission).unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        open_and_relay_udp_target(
            vector.inner.clone(),
            socket,
            Arc::new(StdMutex::new(Some("127.0.0.1:10000".parse().unwrap()))),
            SocksAddress::Domain("-bad".to_owned(), 53),
            receiver,
            CancellationToken::new(),
            permit,
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn idle_association_exits_on_control_close_and_cancellation() {
    for cancel in [false, true] {
        let vector = Vector::new(
            Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:9?in=127.0.0.1:1080")
                .unwrap(),
            Logger,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (control, peer) = listener.accept().await.unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_udp_association(
            vector.inner.clone(),
            control,
            peer,
            SocksAddress::unspecified(),
            shutdown.clone(),
        ));
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REPLY_SUCCEEDED);
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        if cancel {
            shutdown.cancel();
        } else {
            drop(client);
        }
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            vector.inner.local_udp_budget.available_permits(),
            4 * 1024 * 1024
        );
    }
}
