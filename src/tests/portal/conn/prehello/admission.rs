// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph TCP admission retention, release, and shutdown regressions.

use crate::protocol::test_support::encode_target;

use super::*;

#[tokio::test]
async fn shutdown_releases_all_morph_prehello_states() {
    for (size, fin) in [
        (0, false),
        (76, false),
        (77, false),
        (77, true),
        (200_000, false),
    ] {
        let h = Harness::new("direct", true).await;
        let inner = h.inner.clone();
        let permits = inner.connection_admission.available_permits();
        let mut stream = TcpStream::connect(h.tcp).await.unwrap();
        stream.write_all(&vec![0xff; size]).await.unwrap();
        if fin {
            stream.shutdown().await.unwrap();
        }
        wait_active(&h, 1).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        h.close().await;
        assert_eq!(inner.unauthenticated_admission.active(), 0);
        assert_eq!(inner.connection_admission.available_permits(), permits);
    }
}

#[tokio::test]
async fn silent_connections_park_above_source_limit_until_original_deadline() {
    let h = Harness::with_handshake_timeout(true, Duration::from_secs(1)).await;
    let mut streams = Vec::new();
    for _ in 0..64 {
        let mut stream = TcpStream::connect(h.tcp).await.unwrap();
        stream.write_all(&[0xff; 77]).await.unwrap();
        streams.push(stream);
    }
    wait_active(&h, 32).await;
    let mut readers = tokio::task::JoinSet::new();
    for mut stream in streams {
        readers.spawn(async move {
            let mut bytes = Vec::new();
            let closed = stream.read_to_end(&mut bytes).await;
            assert_silent_close(closed);
            assert!(bytes.is_empty());
        });
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(200), readers.join_next())
            .await
            .is_err()
    );
    assert_eq!(h.inner.unauthenticated_admission.active(), 32);
    assert_eq!(h.inner.connection_admission.available_permits(), 1024 - 32);
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(result) = readers.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}

#[tokio::test]
async fn admission_limits_park_real_socket_and_promote_waiting_vector() {
    for global in [false, true] {
        let h = Harness::new("direct", true).await;
        let held = (0..if global { 256 } else { 32 })
            .map(|index| {
                h.inner
                    .unauthenticated_admission
                    .try_acquire(if global {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            10,
                            0,
                            (index / 255) as u8,
                            index as u8,
                        ))
                    } else {
                        h.tcp.ip()
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut parked = TcpStream::connect(h.tcp).await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), parked.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(h.inner.connection_admission.available_permits(), 1024);
        let (target, echo) = tcp_echo().await;
        let client = h.client("tcp", true);
        let opening = client.open_tcp(&target);
        tokio::pin!(opening);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut opening)
                .await
                .is_err()
        );
        assert_eq!(h.inner.unauthenticated_admission.active(), held.len());
        drop(held);
        let mut tunnel = tokio::time::timeout(Duration::from_secs(2), &mut opening)
            .await
            .unwrap()
            .unwrap();
        tunnel.write_all(b"admission recovered").await.unwrap();
        let mut buffer = [0; 19];
        tunnel.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"admission recovered");
        drop(tunnel);
        client.close(Instant::now() + Duration::from_secs(2)).await;
        h.close().await;
        echo.abort();
    }
}

#[tokio::test]
async fn source_admission_promotion_keeps_original_deadline_and_shutdown_reclaims_waiters() {
    for release in [false, true] {
        let h = Harness::with_handshake_timeout(true, Duration::from_secs(1)).await;
        let inner = h.inner.clone();
        let mut held = (0..32)
            .map(|_| {
                inner
                    .unauthenticated_admission
                    .try_acquire(h.tcp.ip())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut parked = TcpStream::connect(h.tcp).await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(700), parked.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(inner.connection_admission.available_permits(), 1024);
        if release {
            held.clear();
            wait_active(&h, 1).await;
            let mut bytes = Vec::new();
            assert_silent_close(
                tokio::time::timeout(Duration::from_millis(600), parked.read_to_end(&mut bytes))
                    .await
                    .unwrap(),
            );
            assert!(bytes.is_empty());
            wait_active(&h, 0).await;
        }
        h.close().await;
        assert_eq!(inner.unauthenticated_admission.active(), held.len());
        assert_eq!(inner.connection_admission.available_permits(), 1024);
        drop(held);
        assert_eq!(inner.unauthenticated_admission.active(), 0);
    }
}

#[tokio::test]
async fn parked_tls_auth_frame_must_finish_before_original_deadline() {
    for late in [false, true] {
        let h = Harness::with_handshake_timeout(true, Duration::from_millis(1500)).await;
        let held = (0..32)
            .map(|_| {
                h.inner
                    .unauthenticated_admission
                    .try_acquire(h.tcp.ip())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let started = Instant::now();
        let stream = TcpStream::connect(h.tcp).await.unwrap();
        let stream = MorphTcpStream::connect_current_for_test(stream, h.inner.morph_keys.clone())
            .await
            .unwrap();
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(tls_config(&h, crate::protocol::ALPN)));
        let handshake = connector.connect("localhost".try_into().unwrap(), stream);
        tokio::pin!(handshake);
        assert!(
            tokio::time::timeout(Duration::from_millis(700), &mut handshake)
                .await
                .is_err()
        );
        assert_eq!(h.inner.connection_admission.available_permits(), 1024);
        drop(held);
        let mut tls = tokio::time::timeout(Duration::from_millis(400), &mut handshake)
            .await
            .unwrap()
            .unwrap();
        wait_active(&h, 1).await;
        let mut exporter = [0; 32];
        tls.get_ref()
            .1
            .export_keying_material(
                &mut exporter,
                crate::protocol::AUTH_EXPORTER_LABEL,
                Some(&[]),
            )
            .unwrap();
        let frame = encode_auth_frame(
            h.inner.credentials.vector_key,
            AuthTransport::TlsTcp,
            &exporter,
        );
        tls.write_all(&frame[..frame.len() - 1]).await.unwrap();
        tls.flush().await.unwrap();
        if late {
            tokio::time::sleep_until(started + Duration::from_millis(1650)).await;
        }
        let mut request = vec![frame[frame.len() - 1], 0];
        request.extend(encode_target(&Target::Ip(target.local_addr().unwrap())).unwrap());
        let sent = tls.write_all(&request).await;
        if late {
            let _ = tls.flush().await;
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(500),
                    crate::protocol::read_flow_result(&mut tls)
                )
                .await
                .unwrap()
                .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), target.accept())
                    .await
                    .is_err()
            );
            wait_active(&h, 0).await;
            assert_eq!(h.inner.connection_admission.available_permits(), 1024);
        } else {
            sent.unwrap();
            tls.flush().await.unwrap();
            assert_eq!(
                crate::protocol::read_flow_result(&mut tls).await.unwrap(),
                crate::protocol::FlowResult::Ready
            );
            let (mut destination, _) = target.accept().await.unwrap();
            tls.write_all(b"promoted").await.unwrap();
            let mut payload = [0; 8];
            destination.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"promoted");
            wait_active(&h, 0).await;
            assert_eq!(h.inner.connection_admission.available_permits(), 1023);
        }
        h.close().await;
    }
}

#[tokio::test]
async fn promoted_connection_releases_processing_permit_when_business_limit_is_full() {
    let h = Harness::new("direct", true).await;
    let held = (0..32)
        .map(|_| {
            h.inner
                .unauthenticated_admission
                .try_acquire(h.tcp.ip())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let business = h
        .inner
        .connection_admission
        .clone()
        .try_acquire_many_owned(1024)
        .unwrap();
    let mut stream = TcpStream::connect(h.tcp).await.unwrap();
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.read(&mut byte))
            .await
            .is_err()
    );
    drop(held);
    assert_silent_close(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .unwrap(),
    );
    wait_active(&h, 0).await;
    assert_eq!(h.inner.connection_admission.available_permits(), 0);
    drop(business);
    assert_eq!(h.inner.connection_admission.available_permits(), 1024);
    h.close().await;
}
