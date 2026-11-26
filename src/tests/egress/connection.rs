// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress registration ordering, target dialing barriers, and online lifecycle tests.

use url::Url;

use crate::common::Logger;
use crate::protocol::test_support::encode_target;
use crate::protocol::{AUTH_EXPORTER_LABEL, AuthTransport, Credentials};

use super::*;

#[tokio::test]
async fn shutdown_cancels_pending_connection_and_registration() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    let url = Url::parse(&format!("portal://{KEY}@127.0.0.1:2000")).unwrap();
    let (_, tls, quic) = crate::common::new_server_configs_with_reload_interval(
        &url,
        std::time::Duration::from_secs(3600),
        Logger,
    )
    .unwrap();
    let pin = crate::tls_test_support::server_certificate_pin(&tls);
    for accept in [false, true] {
        let endpoint =
            quinn::Endpoint::server(quic.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let egress = Egress::new(
            Url::parse(&format!(
                "egress://{KEY}@{}?morph=0&pin={pin}",
                endpoint.local_addr().unwrap()
            ))
            .unwrap(),
            Logger,
        )
        .unwrap();
        let shutdown = egress.forward.shutdown.clone();
        let task = tokio::spawn(async move { egress.run_connection().await });
        let incoming = tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let held = if accept {
            let connection = incoming.await.unwrap();
            let (send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(16).await.unwrap().len(), 16);
            (connection, send, recv)
        } else {
            shutdown.cancel();
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            incoming.ignore();
            continue;
        };
        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let (connection, _send, _recv) = held;
        tokio::time::timeout(std::time::Duration::from_secs(2), connection.closed())
            .await
            .unwrap();
        endpoint.wait_idle().await;
    }
}

#[tokio::test]
async fn accepted_barrier_prevents_dial_when_business_stream_arrives_first() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    let url = Url::parse(&format!("portal://{KEY}@127.0.0.1:2000")).unwrap();
    let (_, tls, mut quic) = crate::common::new_server_configs_with_reload_interval(
        &url,
        std::time::Duration::from_secs(3600),
        Logger,
    )
    .unwrap();
    let pin = crate::tls_test_support::server_certificate_pin(&tls);
    let limits = crate::transport::transport_flow_control().unwrap();
    let transport = Arc::get_mut(&mut quic.transport).unwrap();
    transport
        .max_concurrent_bidi_streams(1u32.into())
        .receive_window((64 * 1024u32).into())
        .stream_receive_window(limits.stream_receive_window.into());
    let endpoint = quinn::Endpoint::server(quic, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let egress = Egress::new(
        Url::parse(&format!("egress://{KEY}@{address}?morph=0&pin={pin}")).unwrap(),
        Logger,
    )
    .unwrap();
    let task = tokio::spawn(async move { egress.run_connection().await });
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    let (mut auth_send, mut auth_recv) = connection.accept_bi().await.unwrap();
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, b"")
        .unwrap();
    assert_eq!(
        crate::protocol::read_auth_frame(
            &mut auth_recv,
            &Credentials::from_shared_key(KEY.as_bytes()).unwrap(),
            AuthTransport::Quic,
            &exporter
        )
        .await
        .unwrap(),
        crate::protocol::ConnectionRole::Egress
    );
    auth_recv.read_to_end(0).await.unwrap();
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut request = vec![0];
    request
        .extend(encode_target(&crate::protocol::Target::Ip(target.local_addr().unwrap())).unwrap());
    send.write_all(&request).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(60), target.accept())
            .await
            .is_err()
    );
    auth_send.write_all(&[0]).await.unwrap();
    auth_send.finish().unwrap();
    let (_target, _) = tokio::time::timeout(std::time::Duration::from_secs(2), target.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::protocol::SetupResult::from(
            crate::protocol::read_flow_result(&mut recv).await.unwrap()
        ),
        crate::protocol::SetupResult::Ready
    );
    connection.close(0u32.into(), b"test");
    task.await.unwrap().unwrap();
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn registration_deadline_covers_stream_credit_auth_write_and_complete_reply() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    for stage in 0..4 {
        let url = Url::parse(&format!("portal://{KEY}@127.0.0.1:2000")).unwrap();
        let (_, tls, mut quic) = crate::common::new_server_configs_with_reload_interval(
            &url,
            std::time::Duration::from_secs(3600),
            Logger,
        )
        .unwrap();
        let pin = crate::tls_test_support::server_certificate_pin(&tls);
        let transport = Arc::get_mut(&mut quic.transport).unwrap();
        if stage == 1 {
            transport.stream_receive_window(0u32.into());
        } else {
            transport.max_concurrent_bidi_streams(0u32.into());
        }
        let endpoint = quinn::Endpoint::server(quic, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut egress = Egress::new(
            Url::parse(&format!(
                "egress://{KEY}@{}?morph=0&pin={pin}",
                endpoint.local_addr().unwrap(),
            ))
            .unwrap(),
            Logger,
        )
        .unwrap();
        Arc::get_mut(&mut egress.forward)
            .unwrap()
            .runtime
            .handshake_timeout = std::time::Duration::from_millis(600);
        let task = tokio::spawn(async move { egress.run_connection().await });
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let held = if stage >= 2 {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            connection.set_max_concurrent_bi_streams(1u32.into());
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(16).await.unwrap().len(), 16);
            if stage == 3 {
                send.write_all(&[0]).await.unwrap();
            }
            Some((send, recv))
        } else {
            None
        };
        let error = tokio::time::timeout(
            std::time::Duration::from_millis(if stage >= 2 { 550 } else { 850 }),
            task,
        )
        .await
        .expect("registration ignored its total deadline")
        .unwrap()
        .unwrap_err();
        assert!(
            error
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some(),
            "{error:#}"
        );
        assert!(format!("{error:#}").contains("registration timeout"));
        tokio::time::timeout(std::time::Duration::from_secs(1), connection.closed())
            .await
            .expect("registration timeout retained its connection");
        drop(held);
        endpoint.close(0u32.into(), b"done");
    }
}
