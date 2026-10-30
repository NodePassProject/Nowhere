// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC first-flow pipelining, rejection, and authenticated reuse tests.

use super::*;

#[tokio::test]
async fn rejected_udp_setup_releases_its_route_and_reuses_the_authenticated_connection_concurrently()
 {
    let (endpoint, client) = quic_fixture();
    let peer_endpoint = endpoint.clone();
    let credentials = client.credentials.clone();
    let peer = tokio::spawn(async move {
        let connection = peer_endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv, kind) = read_first_request(&connection, &credentials).await;
        assert_eq!(kind, FlowKind::Udp);
        write_flow_result(&mut send, SetupResult::FlowLimit.into())
            .await
            .unwrap();
        send.finish().unwrap();
        for _ in 0..4 {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(
                crate::protocol::read_flow_start(&mut recv).await.unwrap(),
                Some(FlowKind::Udp)
            );
            assert_eq!(
                read_request(&mut recv).await.unwrap(),
                Target::domain("example.com", 53).unwrap()
            );
            write_flow_result(&mut send, FlowResult::Ready)
                .await
                .unwrap();
            send.finish().unwrap();
        }
        connection.closed().await;
    });
    let target = Target::domain("example.com", 53).unwrap();
    assert!(matches!(
        client.open_quic_flow(FlowKind::Udp, &target).await,
        Err(OpenFlowError::Setup(SetupResult::FlowLimit))
    ));
    let cached = client.quic.lock().await.as_ref().unwrap().1.clone();
    drop(
        cached
            .register(1)
            .expect("rejected setup retained its UDP route"),
    );
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let client = client.clone();
        let target = target.clone();
        requests.spawn(async move {
            let flow = client.open_quic_flow(FlowKind::Udp, &target).await.unwrap();
            let id = flow.udp.as_ref().unwrap().0.id;
            drop(flow);
            id
        });
    }
    let ids = timeout(std::time::Duration::from_secs(2), async {
        let mut ids = std::collections::HashSet::new();
        while let Some(result) = requests.join_next().await {
            let id = result.unwrap();
            assert!(ids.insert(id));
            drop(
                cached
                    .register(id)
                    .expect("dropped flow retained its UDP route"),
            );
        }
        ids
    })
    .await
    .unwrap();
    assert_eq!(ids.len(), 4);
    assert!(Arc::ptr_eq(
        &client.quic.lock().await.as_ref().unwrap().1,
        &cached
    ));
    client
        .close(Instant::now() + std::time::Duration::from_secs(1))
        .await;
    timeout(std::time::Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn normal_tcp_and_udp_first_flows_pipeline_on_stream_zero_and_reuse_without_auth() {
    let (endpoint, template) = quic_fixture();
    let credentials = template.credentials.clone();
    let target = Target::domain("example.com", 443).unwrap();
    let expected = target.clone();
    let server_endpoint = endpoint.clone();
    let peer = tokio::spawn(async move {
        for kind in [FlowKind::Tcp, FlowKind::Udp] {
            let q = server_endpoint.accept().await.unwrap().await.unwrap();
            let mut exporter = [0; 32];
            q.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
                .unwrap();
            for index in 0..2 {
                let (mut send, mut recv) = q.accept_bi().await.unwrap();
                assert_eq!(u64::from(recv.id()), index * 4);
                if index == 0 {
                    assert_eq!(
                        read_auth_frame(&mut recv, &credentials, AuthTransport::Quic, &exporter)
                            .await
                            .unwrap(),
                        ConnectionRole::Vector
                    );
                }
                let mut flow_start = [0xff];
                recv.read_exact(&mut flow_start).await.unwrap();
                assert_eq!(flow_start, [kind as u8]);
                assert_eq!(read_request(&mut recv).await.unwrap(), expected);
                write_flow_result(&mut send, FlowResult::Ready)
                    .await
                    .unwrap();
                let _ = recv.read_to_end(0).await;
                let _ = send.finish();
            }
            q.closed().await;
        }
    });
    for kind in [FlowKind::Tcp, FlowKind::Udp] {
        let stats = Arc::new(Stats::default());
        let client = PortalClient::new(
            template.config.clone(),
            &template.credentials,
            template.udp_queue_bytes,
            stats.clone(),
            true,
            CancellationToken::new(),
        )
        .unwrap();
        for _ in 0..2 {
            if kind == FlowKind::Tcp {
                client
                    .open_tcp(&target)
                    .await
                    .unwrap()
                    .close()
                    .await
                    .unwrap();
            } else {
                let mut flow = crate::vector::udp_flow::open_udp(client.clone(), &target)
                    .await
                    .unwrap();
                flow.close().await;
            }
        }
        client
            .close(Instant::now() + std::time::Duration::from_secs(2))
            .await;
        assert_eq!(stats.tcp_active.load(Ordering::Relaxed), 0);
        assert_eq!(stats.udp_active.load(Ordering::Relaxed), 0);
    }
    peer.await.unwrap();
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn server_initiated_stream_still_closes_vector_after_authentication() {
    let (endpoint, client) = quic_fixture();
    let credentials = client.credentials.clone();
    let server_endpoint = endpoint.clone();
    let peer = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv, _) = read_first_request(&connection, &credentials).await;
        write_flow_result(&mut send, FlowResult::Ready)
            .await
            .unwrap();
        let (mut illegal, _) = connection.open_bi().await.unwrap();
        let _ = illegal.write_all(b"illegal").await;
        connection.closed().await
    });
    let flow = client
        .open_tcp(&Target::domain("example.com", 53).unwrap())
        .await
        .unwrap();
    let reason = timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.reason.as_ref(), b"role direction violation")
        }
        other => panic!("unexpected close: {other:?}"),
    }
    drop(flow);
    client.close(Instant::now() + Duration::from_secs(2)).await;
    endpoint.wait_idle().await;
}
