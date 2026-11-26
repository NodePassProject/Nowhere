// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal udp connection regression tests.

use crate::protocol::test_support::encode_udp_data;

use super::*;

#[tokio::test]
async fn persistent_udp_control_fin_reclaims_without_close_datagram() {
    let h = Harness::new("direct", false).await;
    let (target, echo) = udp_echo().await;
    let (endpoint, q) = connect(&h).await;
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    send.write_all(&tag(&q, false)).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(0).await.unwrap();
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    let id = crate::protocol::udp_flow_id(u64::from(send.id()), false).unwrap();
    request(&mut send, 0xff, &target).await;
    assert_eq!(result(&mut recv).await, SetupResult::Ready);
    assert!(
        tokio::time::timeout(Duration::from_millis(40), recv.read_to_end(0))
            .await
            .is_err()
    );
    let frame = encode_udp_data(id, b"packet").unwrap();
    q.send_datagram(bytes::Bytes::from(frame)).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(1), q.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(crate::protocol::decode_udp_frame_owned(response).unwrap(),crate::protocol::OwnedUdpFrame::Data {payload,..} if payload==b"packet"[..])
    );
    send.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(0))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while h
            .inner
            .forward
            .stats
            .udp_active
            .load(std::sync::atomic::Ordering::Relaxed)
            != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    q.send_datagram(bytes::Bytes::from(encode_udp_data(id, b"late").unwrap()))
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(40);
    while let Ok(Ok(bytes)) = tokio::time::timeout_at(deadline, q.read_datagram()).await {
        assert!(matches!(
            crate::protocol::decode_udp_frame_owned(bytes).unwrap(),
            crate::protocol::OwnedUdpFrame::Close { .. }
        ));
    }
    q.close(0u32.into(), b"test");
    endpoint.wait_idle().await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn udp_reset_and_stop_sending_reclaim_only_the_owned_flow() {
    let h = Harness::new("direct", false).await;
    let (target, echo) = udp_echo().await;
    let (endpoint, q) = connect(&h).await;
    let (mut auth, mut response) = q.open_bi().await.unwrap();
    auth.write_all(&tag(&q, false)).await.unwrap();
    auth.finish().unwrap();
    response.read_to_end(0).await.unwrap();
    for reset in [true, false] {
        let (mut send, mut recv) = q.open_bi().await.unwrap();
        request(&mut send, 1, &target).await;
        assert_eq!(result(&mut recv).await, SetupResult::Ready);
        if reset {
            send.reset(7u32.into()).unwrap();
        } else {
            recv.stop(7u32.into()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while h
                .inner
                .forward
                .stats
                .udp_active
                .load(std::sync::atomic::Ordering::Relaxed)
                != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(q.close_reason().is_none());
    }
    q.close(0u32.into(), b"test");
    endpoint.wait_idle().await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn quic_udp_without_datagram_capability_rejects_flow() {
    let h = Harness::new("direct", false).await;

    let (config, _) = PortalClientConfig::from_probe_url(&h.url("vector", "udp", false)).unwrap();
    let tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    let mut client = tls.quic_client_config().unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(None);
    client.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client);
    let q = endpoint.connect(h.udp, "127.0.0.1").unwrap().await.unwrap();
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    send.write_all(&tag(&q, false)).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(0).await.unwrap();
    let (target, echo) = udp_echo().await;
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    request(&mut send, 1, &target).await;
    assert_eq!(result(&mut recv).await, SetupResult::InternalError);
    assert!(q.close_reason().is_none());
    q.close(0u32.into(), b"test");
    endpoint.wait_idle().await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn pre_ready_unknown_and_auth_only_datagrams_never_reach_target() {
    let h = Harness::new("direct", false).await;
    let (endpoint, q) = connect(&h).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = Target::Ip(socket.local_addr().unwrap());
    let frame = encode_udp_data(1, b"auth-only").unwrap();
    q.send_datagram(bytes::Bytes::from(frame)).unwrap();
    let (mut auth, mut response) = q.open_bi().await.unwrap();
    auth.write_all(&tag(&q, false)).await.unwrap();
    auth.finish().unwrap();
    response.read_to_end(0).await.unwrap();
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    let id = crate::protocol::udp_flow_id(u64::from(send.id()), false).unwrap();
    q.send_datagram(bytes::Bytes::from(
        encode_udp_data(id, b"before request").unwrap(),
    ))
    .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    request(&mut send, 1, &target).await;
    assert_eq!(result(&mut recv).await, SetupResult::Ready);
    q.send_datagram(bytes::Bytes::from(
        encode_udp_data(1, b"still auth-only").unwrap(),
    ))
    .unwrap();
    let mut bytes = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), socket.recv(&mut bytes))
            .await
            .is_err()
    );
    send.finish().unwrap();
    let _ = recv.read_to_end(0).await;
    q.close(0u32.into(), b"test");
    endpoint.wait_idle().await;
    h.close().await;
}

#[tokio::test]
async fn a_full_udp_flow_queue_does_not_block_another_flow_and_counters_reclaim() {
    let h = Harness::new("direct", false).await;
    let (target, echo) = udp_echo().await;
    let client = h.client("udp", false);
    let mut slow = crate::vector::udp_flow::open_udp(client.clone(), &target)
        .await
        .unwrap();
    let mut fast = crate::vector::udp_flow::open_udp(client.clone(), &target)
        .await
        .unwrap();
    for i in 0..256 {
        assert!(slow.send(&vec![i as u8; 256]).await.unwrap());
        tokio::time::sleep(Duration::from_micros(100)).await;
    }
    assert!(fast.send(b"independent").await.unwrap());
    let mut buffer = Vec::new();
    let packet = tokio::time::timeout(Duration::from_secs(1), fast.recv_into(&mut buffer))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(packet.payload(&buffer), b"independent");
    assert_eq!(
        client
            .stats
            .udp_active
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    slow.close().await;
    fast.close().await;
    drop(slow);
    drop(fast);
    tokio::time::timeout(Duration::from_secs(1), async {
        while h
            .inner
            .forward
            .stats
            .udp_active
            .load(std::sync::atomic::Ordering::Relaxed)
            != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        client
            .stats
            .udp_active
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(1))
        .await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn datagrams_queued_before_auth_cannot_become_first_udp_flow_payload() {
    let h = Harness::new("direct", false).await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (endpoint, q) = connect(&h).await;
    q.send_datagram(encode_udp_data(1, b"early").unwrap().into())
        .unwrap();
    let (mut send, mut recv) = q.open_bi().await.unwrap();
    send.write_all(&tag(&q, false)).await.unwrap();
    request(&mut send, 1, &Target::Ip(target.local_addr().unwrap())).await;
    assert_eq!(result(&mut recv).await, SetupResult::Ready);
    let mut buffer = [0; 32];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.recv_from(&mut buffer))
            .await
            .is_err()
    );
    q.send_datagram(encode_udp_data(1, b"ready").unwrap().into())
        .unwrap();
    let (size, _) = tokio::time::timeout(Duration::from_secs(1), target.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..size], b"ready");
    send.finish().unwrap();
    q.close(0u32.into(), b"test");
    endpoint.wait_idle().await;
    h.close().await;
}
