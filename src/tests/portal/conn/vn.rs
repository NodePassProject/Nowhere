// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Real UDP regression coverage for Morph-only Version Negotiation suppression.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use crate::protocol::test_support::encode_udp_data;

use super::*;

#[tokio::test]
async fn every_supported_morph_quic_version_authenticates_and_forwards_tcp_and_udp() {
    let h = Harness::new("direct", true).await;
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    let (config, _) = PortalClientConfig::from_probe_url(&h.url("vector", "udp", true)).unwrap();
    let tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    for &version in quinn_proto::DEFAULT_SUPPORTED_VERSIONS {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let runtime = quinn::default_runtime().unwrap();
        let socket = crate::transport::wrap_morph_udp_socket(
            runtime.wrap_udp_socket(socket).unwrap(),
            config.morph_keys.clone(),
            crate::transport::UdpRole::Client,
        )
        .unwrap();
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            crate::transport::morph_endpoint_config(true).unwrap(),
            None,
            socket,
            runtime,
        )
        .unwrap();
        let mut client = tls.quic_client_config().unwrap();
        client.version(version);
        endpoint.set_default_client_config(client);
        let q = tokio::time::timeout(
            Duration::from_secs(3),
            endpoint.connect(h.udp, "127.0.0.1").unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let (mut send, mut recv) = q.open_bi().await.unwrap();
        send.write_all(&tag(&q, false)).await.unwrap();
        request(&mut send, 0, &tcp).await;
        assert_eq!(result(&mut recv).await, SetupResult::Ready);
        send.write_all(b"supported version").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(32).await.unwrap(), b"supported version");

        let (mut send, mut recv) = q.open_bi().await.unwrap();
        let id = crate::protocol::udp_flow_id(u64::from(send.id()), false).unwrap();
        request(&mut send, 1, &udp).await;
        assert_eq!(result(&mut recv).await, SetupResult::Ready);
        q.send_datagram(encode_udp_data(id, b"supported version").unwrap().into())
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), q.read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            crate::protocol::decode_udp_frame_owned(response).unwrap(),
            crate::protocol::OwnedUdpFrame::Data { payload, .. } if payload == b"supported version"[..]
        ));
        q.close(0u32.into(), b"test");
        endpoint.wait_idle().await;
    }
    h.close().await;
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn unsupported_versions_are_silent_only_on_morph_udp() {
    for morph in [false, true] {
        let h = Harness::new("direct", morph).await;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = vec![0xc0, 0x0a, 0x1a, 0x2a, 0x3a, 8];
        packet.extend_from_slice(&[1; 8]);
        packet.push(8);
        packet.extend_from_slice(&[2; 8]);
        packet.resize(1200, 0);
        if morph {
            let (key, _) = crate::transport::MorphKeys::derive(KEY.as_bytes()).udp_keys();
            let nonce = [3; 12];
            ChaCha20::new((&key).into(), (&nonce).into()).apply_keystream(&mut packet);
            packet.splice(..0, nonce);
        }
        for _ in 0..2 {
            socket.send_to(&packet, h.udp).await.unwrap();
            let mut response = [0; 1500];
            let received =
                tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut response))
                    .await;
            if morph {
                assert!(received.is_err());
            } else {
                let (len, peer) = received.unwrap().unwrap();
                assert_eq!(peer, h.udp);
                assert!(len >= 7);
                assert_eq!(response[0] & 0x80, 0x80);
                assert_eq!(&response[1..5], &[0; 4]);
            }
        }
        let (tcp, tcp_task) = tcp_echo().await;
        let (udp, udp_task) = udp_echo().await;
        let client = h.client("udp", morph);
        exchange(&client, &tcp, &udp).await;
        client
            .close(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        h.close().await;
        tcp_task.abort();
        udp_task.abort();
    }
}
