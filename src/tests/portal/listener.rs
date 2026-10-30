// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Tests for IPv6-only listeners coexisting with IPv4 on the same port.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[tokio::test]
async fn ipv6_sockets_are_v6_only_and_allow_ipv4_on_the_same_port() {
    let udp = bind_quic_socket("[::]:0".parse().unwrap()).unwrap();
    assert!(socket2::SockRef::from(&udp).only_v6().unwrap());
    let udp4 = std::net::UdpSocket::bind(("0.0.0.0", udp.local_addr().unwrap().port())).unwrap();
    let tcp = listen_tcp("[::]:0".parse().unwrap())
        .unwrap()
        .into_std()
        .unwrap();
    assert!(socket2::SockRef::from(&tcp).only_v6().unwrap());
    let tcp4 = std::net::TcpListener::bind(("0.0.0.0", tcp.local_addr().unwrap().port())).unwrap();
    drop((udp, udp4, tcp, tcp4));
}

#[tokio::test]
async fn tcp_listener_binding_is_exclusive_and_restarts_after_graceful_close() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let listener = listen_tcp(address.parse().unwrap()).unwrap();
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
        let listener = listen_tcp(endpoint).expect("idle listener did not immediately rebind");
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
            listen_tcp(endpoint).expect("gracefully closed listener did not immediately rebind");
        drop(restarted);
    }
}
