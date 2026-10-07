// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector route policies and carrier fallback tests.

use super::*;

#[tokio::test]
async fn vector_tcp_relays_every_route_policy() {
    for (up, down) in ROUTE_POLICY_MATRIX {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut ping = [0u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let runtime = start_runtime(up, down, 0).await;
        timeout(TEST_TIMEOUT, async {
            let mut socks = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut socks).await;
            socks
                .write_all(&ip_request(1, target_address))
                .await
                .unwrap();
            read_ipv4_reply(&mut socks).await;
            socks.write_all(b"ping").await.unwrap();
            let mut pong = [0u8; 4];
            socks.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong", "up={up} down={down}");
        })
        .await
        .unwrap();
        echo.await.unwrap();
        runtime.stop().await;
    }
}

#[tokio::test]
async fn vector_udp_associate_relays_every_route_policy() {
    for (up, down) in ROUTE_POLICY_MATRIX {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let payload = vec![0x40 | (up == "udp") as u8 | (((down == "udp") as u8) << 1); 4_000];
        let echoed = payload.clone();
        let echo = tokio::spawn(async move {
            let mut packet = vec![0u8; 5_000];
            let (length, peer) = target.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], echoed);
            target.send_to(&echoed, peer).await.unwrap();
        });
        let runtime = start_runtime(up, down, 0).await;
        timeout(TEST_TIMEOUT, async {
            let mut control = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut control).await;
            control
                .write_all(&ip_request(3, SocketAddr::from(([0, 0, 0, 0], 0))))
                .await
                .unwrap();
            let relay = read_ipv4_reply(&mut control).await;
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0, 0, 0];
            packet.extend_from_slice(&ip_request(0, target_address)[3..]);
            packet.extend_from_slice(&payload);
            client.send_to(&packet, relay).await.unwrap();
            let mut response = vec![0u8; 5_000];
            let (length, _) = client.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[10..length], payload, "up={up} down={down}");
            drop(control);
        })
        .await
        .unwrap();
        echo.await.unwrap();
        runtime.stop().await;
    }
}

#[tokio::test]
async fn mix_mix_retries_quic_after_tls_fails_before_commit() {
    let (portal_port, tcp_reservation, udp_reservation) = reserve_mixed_port().await;
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:{portal_port}?log=none&net=udp"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    drop(udp_reservation);
    let endpoint = portal.listen_endpoints().unwrap().pop().unwrap();
    drop(tcp_reservation);
    let shutdown = CancellationToken::new();
    let portal_task = tokio::spawn(crate::portal::listener::accept_endpoint_loop(
        portal.inner.clone(),
        endpoint.clone(),
        shutdown.clone(),
        shutdown.clone(),
    ));

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).await.unwrap();
        stream.write_all(b"pong").await.unwrap();
    });

    let mut session_id = [0u8; crate::protocol::SESSION_ID_LEN];
    session_id[0] = 3;
    let pin = server_certificate_pin(&portal.inner.tls_server_config);
    let client = mix_test_client(portal_port, session_id, &pin);

    let mut tunnel = timeout(
        TEST_TIMEOUT,
        client.open_tcp(&Target::ip(target_address).unwrap(), 0),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(tunnel.carriers(), (Carrier::Quic, Carrier::Quic));
    tunnel.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    tunnel.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");

    drop(tunnel);
    echo.await.unwrap();
    client
        .close(tokio::time::Instant::now() + TEST_TIMEOUT)
        .await;

    let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target_address = udp_target.local_addr().unwrap();
    let udp_echo = tokio::spawn(async move {
        let mut packet = [0u8; 4];
        let (size, peer) = udp_target.recv_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..size], b"ping");
        udp_target.send_to(b"pong", peer).await.unwrap();
    });
    let mut session_id = [0u8; crate::protocol::SESSION_ID_LEN];
    session_id[0] = 3;
    let udp_client = mix_test_client(portal_port, session_id, &pin);
    let mut udp_tunnel = timeout(
        TEST_TIMEOUT,
        udp_client.open_udp(&Target::ip(udp_target_address).unwrap(), 0),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(udp_tunnel.carriers(), (Carrier::Quic, Carrier::Quic));
    assert!(udp_tunnel.send(b"ping").await.unwrap());
    let mut payload = Vec::new();
    let packet = udp_tunnel.recv_into(&mut payload).await.unwrap().unwrap();
    assert_eq!(packet.payload(&payload), b"pong");
    udp_tunnel.close().await;
    udp_echo.await.unwrap();
    udp_client
        .close(tokio::time::Instant::now() + TEST_TIMEOUT)
        .await;

    shutdown.cancel();
    endpoint.close(quinn::VarInt::from_u32(0), b"");
    portal_task.abort();
    let _ = portal_task.await;
}

#[tokio::test]
async fn mix_mix_retries_tls_after_quic_fails_before_commit() {
    let (portal_port, tcp_reservation, udp_reservation) = reserve_mixed_port().await;
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:{portal_port}?log=none&net=tcp"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    drop(tcp_reservation);
    let listener = portal.listen_tcp_listeners().unwrap().pop().unwrap();
    drop(udp_reservation);
    let shutdown = CancellationToken::new();
    let portal_task = tokio::spawn(crate::portal::listener::accept_tcp_loop(
        portal.inner.clone(),
        listener,
        shutdown.clone(),
        shutdown.clone(),
    ));

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).await.unwrap();
        stream.write_all(b"pong").await.unwrap();
    });

    let pin = server_certificate_pin(&portal.inner.tls_server_config);
    let client = mix_test_client(portal_port, [0; crate::protocol::SESSION_ID_LEN], &pin);
    let mut tunnel = timeout(
        TEST_TIMEOUT,
        client.open_tcp(&Target::ip(target_address).unwrap(), 0),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(tunnel.carriers(), (Carrier::TlsTcp, Carrier::TlsTcp));
    tunnel.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    tunnel.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");

    drop(tunnel);
    echo.await.unwrap();
    client
        .close(tokio::time::Instant::now() + TEST_TIMEOUT)
        .await;
    shutdown.cancel();
    portal_task.abort();
    let _ = portal_task.await;
}

#[tokio::test]
async fn native_portal_chain_relays_tcp_and_udp_for_every_upstream_route_policy() {
    for (up, down) in ROUTE_POLICY_MATRIX {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut ping = [0u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let payload = vec![0x80 | (up == "udp") as u8 | (((down == "udp") as u8) << 1); 4_000];
        let echoed = payload.clone();
        let udp_echo = tokio::spawn(async move {
            let mut packet = vec![0u8; 5_000];
            let (length, peer) = udp_target.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], echoed);
            udp_target.send_to(&echoed, peer).await.unwrap();
        });
        let runtime = start_chain_runtime(up, down).await;

        timeout(TEST_TIMEOUT, async {
            let mut tcp = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut tcp).await;
            tcp.write_all(&ip_request(1, tcp_address)).await.unwrap();
            read_ipv4_reply(&mut tcp).await;
            tcp.write_all(b"ping").await.unwrap();
            let mut pong = [0u8; 4];
            tcp.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong", "up={up} down={down}");

            let mut control = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut control).await;
            control
                .write_all(&ip_request(3, SocketAddr::from(([0, 0, 0, 0], 0))))
                .await
                .unwrap();
            let udp_relay = read_ipv4_reply(&mut control).await;
            let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0, 0, 0];
            packet.extend_from_slice(&ip_request(0, udp_address)[3..]);
            packet.extend_from_slice(&payload);
            udp_client.send_to(&packet, udp_relay).await.unwrap();
            let mut response = vec![0u8; 5_000];
            let (length, _) = udp_client.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[10..length], payload, "up={up} down={down}");
            drop(control);
        })
        .await
        .unwrap();

        runtime.relay.inner.outbound.refresh_latency().await;
        assert!(
            runtime.relay.inner.outbound.ping_ms() > 0,
            "up={up} down={down} did not expose upstream RTT"
        );
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
        runtime.stop().await;
    }
}
