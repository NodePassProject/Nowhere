// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Native Portal chaining across different carriers tests.

use super::*;

#[tokio::test]
async fn single_carrier_defaults_relay_tcp4_to_udp6() {
    let origin_reservation = UdpSocket::bind("[::1]:0").await.unwrap();
    let origin_port = origin_reservation.local_addr().unwrap().port();
    let origin = Portal::new(
        Url::parse(&format!(
            "portal://23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@[::1]/udp6:{origin_port}?log=none"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    let origin_pin = server_certificate_pin(&origin.inner.tls_server_config);
    assert!(origin.listen_tcp_listeners().unwrap().is_empty());
    drop(origin_reservation);
    let endpoint = origin.listen_endpoints().unwrap().pop().unwrap();

    let (relay_port, reservation) = reserve_tcp_port().await;
    let relay = Portal::new(
        Url::parse(&format!("portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1/tcp4:{relay_port}?next=23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@[::1]/udp6:{origin_port}&pin={origin_pin}&log=none")).unwrap(),
        Logger::new(LogLevel::None, false),
    ).unwrap();
    let relay_pin = server_certificate_pin(&relay.inner.tls_server_config);
    assert!(relay.listen_endpoints().unwrap().is_empty());
    drop(reservation);
    let listener = relay.listen_tcp_listeners().unwrap().pop().unwrap();
    let shutdown = CancellationToken::new();
    let portal_tasks = vec![
        tokio::spawn(crate::portal::listener::accept_endpoint_loop(
            origin.inner.clone(),
            endpoint.clone(),
            shutdown.clone(),
            shutdown.clone(),
        )),
        tokio::spawn(crate::portal::listener::accept_tcp_loop(
            relay.inner.clone(),
            listener,
            shutdown.clone(),
            shutdown.clone(),
        )),
    ];
    let (socks_port, reservation) = reserve_tcp_port().await;
    let vector = Vector::new(
        Url::parse(&format!("vector://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1/tcp4:{relay_port}?socks=127.0.0.1:{socks_port}&pin={relay_pin}&log=none")).unwrap(),
        Logger::new(LogLevel::None, false),
    ).unwrap();
    drop(reservation);
    let vector_task = tokio::spawn(vector.run());
    let socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
    wait_for_socks(socks).await;
    let runtime = ChainRuntime {
        shutdown,
        endpoints: vec![endpoint],
        portal_tasks,
        vector_task,
        relay,
        socks,
    };

    timeout(TEST_TIMEOUT, async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut packet = [0; 4];
            stream.read_exact(&mut packet).await.unwrap();
            stream.write_all(&packet).await.unwrap();
        });
        let mut stream = TcpStream::connect(socks).await.unwrap();
        negotiate_socks(&mut stream).await;
        stream.write_all(&ip_request(1, address)).await.unwrap();
        read_ipv4_reply(&mut stream).await;
        stream.write_all(b"ping").await.unwrap();
        let mut packet = [0; 4];
        stream.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"ping");
        echo.await.unwrap();

        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut packet = [0; 64];
            let (length, peer) = target.recv_from(&mut packet).await.unwrap();
            target.send_to(&packet[..length], peer).await.unwrap();
        });
        let mut control = TcpStream::connect(socks).await.unwrap();
        negotiate_socks(&mut control).await;
        control
            .write_all(&ip_request(3, "0.0.0.0:0".parse().unwrap()))
            .await
            .unwrap();
        let udp_relay = read_ipv4_reply(&mut control).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(&ip_request(0, address)[3..]);
        packet.extend_from_slice(b"ping");
        client.send_to(&packet, udp_relay).await.unwrap();
        let mut reply = [0; 64];
        let (length, _) = client.recv_from(&mut reply).await.unwrap();
        assert_eq!(&reply[10..length], b"ping");
        echo.await.unwrap();
    })
    .await
    .unwrap();
    runtime.stop().await;
}
