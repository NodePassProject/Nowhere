// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 configuration and outbound dialing tests.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use url::Url;

use super::*;

fn parse(raw: &str) -> Result<Option<SocksConfig>> {
    SocksConfig::from_url(&Url::parse(raw).unwrap())
}

#[test]
fn parses_disabled_and_endpoint_forms() {
    for raw in [
        "portal://secret@127.0.0.1:2077",
        "portal://secret@127.0.0.1:2077?socks=",
        "portal://secret@127.0.0.1:2077?socks=none",
    ] {
        assert!(parse(raw).unwrap().is_none());
    }

    let domain = parse("portal://secret@127.0.0.1:2077?socks=proxy.test:1080")
        .unwrap()
        .unwrap();
    assert_eq!(domain.endpoint(), "proxy.test:1080");

    let ipv6 = parse("portal://secret@127.0.0.1:2077?socks=[::1]:1080")
        .unwrap()
        .unwrap();
    assert_eq!(ipv6.endpoint(), "[::1]:1080");
}

#[test]
fn parses_percent_encoded_credentials_without_exposing_them() {
    let config =
        parse("portal://secret@127.0.0.1:2077?socks=user%3Aname:p%40ss%26word@proxy.test:1080")
            .unwrap()
            .unwrap();
    let credentials = config.credentials().unwrap();
    assert_eq!(credentials.0, "user:name");
    assert_eq!(credentials.1, "p@ss&word");
    assert_eq!(config.endpoint(), "proxy.test:1080");
    let debug = format!("{config:?}");
    assert!(!debug.contains("user"));
    assert!(!debug.contains("pass"));
}

#[test]
fn rejects_ambiguous_or_invalid_configuration() {
    for raw in [
        "portal://secret@127.0.0.1:2077?socks=proxy.test:1080&socks=other.test:1080",
        "portal://secret@127.0.0.1:2077?socks=user@proxy.test:1080",
        "portal://secret@127.0.0.1:2077?socks=:pass@proxy.test:1080",
        "portal://secret@127.0.0.1:2077?socks=user:@proxy.test:1080",
        "portal://secret@127.0.0.1:2077?socks=user:p:ass@proxy.test:1080",
        "portal://secret@127.0.0.1:2077?socks=user:p+ass@proxy.test:1080",
        "portal://secret@127.0.0.1:2077?socks=proxy.test:0",
        "portal://secret@127.0.0.1:2077?socks=::1:1080",
        "portal://secret@127.0.0.1:2077?socks=user:%GG@proxy.test:1080",
    ] {
        assert!(parse(raw).is_err(), "accepted {raw}");
    }
}

#[test]
fn credential_lengths_follow_rfc_1929() {
    let username = "u".repeat(255);
    let password = "p".repeat(255);
    let accepted =
        format!("portal://secret@127.0.0.1:2077?socks={username}:{password}@proxy.test:1080");
    assert!(parse(&accepted).is_ok());

    let username = "u".repeat(256);
    let rejected = format!("portal://secret@127.0.0.1:2077?socks={username}:p@proxy.test:1080");
    assert!(parse(&rejected).is_err());
}

#[tokio::test]
async fn tcp_connect_uses_only_no_auth_and_preserves_domain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_NONE]);
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
        let request = read_test_command(&mut stream).await;
        assert_eq!(request, (COMMAND_CONNECT, "target.test".to_string(), 443));
        write_test_reply(&mut stream, SocketAddr::from(([127, 0, 0, 1], 50000))).await;
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });

    let config = parse(&format!(
        "portal://secret@127.0.0.1:2077?socks=localhost:{}",
        endpoint.port()
    ))
    .unwrap();
    let dialer = OutboundDialer::new("auto".to_string(), config);
    let mut stream = dialer
        .dial_tcp("target.test:443", Duration::from_secs(2))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");
    server.await.unwrap();
}

#[tokio::test]
async fn authenticated_connect_cannot_downgrade_to_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_PASSWORD]);
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
    });

    let config = parse(&format!(
        "portal://secret@127.0.0.1:2077?socks=user:pass@{endpoint}"
    ))
    .unwrap();
    let dialer = OutboundDialer::new("auto".to_string(), config);
    assert!(
        dialer
            .dial_tcp("target.test:443", Duration::from_secs(2))
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn udp_associate_wraps_payload_and_keeps_control_alive() {
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = control_listener.local_addr().unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut control, _) = control_listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        control.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_NONE]);
        control
            .write_all(&[SOCKS_VERSION, AUTH_NONE])
            .await
            .unwrap();
        let request = read_test_command(&mut control).await;
        assert_eq!(request.0, COMMAND_UDP_ASSOCIATE);
        write_test_reply(
            &mut control,
            SocketAddr::from(([0, 0, 0, 0], relay_addr.port())),
        )
        .await;

        let mut packet = [0u8; 512];
        for expected in [b"hello".as_slice(), b"bye".as_slice()] {
            let (size, peer) = relay.recv_from(&mut packet).await.unwrap();
            let (header_len, fragment) = parse_udp_header(&packet[..size]).unwrap();
            assert_eq!(fragment, 0);
            assert_eq!(&packet[header_len..size], expected);
            if expected == b"hello" {
                let mut fragmented = packet[..size].to_vec();
                fragmented[2] = 1;
                relay.send_to(&fragmented, peer).await.unwrap();
            }
            relay.send_to(&packet[..size], peer).await.unwrap();
        }

        let mut eof = [0u8; 1];
        assert_eq!(control.read(&mut eof).await.unwrap(), 0);
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2077?socks={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("127.0.0.1".to_string(), config);
    let socket = dialer
        .dial_udp("dns.test:53", Duration::from_secs(2))
        .await
        .unwrap();
    let mut packet = Vec::new();
    assert_eq!(socket.send(b"hello", &mut packet).await.unwrap(), 5);
    let mut response = [0u8; 512];
    let payload = socket.recv(&mut response).await.unwrap();
    assert_eq!(&response[payload], b"hello");
    let capacity = packet.capacity();
    assert_eq!(socket.send(b"bye", &mut packet).await.unwrap(), 3);
    assert_eq!(packet.capacity(), capacity);
    let payload = socket.recv(&mut response).await.unwrap();
    assert_eq!(&response[payload], b"bye");
    drop(socket);
    server.await.unwrap();
}

#[tokio::test]
async fn proxy_failure_never_falls_back_to_direct_target() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
        let _ = read_test_command(&mut stream).await;
        stream
            .write_all(&[SOCKS_VERSION, 5, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });

    let config = parse(&format!(
        "portal://secret@127.0.0.1:2077?socks={proxy_addr}"
    ))
    .unwrap();
    let dialer = OutboundDialer::new("auto".to_string(), config);
    assert!(
        dialer
            .dial_tcp(&target_addr.to_string(), Duration::from_secs(2))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn udp_association_ends_when_control_connection_closes() {
    let control_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = control_listener.local_addr().unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut control, _) = control_listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        control.read_exact(&mut methods).await.unwrap();
        control
            .write_all(&[SOCKS_VERSION, AUTH_NONE])
            .await
            .unwrap();
        let _ = read_test_command(&mut control).await;
        write_test_reply(&mut control, relay_addr).await;
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2077?socks={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".to_string(), config);
    let socket = dialer
        .dial_udp("dns.test:53", Duration::from_secs(2))
        .await
        .unwrap();
    let mut response = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut response))
            .await
            .unwrap()
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn each_udp_flow_uses_a_distinct_association() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut controls = Vec::new();
        let mut relays = Vec::new();
        for _ in 0..2 {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut methods = [0u8; 3];
            control.read_exact(&mut methods).await.unwrap();
            control
                .write_all(&[SOCKS_VERSION, AUTH_NONE])
                .await
                .unwrap();
            let request = read_test_command(&mut control).await;
            assert_eq!(request.0, COMMAND_UDP_ASSOCIATE);
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            write_test_reply(&mut control, relay.local_addr().unwrap()).await;
            controls.push(control);
            relays.push(relay);
        }

        let [first, second] = controls.as_mut_slice() else {
            unreachable!();
        };
        let mut first_eof = [0u8; 1];
        let mut second_eof = [0u8; 1];
        let (first_read, second_read) =
            tokio::join!(first.read(&mut first_eof), second.read(&mut second_eof));
        assert_eq!(first_read.unwrap(), 0);
        assert_eq!(second_read.unwrap(), 0);
        drop(relays);
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2077?socks={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".to_string(), config);
    let first = dialer
        .dial_udp("one.test:53", Duration::from_secs(2))
        .await
        .unwrap();
    let second = dialer
        .dial_udp("two.test:53", Duration::from_secs(2))
        .await
        .unwrap();
    drop((first, second));
    server.await.unwrap();
}

async fn read_test_command(stream: &mut TcpStream) -> (u8, String, u16) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], SOCKS_VERSION);
    assert_eq!(header[2], 0);
    let address = read_address(stream, header[3]).await.unwrap();
    match address {
        SocksAddress::Ip(addr) => (header[1], addr.ip().to_string(), addr.port()),
        SocksAddress::Domain(host, port) => (header[1], host, port),
    }
}

async fn write_test_reply(stream: &mut TcpStream, address: SocketAddr) {
    let mut response = vec![SOCKS_VERSION, 0, 0];
    encode_address(&mut response, &SocksAddress::Ip(address)).unwrap();
    stream.write_all(&response).await.unwrap();
}
