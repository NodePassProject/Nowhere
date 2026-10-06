// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS5 configuration and outbound dialing tests.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use url::Url;

use super::protocol::{
    ADDRESS_IPV4, AUTH_NONE, AUTH_PASSWORD, SOCKS_VERSION, encode_address, parse_udp_header,
    read_address,
};
use super::*;
use crate::protocol::Target;

fn parse(raw: &str) -> Result<Option<SocksConfig>> {
    SocksConfig::from_url(&Url::parse(raw).unwrap())
}

#[test]
fn parses_disabled_and_endpoint_forms() {
    for raw in [
        "portal://secret@127.0.0.1:2000",
        "portal://secret@127.0.0.1:2000?socks=",
        "portal://secret@127.0.0.1:2000?socks=none",
    ] {
        assert!(parse(raw).unwrap().is_none());
    }

    let domain = parse("portal://secret@127.0.0.1:2000?socks=proxy.test:1080")
        .unwrap()
        .unwrap();
    assert_eq!(domain.endpoint(), "proxy.test:1080");

    let ipv6 = parse("portal://secret@127.0.0.1:2000?socks=[::1]:1080")
        .unwrap()
        .unwrap();
    assert_eq!(ipv6.endpoint(), "[::1]:1080");
}

#[test]
fn parses_percent_encoded_credentials_without_exposing_them() {
    let config =
        parse("portal://secret@127.0.0.1:2000?socks=user%3Aname:p%40ss%26word@proxy.test:1080")
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
        "portal://secret@127.0.0.1:2000?socks=user@proxy.test:1080",
        "portal://secret@127.0.0.1:2000?socks=:pass@proxy.test:1080",
        "portal://secret@127.0.0.1:2000?socks=user:@proxy.test:1080",
        "portal://secret@127.0.0.1:2000?socks=user:p:ass@proxy.test:1080",
        "portal://secret@127.0.0.1:2000?socks=user:p+ass@proxy.test:1080",
        "portal://secret@127.0.0.1:2000?socks=proxy.test:0",
        "portal://secret@127.0.0.1:2000?socks=::1:1080",
        "portal://secret@127.0.0.1:2000?socks=user:%GG@proxy.test:1080",
    ] {
        assert!(parse(raw).is_err(), "accepted {raw}");
    }
}

#[test]
fn duplicate_socks_uses_the_first_value() {
    let config =
        parse("portal://secret@127.0.0.1:2000?socks=proxy.test:1080&socks=other.test:1080")
            .unwrap()
            .unwrap();

    assert_eq!(config.endpoint(), "proxy.test:1080");
}

#[test]
fn malformed_unknown_query_key_is_ignored() {
    let config = parse("portal://secret@127.0.0.1:2000?%FF=x&socks=proxy.test:1080")
        .unwrap()
        .unwrap();

    assert_eq!(config.endpoint(), "proxy.test:1080");
}

#[test]
fn credential_lengths_follow_rfc_1929() {
    let username = "u".repeat(255);
    let password = "p".repeat(255);
    let accepted =
        format!("portal://secret@127.0.0.1:2000?socks={username}:{password}@proxy.test:1080");
    assert!(parse(&accepted).is_ok());

    let username = "u".repeat(256);
    let rejected = format!("portal://secret@127.0.0.1:2000?socks={username}:p@proxy.test:1080");
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

    let config = parse(&format!("portal://secret@127.0.0.1:2000?socks={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("target.test", 443).unwrap();
    let mut stream = dialer
        .dial_tcp_target(&target, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(dialer.ping_ms() > 0);
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");
    drop(stream);
    assert_eq!(dialer.ping_ms(), 0);
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
        "portal://secret@127.0.0.1:2000?socks=user:pass@{endpoint}"
    ))
    .unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("target.test", 443).unwrap();
    assert!(
        dialer
            .dial_tcp_target(&target, Duration::from_secs(2))
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

    let config = parse(&format!("portal://secret@127.0.0.1:2000?socks={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("127.0.0.1".into(), config);
    let target = Target::domain("dns.test", 53).unwrap();
    let socket = dialer
        .dial_udp_target(&target, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(dialer.ping_ms() > 0);
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
    assert_eq!(dialer.ping_ms(), 0);
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
        "portal://secret@127.0.0.1:2000?socks={proxy_addr}"
    ))
    .unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let protocol_target = Target::ip(target_addr).unwrap();
    assert!(
        dialer
            .dial_tcp_target(&protocol_target, Duration::from_secs(2))
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

    let config = parse(&format!("portal://secret@127.0.0.1:2000?socks={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("dns.test", 53).unwrap();
    let socket = dialer
        .dial_udp_target(&target, Duration::from_secs(2))
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

    let config = parse(&format!("portal://secret@127.0.0.1:2000?socks={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let first_target = Target::domain("one.test", 53).unwrap();
    let first = dialer
        .dial_udp_target(&first_target, Duration::from_secs(2))
        .await
        .unwrap();
    let second_target = Target::domain("two.test", 53).unwrap();
    let second = dialer
        .dial_udp_target(&second_target, Duration::from_secs(2))
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

#[tokio::test]
async fn direct_ip_targets_apply_source_policy_and_reject_legacy_family_conflicts() {
    use crate::common::DialPolicy;
    let listener4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener6 = match TcpListener::bind("[::1]:0").await {
        Ok(listener) => Some(listener),
        Err(error) => {
            eprintln!("SKIP IPv6 direct IP target: IPv6 loopback unavailable: {error}");
            None
        }
    };
    for listener in std::iter::once(&listener4).chain(listener6.as_ref()) {
        let address = listener.local_addr().unwrap();
        let policy = DialPolicy::DualStack {
            v4: Some("127.0.0.1".parse().unwrap()),
            v6: Some("::1".parse().unwrap()),
        };
        let dialer = OutboundDialer::new(policy, None);
        let stream = dialer
            .dial_tcp_target(&Target::ip(address).unwrap(), Duration::from_secs(2))
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), address.ip());
        assert_eq!(peer.ip(), address.ip());
        let relay = UdpSocket::bind(SocketAddr::new(address.ip(), 0))
            .await
            .unwrap();
        let target = Target::ip(relay.local_addr().unwrap()).unwrap();
        let socket = dialer
            .dial_udp_target(&target, Duration::from_secs(2))
            .await
            .unwrap();
        socket.send(b"direct", &mut Vec::new()).await.unwrap();
        let mut bytes = [0; 16];
        let (_, peer) = relay.recv_from(&mut bytes).await.unwrap();
        assert_eq!(peer.ip(), address.ip());
        let opposite = if address.is_ipv4() {
            "::1"
        } else {
            "127.0.0.1"
        };
        let legacy = OutboundDialer::new(opposite.into(), None);
        assert!(
            legacy
                .dial_tcp_target(&Target::ip(address).unwrap(), Duration::from_secs(2))
                .await
                .is_err()
        );
        assert!(
            legacy
                .dial_udp_target(&target, Duration::from_secs(2))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn socks_control_and_udp_relay_select_sources_independently() {
    use crate::common::DialPolicy;
    let relay = match UdpSocket::bind("[::1]:0").await {
        Ok(relay) => relay,
        Err(error) => {
            eprintln!("SKIP SOCKS cross-family relay: IPv6 loopback unavailable: {error}");
            return;
        }
    };
    let relay_addr = relay.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut control, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        let mut methods = [0; 3];
        control.read_exact(&mut methods).await.unwrap();
        control
            .write_all(&[SOCKS_VERSION, AUTH_NONE])
            .await
            .unwrap();
        let request = read_test_command(&mut control).await;
        assert_eq!(request.0, COMMAND_UDP_ASSOCIATE);
        write_test_reply(&mut control, relay_addr).await;
        let mut packet = [0; 128];
        let (size, peer) = relay.recv_from(&mut packet).await.unwrap();
        assert_eq!(peer.ip(), "::1".parse::<std::net::IpAddr>().unwrap());
        let (header, _) = parse_udp_header(&packet[..size]).unwrap();
        assert_eq!(&packet[header..size], b"cross-family");
        relay.send_to(&packet[..size], peer).await.unwrap();
        let mut eof = [0];
        assert_eq!(control.read(&mut eof).await.unwrap(), 0);
    });
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: Some("::1".parse().unwrap()),
    };
    let config = parse(&format!("portal://secret@localhost:2000?socks={proxy}")).unwrap();
    let dialer = OutboundDialer::new(policy, config);
    tokio::time::timeout(Duration::from_secs(3), async {
        let socket = dialer
            .dial_udp_target(
                &Target::domain("remote.test", 53).unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        socket.send(b"cross-family", &mut Vec::new()).await.unwrap();
        let mut bytes = [0; 128];
        let payload = socket.recv(&mut bytes).await.unwrap();
        assert_eq!(&bytes[payload], b"cross-family");
        drop(socket);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_tcp_selects_source_without_restricting_the_remote_target_family() {
    use crate::common::DialPolicy;
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let listener = match TcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(error) if bind.starts_with('[') => {
                eprintln!("SKIP IPv6 SOCKS TCP source: IPv6 loopback unavailable: {error}");
                continue;
            }
            Err(error) => panic!("bind failed: {error}"),
        };
        let proxy = listener.local_addr().unwrap();
        let target_addr: SocketAddr = if proxy.is_ipv4() {
            "[2001:db8::1]:443"
        } else {
            "192.0.2.1:443"
        }
        .parse()
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut control, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), proxy.ip());
            let mut methods = [0; 3];
            control.read_exact(&mut methods).await.unwrap();
            control
                .write_all(&[SOCKS_VERSION, AUTH_NONE])
                .await
                .unwrap();
            let (command, host, port) = read_test_command(&mut control).await;
            assert_eq!(command, COMMAND_CONNECT);
            assert_eq!(host, target_addr.ip().to_string());
            assert_eq!(port, target_addr.port());
            write_test_reply(&mut control, proxy).await;
            let mut bytes = [0; 4];
            control.read_exact(&mut bytes).await.unwrap();
            control.write_all(&bytes).await.unwrap();
        });
        let policy = DialPolicy::DualStack {
            v4: Some("127.0.0.1".parse().unwrap()),
            v6: Some("::1".parse().unwrap()),
        };
        let config = parse(&format!("portal://secret@localhost:2000?socks={proxy}")).unwrap();
        let dialer = OutboundDialer::new(policy, config);
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = dialer
                .dial_tcp_target(&Target::ip(target_addr).unwrap(), Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(stream.local_addr().unwrap().ip(), proxy.ip());
            stream.write_all(b"ping").await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn omitted_source_family_remains_automatic_for_tcp_and_udp() {
    use crate::common::{DialPolicy, query_first};
    for (bind, query) in [
        ("127.0.0.1:0", "dial6=2001:db8::dead"),
        ("[::1]:0", "dial4=192.0.2.254"),
    ] {
        let listener = match TcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(error) if bind.starts_with('[') => {
                eprintln!("SKIP automatic IPv6 source: IPv6 loopback unavailable: {error}");
                continue;
            }
            Err(error) => panic!("bind failed: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let url = Url::parse(&format!("portal://secret@localhost:2000?{query}")).unwrap();
        let policy =
            DialPolicy::from_query(&query_first(&url, &["dial", "dial4", "dial6"]).unwrap())
                .unwrap();
        let dialer = OutboundDialer::new(policy, None);
        tokio::time::timeout(Duration::from_secs(3), async {
            let stream = dialer
                .dial_tcp_target(&Target::ip(address).unwrap(), Duration::from_secs(2))
                .await
                .unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), address.ip());
            assert_eq!(stream.local_addr().unwrap().ip(), address.ip());
            let receiver = UdpSocket::bind(SocketAddr::new(address.ip(), 0))
                .await
                .unwrap();
            let target = Target::ip(receiver.local_addr().unwrap()).unwrap();
            let socket = dialer
                .dial_udp_target(&target, Duration::from_secs(2))
                .await
                .unwrap();
            socket.send(b"automatic", &mut Vec::new()).await.unwrap();
            let mut bytes = [0; 16];
            let (size, peer) = receiver.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..size], b"automatic");
            assert_eq!(peer.ip(), address.ip());
        })
        .await
        .unwrap();
    }
}
