// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end Portal/Vector carrier matrix through Vector's SOCKS5 ingress.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger};
use crate::portal::Portal;
use crate::protocol::{Carrier, Target};
use crate::telemetry::{InstanceRole, TelemetryHub};
use crate::transport::Stats;
use crate::vector::{PortalClient, PortalClientConfig, Vector};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const ROUTE_POLICY_MATRIX: [(&str, &str); 9] = [
    ("tcp", "tcp"),
    ("tcp", "udp"),
    ("udp", "tcp"),
    ("udp", "udp"),
    ("mix", "tcp"),
    ("mix", "udp"),
    ("tcp", "mix"),
    ("udp", "mix"),
    ("mix", "mix"),
];

struct TestRuntime {
    shutdown: CancellationToken,
    endpoint: quinn::Endpoint,
    portal_tasks: Vec<JoinHandle<()>>,
    vector_task: JoinHandle<anyhow::Result<()>>,
    portal_stats: Arc<Stats>,
    socks: SocketAddr,
}

struct ChainRuntime {
    shutdown: CancellationToken,
    endpoints: Vec<quinn::Endpoint>,
    portal_tasks: Vec<JoinHandle<()>>,
    vector_task: JoinHandle<anyhow::Result<()>>,
    relay: Portal,
    socks: SocketAddr,
}

impl ChainRuntime {
    async fn stop(self) {
        self.vector_task.abort();
        let _ = self.vector_task.await;
        self.shutdown.cancel();
        for endpoint in self.endpoints {
            endpoint.close(quinn::VarInt::from_u32(0), b"");
        }
        for task in self.portal_tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

impl TestRuntime {
    async fn stop(self) {
        self.vector_task.abort();
        let _ = self.vector_task.await;
        self.shutdown.cancel();
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
        for task in self.portal_tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn reserve_mixed_port() -> (u16, TcpListener, UdpSocket) {
    for _ in 0..32 {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(tcp) => return (port, tcp, udp),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::AddrInUse | ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => panic!("failed to reserve TCP test port {port}: {error}"),
        }
    }
    panic!("failed to reserve one local port for TCP and UDP");
}

async fn reserve_tcp_port() -> (u16, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (listener.local_addr().unwrap().port(), listener)
}

async fn start_runtime(up: &str, down: &str, mux: u8) -> TestRuntime {
    let (portal_port, tcp_reservation, udp_reservation) = reserve_mixed_port().await;
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1:{portal_port}?log=none&net=mix"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    drop(udp_reservation);
    let endpoint = portal.listen_endpoints().unwrap().pop().unwrap();
    drop(tcp_reservation);
    let listener = portal.listen_tcp_listeners().unwrap().pop().unwrap();
    let portal_stats = portal.inner.stats.clone();
    let shutdown = CancellationToken::new();
    let quic_task = tokio::spawn(crate::portal::listener::accept_endpoint_loop(
        portal.inner.clone(),
        endpoint.clone(),
        shutdown.clone(),
        shutdown.clone(),
    ));
    let tcp_task = tokio::spawn(crate::portal::listener::accept_tcp_loop(
        portal.inner.clone(),
        listener,
        shutdown.clone(),
        shutdown.clone(),
    ));
    let (socks_port, socks_reservation) = reserve_tcp_port().await;
    let vector = Vector::new(
        Url::parse(&format!(
            "vector://secret@127.0.0.1:{portal_port}?log=none&up={up}&down={down}&mux={mux}&socks=127.0.0.1:{socks_port}"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();
    drop(socks_reservation);
    let vector_task = tokio::spawn(vector.run());
    let socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
    wait_for_socks(socks).await;
    TestRuntime {
        shutdown,
        endpoint,
        portal_tasks: vec![quic_task, tcp_task],
        vector_task,
        portal_stats,
        socks,
    }
}

#[tokio::test]
async fn mux_symmetric_carriers_relay_tcp_and_fragmented_udp() {
    for carrier in ["tcp", "udp"] {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let mut ping = [0u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        // Above QUIC's datagram MTU, below macOS's default UDP socket limit.
        let payload = vec![0x5a; 8 * 1024];
        let echoed = payload.clone();
        let udp_echo = tokio::spawn(async move {
            let mut packet = vec![0u8; 65_507];
            let (length, peer) = udp_target.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..length], echoed);
            udp_target.send_to(&echoed, peer).await.unwrap();
        });
        let runtime = start_runtime(carrier, carrier, 1).await;
        timeout(TEST_TIMEOUT, async {
            let mut tcp = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut tcp).await;
            tcp.write_all(&ip_request(1, tcp_address)).await.unwrap();
            read_ipv4_reply(&mut tcp).await;
            tcp.write_all(b"ping").await.unwrap();
            let mut pong = [0u8; 4];
            tcp.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");

            let mut control = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut control).await;
            control
                .write_all(&ip_request(3, SocketAddr::from(([0, 0, 0, 0], 0))))
                .await
                .unwrap();
            let relay = read_ipv4_reply(&mut control).await;
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0, 0, 0];
            packet.extend_from_slice(&ip_request(0, udp_address)[3..]);
            packet.extend_from_slice(&payload);
            client.send_to(&packet, relay).await.unwrap();
            let mut response = vec![0u8; 65_535];
            let (length, _) = client.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[10..length], payload);
        })
        .await
        .unwrap();
        tcp_echo.await.unwrap();
        udp_echo.await.unwrap();
        runtime.stop().await;
    }
}

#[tokio::test]
async fn mux_full_duplex_tcp_exceeds_each_direction_credit_window() {
    const DIRECTION_BYTES: usize = 3 * 1024 * 1024;

    for carrier in ["tcp", "udp"] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let (mut reader, mut writer) = stream.into_split();
            let upload = async {
                let mut received = vec![0_u8; DIRECTION_BYTES];
                reader.read_exact(&mut received).await.unwrap();
                assert!(received.iter().all(|byte| *byte == 0xa5));
            };
            let download = async {
                writer
                    .write_all(&vec![0x5a; DIRECTION_BYTES])
                    .await
                    .unwrap();
            };
            tokio::join!(upload, download);
        });
        let runtime = start_runtime(carrier, carrier, 1).await;
        timeout(TEST_TIMEOUT, async {
            let mut stream = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut stream).await;
            stream
                .write_all(&ip_request(1, target_address))
                .await
                .unwrap();
            read_ipv4_reply(&mut stream).await;
            let (mut reader, mut writer) = stream.into_split();
            let upload = async {
                writer
                    .write_all(&vec![0xa5; DIRECTION_BYTES])
                    .await
                    .unwrap();
            };
            let download = async {
                let mut received = vec![0_u8; DIRECTION_BYTES];
                reader.read_exact(&mut received).await.unwrap();
                assert!(received.iter().all(|byte| *byte == 0x5a));
            };
            tokio::join!(upload, download);
        })
        .await
        .unwrap();
        target_task.await.unwrap();
        runtime.stop().await;
    }
}

#[tokio::test]
async fn mux_fifth_active_tcp_flow_opens_a_second_shard() {
    const FLOW_COUNT: usize = 5;

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let target_shutdown = CancellationToken::new();
    let target_child_shutdown = target_shutdown.clone();
    let target_task = tokio::spawn(async move {
        let mut connections = Vec::with_capacity(FLOW_COUNT);
        for _ in 0..FLOW_COUNT {
            connections.push(target.accept().await.unwrap().0);
        }
        target_child_shutdown.cancelled().await;
        drop(connections);
    });
    let runtime = start_runtime("tcp", "tcp", 1).await;

    let flows = timeout(TEST_TIMEOUT, async {
        let mut flows = Vec::with_capacity(FLOW_COUNT);
        for _ in 0..FLOW_COUNT {
            let mut flow = TcpStream::connect(runtime.socks).await.unwrap();
            negotiate_socks(&mut flow).await;
            flow.write_all(&ip_request(1, target_address))
                .await
                .unwrap();
            read_ipv4_reply(&mut flow).await;
            flows.push(flow);
        }
        while runtime.portal_stats.link_tcp.load(Ordering::Relaxed) != 2 {
            tokio::task::yield_now().await;
        }
        flows
    })
    .await
    .unwrap();

    assert_eq!(runtime.portal_stats.link_tcp.load(Ordering::Relaxed), 2);
    assert_eq!(runtime.portal_stats.tcp_active.load(Ordering::Relaxed), 5);
    drop(flows);
    target_shutdown.cancel();
    target_task.await.unwrap();
    runtime.stop().await;
}

async fn start_chain_runtime(up: &str, down: &str) -> ChainRuntime {
    let logger = || Logger::new(LogLevel::None, false);
    let (origin_port, origin_tcp_reservation, origin_udp_reservation) = reserve_mixed_port().await;
    let origin = Portal::new(
        Url::parse(&format!(
            "portal://origin-secret@127.0.0.1:{origin_port}?log=none&net=mix"
        ))
        .unwrap(),
        logger(),
    )
    .unwrap();
    drop(origin_udp_reservation);
    let origin_endpoint = origin.listen_endpoints().unwrap().pop().unwrap();
    drop(origin_tcp_reservation);
    let origin_listener = origin.listen_tcp_listeners().unwrap().pop().unwrap();

    let (relay_port, relay_tcp_reservation, relay_udp_reservation) = reserve_mixed_port().await;
    let relay = Portal::new(
        Url::parse(&format!(
            "portal://relay-secret@127.0.0.1:{relay_port}?log=none&net=mix&next=origin-secret@127.0.0.1:{origin_port}&up={up}&down={down}&mux=1"
        ))
        .unwrap(),
        logger(),
    )
    .unwrap();
    drop(relay_udp_reservation);
    let relay_endpoint = relay.listen_endpoints().unwrap().pop().unwrap();
    drop(relay_tcp_reservation);
    let relay_listener = relay.listen_tcp_listeners().unwrap().pop().unwrap();

    let shutdown = CancellationToken::new();
    let mut endpoints = Vec::with_capacity(2);
    let mut portal_tasks = Vec::with_capacity(4);
    for (portal, endpoint, listener) in [
        (&origin, origin_endpoint, origin_listener),
        (&relay, relay_endpoint, relay_listener),
    ] {
        portal_tasks.push(tokio::spawn(crate::portal::listener::accept_endpoint_loop(
            portal.inner.clone(),
            endpoint.clone(),
            shutdown.clone(),
            shutdown.clone(),
        )));
        portal_tasks.push(tokio::spawn(crate::portal::listener::accept_tcp_loop(
            portal.inner.clone(),
            listener,
            shutdown.clone(),
            shutdown.clone(),
        )));
        endpoints.push(endpoint);
    }
    let (socks_port, socks_reservation) = reserve_tcp_port().await;
    let vector = Vector::new(
        Url::parse(&format!(
            "vector://relay-secret@127.0.0.1:{relay_port}?log=none&mux=1&socks=127.0.0.1:{socks_port}"
        ))
        .unwrap(),
        logger(),
    )
    .unwrap();
    drop(socks_reservation);
    let vector_task = tokio::spawn(vector.run());
    let socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
    wait_for_socks(socks).await;
    ChainRuntime {
        shutdown,
        endpoints,
        portal_tasks,
        vector_task,
        relay,
        socks,
    }
}

async fn wait_for_socks(address: SocketAddr) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn negotiate_socks(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 0]);
}

fn ip_request(command: u8, address: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(address) = address else {
        panic!("test endpoint must be IPv4")
    };
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&address.ip().octets());
    request.extend_from_slice(&address.port().to_be_bytes());
    request
}

async fn read_ipv4_reply(stream: &mut TcpStream) -> SocketAddr {
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ))
}

async fn read_ipv4_reply_code(stream: &mut TcpStream) -> u8 {
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5);
    reply[1]
}

fn mix_test_client(
    portal_port: u16,
    session_id: [u8; crate::protocol::SESSION_ID_LEN],
) -> Arc<PortalClient> {
    let query = HashMap::from([
        ("up".to_owned(), "mix".to_owned()),
        ("down".to_owned(), "mix".to_owned()),
    ]);
    let (config, credentials) = PortalClientConfig::from_upstream_authority(
        &format!("secret@127.0.0.1:{portal_port}"),
        &query,
        "auto",
    )
    .unwrap();
    PortalClient::with_session_id(
        config,
        &credentials,
        Arc::new(Stats::default()),
        false,
        TelemetryHub::for_current_process(
            InstanceRole::Vector,
            "test",
            "up=mix down=mix",
            Duration::from_secs(1),
        ),
        CancellationToken::new(),
        session_id,
    )
    .unwrap()
}

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
            "portal://secret@127.0.0.1:{portal_port}?log=none&net=udp"
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

    // seed=3 and initial flow_id=1 produce the TLS-first SplitMix64 bit.
    let mut session_id = [0u8; crate::protocol::SESSION_ID_LEN];
    session_id[0] = 3;
    let client = mix_test_client(portal_port, session_id);

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
    let udp_client = mix_test_client(portal_port, session_id);
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
            "portal://secret@127.0.0.1:{portal_port}?log=none&net=tcp"
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

    // seed=0 and initial flow_id=1 produce the QUIC-first SplitMix64 bit.
    let client = mix_test_client(portal_port, [0; crate::protocol::SESSION_ID_LEN]);
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

#[path = "vector/chain_failure.rs"]
mod chain_failure;
