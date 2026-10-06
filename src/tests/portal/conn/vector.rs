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
const FULL_DUPLEX_TIMEOUT: Duration = Duration::from_secs(60);
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
    toolbox_url: Url,
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

async fn reserve_udp_port_except(excluded: u16) -> (u16, UdpSocket) {
    loop {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        if port != excluded {
            return (port, socket);
        }
    }
}

async fn start_runtime(up: &str, down: &str, mux: u8) -> TestRuntime {
    start_runtime_with_morph(up, down, mux, false).await
}

async fn start_runtime_with_morph(up: &str, down: &str, mux: u8, morph: bool) -> TestRuntime {
    let (tcp_port, tcp_reservation) = reserve_tcp_port().await;
    let (udp_port, udp_reservation) = reserve_udp_port_except(tcp_port).await;
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://secret@127.0.0.1/tcp:{tcp_port}/udp:{udp_port}?log=none&morph={}",
            u8::from(morph)
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
            "vector://secret@127.0.0.1/tcp:{tcp_port}/udp:{udp_port}?log=none&up={up}&down={down}&mux={mux}&morph={}&socks=127.0.0.1:{socks_port}",
            u8::from(morph)
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
        toolbox_url: Url::parse(&format!("vector://secret@127.0.0.1/tcp:{tcp_port}/udp:{udp_port}?up={up}&down={down}&mux={mux}&morph={}", u8::from(morph))).unwrap(),
        shutdown,
        endpoint,
        portal_tasks: vec![quic_task, tcp_task],
        vector_task,
        portal_stats,
        socks,
    }
}

#[tokio::test]
async fn toolbox_probe_closes_real_flows_without_payload() {
    for (up, down, mux, morph) in [
        ("tcp", "tcp", 0, false),
        ("tcp", "tcp", 1, false),
        ("udp", "udp", 0, false),
        ("tcp", "udp", 1, false),
        ("udp", "tcp", 0, false),
        ("tcp", "tcp", 1, true),
        ("udp", "udp", 0, true),
    ] {
        let runtime = start_runtime_with_morph(up, down, mux, morph).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let received = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        let client = crate::toolbox::ToolboxClient::parse(&runtime.toolbox_url).unwrap();
        let report = timeout(TEST_TIMEOUT, client.probe(Target::Ip(address)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.result.unwrap(), crate::protocol::SetupResult::Ready);
        assert!(
            report.cleanup.is_ok(),
            "{up}/{down}, mux={mux}: {:?}",
            report.cleanup
        );
        assert!(
            timeout(TEST_TIMEOUT, received)
                .await
                .unwrap()
                .unwrap()
                .is_empty()
        );
        runtime.stop().await;
    }
}

#[tokio::test]
async fn toolbox_probe_preserves_remote_setup_failure() {
    for mux in [0, 1] {
        let runtime = start_runtime("tcp", "tcp", mux).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        drop(target);
        let client = crate::toolbox::ToolboxClient::parse(&runtime.toolbox_url).unwrap();
        let report = timeout(TEST_TIMEOUT, client.probe(Target::Ip(address)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            report.result.unwrap(),
            crate::protocol::SetupResult::DialFailed
        );
        runtime.stop().await;
    }
}

async fn start_chain_runtime(up: &str, down: &str) -> ChainRuntime {
    let logger = || Logger::new(LogLevel::None, false);
    let (origin_tcp_port, origin_tcp_reservation) = reserve_tcp_port().await;
    let (origin_udp_port, origin_udp_reservation) = reserve_udp_port_except(origin_tcp_port).await;
    let origin = Portal::new(
        Url::parse(&format!(
            "portal://origin-secret@127.0.0.1/tcp:{origin_tcp_port}/udp:{origin_udp_port}?log=none"
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
            "portal://relay-secret@127.0.0.1:{relay_port}?log=none&next=origin-secret@127.0.0.1/tcp:{origin_tcp_port}/udp:{origin_udp_port}&up={up}&down={down}&mux=1"
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
        &"auto".into(),
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

#[path = "vector/carriers.rs"]
mod carriers;
#[path = "vector/chain.rs"]
mod chain;
#[path = "vector/chain_failure.rs"]
mod chain_failure;
#[path = "vector/routes.rs"]
mod routes;
