// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC UDP route setup ownership and flow-ID reuse tests.

use super::*;
use std::sync::atomic::AtomicBool;
use url::Url;

use crate::telemetry::{InstanceRole, TelemetryHub};
use crate::transport::Stats;
use crate::vector::config::VectorConfig;

struct DropMarker(Arc<AtomicBool>);

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn manager(shutdown: CancellationToken) -> Arc<QuicManager> {
    let url =
        Url::parse("vector://secret@127.0.0.1/udp:9?up=udp&down=udp&socks=127.0.0.1:1080").unwrap();
    let config = VectorConfig::from_url(&url).unwrap();
    let portal = config.portal_client_config();
    let credentials = Credentials::new(&url).unwrap();
    let tls = ClientTls::new(&portal).unwrap();
    let stats = Arc::new(Stats::default());
    let telemetry = TelemetryHub::for_current_process(
        InstanceRole::Vector,
        "test",
        "test",
        Duration::from_secs(1),
    );
    QuicManager::new(
        portal,
        tls,
        &credentials,
        [0; crate::protocol::SESSION_ID_LEN],
        ClientSignals::new(stats, telemetry, LatencyTracker::new()),
        shutdown,
    )
}

fn insert_pending_route(
    routes: &Arc<StdMutex<HashMap<FlowId, UdpRoute>>>,
    flow_id: FlowId,
) -> PendingUdpRoute {
    let (sender, _receiver) = mpsc::channel(1);
    let generation = Arc::new(());
    routes.lock().unwrap().insert(
        flow_id,
        UdpRoute {
            sender,
            ready: false,
            generation: generation.clone(),
        },
    );
    PendingUdpRoute {
        routes: Arc::downgrade(routes),
        flow_id,
        generation,
        armed: true,
    }
}

#[test]
fn cancelled_udp_setup_removes_pending_route() {
    let routes = Arc::new(StdMutex::new(HashMap::new()));
    let pending = insert_pending_route(&routes, 7);

    drop(pending);

    assert!(!routes.lock().unwrap().contains_key(&7));
}

#[test]
fn stale_udp_setup_does_not_remove_reused_flow_id() {
    let routes = Arc::new(StdMutex::new(HashMap::new()));
    let stale = insert_pending_route(&routes, 7);
    let current = insert_pending_route(&routes, 7);

    drop(stale);

    assert!(routes.lock().unwrap().contains_key(&7));
    drop(current);
    assert!(!routes.lock().unwrap().contains_key(&7));
}

#[test]
fn committed_udp_route_outlives_setup_guard() {
    let routes = Arc::new(StdMutex::new(HashMap::new()));
    let pending = insert_pending_route(&routes, 7);

    pending.commit();

    assert!(routes.lock().unwrap().contains_key(&7));
}

#[tokio::test]
async fn stopping_datagram_task_waits_for_owned_state_drop() {
    let task = DatagramTask::default();
    let dropped = Arc::new(AtomicBool::new(false));
    let marker = DropMarker(dropped.clone());
    task.install(tokio::spawn(async move {
        let _marker = marker;
        std::future::pending::<()>().await;
    }));

    task.stop().await;

    assert!(dropped.load(Ordering::Acquire));
    task.stop().await;
}

#[tokio::test]
async fn close_rejects_new_quic_sessions_without_dialing() {
    let shutdown = CancellationToken::new();
    let manager = manager(shutdown.clone());
    manager.close(Instant::now()).await;

    let error = match manager.get().await {
        Ok(_) => panic!("shutdown manager opened a QUIC session"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("shutting down"));
    assert!(shutdown.is_cancelled());
    assert!(manager.state.lock().await.is_none());
}

#[tokio::test]
async fn native_next_quic_uses_the_matching_dual_stack_source() {
    use crate::common::{DialPolicy, LogLevel, Logger, new_server_configs_with_reload_interval};
    for (bind, carrier, source) in [
        ("127.0.0.1:0", "udp4", "127.0.0.1"),
        ("[::1]:0", "udp6", "::1"),
    ] {
        let server_url = Url::parse("portal://secret@localhost:2000").unwrap();
        let (_, _, quic_server) = new_server_configs_with_reload_interval(
            &server_url,
            Duration::from_secs(60),
            Logger::new(LogLevel::None, false),
        )
        .unwrap();
        let server = match Endpoint::server(quic_server, bind.parse().unwrap()) {
            Ok(server) => server,
            Err(error) if carrier == "udp6" => {
                eprintln!("SKIP native next IPv6 QUIC source: IPv6 loopback unavailable: {error}");
                continue;
            }
            Err(error) => panic!("bind failed: {error}"),
        };
        let address = server.local_addr().unwrap();
        let policy = DialPolicy::DualStack {
            v4: Some(
                if carrier == "udp4" {
                    "127.0.0.1"
                } else {
                    "192.0.2.254"
                }
                .parse()
                .unwrap(),
            ),
            v6: Some(
                if carrier == "udp6" {
                    "::1"
                } else {
                    "2001:db8::dead"
                }
                .parse()
                .unwrap(),
            ),
        };
        let (config, credentials) = PortalClientConfig::from_upstream_authority(
            &format!("secret@localhost/{carrier}:{}", address.port()),
            &HashMap::new(),
            &policy,
        )
        .unwrap();
        let tls = ClientTls::new(&config).unwrap();
        let manager = QuicManager::new(
            config,
            tls,
            &credentials,
            [0; crate::protocol::SESSION_ID_LEN],
            ClientSignals::new(
                Arc::new(Stats::default()),
                TelemetryHub::for_current_process(
                    InstanceRole::Portal,
                    "test",
                    "test",
                    Duration::from_secs(1),
                ),
                LatencyTracker::new(),
            ),
            CancellationToken::new(),
        );
        timeout(Duration::from_secs(3), async {
            let accept = async { server.accept().await.unwrap().await.unwrap() };
            let (session, peer) = tokio::join!(manager.get(), accept);
            let session = session.unwrap();
            assert_eq!(
                peer.remote_address().ip(),
                source.parse::<IpAddr>().unwrap()
            );
            assert_eq!(
                session._endpoint.local_addr().unwrap().ip(),
                source.parse::<IpAddr>().unwrap()
            );
            peer.close(VarInt::from_u32(0), b"test complete");
            manager
                .close(Instant::now() + Duration::from_millis(100))
                .await;
        })
        .await
        .unwrap();
        server.close(VarInt::from_u32(0), b"test complete");
        server.wait_idle().await;
    }
}
