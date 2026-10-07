// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Tests for TLS Mux slot allocation, reuse, pressure, and initialization cancellation.

use super::*;
use std::sync::atomic::AtomicBool;
use tokio::io::AsyncReadExt;
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

fn manager() -> Arc<TlsManager> {
    let url = Url::parse("vector://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?mux=1&socks=127.0.0.1:1080").unwrap();
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
    TlsManager::new(
        &portal,
        tls,
        &credentials,
        [0; crate::protocol::SESSION_ID_LEN],
        ClientSignals::new(stats, telemetry, LatencyTracker::new()),
    )
}

fn slot(handle: MuxHandle) -> Arc<TlsMux> {
    let slot = Arc::new(TlsMux::default());
    assert!(slot.handle.set(handle).is_ok());
    slot
}

async fn carrier(pressured: bool) -> (MuxHandle, MuxHandle, crate::mux::Incoming, Vec<MuxStream>) {
    let (left, right) = tokio::io::duplex(1 << 20);
    let config = MuxConfig {
        stream_window_bytes: 4 << 20,
        connection_window_bytes: 8 << 20,
        outbound_frames: 512,
        ..MuxConfig::default()
    };
    let (handle, _) = MuxHandle::start(left, config).unwrap();
    let (peer, mut incoming) = MuxHandle::start(right, config).unwrap();
    let mut streams = Vec::new();
    for id in 1..=2 {
        let mut stream = handle.open_stream(id).await.unwrap();
        streams.push(incoming.accept().await.unwrap().unwrap());
        if pressured {
            stream.write_all(&vec![1; 7 << 19]).await.unwrap();
            stream.flush().await.unwrap();
        }
        streams.push(stream);
    }
    (handle, peer, incoming, streams)
}

#[tokio::test]
async fn cold_reservations_balance_across_eight_connecting_slots() {
    let mut pool = Vec::new();
    let pending: Vec<_> = (0..16)
        .map(|_| reserve_mux(&mut pool, None).unwrap())
        .collect();
    assert_eq!(pool.len(), 8);
    assert!(
        pool.iter()
            .all(|slot| slot.pending.load(Ordering::Relaxed) == 2)
    );
    drop(pending);
    assert!(
        pool.iter()
            .all(|slot| slot.pending.load(Ordering::Relaxed) == 0)
    );
}

#[tokio::test]
async fn idle_carrier_is_reused_before_new_connections() {
    let (handle, peer, _incoming, streams) = carrier(false).await;
    drop(streams);
    let mut pool = vec![slot(handle.clone())];
    let selected = reserve_mux(&mut pool, None).unwrap();
    assert_eq!(pool.len(), 1);
    assert!(selected.0.handle.get().unwrap().same_carrier(&handle));
    handle.close();
    peer.close();
}

#[tokio::test]
async fn retained_flow_id_uses_a_different_carrier() {
    let (carrier, _peer) = tokio::io::duplex(1 << 20);
    let (handle, _incoming) = MuxHandle::start(carrier, MuxConfig::default()).unwrap();
    let retained_id = 77;
    drop(handle.prepare_stream(retained_id).unwrap());
    assert_eq!(handle.active_streams(), 0);
    assert!(handle.contains_flow(retained_id));

    let mut pool = vec![slot(handle.clone())];
    let selected = reserve_mux(&mut pool, Some(retained_id)).unwrap();
    assert_eq!(pool.len(), 2);
    assert!(selected.0.handle.get().is_none());

    handle.close();
}

#[tokio::test]
async fn retained_metadata_limit_uses_a_different_carrier() {
    let (carrier, _peer) = tokio::io::duplex(1 << 20);
    let config = MuxConfig {
        active_stream_limit: 1,
        ..MuxConfig::default()
    };
    let (handle, _incoming) = MuxHandle::start(carrier, config).unwrap();
    drop(handle.prepare_stream(1).unwrap());
    assert_eq!(handle.active_streams(), 0);
    assert!(!handle.can_open_flow(2));

    let mut pool = vec![slot(handle.clone())];
    let selected = reserve_mux(&mut pool, Some(2)).unwrap();
    assert_eq!(pool.len(), 2);
    assert!(selected.0.handle.get().is_none());

    handle.close();
}

#[tokio::test]
async fn full_pool_prefers_lower_pressure_and_still_transfers_new_flows() {
    let mut pool = Vec::new();
    let mut peers = Vec::new();
    let mut streams = Vec::new();
    let mut incoming = Vec::new();
    for index in 0..8 {
        let (handle, peer, receiver, held) = carrier(index != 7).await;
        pool.push(slot(handle));
        peers.push(peer);
        streams.extend(held);
        incoming.push(receiver);
    }
    let selected = reserve_mux(&mut pool, None).unwrap();
    assert!(Arc::ptr_eq(&selected.0, &pool[7]));
    let handle = selected.0.handle.get().unwrap();
    let mut stream = handle.open_stream(99).await.unwrap();
    let mut accepted = incoming[7].accept().await.unwrap().unwrap();
    stream.write_all(b"new").await.unwrap();
    let mut bytes = [0; 3];
    accepted.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"new");
    assert_eq!(pool.len(), 8);
    for slot in &pool {
        slot.handle.get().unwrap().close();
    }
    for peer in &peers {
        peer.close();
    }
    drop((streams, stream));
}

#[tokio::test]
async fn cancelling_initializer_releases_reservation_and_allows_retry() {
    let mut pool = Vec::new();
    let pending = reserve_mux(&mut pool, None).unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _pending = pending;
        _pending
            .0
            .handle
            .get_or_try_init(|| async {
                let _ = started.send(());
                std::future::pending::<Result<MuxHandle>>().await
            })
            .await
            .map(|_| ())
    });
    ready.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(pool[0].pending.load(Ordering::Relaxed), 0);
    let retry = reserve_mux(&mut pool, None).unwrap();
    assert_eq!(pool.len(), 1);
    let (handle, peer, _incoming, streams) = carrier(false).await;
    retry
        .0
        .handle
        .get_or_try_init(|| async { Ok::<_, anyhow::Error>(handle.clone()) })
        .await
        .unwrap();
    assert!(retry.0.handle.get().unwrap().same_carrier(&handle));
    handle.close();
    peer.close();
    drop(streams);
}

#[tokio::test]
async fn closed_carrier_is_replaced_with_a_reusable_slot() {
    let (handle, peer, _incoming, streams) = carrier(false).await;
    let mut pool = vec![slot(handle.clone())];
    let old = pool[0].clone();
    handle.close();
    let pending = reserve_mux(&mut pool, None).unwrap();
    assert_eq!(pool.len(), 1);
    assert!(!Arc::ptr_eq(&pending.0, &old));
    peer.close();
    drop(streams);
}

#[tokio::test]
async fn shutdown_closes_mux_pool_and_drains_monitors() {
    let manager = manager();
    let (handle, peer, _incoming, streams) = carrier(false).await;
    manager.mux.lock().await.push(slot(handle.clone()));
    let (orphan, orphan_peer, _orphan_incoming, orphan_streams) = carrier(false).await;

    let dropped = Arc::new(AtomicBool::new(false));
    let marker = DropMarker(dropped.clone());
    let orphan_lifetime = orphan.clone();
    let close = CloseMuxOnDrop(orphan_lifetime);
    manager.mux_monitors.lock().await.spawn(async move {
        let _marker = marker;
        let _close = close;
        std::future::pending::<()>().await;
    });

    manager.close().await;

    assert!(manager.closed.load(Ordering::Acquire));
    assert!(manager.mux.lock().await.is_empty());
    assert!(manager.mux_monitors.lock().await.is_empty());
    assert!(handle.is_closed());
    assert!(orphan.is_closed());
    assert!(dropped.load(Ordering::Acquire));
    assert!(manager.open(99).await.is_err());

    manager.close().await;
    peer.close();
    orphan_peer.close();
    drop((streams, orphan_streams));
}

#[tokio::test]
async fn idle_retirement_reports_failure_that_closed_carrier_first() {
    let manager = manager();
    let (left, _peer) = tokio::io::duplex(1024);
    let (handle, _incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let slot = slot(handle.clone());
    let mut pool = manager.mux.lock().await;
    pool.push(slot.clone());
    let _detail = manager.telemetry.detail_guard();
    let mut events = manager.telemetry.event_receiver();
    let link = LinkGuard::new(manager.stats.clone(), manager.telemetry.clone(), false);
    let latency = manager.latency.register();
    let mut monitor =
        Box::pin(
            manager
                .clone()
                .monitor_mux(slot, handle.clone(), link, latency, Duration::ZERO),
        );
    std::future::poll_fn(|cx| {
        assert!(monitor.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    std::future::poll_fn(|cx| {
        assert!(monitor.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    handle.close_with_reason(MuxCloseReason::WriterFailure);
    drop(pool);
    tokio::time::timeout(Duration::from_secs(1), monitor)
        .await
        .unwrap();
    let mut message = None;
    while let Ok(event) = events.try_recv() {
        if let crate::telemetry::ServerMessage::RuntimeEvent(event) = event
            && event.kind == RuntimeKind::Mux
        {
            message = Some(event.message);
        }
    }
    assert_eq!(
        message.as_deref(),
        Some("TLS mux carrier disconnected: mux writer failure")
    );
    assert!(manager.mux.lock().await.is_empty());
}

#[tokio::test]
async fn native_next_tls_uses_the_matching_dual_stack_source() {
    use crate::common::{DialPolicy, LogLevel, Logger, new_server_configs_with_reload_interval};
    for (bind, carrier, source) in [
        ("127.0.0.1:0", "tcp4", "127.0.0.1"),
        ("[::1]:0", "tcp6", "::1"),
    ] {
        let listener = match tokio::net::TcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(error) if carrier == "tcp6" => {
                eprintln!("SKIP native next IPv6 TLS source: IPv6 loopback unavailable: {error}");
                continue;
            }
            Err(error) => panic!("bind failed: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let server_url = Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@localhost:2000").unwrap();
        let (_, tls_server, _) = new_server_configs_with_reload_interval(
            &server_url,
            Duration::from_secs(60),
            Logger::new(LogLevel::None, false),
        )
        .unwrap();
        let policy = DialPolicy::DualStack {
            v4: Some(
                if carrier == "tcp4" {
                    "127.0.0.1"
                } else {
                    "192.0.2.254"
                }
                .parse()
                .unwrap(),
            ),
            v6: Some(
                if carrier == "tcp6" {
                    "::1"
                } else {
                    "2001:db8::dead"
                }
                .parse()
                .unwrap(),
            ),
        };
        let (config, credentials) = PortalClientConfig::from_upstream_authority(
            &format!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@localhost/{carrier}:{}", address.port()),
            &HashMap::from([(
                "pin".to_owned(),
                crate::tls_test_support::server_certificate_pin(&tls_server),
            )]),
            &policy,
        )
        .unwrap();
        let tls = ClientTls::new(&config).unwrap();
        let manager = TlsManager::new(
            &config,
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
        );
        timeout(Duration::from_secs(3), async {
            let server = async {
                let (stream, peer) = listener.accept().await.unwrap();
                assert_eq!(peer.ip(), source.parse::<IpAddr>().unwrap());
                tokio_rustls::TlsAcceptor::from(tls_server)
                    .accept(stream)
                    .await
                    .unwrap()
            };
            let (lane, _server) = tokio::join!(manager.connect_lane(), server);
            let lane = lane.unwrap();
            assert_eq!(
                lane.stream.get_ref().0.get_ref().local_addr().unwrap().ip(),
                source.parse::<IpAddr>().unwrap()
            );
        })
        .await
        .unwrap();
        manager.close().await;
    }
}
