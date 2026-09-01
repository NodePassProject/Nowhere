// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::*;
use crate::protocol::{Credentials, encode_target, write_flow_header};
use crate::telemetry::{InstanceRole, TelemetryHub};
use crate::transport::Stats;
use crate::vector::config::VectorConfig;

fn test_portal_client() -> Arc<PortalClient> {
    let url =
        Url::parse("vector://secret@127.0.0.1:2077?up=mix&down=mix&socks=127.0.0.1:1080").unwrap();
    let config = VectorConfig::from_url(&url).unwrap();
    let credentials = Credentials::new(&url).unwrap();
    PortalClient::with_session_id(
        config.portal_client_config(),
        &credentials,
        Arc::new(Stats::default()),
        false,
        TelemetryHub::for_current_process(
            InstanceRole::Vector,
            "test",
            "test",
            Duration::from_secs(1),
        ),
        CancellationToken::new(),
        [0; crate::protocol::SESSION_ID_LEN],
    )
    .unwrap()
}

#[tokio::test]
async fn cold_lane_coalesces_auth_flow_and_target() {
    let (writer, mut reader) = tokio::io::duplex(512);
    let mut writer: BoxWriter = Box::pin(writer);
    let auth = [0xa5; AUTH_FRAME_LEN];
    let header = FlowHeader {
        role: FlowRole::Duplex,
        flow_id: 7,
        kind: FlowKind::Tcp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::TlsTcp,
        hops: 0,
    };
    let target = Target::ip(SocketAddr::from(([127, 0, 0, 1], 443))).unwrap();

    write_open_request(&mut writer, Some(auth), header, &target)
        .await
        .unwrap();
    drop(writer);

    let mut wire = Vec::new();
    reader.read_to_end(&mut wire).await.unwrap();
    let encoded_target = encode_target(&target).unwrap();
    assert_eq!(&wire[..AUTH_FRAME_LEN], &auth);
    assert_eq!(
        &wire[AUTH_FRAME_LEN..AUTH_FRAME_LEN + FLOW_HEADER_LEN],
        &write_flow_header(header)
    );
    assert_eq!(&wire[AUTH_FRAME_LEN + FLOW_HEADER_LEN..], encoded_target);
}

#[tokio::test]
async fn cold_attach_lane_coalesces_auth_and_flow_header() {
    let (writer, mut reader) = tokio::io::duplex(128);
    let mut writer: BoxWriter = Box::pin(writer);
    let auth = [0x5a; AUTH_FRAME_LEN];
    let header = FlowHeader {
        role: FlowRole::Attach,
        flow_id: 9,
        kind: FlowKind::Udp,
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
        hops: 0,
    };

    write_header(&mut writer, Some(auth), header).await.unwrap();
    drop(writer);

    let mut wire = Vec::new();
    reader.read_to_end(&mut wire).await.unwrap();
    assert_eq!(&wire[..AUTH_FRAME_LEN], &auth);
    assert_eq!(&wire[AUTH_FRAME_LEN..], &write_flow_header(header));
}

#[tokio::test]
async fn ready_wait_uses_its_own_deadline() {
    let (_writer, reader) = tokio::io::duplex(1);
    let mut reader: BoxReader = Box::pin(reader);

    let started = tokio::time::Instant::now();
    assert_eq!(
        read_ready_with_timeout(&mut reader, Duration::from_millis(20)).await,
        Err(SetupResult::InternalError)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn precommit_failure_uses_the_other_route_and_a_new_flow_id_once() {
    let client = test_portal_client();
    let initial_lease = client.flow_ids.allocate().unwrap();
    let initial_id = initial_lease.id();
    let plan = RoutePlan {
        primary: ResolvedRoute {
            uplink: Carrier::Quic,
            downlink: Carrier::Quic,
        },
        fallback: Some(ResolvedRoute {
            uplink: Carrier::TlsTcp,
            downlink: Carrier::TlsTcp,
        }),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let call_counter = calls.clone();
    let recorded = attempts.clone();

    let (_, fallback_lease, route) =
        prepare_with_fallback(&client, initial_lease, plan, move |flow_id, route| {
            let call = call_counter.fetch_add(1, Ordering::Relaxed);
            recorded.lock().unwrap().push((flow_id, route));
            async move {
                if call == 0 {
                    Err(anyhow!("primary unavailable"))
                } else {
                    Ok(())
                }
            }
        })
        .await
        .unwrap();

    assert_eq!(route, plan.fallback.unwrap());
    assert_ne!(fallback_lease.id(), initial_id);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        attempts.lock().unwrap().as_slice(),
        &[
            (initial_id, plan.primary),
            (fallback_lease.id(), plan.fallback.unwrap()),
        ]
    );
}

#[tokio::test]
async fn mixed_primary_preparation_timeout_uses_the_fallback_once() {
    let client = test_portal_client();
    let primary = ResolvedRoute {
        uplink: Carrier::Quic,
        downlink: Carrier::Quic,
    };
    let fallback = ResolvedRoute {
        uplink: Carrier::TlsTcp,
        downlink: Carrier::TlsTcp,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let call_counter = calls.clone();
    let started = tokio::time::Instant::now();

    let (_, _, route) = prepare_with_fallback_timeout(
        &client,
        client.flow_ids.allocate().unwrap(),
        RoutePlan {
            primary,
            fallback: Some(fallback),
        },
        Duration::from_millis(20),
        move |_, route| {
            let call = call_counter.fetch_add(1, Ordering::Relaxed);
            async move {
                if call == 0 {
                    std::future::pending::<Result<()>>().await
                } else {
                    assert_eq!(route, fallback);
                    Ok(())
                }
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(route, fallback);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn fixed_route_and_failed_fallback_never_create_a_third_attempt() {
    let client = test_portal_client();
    let fixed = ResolvedRoute {
        uplink: Carrier::TlsTcp,
        downlink: Carrier::Quic,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let call_counter = calls.clone();
    let error = prepare_with_fallback(
        &client,
        client.flow_ids.allocate().unwrap(),
        RoutePlan {
            primary: fixed,
            fallback: None,
        },
        move |_, _| {
            call_counter.fetch_add(1, Ordering::Relaxed);
            async { Err::<(), _>(anyhow!("fixed route failed")) }
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("fixed route failed"));
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let calls = Arc::new(AtomicUsize::new(0));
    let call_counter = calls.clone();
    let error = prepare_with_fallback(
        &client,
        client.flow_ids.allocate().unwrap(),
        RoutePlan {
            primary: ResolvedRoute {
                uplink: Carrier::Quic,
                downlink: Carrier::Quic,
            },
            fallback: Some(ResolvedRoute {
                uplink: Carrier::TlsTcp,
                downlink: Carrier::TlsTcp,
            }),
        },
        move |_, route| {
            call_counter.fetch_add(1, Ordering::Relaxed);
            async move { Err::<(), _>(anyhow!("{} unavailable", route.label())) }
        },
    )
    .await
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("QQ unavailable"));
    assert!(message.contains("TT unavailable"));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}
