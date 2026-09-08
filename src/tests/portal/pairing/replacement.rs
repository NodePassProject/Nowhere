// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

#[tokio::test]
async fn old_quic_guard_does_not_cancel_flow_on_replacement_generation() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [1; SESSION_ID_LEN];
    let _tcp_guard = registry.register_tcp_link(session_id, stats.clone());

    let first_replaced = tokio_util::sync::CancellationToken::new();
    let first = registry
        .register_quic_link(session_id, stats.clone(), first_replaced.clone())
        .await;
    let second_replaced = tokio_util::sync::CancellationToken::new();
    let second = registry
        .register_quic_link(session_id, stats.clone(), second_replaced.clone())
        .await;
    assert!(first_replaced.is_cancelled());
    assert!(!second_replaced.is_cancelled());

    let (downlink, mut downlink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Attach,
                    7,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::Quic,
                ),
                None,
                quic_half("new", second.quic_generation()),
                None,
                Some(Box::pin(downlink)),
                None,
            )
            .await
            .unwrap()
            .is_none()
    );
    let (uplink, _uplink_peer) = tokio::io::duplex(64);
    let mut paired = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Open,
                7,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::Quic,
            ),
            Some(target("target.test:443")),
            tcp_half("up"),
            Some(Box::pin(uplink)),
            None,
            None,
        )
        .await
        .unwrap()
        .expect("new generation should pair");
    let flow_cancel = paired._flow_lease.cancellation_token();

    drop(first);
    tokio::task::yield_now().await;
    assert!(!flow_cancel.is_cancelled());
    assert_eq!(stats.link_udp.load(Ordering::Relaxed), 1);

    paired.downlink.write_all(b"new").await.unwrap();
    let mut received = [0; 3];
    downlink_peer.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"new");
    drop(paired);
    drop(second);
    assert_eq!(stats.link_udp.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn quic_replacement_immediately_rejects_pending_split_flows() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [0x33; SESSION_ID_LEN];
    let _tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let first = registry
        .register_quic_link(
            session_id,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

    let (tcp_uplink, _tcp_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Open,
                    30,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::Quic,
                ),
                Some(target("target.test:443")),
                tcp_half("tcp-pending"),
                Some(Box::pin(tcp_uplink)),
                None,
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    let (uot_downlink, mut uot_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_udp(
                session_id,
                header(
                    FlowRole::Attach,
                    31,
                    FlowKind::Udp,
                    Carrier::Quic,
                    Carrier::TlsTcp,
                ),
                None,
                tcp_half("udp-pending"),
                UdpHalf::Downlink(UdpDown::TlsTcp {
                    writer: Box::pin(uot_downlink),
                    liveness: None,
                }),
            )
            .await
            .unwrap()
            .is_none()
    );

    let second = registry
        .register_quic_link(
            session_id,
            stats,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    assert!(registry.tcp.lock().await.is_empty());
    assert!(registry.udp.lock().await.is_empty());
    assert_eq!(
        read_flow_result(&mut uot_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );

    let (tcp_downlink, mut tcp_result) = tokio::io::duplex(64);
    let error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Attach,
                30,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::Quic,
            ),
            None,
            quic_half("replacement", second.quic_generation()),
            None,
            Some(Box::pin(tcp_downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::SessionReplaced);
    assert_eq!(
        read_flow_result(&mut tcp_result).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );

    drop(first);
    drop(second);
}

#[tokio::test]
async fn stale_open_after_map_lock_leaves_exact_rejection_for_tcp_attach() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [2; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let first = registry
        .register_quic_link(
            session_id,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    let old_generation = first.quic_generation();

    let map_guard = registry.tcp.lock().await;
    let (uplink, _uplink_peer) = tokio::io::duplex(64);
    let submit_registry = registry.clone();
    let submit = tokio::spawn(async move {
        submit_registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Open,
                    8,
                    FlowKind::Tcp,
                    Carrier::Quic,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:443")),
                quic_half("stale", old_generation),
                Some(Box::pin(uplink)),
                None,
                None,
            )
            .await
    });
    tokio::task::yield_now().await;

    let replace_registry = registry.clone();
    let replace_stats = stats.clone();
    let replacement = tokio::spawn(async move {
        replace_registry
            .register_quic_link(
                session_id,
                replace_stats,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.active_quic_generation(session_id) == Some(old_generation) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement generation should become visible");
    drop(map_guard);

    let error = tokio::time::timeout(Duration::from_secs(1), submit)
        .await
        .expect("stale submit should finish")
        .unwrap()
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::SessionReplaced);

    let (downlink, mut downlink_peer) = tokio::io::duplex(64);
    let attach_error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Attach,
                8,
                FlowKind::Tcp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("downlink"),
            None,
            Some(Box::pin(downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(attach_error.code(), FlowErrorCode::SessionReplaced);
    let mut result = [0; 1];
    downlink_peer.read_exact(&mut result).await.unwrap();
    assert_eq!(
        result,
        encode_flow_result(FlowResult::Reject(FlowErrorCode::SessionReplaced))
    );

    let second = replacement.await.unwrap();
    drop(first);
    drop(second);
    drop(tcp_guard);
}
