// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

#[tokio::test]
async fn tcp_sessions_admit_more_than_the_former_flow_limit() {
    let registry = registry(Duration::from_secs(30));
    let session = [0x31; SESSION_ID_LEN];
    let _guard = registry.register_tcp_link(session, Arc::new(Stats::default()));
    let mut held = Vec::new();
    for id in 1..=2048 {
        let (up, _) = tokio::io::duplex(64);
        let (down, _) = tokio::io::duplex(64);
        held.push(
            registry
                .submit_tcp(
                    session,
                    header(
                        FlowRole::Duplex,
                        id,
                        FlowKind::Tcp,
                        Carrier::TlsTcp,
                        Carrier::TlsTcp,
                    ),
                    Some(target("target.test:443")),
                    tcp_half("live"),
                    Some(Box::pin(up)),
                    Some(Box::pin(down)),
                    None,
                )
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(registry.claims.lock().unwrap().len(), 2048);
    drop(held);
    assert!(registry.claims.lock().unwrap().is_empty());
}

#[tokio::test]
async fn drain_rejects_pending_and_new_flows_but_preserves_active_claims() {
    let registry = registry(Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [0x5a; SESSION_ID_LEN];
    let _tcp_guard = registry.register_tcp_link(session_id, stats);

    let (active_up, _active_up_peer) = tokio::io::duplex(64);
    let (active_down, _active_down_peer) = tokio::io::duplex(64);
    let active = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Duplex,
                40,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:443")),
            tcp_half("active"),
            Some(Box::pin(active_up)),
            Some(Box::pin(active_down)),
            None,
        )
        .await
        .unwrap()
        .expect("flow should activate before drain");
    let active_cancel = active._flow_lease.cancellation_token();

    let (pending_up, _pending_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Open,
                    41,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:443")),
                tcp_half("pending"),
                Some(Box::pin(pending_up)),
                None,
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    registry.begin_drain().await;
    assert!(!registry.is_accepting());
    assert!(!active_cancel.is_cancelled());
    assert!(registry.tcp.lock().await.is_empty());

    let (late_down, mut late_peer) = tokio::io::duplex(64);
    let error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Attach,
                41,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("late"),
            None,
            Some(Box::pin(late_down)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::FlowLimit);
    assert_eq!(
        read_flow_result(&mut late_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::FlowLimit)
    );

    let (new_up, _new_up_peer) = tokio::io::duplex(64);
    let (new_down, mut new_peer) = tokio::io::duplex(64);
    let error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Duplex,
                42,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:443")),
            tcp_half("new"),
            Some(Box::pin(new_up)),
            Some(Box::pin(new_down)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::FlowLimit);
    assert_eq!(
        read_flow_result(&mut new_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::FlowLimit)
    );

    drop(active);
}

#[tokio::test]
async fn cancel_all_cancels_active_flows_without_waiting_for_pending_writer() {
    let registry = registry(Duration::from_secs(60));
    let stats = Arc::new(Stats::default());
    let session_id = [5; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let quic_guard = registry
        .register_quic_link(
            session_id,
            stats,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Attach,
                    11,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::Quic,
                ),
                None,
                quic_half("blocked", quic_guard.quic_generation()),
                None,
                Some(Box::pin(PendingWriter)),
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    let (active_stream, _active_peer) = tokio::io::duplex(64);
    let (active_downlink, _downlink_peer) = tokio::io::duplex(64);
    let active = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Duplex,
                12,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:443")),
            tcp_half("active"),
            Some(Box::pin(active_stream)),
            Some(Box::pin(active_downlink)),
            None,
        )
        .await
        .unwrap()
        .expect("duplex flow should activate");
    let active_cancel = active._flow_lease.cancellation_token();

    tokio::time::timeout(Duration::from_millis(500), registry.cancel_all())
        .await
        .expect("cancel_all must not await a blocked network writer");
    assert!(active_cancel.is_cancelled());
    assert!(registry.tcp.lock().await.is_empty());
    assert!(registry.udp.lock().await.is_empty());
    assert_eq!(
        registry
            .claims
            .lock()
            .expect("flow claim registry poisoned")
            .len(),
        1,
        "only the cancelled active lease remains until it is dropped"
    );
    drop(active);
    assert!(
        registry
            .claims
            .lock()
            .expect("flow claim registry poisoned")
            .is_empty()
    );

    drop(quic_guard);
    drop(tcp_guard);
}

#[tokio::test]
async fn pending_pairs_exceed_former_limit_and_release_quic_credit_on_drain() {
    let registry = registry(Duration::from_secs(30));
    let session = [0x32; SESSION_ID_LEN];
    let _guard = registry.register_tcp_link(session, Arc::new(Stats::default()));
    let mut peers = Vec::new();
    for id in 1..=2048 {
        let (up, peer) = tokio::io::duplex(64);
        peers.push(peer);
        assert!(
            registry
                .submit_tcp(
                    session,
                    header(
                        FlowRole::Open,
                        id,
                        FlowKind::Tcp,
                        Carrier::TlsTcp,
                        Carrier::Quic
                    ),
                    Some(target("target.test:443")),
                    tcp_half("pending"),
                    Some(Box::pin(up)),
                    None,
                    None,
                )
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(registry.claims.lock().unwrap().len(), 2048);
    assert_eq!(registry.quic_stream_credit(session).into_inner(), 2560);
    registry.begin_drain().await;
    assert!(registry.claims.lock().unwrap().is_empty());
    assert_eq!(registry.quic_stream_credit(session).into_inner(), 64);
}
