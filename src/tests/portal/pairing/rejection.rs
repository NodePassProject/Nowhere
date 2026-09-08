// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

#[tokio::test]
async fn initially_stale_udp_open_leaves_exact_rejection_for_uot_attach() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [7; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let first = registry
        .register_quic_link(
            session_id,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    let old_generation = first.quic_generation();
    let second = registry
        .register_quic_link(
            session_id,
            stats,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

    let (_datagram_tx, datagram_rx) = mpsc::channel(1);
    let open_error = registry
        .submit_udp(
            session_id,
            header(
                FlowRole::Open,
                15,
                FlowKind::Udp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:53")),
            quic_half("stale-uplink", old_generation),
            UdpHalf::Uplink {
                uplink: UdpUp::Quic(QuicUdpReceiver::new_without_barrier(
                    datagram_rx,
                    Arc::new(AtomicBool::new(false)),
                    || {},
                )),
            },
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(open_error.code(), FlowErrorCode::SessionReplaced);

    let (downlink, mut peer) = tokio::io::duplex(64);
    let attach_error = registry
        .submit_udp(
            session_id,
            header(
                FlowRole::Attach,
                15,
                FlowKind::Udp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("uot-downlink"),
            UdpHalf::Downlink(UdpDown::TlsTcp {
                writer: Box::pin(downlink),
                liveness: None,
            }),
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(attach_error.code(), FlowErrorCode::SessionReplaced);
    assert_eq!(
        read_flow_result(&mut peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );

    drop(first);
    drop(second);
    drop(tcp_guard);
}

#[tokio::test]
async fn late_attach_receives_original_open_pair_timeout() {
    let registry = registry(8, Duration::from_millis(10));
    let stats = Arc::new(Stats::default());

    let tcp_session = [8; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(tcp_session, stats.clone());
    let (tcp_uplink, _tcp_uplink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                tcp_session,
                header(
                    FlowRole::Open,
                    16,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:443")),
                tcp_half("tcp-open"),
                Some(Box::pin(tcp_uplink)),
                None,
                None,
            )
            .await
            .unwrap()
            .is_none()
    );
    let tcp_key = FlowKey {
        session_id: tcp_session,
        flow_id: 16,
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.terminal_rejection(tcp_key, false) != Some(FlowErrorCode::PairTimeout) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (tcp_downlink, mut tcp_peer) = tokio::io::duplex(64);
    let tcp_error = registry
        .submit_tcp(
            tcp_session,
            header(
                FlowRole::Attach,
                16,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("tcp-attach"),
            None,
            Some(Box::pin(tcp_downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(tcp_error.code(), FlowErrorCode::PairTimeout);
    assert_eq!(
        read_flow_result(&mut tcp_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::PairTimeout)
    );

    let udp_session = [9; SESSION_ID_LEN];
    let udp_guard = registry.register_tcp_link(udp_session, stats);
    let (udp_uplink, _udp_uplink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_udp(
                udp_session,
                header(
                    FlowRole::Open,
                    17,
                    FlowKind::Udp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:53")),
                tcp_half("udp-open"),
                UdpHalf::Uplink {
                    uplink: UdpUp::TlsTcp(Box::pin(udp_uplink)),
                },
            )
            .await
            .unwrap()
            .is_none()
    );
    let udp_key = FlowKey {
        session_id: udp_session,
        flow_id: 17,
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.terminal_rejection(udp_key, false) != Some(FlowErrorCode::PairTimeout) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (udp_downlink, mut udp_peer) = tokio::io::duplex(64);
    let udp_error = registry
        .submit_udp(
            udp_session,
            header(
                FlowRole::Attach,
                17,
                FlowKind::Udp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("udp-attach"),
            UdpHalf::Downlink(UdpDown::TlsTcp {
                writer: Box::pin(udp_downlink),
                liveness: None,
            }),
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(udp_error.code(), FlowErrorCode::PairTimeout);
    assert_eq!(
        read_flow_result(&mut udp_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::PairTimeout)
    );

    drop(tcp_guard);
    drop(udp_guard);
}

#[tokio::test]
async fn tombstones_deliver_exact_reject_on_selected_downlink() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());

    let tcp_session = [3; SESSION_ID_LEN];
    let quic_guard = registry
        .register_quic_link(
            tcp_session,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    registry
        .reject_flow_setup(tcp_session, 9, FlowErrorCode::DialFailed)
        .await;
    let (tcp_downlink, mut tcp_peer) = tokio::io::duplex(64);
    let tcp_error = registry
        .submit_tcp(
            tcp_session,
            header(
                FlowRole::Attach,
                9,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::Quic,
            ),
            None,
            quic_half("tcp-reject", quic_guard.quic_generation()),
            None,
            Some(Box::pin(tcp_downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(tcp_error.code(), FlowErrorCode::DialFailed);
    let mut tcp_result = [0; 1];
    tcp_peer.read_exact(&mut tcp_result).await.unwrap();
    assert_eq!(
        tcp_result,
        encode_flow_result(FlowResult::Reject(FlowErrorCode::DialFailed))
    );

    let udp_session = [4; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(udp_session, stats);
    registry
        .reject_flow_setup(udp_session, 10, FlowErrorCode::InternalError)
        .await;
    let (uot_downlink, mut uot_peer) = tokio::io::duplex(64);
    let udp_error = registry
        .submit_udp(
            udp_session,
            header(
                FlowRole::Attach,
                10,
                FlowKind::Udp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("udp-reject"),
            UdpHalf::Downlink(UdpDown::TlsTcp {
                writer: Box::pin(uot_downlink),
                liveness: None,
            }),
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(udp_error.code(), FlowErrorCode::InternalError);
    assert_eq!(
        read_flow_result(&mut uot_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::InternalError)
    );

    drop(quic_guard);
    drop(tcp_guard);
}
