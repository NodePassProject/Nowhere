use super::*;
use crate::protocol::ProtocolVersion;

fn versioned_half(version: ProtocolVersion, label: &str) -> LinkHalf {
    LinkHalf::tcp(LinkPath {
        version,
        peer: format!("{label}.client:1234"),
        local: "portal.test:2077".into(),
    })
}

#[tokio::test]
async fn identical_session_and_flow_ids_are_isolated_by_protocol_version() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let id = [41; SESSION_ID_LEN];
    let v1 = SessionKey::new(ProtocolVersion::V1, id);
    let v2 = SessionKey::new(ProtocolVersion::V2, id);
    let _v1_link = registry.register_tcp_link(v1, stats.clone());
    let _v2_link = registry.register_tcp_link(v2, stats);

    let (uplink, _uplink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                v1,
                header(
                    FlowRole::Open,
                    9,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:443")),
                versioned_half(ProtocolVersion::V1, "v1"),
                Some(Box::pin(uplink)),
                None,
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    let (downlink, _downlink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                v2,
                header(
                    FlowRole::Attach,
                    9,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                None,
                versioned_half(ProtocolVersion::V2, "v2"),
                None,
                Some(Box::pin(downlink)),
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    let pending = registry.tcp.lock().await;
    assert!(pending.contains_key(&FlowKey {
        session_id: v1,
        flow_id: 9
    }));
    assert!(pending.contains_key(&FlowKey {
        session_id: v2,
        flow_id: 9
    }));
    assert_eq!(pending.len(), 2);
    drop(pending);

    registry
        .reject_flow_setup(v1, 77, FlowErrorCode::DialFailed)
        .await;
    assert_eq!(
        registry.terminal_rejection(
            FlowKey {
                session_id: v1,
                flow_id: 77,
            },
            false,
        ),
        Some(FlowErrorCode::DialFailed)
    );
    assert_eq!(
        registry.terminal_rejection(
            FlowKey {
                session_id: v2,
                flow_id: 77,
            },
            false,
        ),
        None
    );
}

#[tokio::test]
async fn quic_replacement_is_scoped_to_protocol_version() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let id = [42; SESSION_ID_LEN];
    let v1 = SessionKey::new(ProtocolVersion::V1, id);
    let v2 = SessionKey::new(ProtocolVersion::V2, id);
    let v1_replaced = tokio_util::sync::CancellationToken::new();

    let _v1 = registry
        .register_quic_link(v1, stats.clone(), v1_replaced.clone())
        .await;
    let _v2 = registry
        .register_quic_link(v2, stats, tokio_util::sync::CancellationToken::new())
        .await;

    assert!(!v1_replaced.is_cancelled());
    assert!(registry.active_quic_generation(v1).is_some());
    assert!(registry.active_quic_generation(v2).is_some());
}
