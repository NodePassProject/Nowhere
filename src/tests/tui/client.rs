use super::*;
use crate::telemetry::wire::{InstanceDescriptor, LifecycleSnapshot};
use crate::telemetry::{AccessOutcome, InstanceRole as WireRole, PROTOCOL_VERSION};

fn hello() -> Hello {
    Hello {
        instance: InstanceDescriptor {
            protocol_version: PROTOCOL_VERSION,
            id: "0:42:7".to_owned(),
            role: WireRole::Portal,
            pid: 42,
            uid: 0,
            incarnation: 7,
            version: "test".to_owned(),
            endpoint: ":2077".to_owned(),
            config_summary: "net=mix".to_owned(),
            telemetry_interval_ms: 1_000,
        },
        lifecycle: "READY".to_owned(),
        lifecycle_reason: "STARTUP".to_owned(),
    }
}

#[test]
fn maps_hello_without_sensitive_fields() {
    let UiEvent::Upsert {
        meta, lifecycle, ..
    } = hello_ui_event(&hello())
    else {
        panic!("expected upsert");
    };
    assert_eq!(meta.role, InstanceRole::Portal);
    assert_eq!(meta.pid, 42);
    assert_eq!(lifecycle, Lifecycle::Ready);
}

#[test]
fn completion_inherits_access_path() {
    let started = AccessStarted {
        id: 9,
        timestamp_ms: 1,
        protocol: TrafficProtocol::Tcp,
        wire_version: Some(crate::protocol::ProtocolVersion::V1),
        flow_id: None,
        session_tag: Some("abc123".to_owned()),
        client: Some("10.0.0.1:9".to_owned()),
        path_peers: vec!["10.0.0.1:9".to_owned()],
        target: "example.com:443".to_owned(),
        initial_uplink: Some("udp".to_owned()),
        initial_downlink: Some("tcp".to_owned()),
        path: Some("client -> QUIC -> TLS -> target".to_owned()),
    };
    let mut starts = HashMap::from([(9, access_start_ui_value(started))]);
    let finished = AccessFinished {
        id: 9,
        timestamp_ms: 2,
        duration_ms: 1,
        protocol: TrafficProtocol::Tcp,
        wire_version: Some(crate::protocol::ProtocolVersion::V1),
        flow_id: None,
        session_tag: Some("abc123".to_owned()),
        client: Some("10.0.0.1:9".to_owned()),
        path_peers: vec!["10.0.0.1:9".to_owned()],
        target: "example.com:443".to_owned(),
        initial_uplink: Some("udp".to_owned()),
        initial_downlink: Some("tcp".to_owned()),
        path: Some("client -> QUIC -> TLS -> target".to_owned()),
        upload_bytes: 10,
        download_bytes: 20,
        outcome: AccessOutcome::Success,
        error: None,
    };
    let record = access_finish_ui_value(finished, &mut starts);
    assert_eq!(record.phase, AccessPhase::Finish);
    assert_eq!(record.route, "client -> QUIC -> TLS -> target");
    assert_eq!(record.status, Some(AccessStatus::Success));
    assert_eq!(record.download_bytes, Some(20));
}

#[test]
fn peer_close_is_a_quiet_normal_end() {
    assert!(is_benign_access_end(
        "connection closed by peer with error code 256"
    ));
}

#[test]
fn lifecycle_runtime_updates_status_and_feed() {
    let events = server_ui_events(
        ServerMessage::RuntimeEvent(RuntimeEvent {
            timestamp_ms: 1,
            level: RuntimeLevel::Info,
            kind: RuntimeKind::Lifecycle,
            message: "DRAINING: SHUTDOWN".to_owned(),
            client: None,
        }),
        "instance",
        &mut HashMap::new(),
    );
    assert!(matches!(
        events.first(),
        Some(UiEvent::Lifecycle {
            lifecycle: Lifecycle::Draining,
            ..
        })
    ));
    assert!(matches!(events.get(1), Some(UiEvent::Runtime { .. })));
}

#[test]
fn lifecycle_snapshot_updates_summary_status() {
    let events = server_ui_events(
        ServerMessage::Lifecycle(LifecycleSnapshot {
            state: "STOPPED".to_owned(),
            reason: "CLEANUP_COMPLETE".to_owned(),
            timestamp_ms: 2,
        }),
        "instance",
        &mut HashMap::new(),
    );
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events.first(),
        Some(UiEvent::Lifecycle {
            id,
            lifecycle: Lifecycle::Stopped,
        }) if id == "instance"
    ));
}
