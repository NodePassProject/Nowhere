use std::sync::atomic::Ordering;

use crate::protocol::Carrier;
use crate::telemetry::wire::InstanceDescriptor;
use crate::telemetry::{
    AccessOutcome, AccessStart, InstanceRole, PROTOCOL_VERSION, ServerMessage, TelemetryHub,
    TrafficProtocol,
};
use crate::transport::Stats;

fn descriptor() -> InstanceDescriptor {
    InstanceDescriptor {
        protocol_version: PROTOCOL_VERSION,
        id: "1:2:3".to_owned(),
        role: InstanceRole::Portal,
        pid: 2,
        uid: 1,
        incarnation: 3,
        version: "test".to_owned(),
        endpoint: ":2077".to_owned(),
        config_summary: "portal net=mix".to_owned(),
        telemetry_interval_ms: 1_000,
    }
}

#[test]
fn access_span_finishes_only_once() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    let span = hub.start_access(|| AccessStart {
        id: 0,
        timestamp_ms: 1,
        protocol: TrafficProtocol::Tcp,
        wire_version: Some(crate::protocol::ProtocolVersion::V1),
        flow_id: Some(7),
        session_tag: Some("abc123".to_owned()),
        client: Some("127.0.0.1:1".to_owned()),
        path_peers: vec!["127.0.0.1:1".to_owned()],
        target: "example:443".to_owned(),
        initial_uplink: Some(Carrier::TlsTcp),
        initial_downlink: Some(Carrier::Quic),
        path: None,
    });
    span.add_upload(10);
    span.add_download(20);
    span.finish(AccessOutcome::Success, None);

    assert!(matches!(
        events.try_recv(),
        Ok(ServerMessage::AccessStart(_))
    ));
    let Ok(ServerMessage::AccessFinish(finish)) = events.try_recv() else {
        panic!("missing access finish");
    };
    assert_eq!(finish.upload_bytes, 10);
    assert_eq!(finish.download_bytes, 20);
    assert_eq!(finish.outcome, AccessOutcome::Success);
    assert!(events.try_recv().is_err());
}

#[test]
fn access_fields_are_not_built_without_a_receiver() {
    let hub = TelemetryHub::new(descriptor());
    let span = hub.start_access(|| panic!("unobservable access must stay lazy"));

    span.add_upload(10);
    span.add_download(20);
    span.finish(AccessOutcome::Success, None);
}

#[test]
fn negotiated_wire_version_is_added_to_completion() {
    let hub = TelemetryHub::new(descriptor());
    let mut events = hub.event_receiver();
    let mut span = hub.start_access(|| AccessStart {
        id: 0,
        timestamp_ms: 1,
        protocol: TrafficProtocol::Tcp,
        wire_version: None,
        flow_id: None,
        session_tag: None,
        client: None,
        path_peers: Vec::new(),
        target: "example:443".to_owned(),
        initial_uplink: Some(Carrier::TlsTcp),
        initial_downlink: Some(Carrier::TlsTcp),
        path: None,
    });
    span.set_wire_version(crate::protocol::ProtocolVersion::V2);
    span.finish(AccessOutcome::Success, None);

    let Ok(ServerMessage::AccessStart(start)) = events.try_recv() else {
        panic!("missing access start");
    };
    assert_eq!(start.wire_version, None);
    let Ok(ServerMessage::AccessFinish(finish)) = events.try_recv() else {
        panic!("missing access finish");
    };
    assert_eq!(
        finish.wire_version,
        Some(crate::protocol::ProtocolVersion::V2)
    );
}

#[test]
fn snapshot_contains_existing_transport_counters() {
    let hub = TelemetryHub::new(descriptor());
    let stats = Stats::default();
    stats.tcp_rx.store(42, Ordering::Relaxed);
    stats.link_tcp.store(2, Ordering::Relaxed);
    hub.capture_and_publish(&stats, 17);
    let snapshot = hub.snapshots.borrow().clone();
    assert_eq!(snapshot.tcp_logical_up, 42);
    assert_eq!(snapshot.tls_carriers_active, 2);
    assert_eq!(snapshot.ping_ms, 17);
}
