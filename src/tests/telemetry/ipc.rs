use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::telemetry::wire::InstanceDescriptor;
use crate::telemetry::{InstanceRole, RuntimeEvent, RuntimeKind, RuntimeLevel, TelemetrySnapshot};
use crate::transport::Stats;

fn parse_registry_name(name: &str) -> Option<DiscoveredInstance> {
    let mut components = name.split('.');
    if components.next()? != "nowhere" || components.next()? != "2" {
        return None;
    }
    let uid = components.next()?.parse().ok()?;
    let pid = components.next()?.parse().ok()?;
    let incarnation = components.next()?.parse().ok()?;
    if components.next().is_some() {
        return None;
    }
    Some(DiscoveredInstance {
        registry_name: name.to_owned(),
        uid,
        pid,
        incarnation,
    })
}

#[test]
fn parses_only_nowhere_2_registry_names() {
    assert_eq!(
        parse_registry_name("nowhere.2.1000.42.900"),
        Some(DiscoveredInstance {
            registry_name: "nowhere.2.1000.42.900".to_owned(),
            uid: 1000,
            pid: 42,
            incarnation: 900,
        })
    );
    assert!(parse_registry_name("nowhere.v2.1000.42.900").is_none());
    assert!(parse_registry_name("nowhere.2.1000.42").is_none());
    assert!(parse_registry_name("nowhere.2.1000.42.900.extra").is_none());
}

#[test]
fn nowhere_2_snapshot_round_trips_transport_counters() {
    let snapshot = TelemetrySnapshot {
        tls_carriers_active: 2,
        quic_carriers_active: 3,
        tcp_logical_up: 4,
        ..TelemetrySnapshot::default()
    };
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded: TelemetrySnapshot = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, snapshot);
}

#[tokio::test]
async fn framing_round_trips_and_rejects_oversize_lengths() {
    let (mut left, mut right) = tokio::io::duplex(MAX_FRAME_SIZE + 16);
    let message = ClientMessage::Subscribe {
        subscription: Subscription::Detail,
    };
    write_frame(&mut left, &message).await.unwrap();
    let mut framed = FrameReader::new(&mut right);
    let decoded: ClientMessage = framed.next().await.unwrap();
    assert_eq!(decoded, message);

    let (mut left, mut right) = tokio::io::duplex(16);
    left.write_u32((MAX_FRAME_SIZE + 1) as u32).await.unwrap();
    let mut framed = FrameReader::new(&mut right);
    let result = framed.next::<ClientMessage>().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn frame_reader_survives_cancelled_partial_reads() {
    let message = ClientMessage::Subscribe {
        subscription: Subscription::Detail,
    };
    let payload = serde_json::to_vec(&message).unwrap();
    let length = (payload.len() as u32).to_be_bytes();
    let (mut writer, reader) = tokio::io::duplex(MAX_FRAME_SIZE + 16);
    let mut framed = FrameReader::new(reader);

    writer.write_all(&length[..2]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), framed.next::<ClientMessage>())
            .await
            .is_err()
    );
    writer.write_all(&length[2..]).await.unwrap();
    writer.write_all(&payload[..1]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), framed.next::<ClientMessage>())
            .await
            .is_err()
    );
    writer.write_all(&payload[1..]).await.unwrap();

    assert_eq!(framed.next::<ClientMessage>().await.unwrap(), message);
}

#[tokio::test]
async fn slow_frame_writes_time_out() {
    let (mut writer, _reader) = tokio::io::duplex(1);
    let payload = vec![b'x'; 1_024];
    let result = write_payload_with_timeout(&mut writer, &payload, Duration::from_millis(10)).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timed out"));
}

#[tokio::test]
async fn multiple_clients_can_read_and_change_subscriptions() {
    let mut descriptor = InstanceDescriptor::current(
        InstanceRole::Portal,
        ":2077",
        "net=mix",
        Duration::from_secs(1),
    )
    .unwrap();
    // Unit tests share one process incarnation and run in parallel with
    // Portal runtime tests, so use a test-only registry identity.
    descriptor.incarnation = descriptor.incarnation.saturating_add(10_000_000);
    descriptor.id = format!(
        "{}:{}:{}",
        descriptor.uid, descriptor.pid, descriptor.incarnation
    );
    let discovered = DiscoveredInstance {
        registry_name: descriptor.registry_name(),
        uid: descriptor.uid,
        pid: descriptor.pid,
        incarnation: descriptor.incarnation,
    };
    let hub = TelemetryHub::new(descriptor);
    let shutdown = CancellationToken::new();
    let server = TelemetryServer::bind(hub.clone()).unwrap();
    let server_task = tokio::spawn(server.run(shutdown.clone()));

    let summary = TelemetryClient::connect(&discovered, Subscription::Summary)
        .await
        .unwrap();
    let detail = TelemetryClient::connect(&discovered, Subscription::Detail)
        .await
        .unwrap();
    let (_, mut summary_reader, mut summary_writer) = summary.into_parts();
    let (_, mut detail_reader, _detail_writer) = detail.into_parts();

    assert!(matches!(
        summary_reader.next_message().await.unwrap(),
        ServerMessage::Snapshot(_)
    ));
    assert!(matches!(
        detail_reader.next_message().await.unwrap(),
        ServerMessage::Snapshot(_)
    ));
    tokio::time::sleep(Duration::from_millis(10)).await;

    hub.set_lifecycle("READY", "LISTENING");
    let summary_lifecycle =
        tokio::time::timeout(Duration::from_secs(1), summary_reader.next_message())
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(
        summary_lifecycle,
        ServerMessage::Lifecycle(ref lifecycle)
            if lifecycle.state == "READY" && lifecycle.reason == "LISTENING"
    ));
    let detail_lifecycle = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let message = detail_reader.next_message().await?;
            if matches!(message, ServerMessage::Lifecycle(_)) {
                return Ok::<_, anyhow::Error>(message);
            }
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        detail_lifecycle,
        ServerMessage::Lifecycle(ref lifecycle)
            if lifecycle.state == "READY" && lifecycle.reason == "LISTENING"
    ));

    hub.emit_runtime(RuntimeEvent::new(
        RuntimeLevel::Info,
        RuntimeKind::Listener,
        "listener ready",
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), detail_reader.next_message())
            .await
            .unwrap()
            .unwrap(),
        ServerMessage::RuntimeEvent(_)
    ));

    hub.capture_and_publish(&Stats::default(), 0);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), summary_reader.next_message())
            .await
            .unwrap()
            .unwrap(),
        ServerMessage::Snapshot(_)
    ));

    summary_writer
        .subscribe(Subscription::Detail)
        .await
        .unwrap();
    let subscribed_event = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            hub.emit_runtime(RuntimeEvent::new(
                RuntimeLevel::Warn,
                RuntimeKind::Backpressure,
                "buffer pressure changed",
            ));
            if let Ok(message) =
                tokio::time::timeout(Duration::from_millis(25), summary_reader.next_message()).await
            {
                return message;
            }
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(subscribed_event, ServerMessage::RuntimeEvent(_)));

    shutdown.cancel();
    server_task.await.unwrap();
}
