// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Versioned messages exchanged between a Nowhere service and local TUI clients.

use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::protocol::{Carrier, ProtocolVersion};

use super::process::{now_unix_ms, process_incarnation, process_uid};

/// Local telemetry generation, aligned with the Nowhere application major version.
pub(crate) const TELEMETRY_VERSION: u16 = 2;
/// Maximum accepted JSON payload, excluding the four-byte length prefix.
pub(crate) const MAX_FRAME_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstanceRole {
    Portal,
    Vector,
}

/// Non-secret metadata identifying a single process incarnation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct InstanceDescriptor {
    pub(crate) telemetry_version: u16,
    pub(crate) id: String,
    pub(crate) role: InstanceRole,
    pub(crate) pid: u32,
    pub(crate) uid: u32,
    pub(crate) incarnation: u64,
    pub(crate) version: String,
    pub(crate) endpoint: String,
    pub(crate) config_summary: String,
    pub(crate) telemetry_interval_ms: u64,
}

impl InstanceDescriptor {
    pub(crate) fn current(
        role: InstanceRole,
        endpoint: impl Into<String>,
        config_summary: impl Into<String>,
        telemetry_interval: Duration,
    ) -> Result<Self> {
        let pid = std::process::id();
        let uid = process_uid();
        let incarnation = process_incarnation(pid)?;
        Ok(Self {
            telemetry_version: TELEMETRY_VERSION,
            id: format!("{uid}:{pid}:{incarnation}"),
            role,
            pid,
            uid,
            incarnation,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint: endpoint.into(),
            config_summary: config_summary.into(),
            telemetry_interval_ms: telemetry_interval.as_millis().min(u64::MAX as u128) as u64,
        })
    }

    pub(crate) fn registry_name(&self) -> String {
        format!(
            "nowhere.{}.{}.{}.{}",
            TELEMETRY_VERSION, self.uid, self.pid, self.incarnation
        )
    }

    pub(super) fn unavailable(
        role: InstanceRole,
        endpoint: String,
        config_summary: String,
        telemetry_interval: Duration,
    ) -> Self {
        let pid = std::process::id();
        let uid = process_uid();
        Self {
            telemetry_version: TELEMETRY_VERSION,
            id: format!("{uid}:{pid}:unavailable"),
            role,
            pid,
            uid,
            incarnation: 0,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint,
            config_summary,
            telemetry_interval_ms: telemetry_interval.as_millis().min(u64::MAX as u128) as u64,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct TelemetrySnapshot {
    pub(crate) sequence: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) uptime_ms: u64,
    pub(crate) tcp_logical_up: u64,
    pub(crate) tcp_logical_down: u64,
    pub(crate) udp_logical_up: u64,
    pub(crate) udp_logical_down: u64,
    pub(crate) tls_wire_up: u64,
    pub(crate) tls_wire_down: u64,
    pub(crate) quic_wire_up: u64,
    pub(crate) quic_wire_down: u64,
    pub(crate) tcp_active: i64,
    pub(crate) udp_active: i64,
    pub(crate) tls_carriers_active: u64,
    pub(crate) quic_carriers_active: u64,
    pub(crate) ping_ms: u64,
    pub(crate) cpu_percent: Option<f64>,
    pub(crate) rss_bytes: Option<u64>,
    pub(crate) open_fds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrafficProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessOutcome {
    Success,
    Error,
    Timeout,
    Cancelled,
    Rejected,
}

/// Internal flow-start data. Carrier values are converted to stable strings
/// before crossing IPC so the data-plane protocol types stay unchanged.
#[derive(Clone, Debug)]
pub(crate) struct AccessStart {
    pub(crate) id: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) protocol: TrafficProtocol,
    pub(crate) wire_version: Option<ProtocolVersion>,
    pub(crate) flow_id: Option<u64>,
    pub(crate) session_tag: Option<String>,
    pub(crate) client: Option<String>,
    pub(crate) path_peers: Vec<String>,
    pub(crate) target: String,
    pub(crate) initial_uplink: Option<Carrier>,
    pub(crate) initial_downlink: Option<Carrier>,
    pub(crate) path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AccessStarted {
    pub(crate) id: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) protocol: TrafficProtocol,
    pub(crate) wire_version: Option<ProtocolVersion>,
    pub(crate) flow_id: Option<u64>,
    pub(crate) session_tag: Option<String>,
    pub(crate) client: Option<String>,
    #[serde(default)]
    pub(crate) path_peers: Vec<String>,
    pub(crate) target: String,
    pub(crate) initial_uplink: Option<String>,
    pub(crate) initial_downlink: Option<String>,
    pub(crate) path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AccessFinished {
    pub(crate) id: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) duration_ms: u64,
    pub(crate) protocol: TrafficProtocol,
    pub(crate) wire_version: Option<ProtocolVersion>,
    pub(crate) flow_id: Option<u64>,
    pub(crate) session_tag: Option<String>,
    pub(crate) client: Option<String>,
    #[serde(default)]
    pub(crate) path_peers: Vec<String>,
    pub(crate) target: String,
    pub(crate) initial_uplink: Option<String>,
    pub(crate) initial_downlink: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) upload_bytes: u64,
    pub(crate) download_bytes: u64,
    pub(crate) outcome: AccessOutcome,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeLevel {
    Info,
    Warn,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeKind {
    Lifecycle,
    Listener,
    Authentication,
    Session,
    Carrier,
    Mux,
    Backpressure,
    Datagram,
    Reconnect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RuntimeEvent {
    pub(crate) timestamp_ms: u64,
    pub(crate) level: RuntimeLevel,
    pub(crate) kind: RuntimeKind,
    pub(crate) message: String,
    pub(crate) client: Option<String>,
}

impl RuntimeEvent {
    pub(crate) fn new(level: RuntimeLevel, kind: RuntimeKind, message: impl Into<String>) -> Self {
        Self {
            timestamp_ms: now_unix_ms(),
            level,
            kind,
            message: message.into(),
            client: None,
        }
    }

    pub(crate) fn with_client(mut self, client: impl Into<String>) -> Self {
        self.client = Some(client.into());
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Subscription {
    Summary,
    Detail,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub(crate) enum ClientMessage {
    Subscribe { subscription: Subscription },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub(crate) enum ServerMessage {
    Hello(Hello),
    Snapshot(TelemetrySnapshot),
    Lifecycle(LifecycleSnapshot),
    RuntimeEvent(RuntimeEvent),
    AccessStart(AccessStarted),
    AccessFinish(AccessFinished),
    Gap { missed: u64 },
    Error { message: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Hello {
    pub(crate) instance: InstanceDescriptor,
    pub(crate) lifecycle: String,
    pub(crate) lifecycle_reason: String,
}

/// Latest process lifecycle state, delivered to both summary and detail
/// subscribers independently from the optional runtime-event stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LifecycleSnapshot {
    pub(crate) state: String,
    pub(crate) reason: String,
    pub(crate) timestamp_ms: u64,
}

impl Default for LifecycleSnapshot {
    fn default() -> Self {
        Self {
            state: "STARTING".to_owned(),
            reason: "STARTUP".to_owned(),
            timestamp_ms: now_unix_ms(),
        }
    }
}
