// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Normalized instance, event, navigation, and feed types.

use super::TelemetrySnapshot;

/// A stable identifier for one running Nowhere process.
pub type InstanceId = String;

/// The role of a monitored Nowhere process.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum InstanceRole {
    Portal,
    Vector,
    #[default]
    Unknown,
}

impl InstanceRole {
    pub const fn short(self) -> &'static str {
        match self {
            Self::Portal => "P",
            Self::Vector => "V",
            Self::Unknown => "?",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Portal => "Portal",
            Self::Vector => "Vector",
            Self::Unknown => "Unknown",
        }
    }
}

/// Coarse lifecycle state used for status styling.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Lifecycle {
    Starting,
    Ready,
    Draining,
    Stopped,
    Failed,
    #[default]
    Unknown,
    Other(String),
}

impl Lifecycle {
    pub fn label(&self) -> &str {
        match self {
            Self::Starting => "STARTING",
            Self::Ready => "READY",
            Self::Draining => "DRAINING",
            Self::Stopped => "STOPPED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
            Self::Other(value) => value,
        }
    }

    pub fn from_label(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "STARTING" => Self::Starting,
            "READY" | "RUNNING" => Self::Ready,
            "DRAINING" | "STOPPING" => Self::Draining,
            "STOPPED" => Self::Stopped,
            "FAILED" | "ERROR" => Self::Failed,
            "UNKNOWN" => Self::Unknown,
            _ => Self::Other(value.to_owned()),
        }
    }
}

/// Instance metadata normalized from IPC.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstanceMeta {
    pub id: InstanceId,
    pub role: InstanceRole,
    pub pid: u32,
    pub uid: u32,
    pub version: String,
    pub endpoint: String,
    pub config_summary: String,
    pub telemetry_interval_ms: u64,
    pub telemetry_version: u16,
}

/// Runtime event severity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// A structured, non-periodic process event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeRecord {
    pub timestamp_ms: u64,
    pub level: EventLevel,
    pub kind: String,
    pub message: String,
    pub client: Option<String>,
}

/// Start or completion of one access.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AccessPhase {
    #[default]
    Start,
    Finish,
}

/// Compact completion state shown by the access feed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessStatus {
    Success,
    Ended,
    Error,
    Timeout,
    Rejected,
}

/// A structured access-path record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessRecord {
    pub timestamp_ms: u64,
    pub event_id: u64,
    pub phase: AccessPhase,
    pub protocol: String,
    pub wire_version: Option<String>,
    pub session_tag: Option<String>,
    pub client: Option<String>,
    pub path_peers: Vec<String>,
    pub route: String,
    pub target: Option<String>,
    pub status: Option<AccessStatus>,
    pub message: Option<String>,
    pub duration_ms: Option<u64>,
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
}

/// Messages accepted by the view model.
#[derive(Clone, Debug, PartialEq)]
pub enum UiEvent {
    Upsert {
        meta: InstanceMeta,
        lifecycle: Lifecycle,
        snapshot: Option<TelemetrySnapshot>,
    },
    Snapshot {
        id: InstanceId,
        snapshot: TelemetrySnapshot,
    },
    Lifecycle {
        id: InstanceId,
        lifecycle: Lifecycle,
    },
    Runtime {
        id: InstanceId,
        record: RuntimeRecord,
    },
    Access {
        id: InstanceId,
        record: AccessRecord,
    },
    Gap {
        id: InstanceId,
        missed: u64,
    },
    Offline {
        id: InstanceId,
    },
    Error {
        id: Option<InstanceId>,
        message: String,
    },
}

/// Which log is focused for scrolling, pausing, and clearing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FeedKind {
    #[default]
    Access,
    Runtime,
}

/// Keyboard focus for directional navigation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Focus {
    #[default]
    Instances,
    Feed,
}

/// Top-level TUI workspace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Page {
    #[default]
    Overview,
    Logs,
}

impl Page {
    pub const ALL: [Self; 2] = [Self::Overview, Self::Logs];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Logs => "Logs",
        }
    }
}
