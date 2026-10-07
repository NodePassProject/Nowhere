// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Toolbox utilities for keys, certificates, connectivity, and local status.

use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{flow_setup_timeout, handshake_timeout, shutdown_timeout};
use crate::protocol::{Carrier, Credentials, SetupResult, Target};
use crate::telemetry::{
    Hello, InstanceRole, ServerMessage, Subscription, TelemetryClient, TelemetryHub,
    TelemetrySnapshot, discover_instances,
};
use crate::transport::Stats;
use crate::tui::{bytes, duration_ms};
use crate::vector::{PortalClient, PortalClientConfig};

const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const STATUS_CONCURRENCY: usize = 8;

pub fn generate_key() -> Result<String> {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).context("failed to generate a random key")?;
    let mut hex = String::with_capacity(key.len() * 2);
    for byte in key {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(hex)
}

pub async fn fingerprint(url: Url) -> Result<()> {
    let config =
        PortalClientConfig::from_fingerprint_url(&url).context("invalid Nowhere share link")?;
    if config.tcp_endpoint().is_none() {
        bail!("fingerprint requires a TCP carrier in the Nowhere share link");
    }
    let fingerprint = crate::vector::fetch_certificate_fingerprint(&config)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to retrieve Portal TLS certificate: {}",
                connection_failure_reason(&error)
            )
        })?;
    println!("{fingerprint}");
    Ok(())
}

pub(crate) struct ToolboxClient {
    config: PortalClientConfig,
    credentials: Credentials,
}

pub(crate) struct ProbeReport {
    pub(crate) endpoint: String,
    pub(crate) target: String,
    pub(crate) uplink: &'static str,
    pub(crate) downlink: &'static str,
    pub(crate) elapsed: Duration,
    pub(crate) result: Result<SetupResult>,
    pub(crate) cleanup: Result<()>,
}

impl ToolboxClient {
    pub(crate) fn parse(url: &Url) -> Result<Self> {
        let (config, credentials) = PortalClientConfig::from_probe_url(url)?;
        Ok(Self {
            config,
            credentials,
        })
    }

    pub(crate) async fn probe(&self, target: Target) -> Result<ProbeReport> {
        let shutdown = CancellationToken::new();
        let client = PortalClient::new(
            self.config.clone(),
            &self.credentials,
            Arc::new(Stats::default()),
            false,
            TelemetryHub::for_current_process(
                InstanceRole::Vector,
                "toolbox",
                "toolbox",
                Duration::from_secs(1),
            ),
            shutdown,
        )?;
        let started = Instant::now();
        let opened = tokio::time::timeout(
            handshake_timeout() * 2 + flow_setup_timeout(),
            client.open_tcp(&target, 0),
        )
        .await;
        let elapsed = started.elapsed();
        let mut cleanup = Ok(());
        let (uplink, downlink, result) = match opened {
            Ok(Ok(tunnel)) => {
                let (uplink, downlink) = tunnel.carriers();
                cleanup = tokio::time::timeout(shutdown_timeout(), tunnel.close())
                    .await
                    .context("Flow close timeout")
                    .and_then(|result| result.map_err(Into::into));
                (
                    carrier_name(uplink),
                    carrier_name(downlink),
                    Ok(SetupResult::Ready),
                )
            }
            Ok(Err(error)) => {
                let result = error
                    .setup_result()
                    .map_or_else(|| Err(anyhow::anyhow!("{error:#}")), Ok);
                ("—", "—", result)
            }
            Err(_) => ("—", "—", Err(anyhow::anyhow!("Flow setup timeout"))),
        };
        if tokio::time::timeout(
            shutdown_timeout(),
            client.close(tokio::time::Instant::now() + shutdown_timeout()),
        )
        .await
        .is_err()
        {
            cleanup = Err(anyhow::anyhow!("client close timeout"));
        }
        Ok(ProbeReport {
            endpoint: self.config.endpoint(),
            target: target.to_string(),
            uplink,
            downlink,
            elapsed,
            result,
            cleanup,
        })
    }
}

fn carrier_name(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::TlsTcp => "TLS",
        Carrier::Quic => "QUIC",
    }
}

pub async fn probe(url: Url, raw_target: &str) -> Result<bool> {
    let target = raw_target
        .parse::<Target>()
        .context("invalid TCP target; expected host:port or [IPv6]:port")?;
    let client = parse_client(&url)?;
    let report = client.probe(target).await.map_err(|error| {
        anyhow::anyhow!(
            "failed to initialize Flow client: {}",
            connection_failure_reason(&error)
        )
    })?;
    let ready = matches!(report.result, Ok(SetupResult::Ready));
    let result = match &report.result {
        Ok(SetupResult::Ready) if report.cleanup.is_ok() => "OK".to_owned(),
        Ok(SetupResult::Ready) => "CLEANUP_FAILED".to_owned(),
        Ok(result) => setup_name(*result),
        Err(_) => "TRANSPORT_FAILED".to_owned(),
    };
    let rows = vec![
        ("Result", result.clone()),
        ("Portal", report.endpoint),
        ("Target", report.target),
        (
            "Route",
            if ready {
                format!("↑ {} · ↓ {}", report.uplink, report.downlink)
            } else {
                "—".to_owned()
            },
        ),
        ("Setup", format_duration(report.elapsed)),
    ];
    println!("{}", panel("NOWHERE PROBE", &rows));
    Ok(result == "OK")
}

pub async fn status() -> Result<()> {
    let discovered = discover_instances().context("failed to discover local instances")?;
    if discovered.is_empty() {
        println!(
            "{}",
            panel("NOWHERE STATUS", &[("Status", "IDLE".to_owned())])
        );
        return Ok(());
    }
    let semaphore = Arc::new(Semaphore::new(STATUS_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for instance in discovered {
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("status semaphore");
            (instance.pid, read_status(instance).await)
        });
    }
    let mut items = Vec::new();
    let mut failures = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((_, Ok(item))) => items.push(item),
            Ok((pid, Err(error))) => {
                failures.push(format!("PID {pid}: {}", connection_failure_reason(&error)))
            }
            Err(_) => failures.push("status task failed".to_owned()),
        }
    }
    items.sort_by_key(|item| (item.role, item.pid, item.id.clone()));
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("{}", status_panel(item));
    }
    if !failures.is_empty() {
        failures.sort();
        bail!(
            "{} local instance(s) could not be read: {}",
            failures.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

struct StatusItem {
    role: &'static str,
    pid: u32,
    id: String,
    lifecycle: String,
    endpoint: String,
    snapshot: TelemetrySnapshot,
}

async fn read_status(instance: crate::telemetry::DiscoveredInstance) -> Result<StatusItem> {
    tokio::time::timeout(STATUS_TIMEOUT, async {
        let client = TelemetryClient::connect(&instance, Subscription::Summary).await?;
        let hello = client.hello().clone();
        let (_, mut reader, _writer) = client.into_parts();
        loop {
            match reader.next_message().await? {
                ServerMessage::Snapshot(snapshot) => return Ok(status_item(hello, snapshot)),
                ServerMessage::Error { message } => {
                    bail!("telemetry rejected status: {message}")
                }
                _ => {}
            }
        }
    })
    .await
    .context("telemetry snapshot timed out")?
}

fn status_item(hello: Hello, snapshot: TelemetrySnapshot) -> StatusItem {
    let role = match hello.instance.role {
        InstanceRole::Portal => "PORTAL",
        InstanceRole::Vector => "VECTOR",
    };
    StatusItem {
        role,
        pid: hello.instance.pid,
        id: hello.instance.id,
        lifecycle: match hello.lifecycle.to_ascii_uppercase().as_str() {
            "STARTING" => "STARTING",
            "READY" | "RUNNING" => "READY",
            "DRAINING" | "STOPPING" => "DRAINING",
            "STOPPED" => "STOPPED",
            "FAILED" | "ERROR" => "FAILED",
            _ => "UNKNOWN",
        }
        .to_owned(),
        endpoint: crate::telemetry::display_endpoint(&hello.instance.endpoint),
        snapshot,
    }
}

fn status_panel(item: &StatusItem) -> String {
    let upload = item
        .snapshot
        .tcp_logical_up
        .saturating_add(item.snapshot.udp_logical_up);
    let download = item
        .snapshot
        .tcp_logical_down
        .saturating_add(item.snapshot.udp_logical_down);
    panel(
        &format!("{} · PID {}", item.role, item.pid),
        &[
            ("Status", item.lifecycle.clone()),
            ("Endpoint", item.endpoint.clone()),
            ("Uptime", duration_ms(item.snapshot.uptime_ms)),
            (
                "Flows",
                format!(
                    "TCP {} · UDP {}",
                    item.snapshot.tcp_active, item.snapshot.udp_active
                ),
            ),
            (
                "Carriers",
                format!(
                    "TLS {} · QUIC {}",
                    item.snapshot.tls_carriers_active, item.snapshot.quic_carriers_active
                ),
            ),
            (
                "Traffic",
                format!("↑ {} · ↓ {}", bytes(upload), bytes(download)),
            ),
        ],
    )
}

fn panel(title: &str, rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);
    let mut output = format!("{title}\n{}\n", "─".repeat(title.chars().count()));
    for (label, value) in rows {
        output.push_str(&format!("{label:>width$}  {value}\n"));
    }
    output.pop();
    output
}

fn setup_name(result: SetupResult) -> String {
    result.as_str().replace(' ', "_").to_ascii_uppercase()
}

fn format_duration(value: Duration) -> String {
    let milliseconds = value.as_secs_f64() * 1_000.0;
    if milliseconds < 10.0 {
        format!("{milliseconds:.1} ms")
    } else {
        format!("{milliseconds:.0} ms")
    }
}

fn parse_client(url: &Url) -> Result<ToolboxClient> {
    let query = crate::query_first(url, &["log"]).context("invalid configuration query")?;
    if !matches!(
        query.get("log").map(String::as_str),
        None | Some("none" | "debug" | "info" | "warn" | "error")
    ) {
        bail!("log must be none, debug, info, warn, or error");
    }
    ToolboxClient::parse(url).context("invalid Vector configuration")
}

fn connection_failure_reason(error: &anyhow::Error) -> String {
    let messages: Vec<_> = error.chain().map(ToString::to_string).collect();
    let stage = [
        (
            "common::util::dial_tcp_from_local_ip: failed to resolve target:",
            "DNS resolution failed",
        ),
        (
            "common::util::dial_tcp_from_local_ip: dial timeout",
            "TCP connection timed out",
        ),
        (
            "vector::tls::connect_tcp: TLS handshake timeout",
            "TLS/Morph handshake timed out",
        ),
        (
            "vector::tls::connect_tcp: invalid negotiated protocol",
            "Portal did not negotiate nw2 ALPN",
        ),
        (
            "vector::tls::ClientTls::new: system root loading failed:",
            "system CA loading failed",
        ),
        (
            "vector::tls::ClientTls::new: invalid system root",
            "invalid system CA certificate",
        ),
        (
            "vector::tls::ClientTls::new: no system trust roots available",
            "no system CA trust roots available",
        ),
        (
            "vector::tls::ClientTls::new: invalid TLS server name",
            "invalid TLS server name",
        ),
        (
            "Portal did not provide a TLS certificate",
            "Portal did not provide a TLS certificate",
        ),
        ("telemetry snapshot timed out", "IPC status read timed out"),
        ("telemetry: hello timed out", "IPC hello timed out"),
        (
            "telemetry: discovered registry disappeared",
            "IPC registry unavailable",
        ),
        (
            "telemetry: invalid discovered registry",
            "invalid IPC registry",
        ),
        (
            "telemetry: discovered registry identity mismatch",
            "IPC registry identity mismatch",
        ),
        (
            "telemetry: hello identity does not match discovered registry",
            "IPC service identity mismatch",
        ),
        (
            "telemetry: service rejected connection:",
            "IPC service rejected connection",
        ),
        (
            "telemetry rejected status:",
            "IPC service rejected status request",
        ),
        (
            "telemetry: service did not begin with hello",
            "invalid IPC hello",
        ),
        (
            "telemetry: failed to decode JSON frame",
            "invalid IPC message",
        ),
        ("telemetry: failed to read frame", "IPC message read failed"),
        (
            "telemetry: failed to write frame",
            "IPC subscription write failed",
        ),
        (
            "telemetry: timed out writing frame",
            "IPC subscription write timed out",
        ),
        ("partial frame timeout", "IPC message read timed out"),
        (
            "vector::tls::connect_tcp: TLS handshake failed",
            "TLS/Morph handshake failed",
        ),
        (
            "vector::tls::connect_tcp: TLS exporter failed",
            "TLS exporter failed",
        ),
        (
            "vector::tls::connect_tcp: failed to dial",
            "TCP connection failed",
        ),
        (
            "vector::PortalClient::new: failed to generate logical session ID:",
            "session randomness unavailable",
        ),
        (
            "vector::PortalClient::new: failed to build client TLS policy",
            "client TLS policy initialization failed",
        ),
    ]
    .into_iter()
    .find_map(|(prefix, reason)| {
        messages
            .iter()
            .any(|message| message.starts_with(prefix))
            .then_some(reason)
    })
    .unwrap_or("connection or local IPC failed");
    let detail = error.chain().find_map(|cause| {
        let tls_error = cause.downcast_ref::<rustls::Error>().or_else(|| {
            cause
                .downcast_ref::<std::io::Error>()?
                .get_ref()?
                .downcast_ref::<rustls::Error>()
        });
        if let Some(error) = tls_error {
            return Some(match error {
                rustls::Error::InvalidCertificate(_) => "certificate validation failed",
                rustls::Error::NoCertificatesPresented => "peer provided no certificate",
                rustls::Error::AlertReceived(_) => "peer sent a TLS alert",
                _ => "TLS protocol error",
            });
        }
        cause.downcast_ref::<std::io::Error>().and_then(|error| {
            use std::io::ErrorKind;
            match error.kind() {
                ErrorKind::ConnectionRefused => Some("connection refused"),
                ErrorKind::ConnectionReset => Some("connection reset"),
                ErrorKind::TimedOut => Some("operation timed out"),
                ErrorKind::PermissionDenied => Some("permission denied"),
                ErrorKind::NotFound => Some("endpoint or registry not found"),
                ErrorKind::UnexpectedEof => Some("peer closed the connection"),
                ErrorKind::BrokenPipe => Some("connection closed"),
                _ => None,
            }
        })
    });
    detail.map_or_else(|| stage.to_owned(), |detail| format!("{stage}: {detail}"))
}

#[cfg(test)]
#[path = "tests/toolbox.rs"]
mod tests;
