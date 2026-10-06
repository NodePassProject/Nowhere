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
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).context("failed to generate a random key")?;
    let mut hex = String::with_capacity(key.len() * 2);
    for byte in key {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(hex)
}

pub async fn fingerprint(url: Url) -> Result<()> {
    let config = PortalClientConfig::from_fingerprint_url(&url).map_err(|_| {
        anyhow::anyhow!("invalid Portal URL; expected a concrete host and valid TLS/Morph options")
    })?;
    if config.tcp_endpoint().is_none() {
        bail!("fingerprint requires a TCP carrier in the Portal URL");
    }
    let fingerprint = crate::vector::fetch_certificate_fingerprint(&config)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "failed to retrieve Portal TLS certificate; check the endpoint and Morph key"
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
        .map_err(|_| anyhow::anyhow!("invalid TCP target; expected host:port or [IPv6]:port"))?;
    let client = parse_client(&url)?;
    let report = client
        .probe(target)
        .await
        .map_err(|_| anyhow::anyhow!("failed to initialize Flow client"))?;
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
            read_status(instance).await
        });
    }
    let mut items = Vec::new();
    let mut failures = 0;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(item)) => items.push(item),
            Ok(Err(_)) | Err(_) => failures += 1,
        }
    }
    items.sort_by_key(|item| (item.role, item.pid, item.id.clone()));
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("{}", status_panel(item));
    }
    if failures > 0 {
        bail!("{failures} local instance(s) could not be read");
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
    let query = crate::query_first(url, &["log"])
        .map_err(|_| anyhow::anyhow!("invalid configuration query"))?;
    if !matches!(
        query.get("log").map(String::as_str),
        None | Some("none" | "debug" | "info" | "warn" | "error")
    ) {
        bail!("log must be none, debug, info, warn, or error");
    }
    ToolboxClient::parse(url)
        .map_err(|_| anyhow::anyhow!("invalid Vector configuration or TLS policy"))
}

#[cfg(test)]
#[path = "tests/toolbox.rs"]
mod tests;
