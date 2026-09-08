// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Immutable, startup-validated Portal runtime configuration.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::Semaphore;

use crate::common::{DEFAULT_TELEMETRY_INTERVAL, MAX_TELEMETRY_INTERVAL, MIN_TELEMETRY_INTERVAL};

use super::DEFAULT_QUIC_UDP_QUEUE_BYTES;

const DEFAULT_TCP_DATA_BUF_SIZE: usize = 32 * 1024;
const DEFAULT_UDP_DATA_BUF_SIZE: usize = 64 * 1024;
const DEFAULT_TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_UDP_DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_TCP_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REPORT_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_RELOAD_INTERVAL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_FLOW_PAIR_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PortalRuntimeConfig {
    pub(super) udp_queue_bytes: usize,
    pub(super) tcp_data_buf_size: usize,
    pub(super) udp_data_buf_size: usize,
    pub(super) tcp_dial_timeout: Duration,
    pub(super) udp_dial_timeout: Duration,
    pub(super) tcp_read_timeout: Duration,
    pub(super) udp_idle_timeout: Duration,
    pub(super) handshake_timeout: Duration,
    pub(super) report_interval: Duration,
    pub(super) telemetry_interval: Duration,
    pub(super) shutdown_timeout: Duration,
    pub(super) reload_interval: Duration,
    pub(super) flow_pair_timeout: Duration,
}

impl PortalRuntimeConfig {
    pub(super) fn from_env() -> Result<Self> {
        Self::from_source(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(value)) => {
                bail!("portal::config: {name} is not valid Unicode: {value:?}")
            }
        })
    }

    fn from_source<F>(mut source: F) -> Result<Self>
    where
        F: FnMut(&str) -> Result<Option<String>>,
    {
        let udp_queue_bytes = read_usize(
            &mut source,
            "NOW_QUIC_UDP_QUEUE_BYTES",
            DEFAULT_QUIC_UDP_QUEUE_BYTES,
            Semaphore::MAX_PERMITS.min(u32::MAX as usize),
        )?;
        let tcp_data_buf_size = read_usize(
            &mut source,
            "NOW_TCP_DATA_BUF_SIZE",
            DEFAULT_TCP_DATA_BUF_SIZE,
            isize::MAX as usize,
        )?;
        let udp_data_buf_size = read_usize(
            &mut source,
            "NOW_UDP_DATA_BUF_SIZE",
            DEFAULT_UDP_DATA_BUF_SIZE,
            isize::MAX as usize,
        )?;
        let tcp_dial_timeout = read_duration(
            &mut source,
            "NOW_TCP_DIAL_TIMEOUT",
            DEFAULT_TCP_DIAL_TIMEOUT,
        )?;
        let udp_dial_timeout = read_duration(
            &mut source,
            "NOW_UDP_DIAL_TIMEOUT",
            DEFAULT_UDP_DIAL_TIMEOUT,
        )?;
        let tcp_read_timeout = read_duration(
            &mut source,
            "NOW_TCP_READ_TIMEOUT",
            DEFAULT_TCP_READ_TIMEOUT,
        )?;
        let udp_idle_timeout = read_duration(
            &mut source,
            "NOW_UDP_IDLE_TIMEOUT",
            DEFAULT_UDP_IDLE_TIMEOUT,
        )?;
        quinn::IdleTimeout::try_from(udp_idle_timeout)
            .context("portal::config: NOW_UDP_IDLE_TIMEOUT exceeds QUIC implementation limit")?;
        let handshake_timeout = read_duration(
            &mut source,
            "NOW_HANDSHAKE_TIMEOUT",
            DEFAULT_HANDSHAKE_TIMEOUT,
        )?;
        let report_interval =
            read_duration(&mut source, "NOW_REPORT_INTERVAL", DEFAULT_REPORT_INTERVAL)?;
        let telemetry_interval = read_duration(
            &mut source,
            "NOW_TELEMETRY_INTERVAL",
            DEFAULT_TELEMETRY_INTERVAL,
        )?;
        if !(MIN_TELEMETRY_INTERVAL..=MAX_TELEMETRY_INTERVAL).contains(&telemetry_interval) {
            bail!(
                "portal::config: NOW_TELEMETRY_INTERVAL must be in {}..={}",
                humantime::format_duration(MIN_TELEMETRY_INTERVAL),
                humantime::format_duration(MAX_TELEMETRY_INTERVAL)
            );
        }
        let shutdown_timeout = read_duration(
            &mut source,
            "NOW_SHUTDOWN_TIMEOUT",
            DEFAULT_SHUTDOWN_TIMEOUT,
        )?;
        let reload_interval =
            read_duration(&mut source, "NOW_RELOAD_INTERVAL", DEFAULT_RELOAD_INTERVAL)?;
        let flow_pair_timeout = read_duration(
            &mut source,
            "NOW_FLOW_PAIR_TIMEOUT",
            DEFAULT_FLOW_PAIR_TIMEOUT,
        )?;

        Ok(Self {
            udp_queue_bytes,
            tcp_data_buf_size,
            udp_data_buf_size,
            tcp_dial_timeout,
            udp_dial_timeout,
            tcp_read_timeout,
            udp_idle_timeout,
            handshake_timeout,
            report_interval,
            telemetry_interval,
            shutdown_timeout,
            reload_interval,
            flow_pair_timeout,
        })
    }
}

fn read_usize<F>(source: &mut F, name: &str, default: usize, max: usize) -> Result<usize>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let Some(raw) = source(name)? else {
        return Ok(default);
    };
    let value = raw
        .parse::<usize>()
        .with_context(|| format!("portal::config: invalid {name}={raw:?}"))?;
    if value == 0 || value > max {
        bail!("portal::config: {name} must be in 1..={max}: {raw:?}");
    }
    Ok(value)
}

fn read_duration<F>(source: &mut F, name: &str, default: Duration) -> Result<Duration>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let Some(raw) = source(name)? else {
        return Ok(default);
    };
    let value = humantime::parse_duration(&raw)
        .with_context(|| format!("portal::config: invalid {name}={raw:?}"))?;
    if value.is_zero() {
        bail!("portal::config: {name} must be greater than zero: {raw:?}");
    }
    if tokio::time::Instant::now().checked_add(value).is_none()
        || std::time::Instant::now().checked_add(value).is_none()
    {
        bail!("portal::config: {name} exceeds timer implementation limit: {raw:?}");
    }
    Ok(value)
}

#[cfg(test)]
#[path = "../tests/portal/config.rs"]
mod tests;
