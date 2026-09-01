// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Runtime defaults and helpers for environment and URL-derived configuration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use percent_encoding::percent_decode_str;
use url::Url;

/// Sentinel value that lets the OS choose the outbound local address.
pub const DEFAULT_DIALER_IP: &str = "auto";
/// Default disabled Mbps limit for inbound and outbound relay directions.
pub const DEFAULT_RATE_LIMIT: i32 = 0;
/// Default interval for structured TUI telemetry snapshots.
pub const DEFAULT_TELEMETRY_INTERVAL: Duration = Duration::from_secs(1);
/// Fastest supported structured telemetry cadence.
pub const MIN_TELEMETRY_INTERVAL: Duration = Duration::from_millis(250);
/// Slowest supported structured telemetry cadence.
pub const MAX_TELEMETRY_INTERVAL: Duration = Duration::from_secs(60);
/// Default concurrent logical TCP flows per authenticated client session.
pub const DEFAULT_MAX_TCP_FLOWS: u32 = 1024;
/// Default concurrent logical UDP flows per authenticated client session.
pub const DEFAULT_MAX_UDP_FLOWS: usize = 256;

/// Parses the first value of each recognized URL query key without treating
/// `+` as a space. Unknown keys and later duplicates are ignored.
pub fn query_first(parsed_url: &Url, allowed: &[&str]) -> Result<HashMap<String, String>> {
    let mut values = HashMap::with_capacity(allowed.len());
    let Some(query) = parsed_url.query() else {
        return Ok(values);
    };
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let Ok(key) = decode_query_component(raw_key, "query key") else {
            continue;
        };
        if !allowed.contains(&key.as_str()) || values.contains_key(&key) {
            continue;
        }
        values.insert(key, decode_query_component(raw_value, "query value")?);
    }
    Ok(values)
}

/// Returns the first raw value for one decoded query key. Delimiters inside
/// the value remain percent-encoded so nested authority syntax stays safe.
pub(crate) fn first_raw_query_value<'a>(parsed_url: &'a Url, name: &str) -> Option<&'a str> {
    let query = parsed_url.query()?;
    query.split('&').find_map(|pair| {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        decode_query_component(raw_key, "query key")
            .is_ok_and(|key| key == name)
            .then_some(raw_value)
    })
}

fn decode_query_component(raw: &str, name: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                bail!("common::config::query_first: invalid percent encoding in {name}");
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    percent_decode_str(raw)
        .decode_utf8()
        .with_context(|| format!("common::config::query_first: invalid UTF-8 in {name}"))
        .map(|value| value.into_owned())
}

/// Reads a non-negative integer from the environment, falling back on invalid input.
pub fn env_int(name: &str, default_value: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(default_value)
}

/// Reads a duration from the environment using humantime syntax.
pub fn env_duration(name: &str, default_value: Duration) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|s| humantime::parse_duration(&s).ok())
        .unwrap_or(default_value)
}

/// Accepts only IP literals for the dialer bind address, or `auto`.
pub fn init_dialer_ip(value: Option<&str>) -> String {
    match value {
        Some(ip) if ip != DEFAULT_DIALER_IP && ip.parse::<IpAddr>().is_ok() => ip.to_string(),
        _ => DEFAULT_DIALER_IP.to_string(),
    }
}

/// Converts a Mbps value to bytes per second, preserving zero as "unlimited".
pub fn rate_limit_bytes_per_second(mbps: i32) -> u64 {
    if mbps <= 0 { 0 } else { mbps as u64 * 125_000 }
}

/// Maximum concurrent logical TCP flows in one authenticated client session.
pub fn max_tcp_flows() -> u32 {
    env_int("NOW_MAX_TCP_FLOWS", DEFAULT_MAX_TCP_FLOWS as i32) as u32
}

/// Maximum concurrent logical UDP flows in one authenticated client session.
pub fn max_udp_flows() -> usize {
    env_int("NOW_MAX_UDP_FLOWS", DEFAULT_MAX_UDP_FLOWS as i32).max(1) as usize
}

/// Per-direction TCP relay buffer size.
pub fn tcp_data_buf_size() -> usize {
    env_int("NOW_TCP_DATA_BUF_SIZE", 32 * 1024) as usize
}

/// UDP relay receive buffer size.
pub fn udp_data_buf_size() -> usize {
    env_int("NOW_UDP_DATA_BUF_SIZE", 64 * 1024) as usize
}

/// Timeout for outbound TCP target dials.
pub fn tcp_dial_timeout() -> Duration {
    env_duration("NOW_TCP_DIAL_TIMEOUT", Duration::from_secs(15))
}

/// Timeout for outbound UDP socket setup.
pub fn udp_dial_timeout() -> Duration {
    env_duration("NOW_UDP_DIAL_TIMEOUT", Duration::from_secs(15))
}

/// Grace period for draining the opposite TCP direction after one side closes.
pub fn tcp_read_timeout() -> Duration {
    env_duration("NOW_TCP_READ_TIMEOUT", Duration::from_secs(30))
}

/// Idle timeout for UDP flows.
pub fn udp_idle_timeout() -> Duration {
    env_duration("NOW_UDP_IDLE_TIMEOUT", Duration::from_secs(2 * 60))
}

/// Deadline for client authentication and first request setup.
pub fn handshake_timeout() -> Duration {
    env_duration("NOW_HANDSHAKE_TIMEOUT", Duration::from_secs(5))
}

/// Deadline for waiting for a logical flow to become ready.
pub fn flow_setup_timeout() -> Duration {
    env_duration("NOW_FLOW_SETUP_TIMEOUT", Duration::from_secs(20))
}

/// Deadline for preparing the primary route selected by a mixed carrier policy.
pub fn mix_fallback_timeout() -> Duration {
    env_duration("NOW_MIX_FALLBACK_TIMEOUT", Duration::from_secs(1))
}

/// Interval between event checkpoint log lines.
pub fn report_interval() -> Duration {
    env_duration("NOW_REPORT_INTERVAL", Duration::from_secs(5))
}

/// Reads and strictly validates the structured TUI telemetry cadence.
pub fn telemetry_interval() -> Result<Duration> {
    let raw = match std::env::var("NOW_TELEMETRY_INTERVAL") {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(raw)) => {
            bail!("NOW_TELEMETRY_INTERVAL is not valid Unicode: {raw:?}")
        }
    };
    parse_telemetry_interval(raw.as_deref())
}

fn parse_telemetry_interval(raw: Option<&str>) -> Result<Duration> {
    let value = match raw {
        Some(raw) => humantime::parse_duration(raw)
            .with_context(|| format!("invalid NOW_TELEMETRY_INTERVAL={raw:?}"))?,
        None => DEFAULT_TELEMETRY_INTERVAL,
    };
    if !(MIN_TELEMETRY_INTERVAL..=MAX_TELEMETRY_INTERVAL).contains(&value) {
        bail!(
            "NOW_TELEMETRY_INTERVAL must be in {}..={}",
            humantime::format_duration(MIN_TELEMETRY_INTERVAL),
            humantime::format_duration(MAX_TELEMETRY_INTERVAL)
        );
    }
    Ok(value)
}

/// Delay used by service-side retry paths.
pub fn service_cooldown() -> Duration {
    env_duration("NOW_SERVICE_COOLDOWN", Duration::from_secs(3))
}

/// Maximum time spent draining tasks during shutdown.
pub fn shutdown_timeout() -> Duration {
    env_duration("NOW_SHUTDOWN_TIMEOUT", Duration::from_secs(5))
}

/// Certificate reload polling interval for CA-trusted TLS mode.
pub fn reload_interval() -> Duration {
    env_duration("NOW_RELOAD_INTERVAL", Duration::from_secs(60 * 60))
}

#[cfg(test)]
#[path = "../tests/common/config.rs"]
mod tests;
