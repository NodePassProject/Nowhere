// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Runtime defaults and helpers for environment and URL-derived configuration.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::percent_decode_str;
use sha2::Sha256;
use tokio::sync::Semaphore;
use url::Url;

pub const DEFAULT_RATE_LIMIT: i32 = 0;
pub(crate) const EGRESS_TLS_IDLE_TTL: Duration = Duration::from_secs(120);

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
                bail!("invalid percent encoding in {name}");
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    percent_decode_str(raw)
        .decode_utf8()
        .with_context(|| format!("invalid UTF-8 in {name}"))
        .map(|value| value.into_owned())
}

pub fn env_int(name: &str, default_value: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(default_value)
}

pub(crate) fn env_value(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid Unicode"),
    }
}

pub(crate) fn read_quic_udp_queue_bytes<F>(source: &mut F) -> Result<usize>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let name = "NOW_QUIC_UDP_QUEUE_BYTES";
    let Some(raw) = source(name)? else {
        return Ok(4 * 1024 * 1024);
    };
    let max = Semaphore::MAX_PERMITS.min(u32::MAX as usize);
    let bytes = raw
        .parse::<usize>()
        .with_context(|| format!("invalid {name}={raw:?}"))?;
    if bytes == 0 || bytes > max {
        bail!("{name} must be in 1..={max}: {raw:?}");
    }
    Ok(bytes)
}

pub(crate) fn read_duration<F>(source: &mut F, name: &str, default: Duration) -> Result<Duration>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    let Some(raw) = source(name)? else {
        return Ok(default);
    };
    parse_duration(name, &raw)
}

fn parse_duration(name: &str, raw: &str) -> Result<Duration> {
    let value =
        humantime::parse_duration(raw).with_context(|| format!("invalid {name}={raw:?}"))?;
    if value.is_zero() {
        bail!("{name} must be greater than zero: {raw:?}");
    }
    if tokio::time::Instant::now().checked_add(value).is_none()
        || std::time::Instant::now().checked_add(value).is_none()
    {
        bail!("{name} exceeds timer implementation limit: {raw:?}");
    }
    if name == "NOW_UDP_IDLE_TIMEOUT" {
        quinn::IdleTimeout::try_from(value)
            .context("NOW_UDP_IDLE_TIMEOUT exceeds QUIC implementation limit")?;
    }
    Ok(value)
}

pub(crate) fn validate_timeout_env() -> Result<()> {
    validate_timeouts(&mut env_value)
}

pub(crate) fn validate_timeouts<F>(source: &mut F) -> Result<()>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    for name in [
        "NOW_TCP_DIAL_TIMEOUT",
        "NOW_UDP_DIAL_TIMEOUT",
        "NOW_TCP_READ_TIMEOUT",
        "NOW_UDP_IDLE_TIMEOUT",
        "NOW_HANDSHAKE_TIMEOUT",
        "NOW_FLOW_SETUP_TIMEOUT",
        "NOW_SHUTDOWN_TIMEOUT",
        "NOW_RELOAD_INTERVAL",
        "NOW_SERVICE_COOLDOWN",
    ] {
        if let Some(raw) = source(name)? {
            parse_duration(name, &raw)?;
        }
    }
    Ok(())
}

fn env_duration(name: &str, default_value: Duration) -> Duration {
    read_duration(&mut env_value, name, default_value)
        .expect("duration environment must be validated at startup")
}

pub fn rate_limit_bytes_per_second(mbps: i32) -> u64 {
    if mbps <= 0 { 0 } else { mbps as u64 * 125_000 }
}

pub fn tcp_data_buf_size() -> usize {
    env_int("NOW_TCP_DATA_BUF_SIZE", 32 * 1024) as usize
}

pub fn tcp_read_timeout() -> Duration {
    env_duration("NOW_TCP_READ_TIMEOUT", Duration::from_secs(30))
}

pub fn udp_idle_timeout() -> Duration {
    env_duration("NOW_UDP_IDLE_TIMEOUT", Duration::from_secs(2 * 60))
}

pub(crate) fn read_handshake_timeout<F>(source: &mut F, url: &Url) -> Result<Duration>
where
    F: FnMut(&str) -> Result<Option<String>>,
{
    if let Some(raw) = source("NOW_HANDSHAKE_TIMEOUT")? {
        return parse_duration("NOW_HANDSHAKE_TIMEOUT", &raw);
    }
    let shared_key = crate::protocol::Credentials::decode_shared_key(url)?;
    Ok(derive_handshake_timeout(&shared_key))
}

fn derive_handshake_timeout(shared_key: &[u8]) -> Duration {
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_key).expect("HMAC accepts any key length");
    mac.update(b"nowhere/handshake-timeout");
    let digest = mac.finalize().into_bytes();
    let value = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes"));
    Duration::from_millis(3000 + 100 * (value % 271))
}

pub fn flow_setup_timeout() -> Duration {
    env_duration("NOW_FLOW_SETUP_TIMEOUT", Duration::from_secs(20))
}

pub fn service_cooldown() -> Duration {
    env_duration("NOW_SERVICE_COOLDOWN", Duration::from_secs(3))
}

pub fn shutdown_timeout() -> Duration {
    env_duration("NOW_SHUTDOWN_TIMEOUT", Duration::from_secs(5))
}

#[cfg(test)]
#[path = "../tests/common/config.rs"]
mod tests;
