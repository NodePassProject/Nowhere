// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Instance-local, category-separated pseudonyms. Keys never leave memory.

use anyhow::Result;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;

use super::wire::{RuntimeKind, RuntimeLevel};
use crate::protocol::Target;

const ALIAS_CAPACITY: usize = 4_096;

pub(crate) fn endpoint(value: &str) -> String {
    let address = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.to_owned()
    };
    if value.len() <= 512
        && !value.contains(['@', '?', '#', '%', '\\'])
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        && crate::common::validate_endpoint_url_input(&format!("portal://{address}"), "telemetry")
            .is_ok()
        && url::Url::parse(&format!("portal://{address}"))
            .ok()
            .and_then(|url| crate::common::ServiceEndpoint::parse(&url, true, "telemetry").ok())
            .is_some()
    {
        value.to_owned()
    } else {
        "<redacted>".to_owned()
    }
}

pub(crate) fn config_summary(value: &str) -> String {
    value
        .split_whitespace()
        .take(64)
        .filter_map(|token| {
            let (key, value) = token.split_once('=')?;
            let option = key.strip_prefix("next.").unwrap_or(key);
            let safe = match option {
                "listen" | "portal" | "socks" | "next" => {
                    if value == "none" {
                        value.to_owned()
                    } else {
                        endpoint(value)
                    }
                }
                "up" | "down" | "net" if matches!(value, "tcp" | "udp" | "mix") => value.to_owned(),
                "tls" if matches!(value, "0" | "1" | "2") => value.to_owned(),
                "mux" | "morph" if matches!(value, "0" | "1") => value.to_owned(),
                "rate" | "etar" => value.parse::<i32>().ok()?.to_string(),
                "dial" if value == "auto" || value.parse::<std::net::IpAddr>().is_ok() => {
                    value.to_owned()
                }
                "dial4" if value == "auto" || value.parse::<std::net::Ipv4Addr>().is_ok() => {
                    value.to_owned()
                }
                "dial6"
                    if value == "auto"
                        || value
                            .parse::<std::net::Ipv6Addr>()
                            .is_ok_and(|ip| ip.to_ipv4_mapped().is_none()) =>
                {
                    value.to_owned()
                }
                "sni"
                    if value.len() <= 253
                        && value
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')) =>
                {
                    value.to_owned()
                }
                "pin" => if value == "none" { "none" } else { "present" }.to_owned(),
                _ => return None,
            };
            Some(format!("{key}={safe}"))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn lifecycle_reason(value: &str) -> &str {
    match value {
        "STARTUP"
        | "LISTENING"
        | "SIGINT"
        | "SIGTERM"
        | "TCP_LISTENER_EXIT"
        | "QUIC_LISTENER_EXIT"
        | "SOCKS_LISTENER_EXIT"
        | "DRAINED"
        | "CLEANUP_COMPLETE"
        | "TIMEOUT"
        | "FORCED"
        | "START_FAILED"
        | "STATE_CHANGED" => value,
        _ => "STATE_CHANGED",
    }
}

#[derive(Default)]
struct Aliases {
    next: u64,
    values: HashMap<[u8; 32], u64>,
    order: VecDeque<[u8; 32]>,
}

pub(super) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| anyhow::anyhow!("telemetry entropy unavailable: {e}"))?;
    Ok(hex(&bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) struct Privacy {
    key: [u8; 32],
    clients: Mutex<Aliases>,
    peers: Mutex<Aliases>,
}
impl Privacy {
    pub(super) fn new() -> Result<Self> {
        let mut key = [0; 32];
        getrandom::fill(&mut key)
            .map_err(|e| anyhow::anyhow!("telemetry entropy unavailable: {e}"))?;
        Ok(Self {
            key,
            clients: Mutex::new(Aliases::default()),
            peers: Mutex::new(Aliases::default()),
        })
    }
    pub(super) fn alias(&self, category: &str, value: &str) -> String {
        let identity = if category == "client" {
            value
                .parse::<SocketAddr>()
                .map(|v| v.ip().to_string())
                .unwrap_or_else(|_| value.to_owned())
        } else {
            value.to_owned()
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("fixed key");
        mac.update(category.as_bytes());
        mac.update(&[0]);
        mac.update(identity.as_bytes());
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        let (prefix, aliases) = if category == "client" {
            ("C", &self.clients)
        } else {
            ("P", &self.peers)
        };
        let mut aliases = aliases.lock().unwrap_or_else(|e| e.into_inner());
        let id = if let Some(id) = aliases.values.get(&digest) {
            *id
        } else {
            if aliases.values.len() == ALIAS_CAPACITY {
                let oldest = aliases.order.pop_front().expect("full alias cache");
                aliases.values.remove(&oldest);
            }
            aliases.next += 1;
            let id = aliases.next;
            aliases.values.insert(digest, id);
            aliases.order.push_back(digest);
            id
        };
        format!("{prefix}{id:03}")
    }
}
impl Drop for Privacy {
    fn drop(&mut self) {
        for byte in &mut self.key {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

pub(super) fn target(value: &str) -> String {
    value
        .parse::<Target>()
        .map(|target| target.to_string())
        .unwrap_or_else(|_| "<redacted>".to_owned())
}

pub(super) fn error_reason(value: &str) -> &'static str {
    let lower = value
        .chars()
        .take(4096)
        .collect::<String>()
        .to_ascii_lowercase();
    if lower.contains("cert") && lower.contains("expired") {
        return "certificate expired";
    }
    match lower
        .strip_prefix("flow setup rejected: ")
        .unwrap_or(&lower)
    {
        "application closed" => return "application closed",
        "idle timeout" => return "idle timeout",
        "pair timeout" | "flow pairing timed out" => return "flow pairing timed out",
        "portal draining" | "service draining" => return "service draining",
        "dial failed" | "target connection failed" => return "target connection failed",
        "flow limit" => return "resource limit reached",
        "invalid request" => return "invalid request",
        "metadata conflict" => return "metadata conflict",
        "session replaced" => return "session replaced",
        "internal error" => return "internal error",
        "mux reader failure" => return "mux reader failure",
        "mux writer failure" => return "mux writer failure",
        "flow setup rejected" => return "flow setup rejected",
        "quic datagram route preparation failed" | "datagram route unavailable" => {
            return "datagram route unavailable";
        }
        _ => {}
    }
    for (patterns, reason) in [
        (
            &[
                "certificate expired",
                "certexpired",
                "certificate has expired",
                "expired certificate",
            ][..],
            "certificate expired",
        ),
        (
            &[
                "unknown issuer",
                "unknownissuer",
                "unknown ca",
                "unknown certificate issuer",
            ][..],
            "unknown certificate issuer",
        ),
        (
            &["certificate", "invalid peer", "pin mismatch"][..],
            "certificate verification failed",
        ),
        (
            &[
                "connection refused",
                "os error 111",
                "os error 61",
                "os error 10061",
            ][..],
            "connection refused",
        ),
        (
            &[
                "dns",
                "failed to lookup",
                "name or service not known",
                "no records",
                "resolve",
            ][..],
            "DNS lookup failed",
        ),
        (&["timed out", "timeout"][..], "connection timed out"),
        (
            &[
                "network unreachable",
                "network is unreachable",
                "no route to host",
            ][..],
            "network unreachable",
        ),
        (
            &["connection reset", "reset by peer"][..],
            "connection reset by peer",
        ),
        (&["broken pipe"][..], "broken pipe"),
        (&["unexpected eof", "early eof"][..], "unexpected EOF"),
        (
            &[
                "connection closed",
                "closed by peer",
                "application closed",
                "connection aborted",
            ][..],
            "connection closed",
        ),
        (
            &["authentication", "unauthorized", "invalid key"][..],
            "authentication failed",
        ),
        (
            &["resource limit", "too many", "limit exceeded"][..],
            "resource limit reached",
        ),
        (&["permission denied"][..], "permission denied"),
        (&["handshake"][..], "handshake failed"),
        (
            &["protocol", "invalid frame", "malformed"][..],
            "protocol error",
        ),
        (&["cancelled", "canceled"][..], "operation cancelled"),
    ] {
        if patterns.iter().any(|pattern| lower.contains(pattern)) {
            return reason;
        }
    }
    "operation failed"
}

pub(super) fn runtime_message(kind: RuntimeKind, level: RuntimeLevel, value: &str) -> String {
    const MESSAGES: &[&str] = &[
        "QUIC carrier connected",
        "QUIC carrier disconnected",
        "QUIC carrier replaced",
        "TLS/TCP carrier connected",
        "TLS/TCP carrier disconnected",
        "TLS mux carrier connected",
        "TLS mux carrier disconnected",
        "QUIC unauthenticated connection limit exceeded",
        "TCP unauthenticated connection limit exceeded",
        "SOCKS client resource limit reached",
        "SOCKS5 handshake timed out",
        "failed to send QUIC Retry",
        "TCP accept failed",
        "SOCKS accept failed",
        "QUIC TLS handshake failed",
        "QUIC authentication failed",
        "TLS/TCP authentication failed",
        "QUIC carrier stream loop closed",
        "TLS carrier connection failed",
        "QUIC carrier connection failed",
        "QUIC carrier stream open failed",
        "SOCKS5 handshake failed",
        "route failed before commit; retrying alternate carrier",
    ];
    let (template, detail) = value.split_once(": ").unwrap_or((value, ""));
    if MESSAGES.contains(&template) {
        return if detail.is_empty() {
            template.to_owned()
        } else {
            format!("{template}: {}", error_reason(detail))
        };
    }
    if value.starts_with("route ") {
        return format!(
            "route failed before commit; retrying alternate carrier: {}",
            error_reason(detail)
        );
    }
    if kind == RuntimeKind::Lifecycle
        && matches!(template, "STARTING" | "READY" | "DRAINING" | "STOPPED")
    {
        return if detail.is_empty() {
            template.to_owned()
        } else {
            format!("{template}: {}", lifecycle_reason(detail))
        };
    }
    let severity = match level {
        RuntimeLevel::Info => "update",
        RuntimeLevel::Warn => "warning",
        RuntimeLevel::Error => "failed",
    };
    format!("{kind:?} {severity}")
}
#[cfg(test)]
#[path = "../tests/telemetry/privacy.rs"]
mod tests;
