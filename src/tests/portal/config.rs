// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal startup configuration snapshot tests.

use std::collections::HashMap;

use super::*;

fn parse(values: &[(&str, &str)]) -> anyhow::Result<PortalRuntimeConfig> {
    let values = values
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect::<HashMap<_, _>>();
    let mut source = |name: &str| Ok(values.get(name).cloned());
    let url = url::Url::parse("portal://0123456789abcdef0123456789abcdef@localhost:2000")?;
    let handshake_timeout = crate::common::read_handshake_timeout(&mut source, &url)?;
    PortalRuntimeConfig::from_source(source, handshake_timeout)
}

#[test]
fn absent_values_use_the_existing_defaults() {
    let config = parse(&[]).unwrap();
    assert_eq!(config.egress_tls_pending_max, 128);
    assert_eq!(config.egress_tls_idle_ttl, Duration::from_secs(120));
    assert_eq!(config.udp_queue_bytes, 4 * 1024 * 1024);
    assert_eq!(config.tcp_data_buf_size, DEFAULT_TCP_DATA_BUF_SIZE);
    assert_eq!(config.tcp_dial_timeout, DEFAULT_TCP_DIAL_TIMEOUT);
    assert_eq!(config.udp_dial_timeout, DEFAULT_UDP_DIAL_TIMEOUT);
    assert_eq!(config.tcp_read_timeout, DEFAULT_TCP_READ_TIMEOUT);
    assert_eq!(config.udp_idle_timeout, DEFAULT_UDP_IDLE_TIMEOUT);
    assert_eq!(config.handshake_timeout, Duration::from_millis(9100));
    assert_eq!(config.shutdown_timeout, DEFAULT_SHUTDOWN_TIMEOUT);
    assert_eq!(config.reload_interval, DEFAULT_RELOAD_INTERVAL);
}

#[test]
fn all_integer_limits_reject_zero_instead_of_falling_back() {
    for name in [
        "NOW_QUIC_UDP_QUEUE_BYTES",
        "NOW_TCP_DATA_BUF_SIZE",
        "NOW_PORTAL_TLS_IDLE_MAX",
    ] {
        let error = parse(&[(name, "0")]).unwrap_err().to_string();
        assert!(error.contains(name), "unexpected error for {name}: {error}");
    }
}

#[test]
fn all_durations_reject_zero_and_invalid_syntax() {
    for name in [
        "NOW_TCP_DIAL_TIMEOUT",
        "NOW_UDP_DIAL_TIMEOUT",
        "NOW_TCP_READ_TIMEOUT",
        "NOW_UDP_IDLE_TIMEOUT",
        "NOW_HANDSHAKE_TIMEOUT",
        "NOW_FLOW_SETUP_TIMEOUT",
        "NOW_SERVICE_COOLDOWN",
        "NOW_SHUTDOWN_TIMEOUT",
        "NOW_RELOAD_INTERVAL",
    ] {
        for value in ["0s", "invalid"] {
            let error = parse(&[(name, value)]).unwrap_err().to_string();
            assert!(error.contains(name), "unexpected error for {name}: {error}");
        }
    }
}

#[test]
fn values_are_parsed_once_into_typed_fields() {
    let config = parse(&[
        ("NOW_PORTAL_TLS_IDLE_MAX", "64"),
        ("NOW_QUIC_UDP_QUEUE_BYTES", "8192"),
        ("NOW_TCP_DATA_BUF_SIZE", "4096"),
        ("NOW_TCP_DIAL_TIMEOUT", "1100ms"),
        ("NOW_UDP_DIAL_TIMEOUT", "1200ms"),
        ("NOW_TCP_READ_TIMEOUT", "1300ms"),
        ("NOW_UDP_IDLE_TIMEOUT", "1400ms"),
        ("NOW_HANDSHAKE_TIMEOUT", "1500ms"),
        ("NOW_SHUTDOWN_TIMEOUT", "1800ms"),
        ("NOW_RELOAD_INTERVAL", "1900ms"),
    ])
    .unwrap();

    assert_eq!(config.egress_tls_pending_max, 64);
    assert_eq!(config.udp_queue_bytes, 8192);
    assert_eq!(config.tcp_data_buf_size, 4096);
    assert_eq!(config.tcp_dial_timeout, Duration::from_millis(1100));
    assert_eq!(config.udp_dial_timeout, Duration::from_millis(1200));
    assert_eq!(config.tcp_read_timeout, Duration::from_millis(1300));
    assert_eq!(config.udp_idle_timeout, Duration::from_millis(1400));
    assert_eq!(config.handshake_timeout, Duration::from_millis(1500));
    assert_eq!(config.shutdown_timeout, Duration::from_millis(1800));
    assert_eq!(config.reload_interval, Duration::from_millis(1900));
}

#[test]
fn overflow_is_a_startup_error() {
    assert!(parse(&[("NOW_TCP_DATA_BUF_SIZE", "999999999999999999999999")]).is_err());
    assert!(parse(&[("NOW_PORTAL_TLS_IDLE_MAX", "1024")]).is_err());
    assert!(parse(&[("NOW_HANDSHAKE_TIMEOUT", "999999999999999999999999h")]).is_err());
}

#[test]
fn unknown_environment_values_are_ignored() {
    for value in ["0", "1", "invalid"] {
        assert_eq!(
            parse(&[("NOW_UNKNOWN_OPTION", value)]).unwrap(),
            parse(&[]).unwrap()
        );
    }
}
