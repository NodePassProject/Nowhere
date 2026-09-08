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
    PortalRuntimeConfig::from_source(|name| Ok(values.get(name).cloned()))
}

#[test]
fn absent_values_use_the_existing_defaults() {
    let config = parse(&[]).unwrap();
    assert_eq!(config.udp_queue_bytes, DEFAULT_QUIC_UDP_QUEUE_BYTES);
    assert_eq!(config.tcp_data_buf_size, DEFAULT_TCP_DATA_BUF_SIZE);
    assert_eq!(config.udp_data_buf_size, DEFAULT_UDP_DATA_BUF_SIZE);
    assert_eq!(config.tcp_dial_timeout, DEFAULT_TCP_DIAL_TIMEOUT);
    assert_eq!(config.udp_dial_timeout, DEFAULT_UDP_DIAL_TIMEOUT);
    assert_eq!(config.tcp_read_timeout, DEFAULT_TCP_READ_TIMEOUT);
    assert_eq!(config.udp_idle_timeout, DEFAULT_UDP_IDLE_TIMEOUT);
    assert_eq!(config.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
    assert_eq!(config.report_interval, DEFAULT_REPORT_INTERVAL);
    assert_eq!(
        config.telemetry_interval,
        crate::common::DEFAULT_TELEMETRY_INTERVAL
    );
    assert_eq!(config.shutdown_timeout, DEFAULT_SHUTDOWN_TIMEOUT);
    assert_eq!(config.reload_interval, DEFAULT_RELOAD_INTERVAL);
    assert_eq!(config.flow_pair_timeout, DEFAULT_FLOW_PAIR_TIMEOUT);
}

#[test]
fn all_integer_limits_reject_zero_instead_of_falling_back() {
    for name in [
        "NOW_QUIC_UDP_QUEUE_BYTES",
        "NOW_TCP_DATA_BUF_SIZE",
        "NOW_UDP_DATA_BUF_SIZE",
    ] {
        let error = parse(&[(name, "0")]).unwrap_err().to_string();
        assert!(error.contains(name), "unexpected error for {name}: {error}");
    }
}

#[test]
fn removed_quic_specific_udp_limit_is_not_an_input() {
    assert_eq!(
        parse(&[("NOW_QUIC_MAX_UDP_FLOWS", "13")]).unwrap(),
        parse(&[]).unwrap()
    );
}

#[test]
fn all_durations_reject_zero_and_invalid_syntax() {
    for name in [
        "NOW_TCP_DIAL_TIMEOUT",
        "NOW_UDP_DIAL_TIMEOUT",
        "NOW_TCP_READ_TIMEOUT",
        "NOW_UDP_IDLE_TIMEOUT",
        "NOW_HANDSHAKE_TIMEOUT",
        "NOW_REPORT_INTERVAL",
        "NOW_TELEMETRY_INTERVAL",
        "NOW_SHUTDOWN_TIMEOUT",
        "NOW_RELOAD_INTERVAL",
        "NOW_FLOW_PAIR_TIMEOUT",
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
        ("NOW_QUIC_UDP_QUEUE_BYTES", "8192"),
        ("NOW_TCP_DATA_BUF_SIZE", "4096"),
        ("NOW_UDP_DATA_BUF_SIZE", "8192"),
        ("NOW_TCP_DIAL_TIMEOUT", "1100ms"),
        ("NOW_UDP_DIAL_TIMEOUT", "1200ms"),
        ("NOW_TCP_READ_TIMEOUT", "1300ms"),
        ("NOW_UDP_IDLE_TIMEOUT", "1400ms"),
        ("NOW_HANDSHAKE_TIMEOUT", "1500ms"),
        ("NOW_REPORT_INTERVAL", "1600ms"),
        ("NOW_TELEMETRY_INTERVAL", "1700ms"),
        ("NOW_SHUTDOWN_TIMEOUT", "1800ms"),
        ("NOW_RELOAD_INTERVAL", "1900ms"),
        ("NOW_FLOW_PAIR_TIMEOUT", "2s"),
    ])
    .unwrap();

    assert_eq!(config.udp_queue_bytes, 8192);
    assert_eq!(config.tcp_data_buf_size, 4096);
    assert_eq!(config.udp_data_buf_size, 8192);
    assert_eq!(config.tcp_dial_timeout, Duration::from_millis(1100));
    assert_eq!(config.udp_dial_timeout, Duration::from_millis(1200));
    assert_eq!(config.tcp_read_timeout, Duration::from_millis(1300));
    assert_eq!(config.udp_idle_timeout, Duration::from_millis(1400));
    assert_eq!(config.handshake_timeout, Duration::from_millis(1500));
    assert_eq!(config.report_interval, Duration::from_millis(1600));
    assert_eq!(config.telemetry_interval, Duration::from_millis(1700));
    assert_eq!(config.shutdown_timeout, Duration::from_millis(1800));
    assert_eq!(config.reload_interval, Duration::from_millis(1900));
    assert_eq!(config.flow_pair_timeout, Duration::from_secs(2));
}

#[test]
fn telemetry_interval_enforces_dashboard_bounds() {
    assert!(parse(&[("NOW_TELEMETRY_INTERVAL", "249ms")]).is_err());
    assert_eq!(
        parse(&[("NOW_TELEMETRY_INTERVAL", "250ms")])
            .unwrap()
            .telemetry_interval,
        Duration::from_millis(250)
    );
    assert_eq!(
        parse(&[("NOW_TELEMETRY_INTERVAL", "60s")])
            .unwrap()
            .telemetry_interval,
        Duration::from_secs(60)
    );
    assert!(parse(&[("NOW_TELEMETRY_INTERVAL", "60001ms")]).is_err());
}

#[test]
fn overflow_is_a_startup_error() {
    assert!(parse(&[("NOW_TCP_DATA_BUF_SIZE", "999999999999999999999999")]).is_err());
    assert!(parse(&[("NOW_HANDSHAKE_TIMEOUT", "999999999999999999999999h")]).is_err());
}

#[test]
fn removed_application_count_limits_are_ignored() {
    for name in [
        "NOW_MAX_TCP_FLOWS",
        "NOW_MAX_UDP_FLOWS",
        "NOW_MAX_PENDING_PAIRS",
    ] {
        for value in ["0", "1", "invalid"] {
            assert_eq!(parse(&[(name, value)]).unwrap(), parse(&[]).unwrap());
        }
    }
}
