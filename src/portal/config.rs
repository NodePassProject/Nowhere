// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Immutable, startup-validated Portal runtime configuration.

use std::time::Duration;

use anyhow::Result;

use crate::common::{
    env_value, read_duration, read_quic_udp_queue_bytes, read_tcp_data_buf_size, read_usize,
    validate_timeouts,
};

const DEFAULT_TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_UDP_DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_TCP_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_RELOAD_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortalRuntimeConfig {
    pub(crate) egress_tls_pending_max: usize,
    pub(crate) egress_tls_idle_ttl: Duration,
    pub(crate) udp_queue_bytes: usize,
    pub(crate) tcp_data_buf_size: usize,
    pub(crate) tcp_dial_timeout: Duration,
    pub(crate) udp_dial_timeout: Duration,
    pub(crate) tcp_read_timeout: Duration,
    pub(crate) udp_idle_timeout: Duration,
    pub(crate) handshake_timeout: Duration,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) reload_interval: Duration,
}

impl PortalRuntimeConfig {
    pub(crate) fn from_env(handshake_timeout: Duration) -> Result<Self> {
        Self::from_source(env_value, handshake_timeout)
    }

    fn from_source<F>(mut source: F, handshake_timeout: Duration) -> Result<Self>
    where
        F: FnMut(&str) -> Result<Option<String>>,
    {
        validate_timeouts(&mut source)?;
        let egress_tls_pending_max = read_usize(&mut source, "NOW_PORTAL_TLS_IDLE_MAX", 128, 1023)?;
        let udp_queue_bytes = read_quic_udp_queue_bytes(&mut source)?;
        let tcp_data_buf_size = read_tcp_data_buf_size(&mut source)?;
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
        let shutdown_timeout = read_duration(
            &mut source,
            "NOW_SHUTDOWN_TIMEOUT",
            DEFAULT_SHUTDOWN_TIMEOUT,
        )?;
        let reload_interval =
            read_duration(&mut source, "NOW_RELOAD_INTERVAL", DEFAULT_RELOAD_INTERVAL)?;

        Ok(Self {
            egress_tls_pending_max,
            egress_tls_idle_ttl: crate::common::EGRESS_TLS_IDLE_TTL,
            udp_queue_bytes,
            tcp_data_buf_size,
            tcp_dial_timeout,
            udp_dial_timeout,
            tcp_read_timeout,
            udp_idle_timeout,
            handshake_timeout,
            shutdown_timeout,
            reload_interval,
        })
    }
}

#[cfg(test)]
#[path = "../tests/portal/config.rs"]
mod tests;
