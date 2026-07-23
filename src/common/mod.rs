// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared configuration, logging, networking, and TLS utilities.

mod config;
mod datagram;
mod lifecycle;
mod logger;
mod network;
pub(crate) mod socks;
mod tls;

pub(crate) use config::env_positive_usize;
pub use config::{
    DEFAULT_DIALER_IP, DEFAULT_RATE_LIMIT, env_duration, env_int, flow_setup_timeout,
    handshake_timeout, init_dialer_ip, query_first, quic_max_streams, rate_limit_bytes_per_second,
    reload_interval, report_interval, service_cooldown, shutdown_timeout, tcp_data_buf_size,
    tcp_dial_timeout, tcp_read_timeout, udp_data_buf_size, udp_dial_timeout, udp_idle_timeout,
};
pub(crate) use datagram::{
    BudgetedDatagram, UdpDatagramSend, reserve_udp_budget, send_quic_udp_packet,
};
pub(crate) use lifecycle::{LifeMode, LifeReason, LifeState, Lifecycle, ShutdownSignals};
pub use logger::{LogLevel, Logger};
pub use network::{bind_udp_addrs, dial_tcp_from_local_ip, dial_udp_from_local_ip};
pub(crate) use socks::{OutboundDialer, SocksConfig};
pub(crate) use tls::certificate_sha256;
pub(crate) use tls::new_server_configs_with_reload_interval;
pub use tls::{TLSMode, new_server_configs};
