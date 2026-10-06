// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared configuration, logging, networking, and TLS utilities.

mod alpn;
mod config;
mod datagram;
mod dial;
mod endpoint;
mod latency;
mod lifecycle;
mod logger;
mod network;
mod socks;
mod tls;

pub(crate) use alpn::MUX_MARKER;
pub(crate) use config::first_raw_query_value;
pub use config::{
    DEFAULT_RATE_LIMIT, DEFAULT_TELEMETRY_INTERVAL, MAX_TELEMETRY_INTERVAL, MIN_TELEMETRY_INTERVAL,
    env_int, flow_setup_timeout, handshake_timeout, mix_fallback_timeout, query_first,
    rate_limit_bytes_per_second, service_cooldown, shutdown_timeout, tcp_data_buf_size,
    tcp_read_timeout, telemetry_interval, udp_data_buf_size, udp_idle_timeout,
};
pub(crate) use datagram::{
    BudgetedDatagram, UdpDatagramSend, reserve_udp_budget, send_quic_udp_packet,
};
pub(crate) use dial::DialPolicy;
pub use endpoint::validate_endpoint_url_input;
pub(crate) use endpoint::{AddressFamily, CarrierEndpoint, ServiceEndpoint};
pub(crate) use latency::{LatencyGuard, LatencyTracker};
pub(crate) use lifecycle::{LifeReason, LifeState, ShutdownSignals};
pub use logger::{LogLevel, Logger};
pub use network::bind_udp_addrs;
pub(crate) use network::{
    dial_tcp_with_policy, dial_udp_with_policy, filter_addrs_for_family, resolve_bind_addrs,
};
pub(crate) use socks::{
    COMMAND_BIND, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, OutboundDialer, OutboundTcpStream,
    OutboundUdpSocket, REPLY_ADDRESS_NOT_SUPPORTED, REPLY_COMMAND_NOT_SUPPORTED,
    REPLY_CONNECTION_NOT_ALLOWED, REPLY_GENERAL_FAILURE, REPLY_HOST_UNREACHABLE,
    REPLY_NETWORK_UNREACHABLE, REPLY_SUCCEEDED, REPLY_TTL_EXPIRED, SocksAddress, SocksConfig,
    SocksCredentials, authenticate, decode_udp_packet, encode_udp_packet_into,
    first_raw_socks_value, format_host_port, parse_host_port, parse_socks_value, read_request,
    write_reply,
};
pub(crate) use tls::TLSMode;
pub(crate) use tls::certificate_sha256;
pub(crate) use tls::new_server_configs_with_reload_interval;
