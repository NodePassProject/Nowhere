// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared configuration, logging, networking, and TLS utilities.

mod config;
mod datagram;
mod dial;
mod endpoint;
mod lifecycle;
mod logger;
mod network;
mod socks;
mod tls;

pub use config::{
    DEFAULT_RATE_LIMIT, flow_setup_timeout, query_first, rate_limit_bytes_per_second,
    service_cooldown, shutdown_timeout, tcp_read_timeout, udp_idle_timeout,
};
pub(crate) use config::{
    EGRESS_TLS_IDLE_TTL, env_value, first_raw_query_value, read_duration, read_handshake_timeout,
    read_quic_udp_queue_bytes, read_tcp_data_buf_size, read_usize, validate_timeout_env,
    validate_timeouts,
};
pub(crate) use datagram::{
    BudgetedDatagram, UdpDatagramSend, reserve_udp_budget, send_quic_udp_packet,
};
pub(crate) use dial::DialPolicy;
pub use endpoint::validate_endpoint_url_input;
pub(crate) use endpoint::{AddressFamily, CarrierEndpoint, ServiceEndpoint};
pub(crate) use lifecycle::ShutdownSignals;
pub use logger::Logger;
pub use network::bind_udp_addrs;
pub(crate) use network::{
    configure_tcp_listener, dial_tcp_with_policy, dial_udp_with_policy, filter_addrs_for_family,
    is_normal_close, resolve_bind_addrs,
};
pub(crate) use socks::{
    COMMAND_BIND, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, OutboundDialer, OutboundUdpSocket,
    REPLY_ADDRESS_NOT_SUPPORTED, REPLY_COMMAND_NOT_SUPPORTED, REPLY_CONNECTION_NOT_ALLOWED,
    REPLY_GENERAL_FAILURE, REPLY_HOST_UNREACHABLE, REPLY_NETWORK_UNREACHABLE, REPLY_SUCCEEDED,
    SocksAddress, SocksConfig, SocksCredentials, authenticate, decode_udp_packet,
    encode_udp_packet_into, format_host_port, parse_host_port, parse_socks_value, read_request,
    write_reply,
};
pub(crate) use tls::{certificate_sha256, new_server_configs_with_reload_interval};
