// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Transport support primitives for buffers, rate limits, and counters.

mod buffers;
mod morph;
mod owned_io;
mod quic;
mod quic_runtime;
mod rate;
mod stats;

pub(crate) use buffers::{BufferLease, Buffers, get_udp_buffer, reserve_bounded};
pub(crate) use morph::{
    AuthenticatedPrelude, ClientPrelude, MorphKeys, MorphTcpStream, UdpRole, configure_morph_mtu,
    morph_endpoint_config, validate_tcp_prelude_env, validate_udp_prelude_env,
    wrap_morph_client_udp_socket, wrap_morph_udp_socket,
};
pub(crate) use owned_io::{AsyncReadAny, AsyncWriteAny, read_with_flush};
pub(crate) use quic::transport_flow_control;
pub(crate) use quic_runtime::{QuicConnection, UdpRoute};
pub(crate) use rate::RateLimiter;
pub use stats::Stats;
