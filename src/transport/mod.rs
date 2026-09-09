// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Transport support primitives for buffers, rate limits, and counters.

mod buffers;
mod morph;
mod owned_io;
mod quic;
mod rate;
mod stats;

pub use buffers::{BufferLease, Buffers};
pub(crate) use owned_io::{
    AsyncReadAny, AsyncWriteAny, read_owned, read_owned_from, write_owned, write_owned_to,
};
pub(crate) use quic::{TransportFlowControl, transport_flow_control};
pub use rate::{RateLimiter, TokenBucket};
pub use stats::Stats;
