// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS Mux wire marker.

pub(crate) const MUX_MARKER: u8 = 0xff;

#[cfg(test)]
#[path = "../tests/common/alpn.rs"]
mod tests;
