// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Optional keyed wire transform below TLS and QUIC.

mod policy;
mod prelude;
mod tcp;
mod udp;
mod udp_socket;

use std::{fmt, io};

use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;

pub(crate) use prelude::{AuthenticatedPrelude, ClientPrelude};
pub(crate) use tcp::{MorphTcpStream, validate_tcp_prelude_env};
pub(crate) use udp::{
    UdpRole, configure_morph_mtu, morph_endpoint_config, validate_udp_prelude_env,
    wrap_morph_client_udp_socket, wrap_morph_udp_socket,
};

const NONCE_LEN: usize = 12;
const TCP_PRELUDE_LEN: usize = 64;
const UDP_PRELUDE_LEN: usize = 12;
const MORPH_ROOT_SALT: &[u8] = b"nowhere/nw3/morph";
const TCP_C2S_INFO: &[u8] = b"tcp c2s";
const TCP_S2C_INFO: &[u8] = b"tcp s2c";
const UDP_C2S_INFO: &[u8] = b"udp c2s";
const UDP_S2C_INFO: &[u8] = b"udp s2c";
const TCP_PRELUDE_AUTH_INFO: &[u8] = b"tcp prelude auth";
const TCP_PRELUDE_MASK_INFO: &[u8] = b"tcp prelude mask";

type MorphKeyBytes = [u8; 32];

#[derive(Clone)]
pub(crate) struct MorphKeys {
    tcp_c2s: MorphKeyBytes,
    tcp_s2c: MorphKeyBytes,
    udp_c2s: MorphKeyBytes,
    udp_s2c: MorphKeyBytes,
    tcp_prelude_auth: MorphKeyBytes,
    tcp_prelude_mask: MorphKeyBytes,
}

impl fmt::Debug for MorphKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MorphKeys(REDACTED)")
    }
}

impl MorphKeys {
    pub(crate) fn from_url(url: &url::Url) -> anyhow::Result<Self> {
        Ok(Self::derive(
            &crate::protocol::Credentials::decode_shared_key(url)?,
        ))
    }

    pub(crate) fn derive(shared_key: &[u8]) -> Self {
        let root = hmac_sha256(MORPH_ROOT_SALT, shared_key);
        Self {
            tcp_c2s: hkdf_expand_one(root, TCP_C2S_INFO),
            tcp_s2c: hkdf_expand_one(root, TCP_S2C_INFO),
            udp_c2s: hkdf_expand_one(root, UDP_C2S_INFO),
            udp_s2c: hkdf_expand_one(root, UDP_S2C_INFO),
            tcp_prelude_auth: hkdf_expand_one(root, TCP_PRELUDE_AUTH_INFO),
            tcp_prelude_mask: hkdf_expand_one(root, TCP_PRELUDE_MASK_INFO),
        }
    }

    pub(crate) fn udp_keys(&self) -> (MorphKeyBytes, MorphKeyBytes) {
        (self.udp_c2s, self.udp_s2c)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> MorphKeyBytes {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand_one(root: MorphKeyBytes, info: &[u8]) -> MorphKeyBytes {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&root).expect("HMAC accepts a 32-byte key");
    mac.update(info);
    mac.update(&[1]);
    mac.finalize().into_bytes().into()
}

fn exhausted() -> io::Error {
    io::Error::other("Morph ChaCha20 keystream exhausted")
}

#[cfg(test)]
#[path = "../tests/transport/morph.rs"]
mod tests;
