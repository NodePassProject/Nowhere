// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Optional keyed wire transform below TLS and QUIC.

use std::fmt;

use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;
const MORPH_ROOT_SALT: &[u8] = b"nowhere/morph";
const TCP_C2S_INFO: &[u8] = b"tcp c2s";
const TCP_S2C_INFO: &[u8] = b"tcp s2c";
const UDP_INFO: &[u8] = b"udp";

type MorphKey = [u8; 32];

#[derive(Clone)]
pub(crate) struct MorphKeys {
    tcp_c2s: MorphKey,
    tcp_s2c: MorphKey,
    udp: MorphKey,
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
            udp: hkdf_expand_one(root, UDP_INFO),
        }
    }

    pub(crate) fn udp_key(&self) -> MorphKey {
        self.udp
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> MorphKey {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand_one(root: MorphKey, info: &[u8]) -> MorphKey {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&root).expect("HMAC accepts a 32-byte key");
    mac.update(info);
    mac.update(&[1]);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
#[path = "../tests/transport/morph.rs"]
mod tests;
