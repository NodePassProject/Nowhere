// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Optional keyed wire transform below TLS and QUIC.

mod cipher;
mod policy;
mod prelude;
mod tcp;
mod udp;
mod udp_socket;

use std::{fmt, io};

use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;

pub(crate) use cipher::MorphCipher;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MorphGrade {
    Full,
    Core,
}

impl MorphGrade {
    fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value {
            None | Some("full") => Ok(Self::Full),
            Some("core") => Ok(Self::Core),
            Some(_) => anyhow::bail!("grade must be full or core"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Core => "core",
        }
    }
}

pub(crate) fn parse_morph(
    query: &std::collections::HashMap<String, String>,
) -> anyhow::Result<Option<(MorphGrade, MorphCipher)>> {
    let enabled = match query.get("morph").map(String::as_str) {
        None | Some("1") => true,
        Some("0") => false,
        Some(_) => anyhow::bail!("morph must be 0 or 1"),
    };
    let grade = MorphGrade::parse(query.get("grade").map(String::as_str))?;
    let cipher = MorphCipher::parse(query.get("cipher").map(String::as_str))?;
    Ok(enabled.then_some((grade, cipher)))
}

type MorphKeyBytes = [u8; 32];

#[derive(Clone)]
pub(crate) struct MorphKeys {
    cipher: MorphCipher,
    grade: MorphGrade,
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
    pub(crate) fn from_url(
        url: &url::Url,
        cipher: MorphCipher,
        grade: MorphGrade,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            cipher,
            grade,
            ..Self::derive(&crate::protocol::Credentials::decode_shared_key(url)?)
        })
    }

    pub(crate) fn effective_query(keys: Option<&Self>) -> String {
        match keys {
            Some(keys) => format!(
                "morph=1&grade={}&cipher={}",
                keys.grade.as_str(),
                keys.cipher.as_str()
            ),
            None => "morph=0".to_owned(),
        }
    }

    pub(crate) fn derive(shared_key: &[u8]) -> Self {
        let root = hmac_sha256(MORPH_ROOT_SALT, shared_key);
        Self {
            cipher: MorphCipher::ChaCha,
            grade: MorphGrade::Full,
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
