// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Connection-bound authentication for TLS/TCP and QUIC carriers.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt};
use url::Url;

use super::util::decode_url_username;

pub const TLS_EXPORTER_LEN: usize = 32;
pub const AUTH_FRAME_LEN: usize = 16;
pub const AUTH_EXPORTER_LABEL: &[u8] = b"EXPORTER-Nowhere-nw3-Auth";
const AUTH_ROOT_SALT_LABEL: &[u8] = b"nowhere/nw3/auth-root";
pub type AuthKey = [u8; 32];
pub type TlsExporter = [u8; TLS_EXPORTER_LEN];
pub type AuthFrame = [u8; AUTH_FRAME_LEN];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthTransport {
    TlsTcp = 1,
    Quic = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionRole {
    Vector,
    Egress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    pub vector_key: AuthKey,
    pub egress_key: AuthKey,
}

impl Credentials {
    pub(crate) fn for_service(parsed_url: &Url, context: &str) -> Result<Self> {
        Self::from_shared_key(&Self::validated_shared_key(parsed_url, context)?)
    }

    pub(crate) fn validated_shared_key(parsed_url: &Url, context: &str) -> Result<Vec<u8>> {
        let shared_key = Self::decode_shared_key(parsed_url)
            .map_err(|error| anyhow::anyhow!("{context}: {error}; use nowhere generate-key"))?;
        if shared_key.len() != 32
            || !shared_key
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!(
                "{context}: shared key must be exactly 32 lowercase hexadecimal characters; use nowhere generate-key"
            );
        }
        Ok(shared_key)
    }

    pub fn new(parsed_url: &Url) -> Result<Self> {
        Self::for_service(
            parsed_url,
            match parsed_url.scheme() {
                "vector" => "Vector configuration",
                "egress" => "Egress configuration",
                "portal" => "Portal listener",
                _ => "Shared Key",
            },
        )
    }

    pub(crate) fn decode_shared_key(parsed_url: &Url) -> Result<Vec<u8>> {
        if parsed_url.password().is_some() {
            bail!("password credentials are not supported; put the shared key before '@'");
        }
        let shared_key = decode_url_username(parsed_url)?;
        if shared_key.is_empty() {
            bail!("missing shared key before '@'");
        }
        if shared_key.len() > u8::MAX as usize {
            bail!("shared key exceeds the 255-byte limit");
        }
        Ok(shared_key)
    }

    pub fn from_shared_key(shared_key: &[u8]) -> Result<Self> {
        if shared_key.is_empty() {
            bail!("missing shared key before '@'");
        }
        if shared_key.len() > u8::MAX as usize {
            bail!("shared key exceeds the 255-byte limit");
        }
        Ok(Self {
            vector_key: derive_key(shared_key, b"vector-authentication"),
            egress_key: derive_key(shared_key, b"egress-authentication"),
        })
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn derive_key(shared_key: &[u8], info: &[u8]) -> AuthKey {
    let salt = Sha256::digest(AUTH_ROOT_SALT_LABEL);
    let root = hmac_sha256(&salt, shared_key);
    let mut input = info.to_vec();
    input.push(1);
    hmac_sha256(&root, &input)
}

pub fn encode_auth_frame(
    key: AuthKey,
    transport: AuthTransport,
    exporter: &TlsExporter,
) -> AuthFrame {
    let mut input = [0; TLS_EXPORTER_LEN + 1];
    input[0] = transport as u8;
    input[1..].copy_from_slice(exporter);
    hmac_sha256(&key, &input)[..AUTH_FRAME_LEN]
        .try_into()
        .expect("fixed tag")
}

pub fn validate_auth_frame(
    frame: &[u8],
    credentials: &Credentials,
    transport: AuthTransport,
    exporter: &TlsExporter,
) -> Result<ConnectionRole> {
    if frame.len() != AUTH_FRAME_LEN {
        bail!("invalid authentication frame length");
    }
    let vector = encode_auth_frame(credentials.vector_key, transport, exporter);
    let egress = encode_auth_frame(credentials.egress_key, transport, exporter);
    let is_vector = bool::from(frame.ct_eq(&vector));
    let is_egress = bool::from(frame.ct_eq(&egress));
    match (is_vector, is_egress) {
        (true, false) => Ok(ConnectionRole::Vector),
        (false, true) => Ok(ConnectionRole::Egress),
        _ => bail!("invalid authentication tag or role"),
    }
}

pub async fn read_auth_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    credentials: &Credentials,
    transport: AuthTransport,
    exporter: &TlsExporter,
) -> Result<ConnectionRole> {
    let mut frame = [0; AUTH_FRAME_LEN];
    reader
        .read_exact(&mut frame)
        .await
        .context("failed to read authentication frame")?;
    validate_auth_frame(&frame, credentials, transport, exporter)
}

#[cfg(test)]
#[path = "../tests/protocol/auth.rs"]
mod tests;
