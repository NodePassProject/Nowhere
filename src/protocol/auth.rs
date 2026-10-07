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
use super::{SESSION_ID_LEN, SessionId};

pub const TLS_EXPORTER_LEN: usize = 32;
pub const AUTH_TAG_LEN: usize = 16;
pub const AUTH_FRAME_LEN: usize = SESSION_ID_LEN + AUTH_TAG_LEN;

const AUTH_ROOT_SALT_LABEL: &[u8] = b"nowhere/nw2/auth-root";
const AUTH_KEY_INFO: &[u8] = b"authentication";

pub type AuthKey = [u8; 32];
pub type TlsExporter = [u8; TLS_EXPORTER_LEN];
pub type AuthFrame = [u8; AUTH_FRAME_LEN];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthTransport {
    TlsTcp = 0x01,
    Quic = 0x02,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    pub auth_key: AuthKey,
}

impl Credentials {
    pub(crate) fn for_portal(parsed_url: &Url, context: &str) -> Result<Self> {
        let shared_key = Self::decode_shared_key(parsed_url)
            .map_err(|error| anyhow::anyhow!("{context}: {error}; use nowhere generate-key"))?;
        if !(32..=64).contains(&shared_key.len())
            || !shared_key
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!(
                "{context}: shared key must be 32–64 lowercase hexadecimal characters; use nowhere generate-key"
            );
        }
        Self::from_shared_key(&shared_key)
    }

    pub fn new(parsed_url: &Url) -> Result<Self> {
        if parsed_url.password().is_some() {
            bail!("password credentials are not supported; put the shared key before '@'");
        }
        let shared_key = Self::decode_shared_key(parsed_url)?;
        Self::from_shared_key(&shared_key)
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
            auth_key: derive_auth_key(shared_key),
        })
    }
}

pub fn derive_auth_key(shared_key: &[u8]) -> AuthKey {
    let salt = Sha256::digest(AUTH_ROOT_SALT_LABEL);
    let auth_root = hmac_sha256(salt.as_ref(), shared_key);

    let mut mac = Hmac::<Sha256>::new_from_slice(&auth_root).expect("HMAC accepts a 32-byte key");
    mac.update(AUTH_KEY_INFO);
    mac.update(&[1]);
    let bytes = mac.finalize().into_bytes();
    let mut auth_key = [0; 32];
    auth_key.copy_from_slice(&bytes);
    auth_key
}

pub fn encode_auth_frame(
    auth_key: AuthKey,
    transport: AuthTransport,
    exporter: &TlsExporter,
    session_id: SessionId,
) -> AuthFrame {
    let tag = authentication_tag(auth_key, transport, exporter, &session_id);
    let mut frame = [0; AUTH_FRAME_LEN];
    frame[..SESSION_ID_LEN].copy_from_slice(&session_id);
    frame[SESSION_ID_LEN..].copy_from_slice(&tag);
    frame
}

pub fn validate_auth_frame(
    frame: &[u8],
    auth_key: AuthKey,
    transport: AuthTransport,
    exporter: &TlsExporter,
) -> Result<SessionId> {
    if frame.len() != AUTH_FRAME_LEN {
        bail!("protocol::auth::validate_auth_frame: invalid authentication frame");
    }

    let mut session_id = [0; SESSION_ID_LEN];
    session_id.copy_from_slice(&frame[..SESSION_ID_LEN]);
    let expected = authentication_tag(auth_key, transport, exporter, &session_id);
    if !bool::from(frame[SESSION_ID_LEN..].ct_eq(&expected)) {
        bail!("protocol::auth::validate_auth_frame: invalid authentication frame");
    }
    Ok(session_id)
}

pub async fn read_auth_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    auth_key: AuthKey,
    transport: AuthTransport,
    exporter: &TlsExporter,
) -> Result<SessionId> {
    let mut frame = [0; AUTH_FRAME_LEN];
    reader
        .read_exact(&mut frame)
        .await
        .context("protocol::auth::read_auth_frame: failed to read authentication frame")?;
    validate_auth_frame(&frame, auth_key, transport, exporter)
}

fn authentication_tag(
    auth_key: AuthKey,
    transport: AuthTransport,
    exporter: &TlsExporter,
    session_id: &SessionId,
) -> [u8; AUTH_TAG_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(&auth_key).expect("HMAC accepts a 32-byte key");
    mac.update(&[transport as u8]);
    mac.update(exporter);
    mac.update(session_id);
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0; AUTH_TAG_LEN];
    tag.copy_from_slice(&bytes[..AUTH_TAG_LEN]);
    tag
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0; 32];
    output.copy_from_slice(&bytes);
    output
}

#[cfg(test)]
#[path = "../tests/protocol/auth.rs"]
mod tests;
