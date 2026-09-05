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

/// Length of a TLS exporter used by the authentication protocol.
pub const TLS_EXPORTER_LEN: usize = 32;
/// Length of the truncated HMAC tag carried on the wire.
pub const AUTH_TAG_LEN: usize = 16;
/// Length of the fixed authentication frame.
pub const AUTH_FRAME_LEN: usize = SESSION_ID_LEN + AUTH_TAG_LEN;

const AUTH_ROOT_SALT_LABEL: &[u8] = b"nowhere/now/1/auth-root";
const AUTH_KEY_INFO: &[u8] = b"authentication";

/// Authentication key derived once from the configured shared key.
pub type AuthKey = [u8; 32];
/// TLS exporter bytes bound to one physical connection.
pub type TlsExporter = [u8; TLS_EXPORTER_LEN];
/// Complete fixed authentication frame.
pub type AuthFrame = [u8; AUTH_FRAME_LEN];

/// Physical carrier domain separator used by connection authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthTransport {
    /// TLS 1.3 over TCP.
    TlsTcp = 0x01,
    /// QUIC over UDP.
    Quic = 0x02,
}

/// Parsed credentials with the connection-independent key already derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    /// Read-only key used to authenticate physical connections.
    pub auth_key: AuthKey,
}

impl Credentials {
    /// Parses the shared key from the URL username and derives its auth key.
    pub fn new(parsed_url: &Url) -> Result<Self> {
        if parsed_url.password().is_some() {
            bail!("password credentials are not supported; put the shared key before '@'");
        }
        let shared_key = decode_url_username(parsed_url)?;
        Self::from_shared_key(&shared_key)
    }

    /// Derives credentials directly from non-empty shared-key bytes.
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

/// Derives the connection-independent auth key with HKDF-SHA256.
pub fn derive_auth_key(shared_key: &[u8]) -> AuthKey {
    let salt = Sha256::digest(AUTH_ROOT_SALT_LABEL);
    let auth_root = hmac_sha256(salt.as_ref(), shared_key);

    // The requested output is exactly one SHA-256 block, so HKDF-Expand is
    // HMAC(PRK, info || 0x01) without an allocation or expansion loop.
    let mut mac = Hmac::<Sha256>::new_from_slice(&auth_root).expect("HMAC accepts a 32-byte key");
    mac.update(AUTH_KEY_INFO);
    mac.update(&[1]);
    let bytes = mac.finalize().into_bytes();
    let mut auth_key = [0; 32];
    auth_key.copy_from_slice(&bytes);
    auth_key
}

/// Encodes a connection-bound authentication frame on the stack.
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

/// Validates a fixed authentication frame and returns its session ID.
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

/// Reads exactly one auth frame, leaving any immediately following flow bytes.
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
