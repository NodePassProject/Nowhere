// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS mode parsing and server configuration construction.

#[path = "tls_cert.rs"]
mod tls_cert;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::crypto::ring;
use url::Url;

pub(crate) use self::tls_cert::certificate_sha256;
use self::tls_cert::{ReloadingCertResolver, new_self_signed_cert};
use super::{Logger, query_first, reload_interval};

const PORTAL_QUERY_PARAMETERS: &[&str] = &[
    "log", "net", "tls", "crt", "key", "alpn", "rate", "etar", "dial", "socks",
];

/// TLS mode selected by the `tls` URL query parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TLSMode {
    /// Parsed `tls=0`; currently rejected before server configuration is built.
    None,
    /// Generate an in-memory self-signed certificate.
    SelfSigned,
    /// Load a certificate and key from `crt` and `key` URL query parameters.
    CATrusted,
}

impl fmt::Display for TLSMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("0"),
            Self::SelfSigned => f.write_str("1"),
            Self::CATrusted => f.write_str("2"),
        }
    }
}

/// Builds rustls and QUIC TLS server configuration for the effective ALPN.
pub fn new_server_configs(
    parsed_url: &Url,
    alpn: &str,
    logger: Logger,
) -> Result<(TLSMode, Arc<rustls::ServerConfig>, quinn::ServerConfig)> {
    new_server_configs_with_reload_interval(parsed_url, alpn, reload_interval(), logger)
}

pub(crate) fn new_server_configs_with_reload_interval(
    parsed_url: &Url,
    alpn: &str,
    reload_interval: Duration,
    logger: Logger,
) -> Result<(TLSMode, Arc<rustls::ServerConfig>, quinn::ServerConfig)> {
    let query = query_first(parsed_url, PORTAL_QUERY_PARAMETERS)?;
    let mode = match query.get("tls").map(String::as_str) {
        None => TLSMode::SelfSigned,
        Some("0") => TLSMode::None,
        Some("1") => TLSMode::SelfSigned,
        Some("2") => TLSMode::CATrusted,
        _ => bail!("common::tls::new_server_configs: invalid tls mode"),
    };

    if mode == TLSMode::None {
        bail!("common::tls::new_server_configs: tls=1 or tls=2 required");
    }

    let provider = Arc::new(ring::default_provider());
    let server_builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("common::tls::new_server_configs: failed to configure TLS versions")?
        .with_no_client_auth();

    let (mut server_crypto, cert_sha256) = match mode {
        TLSMode::SelfSigned => {
            let (certs, key) = new_self_signed_cert()
                .context("common::tls::new_server_configs: failed to create self-signed config")?;
            let cert_sha256 = certificate_sha256(&certs[0]);
            let server_crypto = server_builder
                .with_single_cert(certs, key)
                .context("common::tls::new_server_configs: failed to parse key pair")?;
            (server_crypto, cert_sha256)
        }
        TLSMode::CATrusted => {
            let crt_file = query.get("crt").cloned().unwrap_or_default();
            let key_file = query.get("key").cloned().unwrap_or_default();
            let (resolver, cert_sha256) = ReloadingCertResolver::new(
                crt_file,
                key_file,
                provider,
                reload_interval,
                logger.clone(),
            )
            .context("common::tls::new_server_configs: failed to load certificate")?;
            (
                server_builder.with_cert_resolver(Arc::new(resolver)),
                cert_sha256,
            )
        }
        TLSMode::None => unreachable!(),
    };

    server_crypto.max_early_data_size = 0;
    server_crypto.send_half_rtt_data = false;
    server_crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    let quic_crypto = QuicServerConfig::try_from(server_crypto.clone())
        .map_err(|e| anyhow!("common::tls::new_server_configs: QUIC TLS config failed: {e}"))?;
    logger.event(format_args!("CERT_SHA256|{cert_sha256}"));
    Ok((
        mode,
        Arc::new(server_crypto),
        quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)),
    ))
}

#[cfg(test)]
#[path = "../tests/common/tls.rs"]
mod tests;
