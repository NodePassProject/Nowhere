// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Certificate loading, hot reloading, and self-signed certificate helpers.

use std::fmt::Write;
use std::fs;
use std::io::BufReader;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::common::Logger;
use anyhow::{Context, Result, anyhow, bail};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};

pub(super) fn new_self_signed_cert()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("common::tls::new_self_signed_cert: failed to create certificate")?;
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    Ok((vec![cert.cert.into()], key.into()))
}

pub(crate) fn certificate_sha256(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    let mut fingerprint = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(fingerprint, "{byte:02x}").expect("writing to a String cannot fail");
    }
    fingerprint
}

#[derive(Debug)]
pub(super) struct ReloadingCertResolver {
    crt_file: String,
    key_file: String,
    provider: Arc<CryptoProvider>,
    cached: RwLock<CachedCert>,
    reload_interval: Duration,
    logger: Logger,
}

#[derive(Debug)]
struct CachedCert {
    cert: Arc<CertifiedKey>,
    last_reload: Instant,
}

impl ReloadingCertResolver {
    pub(super) fn new(
        crt_file: String,
        key_file: String,
        provider: Arc<CryptoProvider>,
        reload_interval: Duration,
        logger: Logger,
    ) -> Result<(Self, String)> {
        let cert = Arc::new(load_certified_key(&crt_file, &key_file, &provider)?);
        let fingerprint = certificate_sha256(&cert.cert[0]);
        Ok((
            Self {
                crt_file,
                key_file,
                provider,
                cached: RwLock::new(CachedCert {
                    cert,
                    last_reload: Instant::now(),
                }),
                reload_interval,
                logger,
            },
            fingerprint,
        ))
    }
}

impl ResolvesServerCert for ReloadingCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let should_reload = self
            .cached
            .read()
            .map(|c| c.last_reload.elapsed() >= self.reload_interval)
            .unwrap_or(false);

        if should_reload
            && let Ok(mut cached) = self.cached.write()
            && cached.last_reload.elapsed() >= self.reload_interval
        {
            match load_certified_key(&self.crt_file, &self.key_file, &self.provider) {
                Ok(new_cert) => {
                    self.logger.debug(format_args!(
                        "common::tls::resolve_server_cert: certificate reloaded: {}",
                        self.crt_file
                    ));
                    cached.cert = Arc::new(new_cert);
                }
                Err(err) => {
                    self.logger.error(format_args!(
                        "common::tls::resolve_server_cert: certificate reload failed: {err}"
                    ));
                }
            }
            cached.last_reload = Instant::now();
        }

        self.cached.read().ok().map(|c| c.cert.clone())
    }
}

fn load_certified_key(
    crt_file: &str,
    key_file: &str,
    provider: &CryptoProvider,
) -> Result<CertifiedKey> {
    let cert_bytes = fs::read(crt_file).with_context(|| {
        format!("common::tls::load_certified_key: failed to read certificate: {crt_file}")
    })?;
    let key_bytes = fs::read(key_file).with_context(|| {
        format!("common::tls::load_certified_key: failed to read private key: {key_file}")
    })?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
            .collect::<std::result::Result<_, _>>()
            .context("common::tls::load_certified_key: invalid PEM certificate")?;
    if certs.is_empty() {
        bail!("common::tls::load_certified_key: no certificates found");
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .context("common::tls::load_certified_key: invalid PEM private key")?
        .ok_or_else(|| anyhow!("common::tls::load_certified_key: no private keys found"))?;

    CertifiedKey::from_der(certs, key, provider)
        .context("common::tls::load_certified_key: failed to build certified key")
}
