// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared TLS 1.3 client policy for Vector's TCP and QUIC carriers.

use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use quinn::Connection;
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    WebPkiSupportedAlgorithms, ring, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::common::{certificate_sha256, dial_tcp_from_local_ip, handshake_timeout};
use crate::protocol::{ProtocolVersion, SUPPORTED_ALPNS, TLS_EXPORTER_LEN, TlsExporter};

use super::config::PortalClientConfig;

pub(super) const EXPORTER_LABEL: &[u8] = b"EXPORTER-Nowhere-Auth";

/// Rustls configuration and identity shared by both client carrier types.
#[derive(Clone)]
pub(super) struct ClientTls {
    rustls: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
}

impl ClientTls {
    pub(super) fn new(config: &PortalClientConfig) -> Result<Self> {
        let provider = Arc::new(ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("vector::tls::ClientTls::new: failed to enable TLS 1.3")?;
        let mut client = if let Some(pin) = &config.pin {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCertificateVerification {
                    pin: pin.clone(),
                    algorithms: provider.signature_verification_algorithms,
                }))
                .with_no_client_auth()
        } else if config.sni.is_some() {
            let native = rustls_native_certs::load_native_certs();
            if !native.errors.is_empty() {
                bail!(
                    "vector::tls::ClientTls::new: system root loading failed: {:?}",
                    native.errors
                );
            }
            let mut roots = rustls::RootCertStore::empty();
            for certificate in native.certs {
                roots
                    .add(certificate)
                    .context("vector::tls::ClientTls::new: invalid system root")?;
            }
            if roots.is_empty() {
                bail!("vector::tls::ClientTls::new: no system trust roots available");
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {
                    schemes: provider
                        .signature_verification_algorithms
                        .supported_schemes(),
                }))
                .with_no_client_auth()
        };
        client.alpn_protocols = SUPPORTED_ALPNS.iter().map(|alpn| alpn.to_vec()).collect();
        client.enable_early_data = false;

        let server_name = ServerName::try_from(
            config
                .sni
                .as_deref()
                .unwrap_or(config.remote_host.as_str())
                .to_owned(),
        )
        .map_err(|_| anyhow!("vector::tls::ClientTls::new: invalid TLS server name"))?;
        Ok(Self {
            rustls: Arc::new(client),
            server_name,
        })
    }

    pub(super) fn quic_client_config(&self) -> Result<quinn::ClientConfig> {
        let quic_crypto = QuicClientConfig::try_from(self.rustls.clone())
            .map_err(|error| anyhow!("vector::tls::ClientTls::quic_client_config: {error}"))?;
        Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
    }

    pub(super) fn quic_server_name(&self) -> String {
        match &self.server_name {
            ServerName::DnsName(name) => name.as_ref().to_owned(),
            ServerName::IpAddress(address) => std::net::IpAddr::from(*address).to_string(),
            _ => self.server_name.to_str().into_owned(),
        }
    }

    pub(super) async fn connect_tcp(
        &self,
        endpoint: &str,
        dialer_ip: &str,
    ) -> Result<(TlsStream<TcpStream>, TlsExporter, ProtocolVersion)> {
        let stream = dial_tcp_from_local_ip(dialer_ip, endpoint, handshake_timeout())
            .await
            .with_context(|| format!("vector::tls::connect_tcp: failed to dial {endpoint}"))?;
        stream
            .set_nodelay(true)
            .context("vector::tls::connect_tcp: failed to set TCP_NODELAY")?;
        let connector = TlsConnector::from(self.rustls.clone());
        let tls = timeout(
            handshake_timeout(),
            connector.connect(self.server_name.clone(), stream),
        )
        .await
        .map_err(|_| anyhow!("vector::tls::connect_tcp: TLS handshake timeout"))?
        .context("vector::tls::connect_tcp: TLS handshake failed")?;
        let mut exporter = [0u8; TLS_EXPORTER_LEN];
        tls.get_ref()
            .1
            .export_keying_material(&mut exporter, EXPORTER_LABEL, Some(&[]))
            .context("vector::tls::connect_tcp: TLS exporter failed")?;
        let version = ProtocolVersion::from_alpn(tls.get_ref().1.alpn_protocol())
            .context("vector::tls::connect_tcp: invalid negotiated protocol")?;
        Ok((tls, exporter, version))
    }
}

pub(super) fn quic_protocol_version(connection: &Connection) -> Result<ProtocolVersion> {
    let handshake = connection
        .handshake_data()
        .ok_or_else(|| anyhow!("vector::tls: QUIC handshake data unavailable"))?
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow!("vector::tls: unexpected QUIC handshake data"))?;
    ProtocolVersion::from_alpn(handshake.protocol.as_deref())
        .context("vector::tls: invalid QUIC negotiated protocol")
}

#[derive(Clone)]
struct PinnedCertificateVerification {
    pin: String,
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedCertificateVerification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedCertificateVerification")
    }
}

impl ServerCertVerifier for PinnedCertificateVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if certificate_sha256(end_entity) != self.pin {
            return Err(rustls::Error::General(
                "server certificate pin mismatch".to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Clone)]
struct NoCertificateVerification {
    schemes: Vec<SignatureScheme>,
}

impl fmt::Debug for NoCertificateVerification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoCertificateVerification")
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(test)]
#[path = "../tests/vector/tls.rs"]
mod tests;
