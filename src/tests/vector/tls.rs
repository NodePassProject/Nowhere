use super::*;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::common::certificate_sha256;
use crate::vector::config::VectorConfig;

fn vector_config(raw: &str) -> VectorConfig {
    VectorConfig::from_url(&url::Url::parse(raw).unwrap()).unwrap()
}

fn config(raw: &str) -> PortalClientConfig {
    vector_config(raw).portal_client_config()
}

#[tokio::test]
async fn client_prefers_fixed_v2_alpn() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = generated.cert.into();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let mut server =
        rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
    server.alpn_protocols = vec![b"nw2".to_vec(), b"now/1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        TlsAcceptor::from(Arc::new(server)).accept(stream).await
    });
    let raw = format!("vector://secret@{endpoint}?alpn=private/2&socks=127.0.0.1:1080");

    let (_, _, version) = ClientTls::new(&config(&raw))
        .unwrap()
        .connect_tcp(&endpoint.to_string(), "auto")
        .await
        .unwrap();
    assert_eq!(version, ProtocolVersion::V2);
    server_task.await.unwrap().unwrap();
}

#[test]
fn missing_sni_uses_unverified_policy() {
    let tls = ClientTls::new(&config(
        "vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080",
    ))
    .unwrap();
    assert_eq!(
        vector_config("vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080").sni,
        None
    );
    assert_eq!(tls.quic_server_name(), "127.0.0.1");
    tls.quic_client_config().unwrap();
}

#[test]
fn ipv6_authority_builds_an_ip_server_name() {
    let tls = ClientTls::new(&config("vector://secret@[::1]:2077?socks=127.0.0.1:1080")).unwrap();
    assert_eq!(tls.quic_server_name(), "::1");
}

#[test]
fn explicit_sni_enables_system_verification() {
    let config = config("vector://secret@127.0.0.1:2077?sni=example.com&socks=127.0.0.1:1080");
    let tls = ClientTls::new(&config).unwrap();
    assert_eq!(config.sni.as_deref(), Some("example.com"));
    assert_eq!(tls.quic_server_name(), "example.com");
}

#[derive(Clone, Copy)]
enum TestPin {
    Omitted,
    Empty,
    Exact,
    Uppercase,
    Invalid,
}

async fn test_pinned_handshake(pin: TestPin, sni: Option<&str>) -> Result<ProtocolVersion> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = generated.cert.into();
    let fingerprint = certificate_sha256(&certificate);
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let mut server =
        rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
    server.alpn_protocols = vec![b"now/1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        TlsAcceptor::from(Arc::new(server)).accept(stream).await
    });

    let pin = match pin {
        TestPin::Omitted => None,
        TestPin::Empty => Some(String::new()),
        TestPin::Exact => Some(fingerprint),
        TestPin::Uppercase => Some(fingerprint.to_ascii_uppercase()),
        TestPin::Invalid => Some("not-a-fingerprint".to_owned()),
    };
    let mut raw = format!("vector://secret@{endpoint}?");
    if let Some(sni) = sni {
        raw.push_str(&format!("sni={sni}&"));
    }
    if let Some(pin) = pin {
        raw.push_str(&format!("pin={pin}&"));
    }
    raw.push_str("socks=127.0.0.1:1080");

    let result = ClientTls::new(&config(&raw))?
        .connect_tcp(&endpoint.to_string(), "auto")
        .await
        .map(|(_, _, version)| version);
    let _ = tokio::time::timeout(Duration::from_secs(1), server_task).await;
    result
}

#[tokio::test]
async fn default_v1_tcp_server_is_detected() {
    assert_eq!(
        test_pinned_handshake(TestPin::Omitted, None).await.unwrap(),
        ProtocolVersion::V1
    );
}

async fn negotiate_quic(server_alpns: Vec<Vec<u8>>) -> Result<ProtocolVersion> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = generated.cert.into();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let mut rustls_server =
        rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
    rustls_server.alpn_protocols = server_alpns;
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server).unwrap();
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(quic_server)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        incoming.await
    });

    let raw = format!("vector://secret@{address}?socks=127.0.0.1:1080");
    let tls = ClientTls::new(&config(&raw))?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    client.set_default_client_config(tls.quic_client_config()?);
    let connection = client.connect(address, &tls.quic_server_name())?.await?;
    let version = quic_protocol_version(&connection)?;
    connection.close(quinn::VarInt::from_u32(0), b"");
    let _ = server_task.await;
    Ok(version)
}

#[tokio::test]
async fn quic_prefers_v2_and_falls_back_to_default_v1() {
    assert_eq!(
        negotiate_quic(vec![b"nw2".to_vec(), b"now/1".to_vec()])
            .await
            .unwrap(),
        ProtocolVersion::V2
    );
    assert_eq!(
        negotiate_quic(vec![b"now/1".to_vec()]).await.unwrap(),
        ProtocolVersion::V1
    );
    assert!(negotiate_quic(vec![b"private/2".to_vec()]).await.is_err());
}

#[tokio::test]
async fn exact_pin_overrides_sni_certificate_verification() {
    test_pinned_handshake(TestPin::Exact, Some("wrong.example"))
        .await
        .unwrap();
}

#[tokio::test]
async fn empty_or_omitted_pin_keeps_unverified_policy_without_sni() {
    test_pinned_handshake(TestPin::Omitted, None).await.unwrap();
    test_pinned_handshake(TestPin::Empty, None).await.unwrap();
}

#[tokio::test]
async fn wrong_or_uppercase_pin_fails_the_handshake() {
    assert!(
        test_pinned_handshake(TestPin::Invalid, Some("wrong.example"))
            .await
            .is_err()
    );
    assert!(
        test_pinned_handshake(TestPin::Uppercase, Some("wrong.example"))
            .await
            .is_err()
    );
}
