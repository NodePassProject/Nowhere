// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS verifier selection and certificate validation tests.

use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::common::certificate_sha256;
use crate::vector::config::VectorConfig;

use super::*;

fn vector_config(raw: &str) -> VectorConfig {
    VectorConfig::from_url(&url::Url::parse(raw).unwrap()).unwrap()
}

fn config(raw: &str) -> PortalClientConfig {
    vector_config(raw).portal_client_config()
}

#[tokio::test]
async fn client_prefers_fixed_nw3_alpn() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = generated.cert.into();
    let pin = certificate_sha256(&certificate);
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
    server.alpn_protocols = vec![b"nw3".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        TlsAcceptor::from(Arc::new(server)).accept(stream).await
    });
    let raw = format!(
        "vector://0123456789abcdef0123456789abcdef@{endpoint}?morph=0&unknown=ignored&pin={pin}&in=127.0.0.1:1080"
    );

    let (stream, _) = ClientTls::new(&config(&raw))
        .unwrap()
        .connect_tcp(
            &endpoint.to_string(),
            &"auto".into(),
            crate::common::AddressFamily::Any,
        )
        .await
        .unwrap();
    assert!(
        !socket2::SockRef::from(stream.get_ref().0.get_ref())
            .keepalive()
            .unwrap()
    );
    server_task.await.unwrap().unwrap();
}

#[test]
fn missing_sni_uses_the_endpoint_as_the_verified_server_name() {
    let tls = ClientTls::new(&config(
        "vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080",
    ))
    .unwrap();
    assert_eq!(
        vector_config("vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080")
            .sni,
        None
    );
    assert_eq!(tls.quic_server_name(), "127.0.0.1");
    tls.quic_client_config().unwrap();
}

#[test]
fn ipv6_authority_builds_an_ip_server_name() {
    let tls = ClientTls::new(&config(
        "vector://0123456789abcdef0123456789abcdef@[::1]:2000?in=127.0.0.1:1080",
    ))
    .unwrap();
    assert_eq!(tls.quic_server_name(), "::1");
}

#[test]
fn explicit_sni_overrides_the_verified_server_name() {
    let config = config(
        "vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?sni=example.com&in=127.0.0.1:1080",
    );
    let tls = ClientTls::new(&config).unwrap();
    assert_eq!(config.sni.as_deref(), Some("example.com"));
    assert_eq!(tls.quic_server_name(), "example.com");
}

#[derive(Clone, Copy)]
enum TestPin {
    Omitted,
    Empty,
    Disabled,
    Exact,
    Uppercase,
    Invalid,
}

async fn test_pinned_handshake(pin: TestPin, sni: Option<&str>) -> Result<()> {
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
    server.alpn_protocols = vec![b"nw3".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        TlsAcceptor::from(Arc::new(server)).accept(stream).await
    });

    let pin = match pin {
        TestPin::Omitted => None,
        TestPin::Empty => Some(String::new()),
        TestPin::Disabled => Some("none".to_owned()),
        TestPin::Exact => Some(fingerprint),
        TestPin::Uppercase => Some(fingerprint.to_ascii_uppercase()),
        TestPin::Invalid => Some("not-a-fingerprint".to_owned()),
    };
    let mut raw = format!("vector://0123456789abcdef0123456789abcdef@{endpoint}?morph=0&");
    if let Some(sni) = sni {
        raw.push_str(&format!("sni={sni}&"));
    }
    if let Some(pin) = pin {
        raw.push_str(&format!("pin={pin}&"));
    }
    raw.push_str("in=127.0.0.1:1080");

    let result = ClientTls::new(&PortalClientConfig::from_probe_url(&url::Url::parse(&raw)?)?.0)?
        .connect_tcp(
            &endpoint.to_string(),
            &"auto".into(),
            crate::common::AddressFamily::Any,
        )
        .await
        .map(|_| ());
    let _ = tokio::time::timeout(Duration::from_secs(1), server_task).await;
    result
}

#[tokio::test]
async fn tcp_server_without_nw3_is_rejected() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = generated.cert.into();
    let pin = certificate_sha256(&certificate);
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
    server.alpn_protocols = vec![b"unsupported".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = TlsAcceptor::from(Arc::new(server)).accept(stream).await;
    });
    let raw = format!(
        "vector://0123456789abcdef0123456789abcdef@{endpoint}?morph=0&pin={pin}&in=127.0.0.1:1080"
    );
    assert!(
        ClientTls::new(&config(&raw))
            .unwrap()
            .connect_tcp(
                &endpoint.to_string(),
                &"auto".into(),
                crate::common::AddressFamily::Any
            )
            .await
            .is_err()
    );
}

async fn negotiate_quic(server_alpns: Vec<Vec<u8>>, pin: TestPin) -> Result<()> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = generated.cert.into();
    let fingerprint = certificate_sha256(&certificate);
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

    let pin = match pin {
        TestPin::Omitted => String::new(),
        TestPin::Empty => "&pin=".to_owned(),
        TestPin::Disabled => "&pin=none".to_owned(),
        TestPin::Exact => format!("&pin={fingerprint}"),
        TestPin::Uppercase => format!("&pin={}", fingerprint.to_ascii_uppercase()),
        TestPin::Invalid => "&pin=wrong".to_owned(),
    };
    let raw = format!("vector://0123456789abcdef0123456789abcdef@{address}?in=127.0.0.1:1080{pin}");
    let tls = ClientTls::new(&PortalClientConfig::from_probe_url(&url::Url::parse(&raw)?)?.0)?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    client.set_default_client_config(tls.quic_client_config()?);
    let connection = client.connect(address, &tls.quic_server_name())?.await?;
    require_quic_nw3(&connection)?;
    connection.close(quinn::VarInt::from_u32(0), b"");
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn quic_requires_nw3() {
    negotiate_quic(vec![b"nw3".to_vec()], TestPin::Exact)
        .await
        .unwrap();
    assert!(
        negotiate_quic(vec![b"unsupported".to_vec()], TestPin::Exact)
            .await
            .is_err()
    );
    assert!(
        negotiate_quic(vec![b"http/1.1".to_vec()], TestPin::Exact)
            .await
            .is_err()
    );
    assert!(
        negotiate_quic(vec![b"private/2".to_vec()], TestPin::Exact)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn exact_pin_overrides_sni_certificate_verification() {
    test_pinned_handshake(TestPin::Exact, Some("wrong.example"))
        .await
        .unwrap();
}

#[tokio::test]
async fn missing_empty_or_none_options_never_disable_tcp_certificate_verification() {
    for pin in [TestPin::Omitted, TestPin::Empty, TestPin::Disabled] {
        for sni in [None, Some(""), Some("none"), Some("localhost")] {
            let error = test_pinned_handshake(pin, sni).await.unwrap_err();
            assert!(format!("{error:#}").contains("UnknownIssuer"), "{error:#}");
        }
    }
    test_pinned_handshake(TestPin::Exact, None).await.unwrap();
}

#[tokio::test]
async fn quic_requires_a_trusted_certificate_or_an_exact_pin() {
    for pin in [
        TestPin::Omitted,
        TestPin::Empty,
        TestPin::Disabled,
        TestPin::Uppercase,
        TestPin::Invalid,
    ] {
        assert!(negotiate_quic(vec![b"nw3".to_vec()], pin).await.is_err());
    }
}

#[tokio::test]
async fn wrong_or_uppercase_pin_is_rejected() {
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

#[test]
fn tls_clones_share_prelude_state_and_quic_configuration_does_not_allocate() {
    let tls = ClientTls::new(&config(
        "vector://0123456789abcdef0123456789abcdef@127.0.0.1:2000?in=127.0.0.1:1080",
    ))
    .unwrap();
    let clone = tls.clone();
    assert!(Arc::ptr_eq(&tls.prelude, &clone.prelude));
    assert_eq!(tls.prelude.allocated_for_test(), 0);
    clone.quic_client_config().unwrap();
    assert_eq!(tls.prelude.allocated_for_test(), 0);
}

#[tokio::test]
async fn cloned_tls_clients_send_one_identity_and_distinct_counters_after_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef");
    let server = tokio::spawn(async move {
        let mut tokens = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let (_stream, authentication) =
                MorphTcpStream::accept_bootstrap(stream, Some(keys.clone()))
                    .await
                    .unwrap();
            tokens.push(authentication.unwrap());
        }
        tokens
    });
    let tls = ClientTls::new(&config(&format!(
        "vector://0123456789abcdef0123456789abcdef@{endpoint}?in=127.0.0.1:1080",
    )))
    .unwrap();
    let clone = tls.clone();
    for client in [&tls, &clone] {
        assert!(
            client
                .connect_tcp(
                    &endpoint.to_string(),
                    &"auto".into(),
                    crate::common::AddressFamily::Any
                )
                .await
                .is_err()
        );
    }
    let tokens = server.await.unwrap();
    assert!(tokens[0].identity == tokens[1].identity);
    assert_eq!(tokens[0].counter, 1);
    assert_eq!(tokens[1].counter, 2);
    assert_eq!(tls.prelude.allocated_for_test(), 2);
}

#[tokio::test]
async fn cloned_tls_clients_keep_the_instance_handshake_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    for morph in [0, 1] {
        let mut config = config(&format!(
            "vector://0123456789abcdef0123456789abcdef@{address}?in=127.0.0.1:1080&morph={morph}&pin={}",
            "0".repeat(64)
        ));
        config.handshake_timeout = Duration::from_millis(50);
        let tls = ClientTls::new(&config).unwrap();
        config.handshake_timeout = Duration::from_secs(45);
        let clone = tls.clone();
        for client in [&tls, &clone] {
            assert_eq!(client.handshake_timeout, Duration::from_millis(50));
            let started = tokio::time::Instant::now();
            let error = tokio::time::timeout(
                Duration::from_secs(1),
                client.connect_tcp(
                    &address.to_string(),
                    &config.dial_policy,
                    crate::common::AddressFamily::Any,
                ),
            )
            .await
            .expect("TLS ignored its saved stage budget")
            .unwrap_err();
            assert!(format!("{error:#}").contains("TLS handshake timeout"));
            assert!(started.elapsed() >= Duration::from_millis(50));
        }
    }
}

#[tokio::test]
async fn quic_connect_uses_the_instance_handshake_budget() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for morph in [0, 1] {
        let (mut config, _) = PortalClientConfig::from_probe_url(
            &url::Url::parse(&format!(
                "vector://0123456789abcdef0123456789abcdef@127.0.0.1/udp:{}?morph={morph}&pin={}",
                socket.local_addr().unwrap().port(),
                "0".repeat(64)
            ))
            .unwrap(),
        )
        .unwrap();
        config.handshake_timeout = Duration::from_millis(50);
        let tls = ClientTls::new(&config).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            crate::vector::client::connect_quic(&config, &tls),
        )
        .await
        .expect("QUIC ignored its saved stage budget")
        .unwrap_err();
        assert!(format!("{error:#}").contains("QUIC handshake timeout"));
    }
}
