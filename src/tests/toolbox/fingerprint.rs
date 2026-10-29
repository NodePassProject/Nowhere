// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS fingerprint queries, share-link validation, and error redaction tests.

use std::sync::Arc;
use std::time::Duration;

use super::*;

const KEY: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn fingerprint_connection_refusal_reports_the_cause_without_echoing_the_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let error = fingerprint(
        Url::parse(&format!(
            "nowhere://0123456789abcdef0123456789abcdef@{address}?net=tcp&morph=0"
        ))
        .unwrap(),
    )
    .await
    .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("TCP connection failed: connection refused"),
        "{message}"
    );
    assert!(!message.contains(KEY), "{message}");
    assert!(!message.contains("secret"), "{message}");
    assert!(!message.contains(&address.to_string()), "{message}");
}

#[tokio::test]
async fn fingerprint_rejects_invalid_share_links_without_leaking_secrets() {
    for (raw, expected) in [
        (
            "nowhere://0123456789abcdef0123456789abcdef@localhost/udp:2000#My%20Portal",
            "invalid nowhere share link",
        ),
        (
            "nowhere://0123456789abcdef0123456789abcdef@localhost:2000?net=%ZZ",
            "invalid nowhere share link",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000",
            "invalid nowhere share link",
        ),
        ("nowhere://localhost:2000", "invalid nowhere share link"),
        (
            "nowhere://0123456789abcdef0123456789abcdef:password@localhost:2000",
            "invalid nowhere share link",
        ),
        (
            "nowhere://secret%ZZ@localhost:2000",
            "invalid nowhere share link",
        ),
        (
            "nowhere://0123456789abcdef0123456789abcdef@localhost:2000?net=tcp&morph=secret",
            "invalid nowhere share link",
        ),
        (
            "nowhere://0123456789abcdef0123456789abcdef@localhost:2000?net=tcp&morph=0&sni=secret:443",
            "invalid nowhere share link",
        ),
    ] {
        let error = fingerprint(Url::parse(raw).unwrap()).await.unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(KEY), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[test]
fn fingerprint_share_links_decode_keys_and_ignore_display_names_and_flow_options() {
    let url = Url::parse(
        "nowhere://%30123456789abcdef0123456789abcdef@[::1]:2006?net=udp&net=invalid&morph=1&morph=0&sni=relay.example&unknown=ignored&pin=wrong&socks=missing#My%20Portal",
    ).unwrap();
    let config = PortalClientConfig::from_fingerprint_url(&url).unwrap();
    assert_eq!(config.endpoint(), "[::1]:2006");
    assert_eq!(config.net, crate::vector::config::CarrierMode::Udp);
    assert_eq!(config.sni.as_deref(), Some("relay.example"));
    assert!(config.pin.is_none());
    assert_eq!(
        config.morph_keys.unwrap().udp_keys(),
        crate::transport::MorphKeys::derive(KEY.as_bytes()).udp_keys(),
    );
    let plain = PortalClientConfig::from_fingerprint_url(
        &Url::parse("nowhere://0123456789abcdef0123456789abcdef@localhost:2000?net=tcp&morph=0")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(plain.net, crate::vector::config::CarrierMode::Tcp);
    assert!(!plain.morph);
}

#[test]
fn fingerprint_defaults_carrier_and_requires_morph() {
    for (query, expected) in [
        ("", "fingerprint requires morph=0 or morph=1"),
        ("net=tcp", "fingerprint requires morph=0 or morph=1"),
        ("net=udp", "fingerprint requires morph=0 or morph=1"),
        ("net=&morph=0", "net must be tcp or udp"),
        ("net=invalid&net=tcp&morph=0", "net must be tcp or udp"),
        ("net=tcp&morph=", "morph must be 0 or 1"),
        ("net=tcp&morph=invalid&morph=0", "morph must be 0 or 1"),
    ] {
        let url = Url::parse(&format!(
            "nowhere://0123456789abcdef0123456789abcdef@localhost:2000?{query}#NAME"
        ))
        .unwrap();
        let error = PortalClientConfig::from_fingerprint_url(&url).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(KEY), "{message}");
        assert!(!message.contains("secret"), "{message}");
        assert!(!message.contains("localhost"), "{message}");
    }
    for (query, morph) in [("?morph=0", false), ("?morph=1", true)] {
        let url = Url::parse(&format!(
            "nowhere://0123456789abcdef0123456789abcdef@localhost:2000{query}"
        ))
        .unwrap();
        let config = PortalClientConfig::from_fingerprint_url(&url).unwrap();
        assert_eq!(config.net, crate::vector::config::CarrierMode::Tcp);
        assert_eq!(config.morph, morph);
    }
}

#[tokio::test]
async fn fingerprint_reads_the_leaf_certificate_with_and_without_morph_without_flow_data() {
    use rustls::crypto::ring;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use crate::common::certificate_sha256;
    use crate::transport::MorphTcpStream;

    for (net, morph) in [("tcp", 0), ("tcp", 1), ("udp", 0), ("udp", 1)] {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate: CertificateDer<'static> = generated.cert.into();
        let expected = certificate_sha256(&certificate);
        let key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let mut server =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], key.into())
                .unwrap();
        server.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = Url::parse(&format!(
            "nowhere://0123456789abcdef0123456789abcdef@{address}?net={net}&morph={morph}&sni=wrong.example&unknown=ignored#My%20Portal"
        )).unwrap();
        let config = PortalClientConfig::from_fingerprint_url(&url).unwrap();
        let morph_keys = config.morph_keys.clone();
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = MorphTcpStream::accept(tcp, morph_keys).await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server))
                .accept(stream)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.server_name(), Some("wrong.example"));
            let mut byte = [0];
            match stream.read(&mut byte).await {
                Ok(length) => assert_eq!(length, 0, "fingerprint sent application data"),
                Err(error) => assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ),
                    "unexpected TLS read error: {error}"
                ),
            }
        });
        let actual = crate::vector::fetch_certificate_fingerprint(&config)
            .await
            .unwrap();
        assert_eq!(actual, expected);
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }
}
