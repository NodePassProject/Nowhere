// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Tests for the toolbox utilities.

use std::time::Duration;

use url::Url;

use super::*;

#[test]
fn generated_keys_are_256_bit_lowercase_hex() {
    let first = generate_key().unwrap();
    let second = generate_key().unwrap();
    for key in [&first, &second] {
        assert_eq!(key.len(), 64);
        assert!(
            key.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
    assert_ne!(first, second);
}

#[test]
fn toolbox_configuration_errors_explain_the_failure_without_echoing_values() {
    for (raw, expected) in [
        (
            "vector://secret@localhost:2000?up=secret",
            "up must be tcp, udp, or mix",
        ),
        (
            "vector://secret@localhost/tcp:secret",
            "carrier port must contain decimal digits only",
        ),
        ("vector://secret@localhost/secret:2000", "unknown carrier"),
        (
            "vector://secret@localhost:2000?morph=secret",
            "morph must be 0 or 1",
        ),
        (
            "vector://secret@localhost:2000?sni=secret:443",
            "sni must be an ASCII DNS name",
        ),
        (
            "vector://secret@localhost:2000?socks=user:secret@localhost:secret",
            "port must be in 1..=65535",
        ),
        (
            "vector://secret@localhost:2000?up=%FFsecret",
            "invalid UTF-8 in query value",
        ),
    ] {
        let error = parse_client(&Url::parse(raw).unwrap()).err().unwrap();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("secret"), "{message}");
        assert!(!message.contains("user:"), "{message}");
    }
}

#[test]
fn connection_diagnostics_keep_stages_and_causes_without_echoing_values() {
    let refused = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "secret remote detail",
    ))
    .context("vector::tls::connect_tcp: failed to dial secret:2000");
    assert_eq!(
        connection_failure_reason(&refused),
        "TCP connection failed: connection refused"
    );
    let tls = anyhow::Error::new(rustls::Error::InvalidCertificate(
        rustls::CertificateError::UnknownIssuer,
    ))
    .context("vector::tls::connect_tcp: TLS handshake failed");
    assert_eq!(
        connection_failure_reason(&tls),
        "TLS/Morph handshake failed: certificate validation failed"
    );
    let wrapped_tls = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
    ))
    .context("vector::tls::connect_tcp: TLS handshake failed");
    assert_eq!(
        connection_failure_reason(&wrapped_tls),
        "TLS/Morph handshake failed: certificate validation failed"
    );
    for (raw, expected) in [
        (
            "common::util::dial_tcp_from_local_ip: failed to resolve target: secret",
            "DNS resolution failed",
        ),
        (
            "vector::tls::connect_tcp: TLS handshake timeout",
            "TLS/Morph handshake timed out",
        ),
        (
            "vector::tls::connect_tcp: invalid negotiated protocol: secret",
            "Portal did not negotiate nw2 ALPN",
        ),
        (
            "vector::tls::ClientTls::new: system root loading failed: secret",
            "system CA loading failed",
        ),
        (
            "vector::tls::ClientTls::new: no system trust roots available",
            "no system CA trust roots available",
        ),
        ("telemetry snapshot timed out", "IPC status read timed out"),
        (
            "telemetry: service rejected connection: secret",
            "IPC service rejected connection",
        ),
        (
            "telemetry rejected status: secret",
            "IPC service rejected status request",
        ),
        ("unknown secret error", "connection or local IPC failed"),
    ] {
        assert_eq!(connection_failure_reason(&anyhow::anyhow!(raw)), expected);
    }
}

#[tokio::test]
async fn fingerprint_connection_refusal_reports_the_cause_without_echoing_the_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let error = fingerprint(Url::parse(&format!("nowhere://secret@{address}")).unwrap())
        .await
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("TCP connection failed: connection refused"),
        "{message}"
    );
    assert!(!message.contains("secret"), "{message}");
    assert!(!message.contains(&address.to_string()), "{message}");
}

#[tokio::test]
async fn fingerprint_rejects_udp_only_and_invalid_share_links_without_leaking_secrets() {
    for (raw, expected) in [
        (
            "nowhere://secret@localhost/udp:2000#My%20Portal",
            "requires a TCP carrier",
        ),
        (
            "vector://secret@localhost:2000",
            "invalid Nowhere share link",
        ),
        (
            "portal://secret@localhost:2000",
            "invalid Nowhere share link",
        ),
        ("nowhere://secret@*:2000", "invalid Nowhere share link"),
        ("nowhere://localhost:2000", "invalid Nowhere share link"),
        (
            "nowhere://secret:password@localhost:2000",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret%ZZ@localhost:2000",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret@localhost/tcp4:2000",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret@localhost:2000?morph=secret",
            "invalid Nowhere share link",
        ),
        (
            "nowhere://secret@localhost:2000?sni=secret:443",
            "invalid Nowhere share link",
        ),
    ] {
        let error = fingerprint(Url::parse(raw).unwrap()).await.unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[test]
fn fingerprint_share_links_decode_keys_and_ignore_display_names_and_flow_options() {
    let url = Url::parse(
        "nowhere://shared%40key%3A%2F%3F%23%25%2B@[::1]/tcp:2006/udp:2017?morph=1&morph=0&sni=relay.example&up=udp&down=udp&mux=1&pin=wrong&socks=missing#My%20Portal",
    ).unwrap();
    let config = PortalClientConfig::from_fingerprint_url(&url).unwrap();
    assert_eq!(config.endpoint(), "[::1]/tcp:2006/udp:2017");
    assert_eq!(config.sni.as_deref(), Some("relay.example"));
    assert!(config.pin.is_none());
    assert_eq!(
        config.morph_keys.unwrap().udp_keys(),
        crate::transport::MorphKeys::derive(b"shared@key:/?#%+").udp_keys(),
    );
    assert!(
        PortalClientConfig::from_fingerprint_url(
            &Url::parse("nowhere://secret@localhost:2000").unwrap(),
        )
        .is_ok()
    );
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

    for morph in [0, 1] {
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
            "nowhere://secret@{address}?morph={morph}&sni=wrong.example&up=udp&down=udp&mux=1#My%20Portal"
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
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
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

#[test]
fn panel_aligns_labels_and_values() {
    assert_eq!(
        panel(
            "NOWHERE PROBE",
            &[("Result", "OK".to_owned()), ("Setup", "1.2 ms".to_owned()),],
        ),
        "NOWHERE PROBE\n─────────────\nResult  OK\n Setup  1.2 ms"
    );
}

#[test]
fn duration_uses_compact_consistent_precision() {
    assert_eq!(format_duration(Duration::from_micros(1_250)), "1.2 ms");
    assert_eq!(format_duration(Duration::from_millis(25)), "25 ms");
}

#[test]
fn toolbox_probe_url_allows_missing_socks() {
    let url = Url::parse("vector://secret@127.0.0.1:2000?up=tcp&down=tcp").unwrap();
    assert!(ToolboxClient::parse(&url).is_ok());
}

#[test]
fn setup_results_use_cli_labels() {
    assert_eq!(setup_name(SetupResult::DialFailed), "DIAL_FAILED");
}

#[tokio::test]
async fn status_reads_a_real_local_snapshot_and_redacts_metadata() {
    use crate::telemetry::{DiscoveredInstance, TelemetryHub, TelemetryServer};
    use crate::transport::Stats;
    use tokio_util::sync::CancellationToken;

    let hub = TelemetryHub::for_current_process(
        InstanceRole::Portal,
        "secret@localhost:2000",
        "secret",
        Duration::from_secs(1),
    );
    let descriptor = hub.descriptor();
    let discovered = DiscoveredInstance {
        registry_name: descriptor.registry_name(),
        uid: descriptor.uid,
        pid: descriptor.pid,
        incarnation: descriptor.incarnation,
    };
    let server = TelemetryServer::bind(hub.clone()).unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.run(shutdown.clone()));
    hub.capture_and_publish(&Stats::default(), 0);
    let item = read_status(discovered).await.unwrap();
    assert_eq!(item.id, hub.descriptor().id);
    assert_eq!(item.endpoint, "<redacted>");
    assert_eq!(item.role, "PORTAL");
    shutdown.cancel();
    task.await.unwrap();
}

#[test]
fn status_uses_vertical_rows_without_removed_fields() {
    let item = StatusItem {
        role: "PORTAL",
        pid: 42,
        id: "instance".to_owned(),
        lifecycle: "READY".to_owned(),
        endpoint: "127.0.0.1:2000".to_owned(),
        snapshot: TelemetrySnapshot::default(),
    };
    let output = status_panel(&item);
    assert!(output.contains("PORTAL · PID 42"));
    assert!(!output.contains("CPU"));
    assert!(!output.contains("Memory"));
    assert!(!output.contains("Flows and carriers"));
}
