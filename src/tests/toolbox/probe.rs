// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Probe configuration, target setup, transport failures, and diagnostic redaction tests.

use tokio::io::AsyncReadExt;

use super::*;

#[test]
fn toolbox_configuration_errors_explain_the_failure_without_echoing_values() {
    for (raw, expected) in [
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?rate=secret",
            "rate must be a non-negative integer",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost/tcp:secret",
            "carrier port must contain decimal digits only",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost/secret:2000",
            "unknown carrier",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?morph=secret",
            "morph must be 0, 1 or 2",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?sni=secret:443",
            "sni must be an ASCII DNS name",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?in=user:secret@localhost:secret",
            "port must be in 1..=65535",
        ),
        (
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?rate=%FFsecret",
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

#[tokio::test]
async fn failed_probe_keeps_the_underlying_io_error() {
    let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = unavailable.local_addr().unwrap();
    drop(unavailable);
    let client = ProbeClient::parse(
        &Url::parse(&format!(
            "vector://0123456789abcdef0123456789abcdef@{endpoint}"
        ))
        .unwrap(),
    )
    .unwrap();
    let report = client
        .probe(Target::ip("127.0.0.1:80".parse().unwrap()).unwrap())
        .await
        .unwrap();
    let error = report.result.unwrap_err();
    assert!(error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused)
    }));
    assert!(connection_failure_reason(&error).contains("connection refused"));
}

#[test]
fn probe_deadline_uses_the_real_flow_setup_budget() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "toolbox::probe::tests::probe_deadline_child",
            "--nocapture",
        ])
        .env("NOW_TEST_PROBE_DEADLINE", "1")
        .env("NOW_FLOW_SETUP_TIMEOUT", "250ms")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn probe_deadline_child() {
    if std::env::var_os("NOW_TEST_PROBE_DEADLINE").is_none() {
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = ProbeClient::parse(
        &Url::parse(&format!(
            "vector://0123456789abcdef0123456789abcdef@{}?morph=0&pin={}",
            listener.local_addr().unwrap(),
            "00".repeat(32),
        ))
        .unwrap(),
    )
    .unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).await.unwrap();
    });
    let report = tokio::time::timeout(
        Duration::from_secs(1),
        client.probe(Target::ip("127.0.0.1:80".parse().unwrap()).unwrap()),
    )
    .await
    .expect("Probe used a separate stage-count budget")
    .unwrap();
    let error = report.result.unwrap_err();
    assert!(error.chain().any(|cause| {
        cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    }));
    assert!(report.elapsed >= Duration::from_millis(250));
    assert!(report.cleanup.is_ok());
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}
