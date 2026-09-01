// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector construction and formatting tests.

use super::*;

#[test]
fn vector_constructs_for_each_carrier_pair() {
    for (up, down) in [
        ("tcp", "tcp"),
        ("tcp", "udp"),
        ("udp", "tcp"),
        ("udp", "udp"),
        ("mix", "tcp"),
        ("mix", "udp"),
        ("tcp", "mix"),
        ("udp", "mix"),
        ("mix", "mix"),
    ] {
        let url = Url::parse(&format!(
            "vector://secret@127.0.0.1:2077?up={up}&down={down}&socks=127.0.0.1:1080"
        ))
        .unwrap();
        Vector::new(url, Logger::new(crate::common::LogLevel::None, false)).unwrap();
    }
}

#[test]
fn effective_url_prints_none_for_absent_sni() {
    let config = VectorConfig::from_url(
        &Url::parse("vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080").unwrap(),
    )
    .unwrap();
    assert!(config.effective_url().contains("&sni=none&"));
}

#[tokio::test]
async fn socks_bind_failure_moves_lifecycle_to_stopped() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let vector = Vector::new(
        Url::parse(&format!(
            "vector://secret@127.0.0.1:2077?socks=127.0.0.1:{port}&log=none"
        ))
        .unwrap(),
        Logger::new(crate::common::LogLevel::None, false),
    )
    .unwrap();
    let lifecycle = vector.inner.lifecycle.clone();

    assert!(vector.run().await.is_err());
    assert_eq!(lifecycle.state(), Some(crate::common::LifeState::Stopped));
}
