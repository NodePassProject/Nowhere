// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal TLS/QUIC forwarding matrices, Morph, IPv6, and TCP half-close tests.

mod ingress;
mod socks;

use super::*;

#[tokio::test]
async fn direct_tls_quic_tcp_udp_morph_and_half_close() {
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    for morph in [false, true] {
        let h = Harness::new("direct", morph).await;
        for net in ["tcp", "udp"] {
            let client = h.client(net, morph);
            exchange(&client, &tcp, &udp).await;
            client
                .close(tokio::time::Instant::now() + Duration::from_secs(2))
                .await;
            assert_eq!(
                client
                    .stats
                    .tcp_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
            assert_eq!(
                client
                    .stats
                    .udp_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
        }
        h.close().await;
    }
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn full_ipv6_tls_quic_direct_socks_egress_tcp_udp_morph_matrix() {
    let (tcp, tcp_task) = tcp_echo_family("[::1]").await;
    let (udp, udp_task) = udp_echo_family("[::1]").await;
    let (upstream, proxy) = socks::proxy_family("[::1]").await;
    for (morph, cipher) in [(false, "chacha"), (true, "chacha"), (true, "aes")] {
        for out in [
            "direct".to_owned(),
            format!("a%3Ab:p%40ss@{upstream}"),
            "egress/quic".to_owned(),
            "egress/tls".to_owned(),
        ] {
            let egress = out.strip_prefix("egress/");
            let outlet = if egress.is_some() { "egress" } else { &out };
            let h = Harness::configured_cipher(outlet, morph, "[::1]", cipher, |_| {}).await;
            let egress_task = if let Some(carrier) = egress {
                let net = if carrier == "tls" { "tcp" } else { "udp" };
                let egress = crate::Egress::new(h.url("egress", net, morph), Logger).unwrap();
                let task = tokio::spawn(egress.run());
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !h.inner.egress_registry.as_ref().unwrap().online() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                Some(task)
            } else {
                None
            };
            for net in ["tcp", "udp"] {
                let client = h.client(net, morph);
                exchange(&client, &tcp, &udp).await;
                client
                    .close(tokio::time::Instant::now() + Duration::from_secs(2))
                    .await;
            }
            h.close().await;
            if let Some(task) = egress_task {
                task.abort();
                let _ = task.await;
            }
        }
    }
    tcp_task.abort();
    udp_task.abort();
    proxy.abort();
}

#[tokio::test]
async fn cipher_mismatch_prevents_tls_and_quic_flows() {
    let (tcp, echo) = tcp_echo().await;
    for (portal_cipher, vector_cipher) in [("aes", "chacha"), ("chacha", "aes")] {
        let h = Harness::configured_cipher("direct", true, "127.0.0.1", portal_cipher, |runtime| {
            runtime.handshake_timeout = Duration::from_millis(250);
        })
        .await;
        for net in ["tcp", "udp"] {
            let mut url = h.url("vector", net, true);
            url.set_query(Some(&format!(
                "morph=1&cipher={vector_cipher}&pin={}",
                h.pin
            )));
            let (mut config, credentials) = PortalClientConfig::from_probe_url(&url).unwrap();
            config.handshake_timeout = Duration::from_millis(250);
            let client = PortalClient::new(
                config,
                &credentials,
                h.inner.runtime.udp_queue_bytes,
                Arc::new(crate::transport::Stats::default()),
                true,
                CancellationToken::new(),
            )
            .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(2), client.open_tcp(&tcp))
                .await
                .unwrap();
            assert!(result.is_err(), "{portal_cipher}/{vector_cipher}/{net}");
            client
                .close(tokio::time::Instant::now() + Duration::from_secs(2))
                .await;
        }
        h.close().await;
    }
    echo.abort();
}
