// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal Egress availability, shared exit bridging, counters, and disconnect cleanup tests.

use super::*;

#[test]
fn configured_udp_budget_is_consumed_by_each_quic_role() {
    for role in ["portal", "vector", "egress"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "portal::tests::egress::configured_udp_budget_child",
                "--nocapture",
            ])
            .env("NOW_TEST_UDP_BUDGET_ROLE", role)
            .env(
                "NOW_QUIC_UDP_QUEUE_BYTES",
                if role == "egress" { "1" } else { "8192" },
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{role}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn configured_udp_budget_child() {
    let Ok(role) = std::env::var("NOW_TEST_UDP_BUDGET_ROLE") else {
        return;
    };
    let h = Harness::configured_runtime(
        if role == "egress" { "egress" } else { "direct" },
        false,
        "127.0.0.1",
        |runtime| runtime.udp_queue_bytes = if role == "portal" { 1 } else { 8192 },
    )
    .await;
    let egress_task = if role == "egress" {
        let egress = crate::Egress::new(h.url("egress", "udp", false), Logger).unwrap();
        let task = tokio::spawn(egress.run());
        tokio::time::timeout(Duration::from_secs(2), async {
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
    let (config, credentials) =
        PortalClientConfig::from_probe_url(&h.url("vector", "udp", false)).unwrap();
    let client = PortalClient::new(
        config,
        &credentials,
        if role == "vector" { 1 } else { 8192 },
        Arc::new(crate::transport::Stats::default()),
        true,
        CancellationToken::new(),
    )
    .unwrap();
    let (target, echo) = udp_echo().await;
    let mut tunnel = crate::vector::udp_flow::open_udp(client.clone(), &target)
        .await
        .unwrap();
    let mut buffer = Vec::new();
    assert!(tunnel.send(b"xx").await.unwrap());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), tunnel.recv_into(&mut buffer))
            .await
            .is_err()
    );
    assert!(tunnel.send(b"x").await.unwrap());
    let packet = tokio::time::timeout(Duration::from_secs(2), tunnel.recv_into(&mut buffer))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(packet.payload(&buffer), b"x");
    drop(packet);
    tunnel.close().await;
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(1))
        .await;
    if let Some(task) = egress_task {
        task.abort();
        let _ = task.await;
    }
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn offline_flow_waits_for_a_new_registration() {
    let h = Harness::new("egress", false).await;
    let (target, echo) = tcp_echo().await;
    let client = h.client("udp", false);
    let mut opening = Box::pin(client.open_tcp(&target));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut opening)
            .await
            .is_err()
    );
    let egress = crate::Egress::new(h.url("egress", "tcp", false), Logger).unwrap();
    let task = tokio::spawn(egress.run());
    let tunnel = tokio::time::timeout(Duration::from_secs(3), &mut opening)
        .await
        .unwrap()
        .unwrap();
    drop(tunnel);
    drop(opening);
    task.abort();
    let _ = task.await;
    client
        .close(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    h.close().await;
    echo.abort();
}

#[tokio::test]
async fn egress_bridges_multiple_vectors_and_cleans_up_on_disconnect() {
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    for (morph, carrier) in [(false, "tcp"), (false, "udp"), (true, "tcp"), (true, "udp")] {
        let h = Harness::new("egress", morph).await;
        let egress = crate::Egress::new(h.url("egress", carrier, morph), Logger).unwrap();
        let egress_task = tokio::spawn(egress.run());
        tokio::time::timeout(Duration::from_secs(3), async {
            while !h.inner.egress_registry.as_ref().unwrap().online() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let tls = h.client("tcp", morph);
        let quic = h.client("udp", morph);
        tokio::join!(exchange(&tls, &tcp, &udp), exchange(&quic, &tcp, &udp));
        let stats = &h.inner.forward.stats;
        let udp_bytes = 2 * udp_sizes().iter().sum::<usize>() as u64;
        assert_eq!(
            stats
                .tcp_upload_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            262144
        );
        assert_eq!(
            stats
                .tcp_download_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            262144
        );
        assert_eq!(
            stats
                .udp_upload_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            udp_bytes
        );
        assert_eq!(
            stats
                .udp_download_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            udp_bytes
        );
        let mut held = quic.open_tcp(&tcp).await.unwrap();
        egress_task.abort();
        let _ = egress_task.await;
        let mut byte = [0];
        let _ = tokio::time::timeout(Duration::from_secs(2), held.read(&mut byte))
            .await
            .unwrap();
        drop(held);
        tokio::time::timeout(Duration::from_secs(2), async {
            while h.inner.egress_registry.as_ref().unwrap().online() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), quic.open_tcp(&tcp))
                .await
                .is_err()
        );
        tls.close(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        quic.close(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        h.close().await;
    }
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn mixed_egress_instances_bridge_tls_and_quic_vector_flows() {
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    for morph in [false, true] {
        let h = Harness::new("egress", morph).await;
        let mut tasks = Vec::new();
        for carrier in ["tcp", "tcp", "udp", "udp"] {
            let egress = crate::Egress::new(h.url("egress", carrier, morph), Logger).unwrap();
            tasks.push(tokio::spawn(egress.run()));
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while h.inner.egress_registry.as_ref().unwrap().registered_count() < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let a = h.client("tcp", morph);
        let b = h.client("udp", morph);
        tokio::join!(exchange(&a, &tcp, &udp), exchange(&b, &tcp, &udp));
        a.close(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        b.close(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        h.close().await;
    }
    tcp_task.abort();
    udp_task.abort();
}
