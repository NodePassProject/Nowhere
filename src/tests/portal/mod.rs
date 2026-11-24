// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared Portal integration harness, target servers, and transport exchange fixtures.

mod conn;
mod egress;
mod forward;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::protocol::{SetupResult, Target};
use crate::vector::{PortalClient, PortalClientConfig};

use super::*;

const KEY: &str = "0123456789abcdef0123456789abcdef";

struct Harness {
    inner: Arc<PortalInner>,
    tcp: std::net::SocketAddr,
    udp: std::net::SocketAddr,
    pin: String,
    cipher: &'static str,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<anyhow::Result<()>>>,
}

impl Harness {
    async fn new(out: &str, morph: bool) -> Self {
        Self::family(out, morph, "127.0.0.1").await
    }

    async fn family(out: &str, morph: bool, host: &str) -> Self {
        Self::configured(out, morph, host, None).await
    }

    async fn with_handshake_timeout(morph: bool, timeout: Duration) -> Self {
        Self::configured("direct", morph, "127.0.0.1", Some(timeout)).await
    }

    async fn configured(out: &str, morph: bool, host: &str, timeout: Option<Duration>) -> Self {
        Self::configured_runtime(out, morph, host, |runtime| {
            if let Some(timeout) = timeout {
                runtime.handshake_timeout = timeout;
            }
        })
        .await
    }

    async fn with_egress_ttl(ttl: Duration) -> Self {
        Self::configured_runtime("egress", false, "127.0.0.1", |runtime| {
            runtime.egress_tls_idle_ttl = ttl;
        })
        .await
    }

    async fn configured_runtime(
        out: &str,
        morph: bool,
        host: &str,
        configure: impl FnOnce(&mut PortalRuntimeConfig),
    ) -> Self {
        Self::configured_cipher(out, morph, host, "chacha", configure).await
    }

    async fn configured_cipher(
        out: &str,
        morph: bool,
        host: &str,
        cipher: &'static str,
        configure: impl FnOnce(&mut PortalRuntimeConfig),
    ) -> Self {
        let portal = Portal::new(
            Url::parse(&format!(
                "portal://{KEY}@{host}:2000?out={out}&morph={}&cipher={cipher}",
                u8::from(morph)
            ))
            .unwrap(),
            Logger,
        )
        .unwrap();
        let mut inner = portal.inner;
        {
            let inner = Arc::get_mut(&mut inner).unwrap();
            configure(&mut inner.runtime);
            Arc::get_mut(&mut inner.forward).unwrap().runtime = inner.runtime;
        }
        let tcp_listener = listener::listen_tcp(format!("{host}:0").parse().unwrap()).unwrap();
        let tcp = tcp_listener.local_addr().unwrap();
        let quic = listener::listen_endpoint(
            inner.quic_server_config.clone(),
            format!("{host}:0").parse().unwrap(),
            inner.morph_keys.clone(),
        )
        .unwrap();
        let udp = quic.local_addr().unwrap();
        let pin = crate::tls_test_support::server_certificate_pin(&inner.tls_server_config);
        let stop = CancellationToken::new();
        let tasks = vec![
            tokio::spawn(runtime::tcp_loop(inner.clone(), tcp_listener, stop.clone())),
            tokio::spawn(runtime::quic_loop(inner.clone(), quic, stop.clone())),
        ];
        Self {
            inner,
            tcp,
            udp,
            pin,
            cipher,
            stop,
            tasks,
        }
    }

    fn url(&self, scheme: &str, net: &str, morph: bool) -> Url {
        let host = if self.tcp.is_ipv6() {
            format!("[{}]", self.tcp.ip())
        } else {
            self.tcp.ip().to_string()
        };
        Url::parse(&format!(
            "{scheme}://{KEY}@{host}/{net}:{}?morph={}&pin={}&cipher={}",
            if net == "tcp" {
                self.tcp.port()
            } else {
                self.udp.port()
            },
            u8::from(morph),
            self.pin,
            self.cipher,
        ))
        .unwrap()
    }

    fn client(&self, net: &str, morph: bool) -> Arc<PortalClient> {
        let (config, creds) =
            PortalClientConfig::from_probe_url(&self.url("vector", net, morph)).unwrap();
        PortalClient::new(
            config,
            &creds,
            self.inner.runtime.udp_queue_bytes,
            Arc::new(crate::transport::Stats::default()),
            true,
            CancellationToken::new(),
        )
        .unwrap()
    }

    async fn close(mut self) {
        self.stop.cancel();
        self.inner.forward.shutdown.cancel();
        for task in &mut self.tasks {
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.cancel();
        self.inner.forward.shutdown.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn tcp_echo() -> (Target, JoinHandle<()>) {
    tcp_echo_family("127.0.0.1").await
}

async fn tcp_echo_family(host: &str) -> (Target, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(format!("{host}:0"))
        .await
        .unwrap();
    let target = Target::Ip(listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    (target, task)
}

async fn udp_echo() -> (Target, JoinHandle<()>) {
    udp_echo_family("127.0.0.1").await
}

async fn udp_echo_family(host: &str) -> (Target, JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind(format!("{host}:0"))
        .await
        .unwrap();
    let target = Target::Ip(socket.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (target, task)
}

fn udp_sizes() -> Vec<usize> {
    #[cfg(target_os = "linux")]
    {
        vec![0, 1, 1024, 8000, 32000, 65000]
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![0, 1, 1024, 8000]
    }
}

async fn exchange(client: &Arc<PortalClient>, tcp: &Target, udp: &Target) {
    let mut tunnel = client.open_tcp(tcp).await.unwrap();
    let payload = vec![42; 131072];
    tunnel.write_all(&payload).await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), tunnel.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
    drop(tunnel);
    let mut tunnel = crate::vector::udp_flow::open_udp(client.clone(), udp)
        .await
        .unwrap();
    let mut buffer = Vec::new();
    for size in udp_sizes() {
        let payload = vec![size as u8; size];
        assert!(tunnel.send(&payload).await.unwrap());
        let packet = tokio::time::timeout(Duration::from_secs(3), tunnel.recv_into(&mut buffer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(packet.payload(&buffer), payload);
    }
    tunnel.close().await;
    drop(tunnel);
}
