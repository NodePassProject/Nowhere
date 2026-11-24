// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Relay buffer release before blocked half-close and task cancellation.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use url::Url;

use crate::common::Logger;
use crate::vector::VectorRuntime;

use super::*;

struct BlockedShutdown {
    entered: Arc<AtomicBool>,
}

impl AsyncWrite for BlockedShutdown {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.entered.store(true, Ordering::SeqCst);
        Poll::Pending
    }
}

#[tokio::test]
async fn half_close_returns_its_buffer_before_shutdown_and_cancel_returns_the_other() {
    let vector = VectorRuntime::new(
        Url::parse("vector://0123456789abcdef0123456789abcdef@127.0.0.1:9?in=127.0.0.1:1080")
            .unwrap(),
        Logger,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let (reader, _peer) = tokio::io::duplex(64);
    let entered = Arc::new(AtomicBool::new(false));
    let tunnel = TcpTunnel::new(
        Box::pin(reader),
        Box::pin(BlockedShutdown {
            entered: entered.clone(),
        }),
        Carrier::TlsTcp,
        TcpTunnelGuard { _flow: None },
    );
    let task = tokio::spawn(relay_tcp(vector.inner.clone(), server, tunnel));
    tokio::task::yield_now().await;
    client.write_all(b"payload").await.unwrap();
    client.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!task.is_finished());
    assert_eq!(vector.inner.buffers.cached_tcp_buffers(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(vector.inner.buffers.cached_tcp_buffers(), 2);
    assert_eq!(
        vector.inner.stats.tcp_upload_bytes.load(Ordering::Relaxed),
        7
    );
    assert_eq!(
        vector
            .inner
            .stats
            .tcp_download_bytes
            .load(Ordering::Relaxed),
        0
    );
}
