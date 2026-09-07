// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bidirectional byte-stream relay with idle/read timeouts.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::portal::PortalInner;
use crate::protocol::Carrier;
use crate::telemetry::AccessSpan;
use crate::transport::{
    AsyncReadAny, AsyncWriteAny, read_owned, read_owned_from, write_owned, write_owned_to,
};

/// Relays both directions until one side closes or either direction errors.
pub(in crate::portal) async fn relay_stream<TR, TW>(
    portal: Arc<PortalInner>,
    client_read: &mut std::pin::Pin<Box<dyn AsyncReadAny>>,
    client_write: &mut std::pin::Pin<Box<dyn AsyncWriteAny>>,
    target: (TR, TW),
    carriers: Option<(Carrier, Carrier)>,
    access: &AccessSpan,
) -> anyhow::Result<()>
where
    TR: AsyncRead + Unpin,
    TW: AsyncWrite + Unpin,
{
    let (mut target_read, mut target_write) = target;

    let client_to_target = async {
        loop {
            let Some(chunk) = read_owned(client_read).await? else {
                target_write.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            };
            let n = chunk.len();
            access.add_upload(n as u64);
            portal.stats.tcp_rx.fetch_add(n as u64, Ordering::Relaxed);
            if let Some((uplink, _)) = carriers {
                match uplink {
                    Carrier::TlsTcp => &portal.stats.up_tcp,
                    Carrier::Quic => &portal.stats.up_udp,
                }
                .fetch_add(n as u64, Ordering::Relaxed);
            }
            if let Some(limiter) = &portal.rate_limiter {
                limiter.wait_read(n as i64).await;
            }
            write_owned_to(&mut target_write, chunk).await?;
        }
    };

    let target_to_client = async {
        loop {
            let Some(chunk) = read_owned_from(&mut target_read).await? else {
                client_write.shutdown().await?;
                return Ok::<(), anyhow::Error>(());
            };
            let n = chunk.len();
            if let Some(limiter) = &portal.rate_limiter {
                limiter.wait_write(n as i64).await;
            }
            write_owned(client_write, chunk).await?;
            if carriers.is_some_and(|(uplink, downlink)| {
                uplink == Carrier::TlsTcp && downlink == Carrier::Quic
            }) {
                // Keep the TLS Mux receive/control tasks responsive when the
                // QUIC half remains continuously writable.
                tokio::task::yield_now().await;
            }
            access.add_download(n as u64);
            portal.stats.tcp_tx.fetch_add(n as u64, Ordering::Relaxed);
            if let Some((_, downlink)) = carriers {
                match downlink {
                    Carrier::TlsTcp => &portal.stats.down_tcp,
                    Carrier::Quic => &portal.stats.down_udp,
                }
                .fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    };

    tokio::pin!(client_to_target);
    tokio::pin!(target_to_client);

    let first = tokio::select! {
        r = &mut client_to_target => EitherDone::Client(r),
        r = &mut target_to_client => EitherDone::Target(r),
    };

    match first {
        EitherDone::Client(Ok(())) => {
            // After a clean half-close, give the other direction a short drain
            // window so protocol trailers or final response bytes can pass.
            timeout(portal.runtime.tcp_read_timeout, &mut target_to_client)
                .await
                .unwrap_or(Ok(()))?;
        }
        EitherDone::Target(Ok(())) => {
            // Symmetric drain window for target-initiated close.
            timeout(portal.runtime.tcp_read_timeout, &mut client_to_target)
                .await
                .unwrap_or(Ok(()))?;
        }
        EitherDone::Client(Err(err)) | EitherDone::Target(Err(err)) => return Err(err),
    }

    Ok(())
}

enum EitherDone {
    Client(anyhow::Result<()>),
    Target(anyhow::Result<()>),
}
