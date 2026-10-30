// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS and QUIC ingress authentication, role enforcement, and flow dispatch.

use std::future::pending;
use std::io::ErrorKind;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::protocol::{AUTH_EXPORTER_LABEL, AuthTransport, ConnectionRole, read_auth_frame};
use crate::transport::{MorphTcpStream, QuicConnection};
use crate::vector::TcpTunnelGuard;

use super::{
    PortalInner, admission::UnauthenticatedGuard, egress::TlsConnection, forward::Incoming,
    prehello,
};

pub(super) enum TcpOutcome {
    Closed,
    SilentPreHello,
}

pub(super) async fn tcp(
    portal: Arc<PortalInner>,
    stream: tokio::net::TcpStream,
    admission: UnauthenticatedGuard,
    accepted_at: Instant,
    permit: OwnedSemaphorePermit,
) -> Result<TcpOutcome> {
    let morph = portal.morph_keys.is_some();
    let started_at = if morph { accepted_at } else { Instant::now() };
    let deadline = started_at + portal.runtime.handshake_timeout;
    if morph && Instant::now() >= deadline {
        return Ok(TcpOutcome::SilentPreHello);
    }
    let mut before_hello = morph;
    let authentication = tokio::time::timeout_at(deadline, async {
        stream.set_nodelay(true)?;
        let (mut stream, authentication) =
            match MorphTcpStream::accept_bootstrap(stream, portal.morph_keys.clone()).await {
                Ok(bootstrap) => bootstrap,
                Err((error, _stream))
                    if morph
                        && matches!(
                            error.kind(),
                            ErrorKind::UnexpectedEof | ErrorKind::InvalidData
                        ) =>
                {
                    return pending().await;
                }
                Err((error, _stream)) => return Err(error.into()),
            };
        if let Some(authentication) = authentication
            && !portal
                .prelude_replay
                .as_ref()
                .is_some_and(|replay| replay.precheck(authentication))
        {
            return pending().await;
        }
        let mut tls = if morph {
            let Some(accepted) = prehello::accept(&mut stream).await? else {
                return pending().await;
            };
            if Instant::now() >= deadline {
                return Ok(None);
            }
            if let Some(authentication) = authentication
                && !portal
                    .prelude_replay
                    .as_ref()
                    .is_some_and(|replay| replay.commit(authentication))
            {
                return pending().await;
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            before_hello = false;
            tokio_rustls::StartHandshake::from_parts(accepted, stream)
                .into_stream(portal.tls_server_config.clone())
                .await?
        } else {
            tokio_rustls::TlsAcceptor::from(portal.tls_server_config.clone())
                .accept(stream)
                .await?
        };
        if tls.get_ref().1.alpn_protocol() != Some(crate::protocol::ALPN) {
            bail!("invalid ALPN");
        }
        let mut exporter = [0; 32];
        tls.get_ref()
            .1
            .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, Some(&[]))?;
        let role = read_auth_frame(
            &mut tls,
            &portal.credentials,
            AuthTransport::TlsTcp,
            &exporter,
        )
        .await?;
        if role == ConnectionRole::Egress && portal.egress_registry.is_none() {
            bail!("Egress registration unavailable");
        }
        if morph
            && !prehello::finish_authentication(tls.get_ref().0.get_ref(), deadline)
                .context("restore Morph socket linger")?
        {
            bail!("TLS authentication deadline expired");
        }
        Ok::<_, anyhow::Error>(Some((tls, role)))
    });
    let (mut stream, role) = tokio::select! {
        biased;
        _ = portal.forward.shutdown.cancelled() => return Ok(TcpOutcome::Closed),
        result = authentication => match result {
            Err(_) if before_hello => return Ok(TcpOutcome::SilentPreHello),
            Ok(Err(error)) if before_hello && error.chain().any(|cause| {
                cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                    matches!(error.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)
                })
            }) => return Ok(TcpOutcome::SilentPreHello),
            result => match result.context("TLS authentication timeout")?? {
                Some(stream) => stream,
                None => return Ok(TcpOutcome::SilentPreHello),
            },
        },
    };
    drop(admission);
    if role == ConnectionRole::Egress {
        let Some(registry) = &portal.egress_registry else {
            bail!("Egress registration unavailable");
        };
        let Some(pending) = registry.reserve_tls() else {
            tokio::select! {
                _ = portal.forward.shutdown.cancelled() => {},
                _ = tokio::time::timeout(portal.runtime.handshake_timeout, async {
                    stream.write_all(&[1]).await?;
                    stream.flush().await
                }) => {},
            }
            return Ok(TcpOutcome::Closed);
        };
        tokio::select! {
            biased;
            _ = portal.forward.shutdown.cancelled() => return Ok(TcpOutcome::Closed),
            result = tokio::time::timeout(portal.runtime.handshake_timeout, async {
                stream.write_all(&[0]).await?;
                stream.flush().await
            }) => result.context("Egress registration timeout")??,
        }
        let expires_at = Instant::now() + portal.runtime.egress_tls_idle_ttl;
        let (claim, claimed) = oneshot::channel();
        let _registration = registry.register_tls(claim, expires_at);
        if let Some(transfer) =
            wait_tls_claim(&mut stream, claimed, expires_at, &portal.forward.shutdown).await
        {
            drop(pending);
            let _ = transfer.send(TlsConnection { stream, permit });
        }
        return Ok(TcpOutcome::Closed);
    }
    let _permit = permit;
    let (read, write) = tokio::io::split(stream);
    portal
        .forward
        .clone()
        .serve(
            Incoming::Tls {
                reader: Box::pin(read),
                writer: Box::pin(write),
                guard: TcpTunnelGuard { _flow: None },
            },
            CancellationToken::new(),
        )
        .await;
    Ok(TcpOutcome::Closed)
}

async fn wait_tls_claim<T>(
    stream: &mut (impl AsyncRead + Unpin),
    claimed: oneshot::Receiver<T>,
    expires_at: Instant,
    shutdown: &CancellationToken,
) -> Option<T> {
    let mut byte = [0];
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => None,
        _ = stream.read(&mut byte) => None,
        transfer = claimed => transfer.ok(),
        _ = tokio::time::sleep_until(expires_at) => None,
    }
}

struct QuicOwner(Arc<QuicConnection>);

impl Drop for QuicOwner {
    fn drop(&mut self) {
        self.0.close();
    }
}

pub(super) async fn quic(
    portal: Arc<PortalInner>,
    incoming: quinn::Incoming,
    admission: UnauthenticatedGuard,
) -> Result<()> {
    let connection = tokio::select! {
        biased;
        _ = portal.forward.shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout(portal.runtime.handshake_timeout, incoming) =>
            result.context("QUIC handshake timeout")??,
    };
    let result = quic_authenticated(portal, connection.clone(), admission).await;
    connection.close(0u32.into(), b"connection ended");
    result
}

async fn quic_authenticated(
    portal: Arc<PortalInner>,
    connection: quinn::Connection,
    admission: UnauthenticatedGuard,
) -> Result<()> {
    crate::vector::tls::require_quic_nw3(&connection)?;
    let authentication = tokio::time::timeout(portal.runtime.handshake_timeout, async {
        let authentication = async {
            let (send, mut recv) = connection.accept_bi().await?;
            if u64::from(recv.id()) != 0 {
                bail!("authentication must use first client Stream");
            }
            let mut exporter = [0; 32];
            connection
                .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, b"")
                .map_err(|e| anyhow::anyhow!("exporter failed: {e:?}"))?;
            let role = read_auth_frame(
                &mut recv,
                &portal.credentials,
                AuthTransport::Quic,
                &exporter,
            )
            .await?;
            Ok::<_, anyhow::Error>((send, recv, role))
        };
        tokio::pin!(authentication);
        let mut discarded = 0;
        loop {
            tokio::select! {
                biased;
                datagram=connection.read_datagram()=>{datagram?;discarded+=1;if discarded%64==0 {tokio::task::yield_now().await;}},
                result=&mut authentication=>break result,
            }
        }
    });
    let (mut send, mut recv, role) = tokio::select! {
        biased;
        _ = portal.forward.shutdown.cancelled() => return Ok(()),
        result = authentication => result.context("QUIC authentication timeout")??,
    };
    drop(admission);
    let limits = crate::transport::transport_flow_control()?;
    connection.set_receive_window(limits.connection_receive_window.into());
    if role == ConnectionRole::Vector {
        connection.set_max_concurrent_bi_streams(1024u32.into());
    }
    let q = QuicConnection::new(
        connection.clone(),
        role == ConnectionRole::Egress,
        portal.runtime.udp_queue_bytes,
    );
    let _connection_owner = QuicOwner(q.clone());
    let mut tasks = JoinSet::new();
    let _owner = if role == ConnectionRole::Egress {
        let Some(registry) = &portal.egress_registry else {
            bail!("Egress registration unavailable");
        };
        tokio::select! {
            biased;
            _ = portal.forward.shutdown.cancelled() => return Ok(()),
            result = tokio::time::timeout(portal.runtime.handshake_timeout, recv.read_to_end(0)) => {
                result.context("Egress authentication Stream timeout")??;
            },
        }
        tokio::select! {
            biased;
            _ = portal.forward.shutdown.cancelled() => return Ok(()),
            result = tokio::time::timeout(portal.runtime.handshake_timeout, async {
                send.write_all(&[0]).await?;
                send.finish()?;
                Ok::<_, anyhow::Error>(())
            }) => result.context("Egress registration timeout")??,
        }
        Some(registry.register_quic(q.clone()))
    } else {
        let forward = portal.forward.clone();
        let q = q.clone();
        tasks.spawn(async move {
            forward
                .serve(
                    Incoming::Quic {
                        recv,
                        send,
                        connection: q.clone(),
                    },
                    q.cancel.clone(),
                )
                .await;
        });
        None
    };
    loop {
        tokio::select! {
            _=portal.forward.shutdown.cancelled()=>break,
            _=q.cancel.cancelled()=>break,
            _=q.draining.cancelled()=>break,
            accepted=connection.accept_bi()=>match accepted {
                Ok((send,recv))=>{
                    if role==ConnectionRole::Egress {bail!("Egress opened a business Stream");}
                    let raw=u64::from(recv.id());
                    if raw&3!=0 {bail!("invalid Vector Stream direction");}
                    if q.flow_id(raw).is_err() {break;}
                    let forward=portal.forward.clone();let q=q.clone();
                    tasks.spawn(async move {forward.serve(Incoming::Quic {recv,send,connection:q.clone()},q.cancel.clone()).await;});
                },Err(_)=>break,
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
    if connection.close_reason().is_none() {
        let _ = tokio::time::timeout(crate::common::shutdown_timeout(), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
    }
    q.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
#[path = "../tests/portal/conn/standby.rs"]
mod tests;
