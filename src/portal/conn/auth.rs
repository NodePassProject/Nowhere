// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Connection-bound QUIC authentication and pre-authentication hardening.

use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::protocol::{AuthTransport, read_auth_frame};

use super::session::PortalSession;
use crate::portal::PortalInner;

const AUTH_EXPORTER_LABEL: &[u8] = b"EXPORTER-Nowhere-Auth";

/// QUIC close code and reason used for authentication failures.
pub(super) fn authentication_failure_close() -> (VarInt, &'static [u8]) {
    (VarInt::from_u32(1), b"access denied")
}

/// Authenticated state and the first bidi stream, which may continue directly
/// with a flow header after the fixed authentication frame.
pub(super) struct AuthenticatedConnection {
    pub(super) session: Arc<PortalSession>,
    pub(super) first_send: SendStream,
    pub(super) first_recv: RecvStream,
}

/// Result of the QUIC authentication phase.
pub(super) enum AuthenticationOutcome {
    Success(AuthenticatedConnection),
    Failure(anyhow::Error),
    Shutdown,
}

/// Authenticates the first bidirectional stream while discarding every
/// DATAGRAM received before authentication completes.
pub(super) async fn authenticate_connection(
    portal: Arc<PortalInner>,
    conn: Connection,
    deadline: Instant,
    shutdown: &CancellationToken,
) -> AuthenticationOutcome {
    let mut exporter = [0u8; 32];
    if let Err(err) = conn.export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, b"") {
        return AuthenticationOutcome::Failure(anyhow::anyhow!(
            "portal::conn::authenticate_connection: TLS exporter failed: {err:?}"
        ));
    }
    let auth_key = portal.credentials.auth_key;
    let auth = async {
        let (send, mut recv) = conn.accept_bi().await.map_err(|err| {
            anyhow::anyhow!(
                "portal::conn::authenticate_connection: failed to accept auth stream: {err}"
            )
        })?;
        let session_id = read_auth_frame(&mut recv, auth_key, AuthTransport::Quic, &exporter)
            .await
            .map_err(|err| {
                anyhow::anyhow!("portal::conn::authenticate_connection: failed to read auth: {err}")
            })?;
        anyhow::Ok((session_id, send, recv))
    };
    tokio::pin!(auth);

    let mut auth_pending = true;
    let mut datagrams_open = true;
    let mut auth_error = None;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return AuthenticationOutcome::Shutdown,
            _ = portal.drain.cancelled() => return AuthenticationOutcome::Shutdown,
            _ = sleep_until(deadline) => {
                return AuthenticationOutcome::Failure(auth_error.unwrap_or_else(|| {
                    anyhow::anyhow!(
                        "portal::conn::authenticate_connection: authentication deadline elapsed"
                    )
                }));
            }
            result = &mut auth, if auth_pending => {
                auth_pending = false;
                match result {
                    Ok((session_id, first_send, first_recv)) => {
                        // Establish a hard phase barrier before any flow can
                        // be installed: poll until Quinn reports no queued
                        // DATAGRAM, so no pre-auth backlog can enter a READY
                        // flow.
                        match drain_pre_auth_datagrams(
                            &conn,
                            deadline,
                            shutdown,
                            &portal.drain,
                        ).await {
                            PreAuthDrainOutcome::Complete => {}
                            PreAuthDrainOutcome::Deadline => {
                                return AuthenticationOutcome::Failure(anyhow::anyhow!(
                                    "portal::conn::authenticate_connection: pre-auth DATAGRAM drain deadline elapsed"
                                ));
                            }
                            PreAuthDrainOutcome::Shutdown => {
                                return AuthenticationOutcome::Shutdown;
                            }
                        }
                        return AuthenticationOutcome::Success(AuthenticatedConnection {
                            session: Arc::new(PortalSession::new(
                                portal.clone(),
                                conn.clone(),
                                session_id,
                            )),
                            first_send,
                            first_recv,
                        });
                    }
                    Err(err) => auth_error = Some(err),
                }
            }
            datagram = conn.read_datagram(), if datagrams_open => match datagram {
                Ok(_) => {
                    // Authentication is the resource boundary. Never retain
                    // or replay a DATAGRAM observed before it succeeds.
                }
                Err(_) => datagrams_open = false,
            },
        }
    }
}

enum PreAuthDrainOutcome {
    Complete,
    Deadline,
    Shutdown,
}

async fn drain_pre_auth_datagrams(
    conn: &Connection,
    deadline: Instant,
    shutdown: &CancellationToken,
    drain: &CancellationToken,
) -> PreAuthDrainOutcome {
    let waker = Waker::noop();
    let mut drained = 0usize;
    loop {
        let polled = {
            let read = conn.read_datagram();
            tokio::pin!(read);
            let mut context = Context::from_waker(waker);
            std::future::Future::poll(read.as_mut(), &mut context)
        };
        match polled {
            Poll::Ready(Ok(_)) => {
                drained += 1;
                if shutdown.is_cancelled() || drain.is_cancelled() {
                    return PreAuthDrainOutcome::Shutdown;
                }
                if Instant::now() >= deadline {
                    return PreAuthDrainOutcome::Deadline;
                }
                if drained.is_multiple_of(1_024) {
                    tokio::task::yield_now().await;
                }
            }
            Poll::Ready(Err(_)) | Poll::Pending => return PreAuthDrainOutcome::Complete,
        }
    }
}

/// Returns the fixed absolute authentication deadline.
pub(super) fn authentication_deadline(handshake_timeout: std::time::Duration) -> Instant {
    Instant::now() + handshake_timeout
}

/// Waits for the same auth deadline after a failed auth read.
pub(super) async fn wait_for_auth_deadline(
    deadline: Instant,
    shutdown: &CancellationToken,
    drain: &CancellationToken,
) -> bool {
    tokio::select! {
        _ = sleep_until(deadline) => true,
        _ = shutdown.cancelled() => false,
        _ = drain.cancelled() => false,
    }
}
