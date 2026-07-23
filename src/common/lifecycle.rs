// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared process lifecycle telemetry and Unix shutdown signals.

use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::{Context, Result};

use super::Logger;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifeMode {
    Portal,
    Vector,
}

impl fmt::Display for LifeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Portal => "PORTAL",
            Self::Vector => "VECTOR",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum LifeState {
    Starting = 0,
    Ready = 1,
    Draining = 2,
    Stopped = 3,
}

impl fmt::Display for LifeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Starting => "STARTING",
            Self::Ready => "READY",
            Self::Draining => "DRAINING",
            Self::Stopped => "STOPPED",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifeReason {
    Startup,
    Listening,
    SigInt,
    SigTerm,
    TcpListenerExit,
    QuicListenerExit,
    SocksListenerExit,
    Drained,
    CleanupComplete,
    Timeout,
    Forced,
    StartFailed,
}

impl fmt::Display for LifeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Startup => "STARTUP",
            Self::Listening => "LISTENING",
            Self::SigInt => "SIGINT",
            Self::SigTerm => "SIGTERM",
            Self::TcpListenerExit => "TCP_LISTENER_EXIT",
            Self::QuicListenerExit => "QUIC_LISTENER_EXIT",
            Self::SocksListenerExit => "SOCKS_LISTENER_EXIT",
            Self::Drained => "DRAINED",
            Self::CleanupComplete => "CLEANUP_COMPLETE",
            Self::Timeout => "TIMEOUT",
            Self::Forced => "FORCED",
            Self::StartFailed => "START_FAILED",
        })
    }
}

/// Private lifecycle state with transition-only machine-readable telemetry.
pub(crate) struct Lifecycle {
    mode: LifeMode,
    // u8::MAX represents the pre-STARTING state so the first transition emits.
    state: AtomicU8,
}

impl Lifecycle {
    pub(crate) fn new(mode: LifeMode) -> Self {
        Self {
            mode,
            state: AtomicU8::new(u8::MAX),
        }
    }

    pub(crate) fn transition(&self, logger: &Logger, state: LifeState, reason: LifeReason) {
        if self.state.swap(state as u8, Ordering::AcqRel) == state as u8 {
            return;
        }
        logger.event(format_args!(
            "LIFE_STATUS|MODE={}|STATE={state}|REASON={reason}",
            self.mode
        ));
    }
}

/// Reusable signal receiver so a second signal can force an in-progress shutdown.
pub(crate) struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    pub(crate) fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            Ok(Self {
                interrupt: signal(SignalKind::interrupt())
                    .context("common::lifecycle: failed to install SIGINT handler")?,
                terminate: signal(SignalKind::terminate())
                    .context("common::lifecycle: failed to install SIGTERM handler")?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    pub(crate) async fn recv(&mut self) -> Result<LifeReason> {
        #[cfg(unix)]
        {
            tokio::select! {
                value = self.interrupt.recv() => {
                    value.ok_or_else(|| anyhow::anyhow!("common::lifecycle: SIGINT stream closed"))?;
                    Ok(LifeReason::SigInt)
                }
                value = self.terminate.recv() => {
                    value.ok_or_else(|| anyhow::anyhow!("common::lifecycle: SIGTERM stream closed"))?;
                    Ok(LifeReason::SigTerm)
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .context("common::lifecycle: failed to install Ctrl-C handler")?;
            Ok(LifeReason::SigInt)
        }
    }
}

#[cfg(test)]
#[path = "../tests/common/lifecycle.rs"]
mod tests;
