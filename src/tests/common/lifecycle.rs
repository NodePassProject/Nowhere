// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Lifecycle vocabulary and transition tests.

use super::*;
use crate::common::{LogLevel, Logger};

impl Lifecycle {
    pub(crate) fn state(&self) -> Option<LifeState> {
        match self.state.load(std::sync::atomic::Ordering::Acquire) {
            value if value == LifeState::Starting as u8 => Some(LifeState::Starting),
            value if value == LifeState::Ready as u8 => Some(LifeState::Ready),
            value if value == LifeState::Draining as u8 => Some(LifeState::Draining),
            value if value == LifeState::Stopped as u8 => Some(LifeState::Stopped),
            _ => None,
        }
    }
}

#[test]
fn lifecycle_vocabulary_is_stable() {
    assert_eq!(LifeMode::Portal.to_string(), "PORTAL");
    assert_eq!(LifeMode::Vector.to_string(), "VECTOR");
    assert_eq!(LifeState::Starting.to_string(), "STARTING");
    assert_eq!(LifeState::Ready.to_string(), "READY");
    assert_eq!(LifeState::Draining.to_string(), "DRAINING");
    assert_eq!(LifeState::Stopped.to_string(), "STOPPED");

    let reasons = [
        (LifeReason::Startup, "STARTUP"),
        (LifeReason::Listening, "LISTENING"),
        (LifeReason::SigInt, "SIGINT"),
        (LifeReason::SigTerm, "SIGTERM"),
        (LifeReason::TcpListenerExit, "TCP_LISTENER_EXIT"),
        (LifeReason::QuicListenerExit, "QUIC_LISTENER_EXIT"),
        (LifeReason::SocksListenerExit, "SOCKS_LISTENER_EXIT"),
        (LifeReason::Drained, "DRAINED"),
        (LifeReason::CleanupComplete, "CLEANUP_COMPLETE"),
        (LifeReason::Timeout, "TIMEOUT"),
        (LifeReason::Forced, "FORCED"),
        (LifeReason::StartFailed, "START_FAILED"),
    ];
    for (reason, expected) in reasons {
        assert_eq!(reason.to_string(), expected);
    }
}

#[test]
fn lifecycle_records_only_the_current_state() {
    let lifecycle = Lifecycle::new(LifeMode::Portal);
    let logger = Logger::new(LogLevel::None, false);
    assert_eq!(lifecycle.state(), None);

    lifecycle.transition(&logger, LifeState::Starting, LifeReason::Startup);
    lifecycle.transition(&logger, LifeState::Starting, LifeReason::StartFailed);
    assert_eq!(lifecycle.state(), Some(LifeState::Starting));

    lifecycle.transition(&logger, LifeState::Ready, LifeReason::Listening);
    lifecycle.transition(&logger, LifeState::Draining, LifeReason::SigTerm);
    lifecycle.transition(&logger, LifeState::Stopped, LifeReason::Drained);
    assert_eq!(lifecycle.state(), Some(LifeState::Stopped));
}
