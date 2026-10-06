// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Direct, SOCKS5, or native Portal upstream target establishment.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::time::Instant;

use crate::common::{DialPolicy, OutboundDialer};
use crate::protocol::{MAX_PORTAL_HOPS, SetupResult, Target};
use crate::vector::{OpenFlowError, PortalClient};

mod tcp;
mod udp;

pub(super) use tcp::PortalTcpStream;
pub(super) use udp::PortalUdpTarget;

pub(super) enum PortalOutbound {
    Network(OutboundDialer),
    Portal(Arc<PortalClient>),
}

impl PortalOutbound {
    pub(super) fn network(dialer: OutboundDialer) -> Self {
        Self::Network(dialer)
    }

    pub(super) fn portal(client: Arc<PortalClient>) -> Self {
        Self::Portal(client)
    }

    pub(super) async fn dial_tcp_target(
        &self,
        target: &Target,
        incoming_hops: u8,
        timeout: Duration,
    ) -> Result<PortalTcpStream, OutboundError> {
        match self {
            Self::Network(dialer) => dialer
                .dial_tcp_target(target, timeout)
                .await
                .map(PortalTcpStream::Network)
                .map_err(OutboundError::transport),
            Self::Portal(client) => {
                let hops = forwarded_hops(incoming_hops)?;
                client
                    .open_tcp(target, hops)
                    .await
                    .map(PortalTcpStream::Portal)
                    .map_err(OutboundError::flow)
            }
        }
    }

    pub(super) async fn dial_udp_target(
        &self,
        target: &Target,
        incoming_hops: u8,
        timeout: Duration,
    ) -> Result<PortalUdpTarget, OutboundError> {
        match self {
            Self::Network(dialer) => dialer
                .dial_udp_target(target, timeout)
                .await
                .map(PortalUdpTarget::Network)
                .map_err(OutboundError::transport),
            Self::Portal(client) => {
                let hops = forwarded_hops(incoming_hops)?;
                client
                    .open_udp(target, hops)
                    .await
                    .map(PortalUdpTarget::Portal)
                    .map_err(OutboundError::flow)
            }
        }
    }

    pub(super) fn dial_policy(&self) -> &DialPolicy {
        match self {
            Self::Network(dialer) => dialer.dial_policy(),
            Self::Portal(client) => client.dial_policy(),
        }
    }

    pub(super) fn socks_endpoint(&self) -> String {
        match self {
            Self::Network(dialer) => dialer.socks_endpoint(),
            Self::Portal(_) => "none".to_owned(),
        }
    }

    pub(super) fn next_endpoint(&self) -> String {
        match self {
            Self::Network(_) => "none".to_owned(),
            Self::Portal(client) => client.endpoint(),
        }
    }

    pub(super) fn next_transport(&self) -> Option<String> {
        match self {
            Self::Network(_) => None,
            Self::Portal(client) => Some(client.effective_route()),
        }
    }

    pub(super) fn ping_ms(&self) -> u64 {
        match self {
            Self::Network(dialer) => dialer.ping_ms(),
            Self::Portal(client) => client.ping_ms(),
        }
    }

    pub(super) async fn refresh_latency(&self) {
        if let Self::Portal(client) = self {
            client.refresh_latency().await;
        }
    }

    pub(super) async fn close(&self, deadline: Instant) {
        if let Self::Portal(client) = self {
            client.close(deadline).await;
        }
    }
}

fn forwarded_hops(incoming: u8) -> Result<u8, OutboundError> {
    match incoming {
        0 => Ok(MAX_PORTAL_HOPS),
        1 => Err(OutboundError::setup(SetupResult::FlowLimit)),
        value => Ok(value - 1),
    }
}

pub(super) struct OutboundError {
    setup: Option<SetupResult>,
    error: anyhow::Error,
}

impl OutboundError {
    fn setup(result: SetupResult) -> Self {
        Self {
            setup: Some(result),
            error: anyhow!("upstream flow rejected: {}", result.as_str()),
        }
    }

    fn flow(error: OpenFlowError) -> Self {
        let setup = error.setup_result();
        let error = match error {
            OpenFlowError::Setup(result) => anyhow!("flow setup rejected: {}", result.as_str()),
            OpenFlowError::Transport(error) | OpenFlowError::Protocol(error) => error,
        };
        Self { setup, error }
    }

    fn transport(error: impl Into<anyhow::Error>) -> Self {
        Self {
            setup: None,
            error: error.into(),
        }
    }

    pub(super) fn setup_result(&self) -> Option<SetupResult> {
        self.setup
    }
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::fmt::Debug for OutboundError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for OutboundError {}

#[cfg(test)]
#[path = "../tests/portal/outbound.rs"]
mod tests;
