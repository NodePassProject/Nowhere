// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Session-global logical-flow registry and bounded half pairing.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, OwnedSemaphorePermit};

use crate::protocol::{
    Carrier, FlowErrorCode, FlowHeader, FlowKind, FlowResult, FlowRole, Target, write_flow_result,
};

mod lifecycle;
mod link;
mod state;
mod tcp;
mod udp;

pub(in crate::portal) use self::link::LinkGuard;
pub(super) use self::link::{guarded_reader, guarded_writer};
pub(super) use self::state::{
    BoxReader, BoxWriter, FlowLease, LinkHalf, LinkPath, PairedTcp, PairedUdp, QuicUdpReceiver,
    SessionKey, UdpDown, UdpHalf, UdpUp,
};
use self::state::{FlowClaim, FlowKey, LinkCounts, Metadata, PendingTcp, PendingUdp};
use self::tcp::reject_tcp_writer;
use self::udp::reject_udp_downlink_ref;

const FLOW_RESULT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct TerminalRejection {
    code: FlowErrorCode,
    expires_at: Instant,
}

#[derive(Debug)]
pub(super) struct PairingError {
    code: FlowErrorCode,
    message: &'static str,
}

impl PairingError {
    fn new(code: FlowErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(super) fn code(&self) -> FlowErrorCode {
        self.code
    }
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for PairingError {}

pub(super) struct PairingRegistry {
    pub(super) tcp: Mutex<HashMap<FlowKey, PendingTcp>>,
    pub(super) udp: Mutex<HashMap<FlowKey, PendingUdp>>,
    pub(super) links: StdMutex<HashMap<SessionKey, LinkCounts>>,
    claims: StdMutex<HashMap<FlowKey, FlowClaim>>,
    rejections: StdMutex<HashMap<FlowKey, TerminalRejection>>,
    accepting: AtomicBool,
    pub(super) next_quic_generation: AtomicU64,
    next_epoch: AtomicU64,
    pub(super) max_pending: usize,
    pub(super) timeout: Duration,
    pub(super) max_tcp_flows: usize,
    pub(super) max_udp_flows: usize,
}

impl PairingRegistry {
    pub(super) fn new(
        max_tcp_flows: usize,
        max_udp_flows: usize,
        max_pending: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            links: StdMutex::new(HashMap::new()),
            claims: StdMutex::new(HashMap::new()),
            rejections: StdMutex::new(HashMap::new()),
            accepting: AtomicBool::new(true),
            next_quic_generation: AtomicU64::new(1),
            next_epoch: AtomicU64::new(1),
            max_pending,
            timeout,
            max_tcp_flows,
            max_udp_flows,
        }
    }

    fn active_quic_generation(&self, session_id: SessionKey) -> Option<u64> {
        self.links
            .lock()
            .expect("link registry poisoned")
            .get(&session_id)
            .and_then(|counts| counts.udp.as_ref().map(|active| active.generation))
    }

    fn validate_current_link_locked(
        &self,
        session_id: SessionKey,
        link: &LinkHalf,
        links: &HashMap<SessionKey, LinkCounts>,
    ) -> Result<(), PairingError> {
        let current = links.get(&session_id);
        let valid = match link.quic_generation {
            Some(generation) => current
                .and_then(|counts| counts.udp.as_ref())
                .is_some_and(|active| active.generation == generation),
            None => current.is_some_and(|counts| counts.tcp > 0),
        };
        if valid {
            Ok(())
        } else {
            Err(PairingError::new(
                FlowErrorCode::SessionReplaced,
                "portal::pairing: carrier replaced before flow installation",
            ))
        }
    }

    fn validate_header_and_link(
        &self,
        session_id: SessionKey,
        header: FlowHeader,
        expected_kind: FlowKind,
        target: Option<&Target>,
        link: &LinkHalf,
    ) -> Result<(), PairingError> {
        if link.path.version != session_id.version {
            return Err(PairingError::new(
                FlowErrorCode::MetadataConflict,
                "portal::pairing: carrier protocol version mismatch",
            ));
        }
        if header.kind != expected_kind {
            return Err(PairingError::new(
                FlowErrorCode::InvalidRequest,
                "portal::pairing: flow kind mismatch",
            ));
        }
        match header.role {
            FlowRole::Open | FlowRole::Duplex if target.is_none() => {
                return Err(PairingError::new(
                    FlowErrorCode::InvalidRequest,
                    "portal::pairing: missing target",
                ));
            }
            FlowRole::Attach if target.is_some() => {
                return Err(PairingError::new(
                    FlowErrorCode::InvalidRequest,
                    "portal::pairing: attach target",
                ));
            }
            _ => {}
        }
        let carrier = match header.role {
            FlowRole::Open => header.uplink,
            FlowRole::Attach => header.downlink,
            FlowRole::Duplex => header.uplink,
        };
        let uses_quic = carrier == Carrier::Quic;
        if uses_quic != link.quic_generation.is_some()
            || link.quic_generation.is_some_and(|generation| {
                self.active_quic_generation(session_id) != Some(generation)
            })
        {
            return Err(PairingError::new(
                FlowErrorCode::SessionReplaced,
                "portal::pairing: stale or missing QUIC generation",
            ));
        }
        Ok(())
    }

    fn reserve_claim(
        &self,
        key: FlowKey,
        metadata: Metadata,
        target: Option<Target>,
        quic_generation: Option<u64>,
    ) -> Result<(u64, bool), PairingError> {
        let mut claims = self.claims.lock().expect("flow claim registry poisoned");
        // The claims lock is the drain/admission linearization point. Once
        // draining flips this flag while holding the same lock, neither an
        // OPEN nor a late ATTACH can create or complete another flow.
        if !self.accepting.load(Ordering::Acquire) {
            return Err(PairingError::new(
                FlowErrorCode::FlowLimit,
                "portal::pairing: portal is draining",
            ));
        }
        if let Some(claim) = claims.get_mut(&key) {
            if claim.active || claim.metadata != metadata {
                return Err(PairingError::new(
                    FlowErrorCode::MetadataConflict,
                    "portal::pairing: flow id metadata collision",
                ));
            }
            if let (Some(existing), Some(incoming)) = (&claim.target, &target)
                && existing != incoming
            {
                return Err(PairingError::new(
                    FlowErrorCode::MetadataConflict,
                    "portal::pairing: conflicting flow target",
                ));
            }
            if claim.target.is_none() {
                claim.target = target;
            }
            if let Some(generation) = quic_generation
                && !claim.quic_generations.contains(&generation)
            {
                claim.quic_generations.push(generation);
            }
            return Ok((claim.epoch, false));
        }
        if metadata.kind == FlowKind::Tcp
            && claims
                .iter()
                .filter(|(flow, claim)| {
                    flow.session_id == key.session_id && claim.metadata.kind == FlowKind::Tcp
                })
                .count()
                >= self.max_tcp_flows
        {
            return Err(PairingError::new(
                FlowErrorCode::FlowLimit,
                "portal::pairing: TCP flow limit reached",
            ));
        }
        if claims
            .iter()
            .filter(|(flow, claim)| flow.session_id == key.session_id && !claim.active)
            .count()
            >= self.max_pending
        {
            return Err(PairingError::new(
                FlowErrorCode::FlowLimit,
                "portal::pairing: pending flow limit reached",
            ));
        }
        let epoch = self.next_epoch.fetch_add(1, Ordering::Relaxed);
        claims.insert(
            key,
            FlowClaim {
                epoch,
                metadata,
                target,
                active: false,
                cancel: tokio_util::sync::CancellationToken::new(),
                quic_generations: quic_generation.into_iter().collect(),
            },
        );
        Ok((epoch, true))
    }

    fn refresh_claim(&self, key: FlowKey) -> Result<u64, PairingError> {
        let epoch = self.next_epoch.fetch_add(1, Ordering::Relaxed);
        let mut claims = self.claims.lock().expect("flow claim registry poisoned");
        let claim = claims.get_mut(&key).ok_or_else(|| {
            PairingError::new(
                FlowErrorCode::InternalError,
                "portal::pairing: missing pending flow claim",
            )
        })?;
        claim.epoch = epoch;
        Ok(epoch)
    }

    fn abandon_claim(&self, key: FlowKey, epoch: u64) {
        let mut claims = self.claims.lock().expect("flow claim registry poisoned");
        if claims
            .get(&key)
            .is_some_and(|claim| !claim.active && claim.epoch == epoch)
        {
            claims.remove(&key);
        }
    }

    fn activate_claim(
        self: &Arc<Self>,
        key: FlowKey,
        epoch: u64,
        quic_generations: Vec<u64>,
        udp_permit: Option<Arc<OwnedSemaphorePermit>>,
    ) -> Result<FlowLease, PairingError> {
        // `links -> claims` is the linearization barrier shared with QUIC
        // replacement.  A generation cannot become active after it has been
        // replaced, and replacement cannot miss a claim that just activated.
        let links = self.links.lock().expect("link registry poisoned");
        let active_generation = links
            .get(&key.session_id)
            .and_then(|counts| counts.udp.as_ref().map(|active| active.generation));
        if quic_generations
            .iter()
            .any(|generation| Some(*generation) != active_generation)
        {
            return Err(PairingError::new(
                FlowErrorCode::SessionReplaced,
                "portal::pairing: QUIC generation replaced before activation",
            ));
        }
        let cancel = {
            let mut claims = self.claims.lock().expect("flow claim registry poisoned");
            if !self.accepting.load(Ordering::Acquire) {
                return Err(PairingError::new(
                    FlowErrorCode::FlowLimit,
                    "portal::pairing: portal is draining",
                ));
            }
            let claim = claims.get_mut(&key).ok_or_else(|| {
                PairingError::new(
                    FlowErrorCode::InternalError,
                    "portal::pairing: missing flow claim",
                )
            })?;
            claim.epoch = epoch;
            claim.active = true;
            // A pending claim can survive a QUIC-carrier replacement while its
            // TLS/TCP half remains valid.  Once pairing completes, ownership
            // must describe only the carriers that formed this flow; otherwise
            // dropping the replaced carrier can cancel the new flow.
            claim.quic_generations = quic_generations;
            claim.cancel.clone()
        };
        drop(links);
        Ok(FlowLease {
            registry: Arc::downgrade(self),
            key,
            epoch,
            cancel,
            _udp_permit: udp_permit,
        })
    }

    fn acquire_udp_permit(
        &self,
        session_id: SessionKey,
    ) -> Result<Arc<OwnedSemaphorePermit>, PairingError> {
        let budget = self
            .links
            .lock()
            .expect("link registry poisoned")
            .get(&session_id)
            .map(|counts| counts.udp_flow_budget.clone())
            .ok_or_else(|| {
                PairingError::new(
                    FlowErrorCode::SessionReplaced,
                    "portal::pairing: missing authenticated session",
                )
            })?;
        budget.try_acquire_owned().map(Arc::new).map_err(|_| {
            PairingError::new(
                FlowErrorCode::FlowLimit,
                "portal::pairing: UDP flow limit reached",
            )
        })
    }

    fn terminal_rejection(&self, key: FlowKey, consume: bool) -> Option<FlowErrorCode> {
        let now = Instant::now();
        let mut rejections = self
            .rejections
            .lock()
            .expect("flow rejection registry poisoned");
        rejections.retain(|_, rejection| rejection.expires_at > now);
        if consume {
            rejections.remove(&key).map(|rejection| rejection.code)
        } else {
            rejections.get(&key).map(|rejection| rejection.code)
        }
    }

    /// Terminates a setup attempt and delivers the exact failure to an already
    /// selected downlink.  If OPEN failed before ATTACH arrived, retain a short
    /// tombstone so the later selected downlink receives the same result.
    pub(super) async fn reject_flow_setup<S: Into<SessionKey>>(
        self: &Arc<Self>,
        session_id: S,
        flow_id: u32,
        code: FlowErrorCode,
    ) {
        let session_id = session_id.into();
        let key = FlowKey {
            session_id,
            flow_id,
        };
        let (mut tcp_downlink, udp_downlink) = {
            let mut tcp = self.tcp.lock().await;
            let mut udp = self.udp.lock().await;
            let mut claims = self.claims.lock().expect("flow claim registry poisoned");
            if claims.get(&key).is_some_and(|claim| claim.active) {
                return;
            }
            let tcp_downlink = tcp.remove(&key).and_then(|mut flow| flow.downlink.take());
            let udp_downlink = udp.remove(&key).and_then(|mut flow| flow.downlink.take());
            claims.remove(&key);
            if tcp_downlink.is_none() && udp_downlink.is_none() {
                let expires_at = Instant::now() + self.timeout;
                let mut rejections = self
                    .rejections
                    .lock()
                    .expect("flow rejection registry poisoned");
                let now = Instant::now();
                rejections.retain(|_, rejection| rejection.expires_at > now);
                if !rejections.contains_key(&key)
                    && rejections.len() >= self.max_pending
                    && let Some(oldest) = rejections
                        .iter()
                        .min_by_key(|(_, rejection)| rejection.expires_at)
                        .map(|(key, _)| *key)
                {
                    rejections.remove(&oldest);
                }
                rejections.insert(key, TerminalRejection { code, expires_at });
            }
            (tcp_downlink, udp_downlink)
        };
        reject_tcp_writer(&mut tcp_downlink, code).await;
        if let Some(mut downlink) = udp_downlink {
            reject_udp_downlink_ref(&mut downlink, code).await;
        }
    }
}

#[cfg(test)]
#[path = "../tests/portal/pairing.rs"]
mod tests;
