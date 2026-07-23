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
    Carrier, FlowErrorCode, FlowHeader, FlowKind, FlowResult, FlowRole, SessionId, Target,
    write_flow_result,
};

mod link;
mod state;

pub(super) use self::link::{guarded_reader, guarded_writer};
pub(super) use self::state::{
    BoxReader, BoxWriter, FlowLease, LinkHalf, LinkPath, PairedTcp, PairedUdp, QuicUdpReceiver,
    UdpDown, UdpHalf, UdpUp,
};
use self::state::{FlowClaim, FlowKey, LinkCounts, Metadata, PendingTcp, PendingUdp};

const FLOW_RESULT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct TerminalRejection {
    code: FlowErrorCode,
    expires_at: Instant,
}

enum TcpInstallOutcome {
    Pending(u64),
    Paired(Box<PairedTcp>),
    Rejected {
        error: PairingError,
        downlink: Option<BoxWriter>,
        abort_pending: bool,
    },
}

enum UdpInstallOutcome {
    Pending(u64),
    Paired(Box<PairedUdp>),
    Rejected {
        error: PairingError,
        downlink: Option<UdpDown>,
        abort_pending: bool,
    },
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
    pub(super) links: StdMutex<HashMap<SessionId, LinkCounts>>,
    claims: StdMutex<HashMap<FlowKey, FlowClaim>>,
    rejections: StdMutex<HashMap<FlowKey, TerminalRejection>>,
    accepting: AtomicBool,
    pub(super) next_quic_generation: AtomicU64,
    next_epoch: AtomicU64,
    pub(super) max_pending: usize,
    pub(super) timeout: Duration,
    pub(super) max_udp_flows: usize,
}

impl PairingRegistry {
    pub(super) fn new(max_udp_flows: usize, max_pending: usize, timeout: Duration) -> Self {
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
            max_udp_flows,
        }
    }

    fn active_quic_generation(&self, session_id: SessionId) -> Option<u64> {
        self.links
            .lock()
            .expect("link registry poisoned")
            .get(&session_id)
            .and_then(|counts| counts.udp.as_ref().map(|active| active.generation))
    }

    fn validate_current_link_locked(
        &self,
        session_id: SessionId,
        link: &LinkHalf,
        links: &HashMap<SessionId, LinkCounts>,
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
        session_id: SessionId,
        header: FlowHeader,
        expected_kind: FlowKind,
        target: Option<&Target>,
        link: &LinkHalf,
    ) -> Result<(), PairingError> {
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
        session_id: SessionId,
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
    pub(super) async fn reject_flow_setup(
        self: &Arc<Self>,
        session_id: SessionId,
        flow_id: u32,
        code: FlowErrorCode,
    ) {
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

    #[allow(
        clippy::too_many_arguments,
        reason = "the registry boundary keeps each owned stream half explicit"
    )]
    pub(super) async fn submit_tcp(
        self: &Arc<Self>,
        session_id: SessionId,
        header: FlowHeader,
        target: Option<Target>,
        link: LinkHalf,
        reader: Option<BoxReader>,
        mut writer: Option<BoxWriter>,
        downlink_liveness: Option<BoxReader>,
    ) -> Result<Option<PairedTcp>, PairingError> {
        if let Err(err) =
            self.validate_header_and_link(session_id, header, FlowKind::Tcp, target.as_ref(), &link)
        {
            if header.role == FlowRole::Open {
                self.reject_flow_setup(session_id, header.flow_id, err.code())
                    .await;
            }
            reject_tcp_writer(&mut writer, err.code()).await;
            return Err(err);
        }
        let shape_valid = match header.role {
            FlowRole::Open => reader.is_some(),
            FlowRole::Attach => writer.is_some(),
            FlowRole::Duplex => reader.is_some() && writer.is_some(),
        };
        if !shape_valid {
            let err = PairingError::new(
                FlowErrorCode::InvalidRequest,
                "portal::pairing: missing TCP stream half",
            );
            if header.role == FlowRole::Open {
                self.reject_flow_setup(session_id, header.flow_id, err.code())
                    .await;
            }
            reject_tcp_writer(&mut writer, err.code()).await;
            return Err(err);
        }
        let key = FlowKey {
            session_id,
            flow_id: header.flow_id,
        };
        let metadata = Metadata {
            kind: header.kind,
            uplink: header.uplink,
            downlink: header.downlink,
        };
        if header.role == FlowRole::Duplex {
            if let Some(code) = self.terminal_rejection(key, true) {
                let err = PairingError::new(code, "portal::pairing: terminal flow rejection");
                reject_tcp_writer(&mut writer, code).await;
                return Err(err);
            }
            let (claim_epoch, created) = match self.reserve_claim(
                key,
                metadata.clone(),
                target.clone(),
                link.quic_generation,
            ) {
                Ok(claim) => claim,
                Err(err) => {
                    reject_tcp_writer(&mut writer, err.code()).await;
                    return Err(err);
                }
            };
            if !created {
                let err = PairingError::new(
                    FlowErrorCode::MetadataConflict,
                    "portal::pairing: duplicate TCP flow id",
                );
                reject_tcp_writer(&mut writer, err.code()).await;
                return Err(err);
            }
            let uplink = reader.expect("duplex TCP reader validated");
            let downlink = writer.take().expect("duplex TCP writer validated");
            let generations = link.quic_generation.into_iter().collect();
            let lease = match self.activate_claim(key, claim_epoch, generations, None) {
                Ok(lease) => lease,
                Err(err) => {
                    self.abandon_claim(key, claim_epoch);
                    let mut writer = Some(downlink);
                    reject_tcp_writer(&mut writer, err.code()).await;
                    return Err(err);
                }
            };
            return Ok(Some(PairedTcp {
                target: target.expect("duplex target validated"),
                uplink,
                downlink,
                downlink_liveness,
                uplink_carrier: header.uplink,
                downlink_carrier: header.downlink,
                uplink_path: link.path.clone(),
                downlink_path: link.path,
                _flow_lease: lease,
            }));
        }

        let outcome = 'install: {
            let mut guard = self.tcp.lock().await;
            let links = self.links.lock().expect("link registry poisoned");
            if let Err(error) = self.validate_current_link_locked(session_id, &link, &links) {
                break 'install TcpInstallOutcome::Rejected {
                    error,
                    downlink: writer.take(),
                    abort_pending: header.role == FlowRole::Open,
                };
            }
            let active_generation = links
                .get(&session_id)
                .and_then(|counts| counts.udp.as_ref().map(|active| active.generation));
            let mut stale_snapshot = None;
            let mut remove_stale = false;
            if let Some(pending) = guard.get_mut(&key) {
                if pending.metadata.uplink == Carrier::Quic
                    && pending.uplink_generation != active_generation
                {
                    pending.uplink = None;
                    pending.target = None;
                    pending.uplink_path = None;
                    pending.uplink_generation = None;
                }
                if pending.metadata.downlink == Carrier::Quic
                    && pending.downlink_generation != active_generation
                {
                    pending.downlink = None;
                    pending.downlink_liveness = None;
                    pending.downlink_path = None;
                    pending.downlink_generation = None;
                }
                remove_stale = pending.uplink.is_none() && pending.downlink.is_none();
                if !remove_stale {
                    stale_snapshot = Some((
                        pending.target.clone(),
                        [pending.uplink_generation, pending.downlink_generation]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>(),
                    ));
                }
            }
            if remove_stale {
                guard.remove(&key);
            }
            if remove_stale || stale_snapshot.is_some() {
                let mut claims = self.claims.lock().expect("flow claim registry poisoned");
                if remove_stale {
                    if claims.get(&key).is_some_and(|claim| !claim.active) {
                        claims.remove(&key);
                    }
                } else if let (Some(claim), Some((target, generations))) =
                    (claims.get_mut(&key), stale_snapshot)
                    && !claim.active
                {
                    claim.target = target;
                    claim.quic_generations = generations;
                }
            }
            if let Some(code) = self.terminal_rejection(key, header.role == FlowRole::Attach) {
                break 'install TcpInstallOutcome::Rejected {
                    error: PairingError::new(code, "portal::pairing: terminal flow rejection"),
                    downlink: writer.take(),
                    abort_pending: false,
                };
            }
            let (claim_epoch, _) = match self.reserve_claim(
                key,
                metadata.clone(),
                target.clone(),
                link.quic_generation,
            ) {
                Ok(claim) => claim,
                Err(error) => {
                    break 'install TcpInstallOutcome::Rejected {
                        error,
                        downlink: writer.take(),
                        abort_pending: true,
                    };
                }
            };
            let pending = guard.entry(key).or_insert_with(|| PendingTcp {
                epoch: claim_epoch,
                metadata: metadata.clone(),
                quic_snapshot: active_generation,
                target: target.clone(),
                uplink: None,
                downlink: None,
                downlink_liveness: None,
                uplink_path: None,
                downlink_path: None,
                uplink_generation: None,
                downlink_generation: None,
            });
            if pending.metadata != metadata {
                break 'install TcpInstallOutcome::Rejected {
                    error: PairingError::new(
                        FlowErrorCode::MetadataConflict,
                        "portal::pairing: conflicting TCP flow metadata",
                    ),
                    downlink: writer.take(),
                    abort_pending: true,
                };
            }
            if pending.target.is_none() {
                pending.target = target;
            }
            match header.role {
                FlowRole::Open => {
                    if pending.uplink.is_some() {
                        break 'install TcpInstallOutcome::Rejected {
                            error: PairingError::new(
                                FlowErrorCode::MetadataConflict,
                                "portal::pairing: duplicate TCP uplink",
                            ),
                            downlink: None,
                            abort_pending: true,
                        };
                    }
                    pending.uplink = reader;
                    pending.uplink_path = Some(link.path);
                    pending.uplink_generation = link.quic_generation;
                }
                FlowRole::Attach => {
                    if pending.downlink.is_some() {
                        break 'install TcpInstallOutcome::Rejected {
                            error: PairingError::new(
                                FlowErrorCode::MetadataConflict,
                                "portal::pairing: duplicate TCP downlink",
                            ),
                            downlink: writer.take(),
                            abort_pending: true,
                        };
                    }
                    pending.downlink = writer.take();
                    pending.downlink_liveness = downlink_liveness;
                    pending.downlink_path = Some(link.path);
                    pending.downlink_generation = link.quic_generation;
                }
                FlowRole::Duplex => unreachable!(),
            }
            if pending.uplink.is_some() && pending.downlink.is_some() {
                let mut complete = guard.remove(&key).expect("TCP pair exists");
                let epoch = complete.epoch;
                let generations = [complete.uplink_generation, complete.downlink_generation]
                    .into_iter()
                    .flatten()
                    .collect();
                drop(links);
                drop(guard);
                let lease = match self.activate_claim(key, epoch, generations, None) {
                    Ok(lease) => lease,
                    Err(error) => {
                        self.abandon_claim(key, epoch);
                        break 'install TcpInstallOutcome::Rejected {
                            error,
                            downlink: complete.downlink.take(),
                            abort_pending: false,
                        };
                    }
                };
                break 'install TcpInstallOutcome::Paired(Box::new(PairedTcp {
                    target: complete.target.take().expect("TCP target paired"),
                    uplink: complete.uplink.take().expect("TCP uplink paired"),
                    downlink: complete.downlink.take().expect("TCP downlink paired"),
                    downlink_liveness: complete.downlink_liveness.take(),
                    uplink_carrier: complete.metadata.uplink,
                    downlink_carrier: complete.metadata.downlink,
                    uplink_path: complete.uplink_path.take().expect("TCP uplink path paired"),
                    downlink_path: complete
                        .downlink_path
                        .take()
                        .expect("TCP downlink path paired"),
                    _flow_lease: lease,
                }));
            }
            let epoch = match self.refresh_claim(key) {
                Ok(epoch) => epoch,
                Err(error) => {
                    let downlink = guard
                        .remove(&key)
                        .and_then(|mut pending| pending.downlink.take());
                    break 'install TcpInstallOutcome::Rejected {
                        error,
                        downlink,
                        abort_pending: true,
                    };
                }
            };
            pending.epoch = epoch;
            TcpInstallOutcome::Pending(epoch)
        };
        match outcome {
            TcpInstallOutcome::Pending(epoch) => {
                self.spawn_tcp_timeout(key, epoch);
                Ok(None)
            }
            TcpInstallOutcome::Paired(paired) => Ok(Some(*paired)),
            TcpInstallOutcome::Rejected {
                error,
                mut downlink,
                abort_pending,
            } => {
                if abort_pending {
                    self.reject_flow_setup(session_id, header.flow_id, error.code())
                        .await;
                }
                reject_tcp_writer(&mut downlink, error.code()).await;
                Err(error)
            }
        }
    }

    pub(super) async fn submit_udp(
        self: &Arc<Self>,
        session_id: SessionId,
        header: FlowHeader,
        target: Option<Target>,
        link: LinkHalf,
        mut half: UdpHalf,
    ) -> Result<Option<PairedUdp>, PairingError> {
        if let Err(err) =
            self.validate_header_and_link(session_id, header, FlowKind::Udp, target.as_ref(), &link)
        {
            if header.role == FlowRole::Open {
                self.reject_flow_setup(session_id, header.flow_id, err.code())
                    .await;
            }
            reject_udp_half(&mut half, err.code()).await;
            return Err(err);
        }
        let shape_valid = matches!(
            (&header.role, &half),
            (FlowRole::Open, UdpHalf::Uplink { .. })
                | (FlowRole::Attach, UdpHalf::Downlink(_))
                | (FlowRole::Duplex, UdpHalf::Duplex { .. })
        );
        if !shape_valid {
            let err = PairingError::new(
                FlowErrorCode::InvalidRequest,
                "portal::pairing: UDP half role mismatch",
            );
            if header.role == FlowRole::Open {
                self.reject_flow_setup(session_id, header.flow_id, err.code())
                    .await;
            }
            reject_udp_half(&mut half, err.code()).await;
            return Err(err);
        }
        let key = FlowKey {
            session_id,
            flow_id: header.flow_id,
        };
        let metadata = Metadata {
            kind: header.kind,
            uplink: header.uplink,
            downlink: header.downlink,
        };
        if matches!(header.role, FlowRole::Open | FlowRole::Duplex)
            && let Some(code) = self.terminal_rejection(key, header.role == FlowRole::Duplex)
        {
            let err = PairingError::new(code, "portal::pairing: terminal flow rejection");
            reject_udp_half(&mut half, code).await;
            return Err(err);
        }
        let udp_permit = if matches!(header.role, FlowRole::Open | FlowRole::Duplex) {
            match self.acquire_udp_permit(session_id) {
                Ok(permit) => Some(permit),
                Err(err) => {
                    if header.role == FlowRole::Open {
                        self.reject_flow_setup(session_id, header.flow_id, err.code())
                            .await;
                    }
                    reject_udp_half(&mut half, err.code()).await;
                    return Err(err);
                }
            }
        } else {
            None
        };

        if header.role == FlowRole::Duplex {
            let (claim_epoch, created) = match self.reserve_claim(
                key,
                metadata.clone(),
                target.clone(),
                link.quic_generation,
            ) {
                Ok(claim) => claim,
                Err(err) => {
                    reject_udp_half(&mut half, err.code()).await;
                    return Err(err);
                }
            };
            if !created {
                let err = PairingError::new(
                    FlowErrorCode::MetadataConflict,
                    "portal::pairing: duplicate UDP flow id",
                );
                reject_udp_half(&mut half, err.code()).await;
                return Err(err);
            }
            let UdpHalf::Duplex {
                uplink,
                mut downlink,
            } = half
            else {
                unreachable!("duplex UDP shape validated")
            };
            let generations = link.quic_generation.into_iter().collect();
            let lease = match self.activate_claim(key, claim_epoch, generations, udp_permit) {
                Ok(lease) => lease,
                Err(err) => {
                    self.abandon_claim(key, claim_epoch);
                    reject_udp_downlink_ref(&mut downlink, err.code()).await;
                    return Err(err);
                }
            };
            return Ok(Some(PairedUdp {
                flow_id: header.flow_id,
                target: target.expect("duplex target validated"),
                uplink,
                downlink,
                uplink_carrier: header.uplink,
                downlink_carrier: header.downlink,
                uplink_path: link.path.clone(),
                downlink_path: link.path,
                _flow_lease: lease,
            }));
        }

        let mut half = Some(half);
        let mut udp_permit = udp_permit;
        let outcome = 'install: {
            let mut guard = self.udp.lock().await;
            let links = self.links.lock().expect("link registry poisoned");
            if let Err(error) = self.validate_current_link_locked(session_id, &link, &links) {
                break 'install UdpInstallOutcome::Rejected {
                    error,
                    downlink: half.take().and_then(udp_half_downlink),
                    abort_pending: header.role == FlowRole::Open,
                };
            }
            let active_generation = links
                .get(&session_id)
                .and_then(|counts| counts.udp.as_ref().map(|active| active.generation));
            let mut stale_snapshot = None;
            let mut remove_stale = false;
            if let Some(pending) = guard.get_mut(&key) {
                if pending.metadata.uplink == Carrier::Quic
                    && pending.uplink_generation != active_generation
                {
                    pending.uplink = None;
                    pending.target = None;
                    pending.flow_permit = None;
                    pending.uplink_path = None;
                    pending.uplink_generation = None;
                }
                if pending.metadata.downlink == Carrier::Quic
                    && pending.downlink_generation != active_generation
                {
                    pending.downlink = None;
                    pending.downlink_path = None;
                    pending.downlink_generation = None;
                }
                remove_stale = pending.uplink.is_none() && pending.downlink.is_none();
                if !remove_stale {
                    stale_snapshot = Some((
                        pending.target.clone(),
                        [pending.uplink_generation, pending.downlink_generation]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>(),
                    ));
                }
            }
            if remove_stale {
                guard.remove(&key);
            }
            if remove_stale || stale_snapshot.is_some() {
                let mut claims = self.claims.lock().expect("flow claim registry poisoned");
                if remove_stale {
                    if claims.get(&key).is_some_and(|claim| !claim.active) {
                        claims.remove(&key);
                    }
                } else if let (Some(claim), Some((target, generations))) =
                    (claims.get_mut(&key), stale_snapshot)
                    && !claim.active
                {
                    claim.target = target;
                    claim.quic_generations = generations;
                }
            }
            if let Some(code) = self.terminal_rejection(key, header.role == FlowRole::Attach) {
                break 'install UdpInstallOutcome::Rejected {
                    error: PairingError::new(code, "portal::pairing: terminal flow rejection"),
                    downlink: half.take().and_then(udp_half_downlink),
                    abort_pending: false,
                };
            }
            let (claim_epoch, _) = match self.reserve_claim(
                key,
                metadata.clone(),
                target.clone(),
                link.quic_generation,
            ) {
                Ok(claim) => claim,
                Err(error) => {
                    break 'install UdpInstallOutcome::Rejected {
                        error,
                        downlink: half.take().and_then(udp_half_downlink),
                        abort_pending: true,
                    };
                }
            };
            let pending = guard.entry(key).or_insert_with(|| PendingUdp {
                epoch: claim_epoch,
                metadata: metadata.clone(),
                quic_snapshot: active_generation,
                target: target.clone(),
                uplink: None,
                downlink: None,
                flow_permit: None,
                uplink_path: None,
                downlink_path: None,
                uplink_generation: None,
                downlink_generation: None,
            });
            if pending.metadata != metadata {
                break 'install UdpInstallOutcome::Rejected {
                    error: PairingError::new(
                        FlowErrorCode::MetadataConflict,
                        "portal::pairing: conflicting UDP flow metadata",
                    ),
                    downlink: half.take().and_then(udp_half_downlink),
                    abort_pending: true,
                };
            }
            if pending.target.is_none() {
                pending.target = target;
            }
            match (header.role, half.take().expect("UDP half available")) {
                (FlowRole::Open, UdpHalf::Uplink { uplink }) => {
                    if pending.uplink.is_some() {
                        break 'install UdpInstallOutcome::Rejected {
                            error: PairingError::new(
                                FlowErrorCode::MetadataConflict,
                                "portal::pairing: duplicate UDP uplink",
                            ),
                            downlink: None,
                            abort_pending: true,
                        };
                    }
                    pending.uplink = Some(uplink);
                    pending.flow_permit = udp_permit.take();
                    pending.uplink_path = Some(link.path);
                    pending.uplink_generation = link.quic_generation;
                }
                (FlowRole::Attach, UdpHalf::Downlink(downlink)) => {
                    if pending.downlink.is_some() {
                        break 'install UdpInstallOutcome::Rejected {
                            error: PairingError::new(
                                FlowErrorCode::MetadataConflict,
                                "portal::pairing: duplicate UDP downlink",
                            ),
                            downlink: Some(downlink),
                            abort_pending: true,
                        };
                    }
                    pending.downlink = Some(downlink);
                    pending.downlink_path = Some(link.path);
                    pending.downlink_generation = link.quic_generation;
                }
                _ => unreachable!("split UDP shape validated"),
            }
            if pending.uplink.is_some() && pending.downlink.is_some() {
                let mut complete = guard.remove(&key).expect("UDP pair exists");
                let epoch = complete.epoch;
                let Some(permit) = complete.flow_permit.take() else {
                    self.abandon_claim(key, epoch);
                    break 'install UdpInstallOutcome::Rejected {
                        error: PairingError::new(
                            FlowErrorCode::InternalError,
                            "portal::pairing: missing UDP flow permit",
                        ),
                        downlink: complete.downlink.take(),
                        abort_pending: false,
                    };
                };
                let generations = [complete.uplink_generation, complete.downlink_generation]
                    .into_iter()
                    .flatten()
                    .collect();
                drop(links);
                drop(guard);
                let lease = match self.activate_claim(key, epoch, generations, Some(permit)) {
                    Ok(lease) => lease,
                    Err(error) => {
                        self.abandon_claim(key, epoch);
                        break 'install UdpInstallOutcome::Rejected {
                            error,
                            downlink: complete.downlink.take(),
                            abort_pending: false,
                        };
                    }
                };
                break 'install UdpInstallOutcome::Paired(Box::new(PairedUdp {
                    flow_id: header.flow_id,
                    target: complete.target.take().expect("UDP target paired"),
                    uplink: complete.uplink.take().expect("UDP uplink paired"),
                    downlink: complete.downlink.take().expect("UDP downlink paired"),
                    uplink_carrier: complete.metadata.uplink,
                    downlink_carrier: complete.metadata.downlink,
                    uplink_path: complete.uplink_path.take().expect("UDP uplink path paired"),
                    downlink_path: complete
                        .downlink_path
                        .take()
                        .expect("UDP downlink path paired"),
                    _flow_lease: lease,
                }));
            }
            let epoch = match self.refresh_claim(key) {
                Ok(epoch) => epoch,
                Err(error) => {
                    let downlink = guard
                        .remove(&key)
                        .and_then(|mut pending| pending.downlink.take());
                    break 'install UdpInstallOutcome::Rejected {
                        error,
                        downlink,
                        abort_pending: true,
                    };
                }
            };
            pending.epoch = epoch;
            UdpInstallOutcome::Pending(epoch)
        };
        match outcome {
            UdpInstallOutcome::Pending(epoch) => {
                self.spawn_udp_timeout(key, epoch);
                Ok(None)
            }
            UdpInstallOutcome::Paired(paired) => Ok(Some(*paired)),
            UdpInstallOutcome::Rejected {
                error,
                mut downlink,
                abort_pending,
            } => {
                if abort_pending {
                    self.reject_flow_setup(session_id, header.flow_id, error.code())
                        .await;
                }
                if let Some(mut selected) = downlink.take() {
                    reject_udp_downlink_ref(&mut selected, error.code()).await;
                }
                Err(error)
            }
        }
    }

    fn spawn_tcp_timeout(self: &Arc<Self>, key: FlowKey, epoch: u64) {
        let registry = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(registry.timeout).await;
            let pending = {
                let mut flows = registry.tcp.lock().await;
                if flows.get(&key).is_some_and(|flow| flow.epoch == epoch) {
                    flows.remove(&key)
                } else {
                    None
                }
            };
            if let Some(mut pending) = pending {
                if pending.uplink.is_some() && pending.downlink.is_none() {
                    drop(pending);
                    registry
                        .reject_flow_setup(key.session_id, key.flow_id, FlowErrorCode::PairTimeout)
                        .await;
                } else {
                    reject_tcp_writer(&mut pending.downlink, FlowErrorCode::PairTimeout).await;
                    registry.abandon_claim(key, epoch);
                }
            }
        });
    }

    fn spawn_udp_timeout(self: &Arc<Self>, key: FlowKey, epoch: u64) {
        let registry = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(registry.timeout).await;
            let pending = {
                let mut flows = registry.udp.lock().await;
                if flows.get(&key).is_some_and(|flow| flow.epoch == epoch) {
                    flows.remove(&key)
                } else {
                    None
                }
            };
            if let Some(mut pending) = pending {
                if pending.uplink.is_some() && pending.downlink.is_none() {
                    drop(pending);
                    registry
                        .reject_flow_setup(key.session_id, key.flow_id, FlowErrorCode::PairTimeout)
                        .await;
                } else {
                    if let Some(downlink) = pending.downlink.take() {
                        reject_udp_downlink(downlink, FlowErrorCode::PairTimeout).await;
                    }
                    registry.abandon_claim(key, epoch);
                }
            }
        });
    }

    pub(super) async fn cancel_udp(&self, session_id: SessionId, flow_id: u32) {
        let key = FlowKey {
            session_id,
            flow_id,
        };
        self.udp.lock().await.remove(&key);
        let claim = self
            .claims
            .lock()
            .expect("flow claim registry poisoned")
            .get(&key)
            .map(|claim| (claim.active, claim.cancel.clone(), claim.epoch));
        if let Some((true, cancel, _)) = claim {
            cancel.cancel();
        } else if let Some((false, _, epoch)) = claim {
            self.abandon_claim(key, epoch);
        }
    }

    pub(super) fn finish_flow(&self, key: FlowKey, epoch: u64) {
        let mut claims = self.claims.lock().expect("flow claim registry poisoned");
        if claims
            .get(&key)
            .is_some_and(|claim| claim.active && claim.epoch == epoch)
        {
            claims.remove(&key);
        }
    }

    pub(super) fn cancel_quic_generation(self: &Arc<Self>, session_id: SessionId, generation: u64) {
        self.cancel_active_quic_generation(session_id, generation);
        let registry = self.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                registry.purge_quic_generation(session_id, generation).await;
            });
        }
    }

    pub(super) async fn replace_quic_generation(
        self: &Arc<Self>,
        session_id: SessionId,
        generation: u64,
    ) {
        self.cancel_active_quic_generation(session_id, generation);
        self.purge_quic_generation(session_id, generation).await;
    }

    fn cancel_active_quic_generation(&self, session_id: SessionId, generation: u64) {
        let claims = self.claims.lock().expect("flow claim registry poisoned");
        for (key, claim) in claims.iter() {
            if key.session_id == session_id
                && claim.active
                && claim.quic_generations.contains(&generation)
            {
                claim.cancel.cancel();
            }
        }
    }

    pub(super) async fn cancel_all(self: &Arc<Self>) {
        {
            let claims = self.claims.lock().expect("flow claim registry poisoned");
            for claim in claims.values() {
                claim.cancel.cancel();
            }
        }
        self.drain_pending().await;
    }

    /// Closes logical-flow admission and rejects every setup that has not
    /// activated yet. Active relays retain their claims and are left alone.
    pub(super) async fn begin_drain(self: &Arc<Self>) {
        self.close_admission();

        let mut pending = self
            .tcp
            .lock()
            .await
            .keys()
            .copied()
            .collect::<HashSet<_>>();
        pending.extend(self.udp.lock().await.keys().copied());
        for key in pending {
            self.reject_flow_setup(key.session_id, key.flow_id, FlowErrorCode::FlowLimit)
                .await;
        }
    }

    /// Synchronous admission barrier used at the start of the one absolute
    /// shutdown deadline.
    pub(super) fn close_admission(&self) {
        let _claims = self.claims.lock().expect("flow claim registry poisoned");
        self.accepting.store(false, Ordering::Release);
    }

    async fn purge_quic_generation(self: &Arc<Self>, session_id: SessionId, generation: u64) {
        let mut stale = self
            .tcp
            .lock()
            .await
            .iter()
            .filter(|(key, flow)| {
                key.session_id == session_id && flow.quic_snapshot == Some(generation)
            })
            .map(|(key, _)| *key)
            .collect::<HashSet<_>>();
        stale.extend(
            self.udp
                .lock()
                .await
                .iter()
                .filter(|(key, flow)| {
                    key.session_id == session_id && flow.quic_snapshot == Some(generation)
                })
                .map(|(key, _)| *key),
        );
        for key in stale {
            self.reject_flow_setup(key.session_id, key.flow_id, FlowErrorCode::SessionReplaced)
                .await;
        }
    }

    async fn drain_pending(&self) {
        self.tcp.lock().await.clear();
        self.udp.lock().await.clear();
        self.rejections
            .lock()
            .expect("flow rejection registry poisoned")
            .clear();
        self.claims
            .lock()
            .expect("flow claim registry poisoned")
            .retain(|_, claim| claim.active);
    }
}

async fn reject_udp_downlink(mut downlink: UdpDown, code: FlowErrorCode) {
    reject_udp_downlink_ref(&mut downlink, code).await;
}

async fn reject_udp_downlink_ref(downlink: &mut UdpDown, code: FlowErrorCode) {
    let write = async {
        match downlink {
            UdpDown::TlsTcp { writer, .. } => {
                let _ = write_flow_result(writer, FlowResult::Reject(code)).await;
                let _ = writer.shutdown().await;
            }
            UdpDown::Quic { control, .. } => {
                let _ = write_flow_result(control, FlowResult::Reject(code)).await;
                let _ = control.shutdown().await;
            }
        }
    };
    let _ = tokio::time::timeout(FLOW_RESULT_WRITE_TIMEOUT, write).await;
}

async fn reject_udp_half(half: &mut UdpHalf, code: FlowErrorCode) {
    match half {
        UdpHalf::Downlink(downlink) | UdpHalf::Duplex { downlink, .. } => {
            reject_udp_downlink_ref(downlink, code).await;
        }
        UdpHalf::Uplink { .. } => {}
    }
}

fn udp_half_downlink(half: UdpHalf) -> Option<UdpDown> {
    match half {
        UdpHalf::Downlink(downlink) | UdpHalf::Duplex { downlink, .. } => Some(downlink),
        UdpHalf::Uplink { .. } => None,
    }
}

async fn reject_tcp_writer(writer: &mut Option<BoxWriter>, code: FlowErrorCode) {
    if let Some(writer) = writer {
        let write = async {
            let _ = write_flow_result(writer, FlowResult::Reject(code)).await;
            let _ = writer.shutdown().await;
        };
        let _ = tokio::time::timeout(FLOW_RESULT_WRITE_TIMEOUT, write).await;
    }
}

#[cfg(test)]
#[path = "../tests/portal/pairing.rs"]
mod tests;
