// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP logical-flow installation and split-half pairing.

use super::*;

enum UdpInstallOutcome {
    Pending(u64),
    Paired(Box<PairedUdp>),
    Rejected {
        error: PairingError,
        downlink: Option<UdpDown>,
        abort_pending: bool,
    },
}

impl PairingRegistry {
    pub(in crate::portal) async fn submit_udp<S: Into<SessionKey>>(
        self: &Arc<Self>,
        session_id: S,
        header: FlowHeader,
        target: Option<Target>,
        link: LinkHalf,
        mut half: UdpHalf,
    ) -> Result<Option<PairedUdp>, PairingError> {
        let session_id = session_id.into();
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
            hops: header.hops,
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
                hops: header.hops,
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
                    hops: complete.metadata.hops,
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

    pub(in crate::portal) async fn cancel_udp<S: Into<SessionKey>>(
        &self,
        session_id: S,
        flow_id: u32,
    ) {
        let session_id = session_id.into();
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
}

async fn reject_udp_downlink(mut downlink: UdpDown, code: FlowErrorCode) {
    reject_udp_downlink_ref(&mut downlink, code).await;
}

pub(super) async fn reject_udp_downlink_ref(downlink: &mut UdpDown, code: FlowErrorCode) {
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
