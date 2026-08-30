// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP logical-flow installation and split-half pairing.

use super::*;

enum TcpInstallOutcome {
    Pending(u64),
    Paired(Box<PairedTcp>),
    Rejected {
        error: PairingError,
        downlink: Option<BoxWriter>,
        abort_pending: bool,
    },
}

impl PairingRegistry {
    #[allow(
        clippy::too_many_arguments,
        reason = "the registry boundary keeps each owned stream half explicit"
    )]
    pub(in crate::portal) async fn submit_tcp<S: Into<SessionKey>>(
        self: &Arc<Self>,
        session_id: S,
        header: FlowHeader,
        target: Option<Target>,
        link: LinkHalf,
        reader: Option<BoxReader>,
        mut writer: Option<BoxWriter>,
        downlink_liveness: Option<BoxReader>,
    ) -> Result<Option<PairedTcp>, PairingError> {
        let session_id = session_id.into();
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
            hops: header.hops,
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
                flow_id: header.flow_id,
                target: target.expect("duplex target validated"),
                uplink,
                downlink,
                downlink_liveness,
                uplink_carrier: header.uplink,
                downlink_carrier: header.downlink,
                hops: header.hops,
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
                    flow_id: key.flow_id,
                    target: complete.target.take().expect("TCP target paired"),
                    uplink: complete.uplink.take().expect("TCP uplink paired"),
                    downlink: complete.downlink.take().expect("TCP downlink paired"),
                    downlink_liveness: complete.downlink_liveness.take(),
                    uplink_carrier: complete.metadata.uplink,
                    downlink_carrier: complete.metadata.downlink,
                    hops: complete.metadata.hops,
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
}

pub(super) async fn reject_tcp_writer(writer: &mut Option<BoxWriter>, code: FlowErrorCode) {
    if let Some(writer) = writer {
        let write = async {
            let _ = write_flow_result(writer, FlowResult::Reject(code)).await;
            let _ = writer.shutdown().await;
        };
        let _ = tokio::time::timeout(FLOW_RESULT_WRITE_TIMEOUT, write).await;
    }
}
