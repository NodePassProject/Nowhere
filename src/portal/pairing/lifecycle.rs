// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Flow cancellation, carrier replacement, and drain lifecycle.

use super::*;

impl PairingRegistry {
    pub(in crate::portal) fn finish_flow(&self, key: FlowKey, epoch: u64) {
        let mut claims = self.claims.lock().expect("flow claim registry poisoned");
        if claims
            .get(&key)
            .is_some_and(|claim| claim.active && claim.epoch == epoch)
        {
            claims.remove(&key);
        }
    }

    pub(in crate::portal) fn cancel_quic_generation(
        self: &Arc<Self>,
        session_id: SessionKey,
        generation: u64,
    ) {
        self.cancel_active_quic_generation(session_id, generation);
        let registry = self.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                registry.purge_quic_generation(session_id, generation).await;
            });
        }
    }

    pub(in crate::portal) async fn replace_quic_generation(
        self: &Arc<Self>,
        session_id: SessionKey,
        generation: u64,
    ) {
        self.cancel_active_quic_generation(session_id, generation);
        self.purge_quic_generation(session_id, generation).await;
    }

    fn cancel_active_quic_generation(&self, session_id: SessionKey, generation: u64) {
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

    pub(in crate::portal) async fn cancel_all(self: &Arc<Self>) {
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
    pub(in crate::portal) async fn begin_drain(self: &Arc<Self>) {
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
    pub(in crate::portal) fn close_admission(&self) {
        let _claims = self.claims.lock().expect("flow claim registry poisoned");
        self.accepting.store(false, Ordering::Release);
    }

    async fn purge_quic_generation(self: &Arc<Self>, session_id: SessionKey, generation: u64) {
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
