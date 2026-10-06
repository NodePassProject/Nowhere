// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS carrier establishment and shared Mux connection management.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use tokio::sync::OnceCell;
use tokio::task::JoinSet;

pub(in crate::vector) struct TlsManager {
    endpoint: Option<(String, crate::common::AddressFamily)>,
    dial_policy: crate::common::DialPolicy,
    tls: ClientTls,
    auth_key: AuthKey,
    session_id: SessionId,
    stats: Arc<Stats>,
    telemetry: Arc<TelemetryHub>,
    latency: Arc<LatencyTracker>,
    mux: Mutex<Vec<Arc<TlsMux>>>,
    mux_monitors: Mutex<JoinSet<()>>,
    mux_enabled: bool,
    closed: AtomicBool,
}

pub(in crate::vector) enum OpenedTls {
    Dedicated(Box<TlsLane>),
    Mux(MuxStream),
}

#[derive(Default)]
struct TlsMux {
    handle: OnceCell<MuxHandle>,
    pending: AtomicUsize,
}

struct PendingMux(Arc<TlsMux>);

impl Drop for PendingMux {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

impl TlsManager {
    pub(in crate::vector) fn new(
        config: &PortalClientConfig,
        tls: ClientTls,
        credentials: &Credentials,
        session_id: SessionId,
        signals: ClientSignals,
    ) -> Arc<Self> {
        Arc::new(Self {
            endpoint: config
                .tcp_endpoint()
                .map(|endpoint| (config.remote.carrier_addr(endpoint), endpoint.family)),
            dial_policy: config.dial_policy.clone(),
            tls,
            auth_key: credentials.auth_key,
            session_id,
            stats: signals.stats,
            telemetry: signals.telemetry,
            latency: signals.latency,
            mux: Mutex::new(Vec::new()),
            mux_monitors: Mutex::new(JoinSet::new()),
            mux_enabled: config.mux.enabled(),
            closed: AtomicBool::new(false),
        })
    }

    pub(in crate::vector) async fn open(self: &Arc<Self>, flow_id: u32) -> Result<OpenedTls> {
        if self.closed.load(Ordering::Acquire) {
            bail!("vector::session::TlsManager: shutting down");
        }
        if !self.mux_enabled {
            let lane = self.connect_lane().await?;
            if self.closed.load(Ordering::Acquire) {
                bail!("vector::session::TlsManager: shutting down");
            }
            return Ok(OpenedTls::Dedicated(Box::new(lane)));
        }
        let pending = {
            let mut pool = self.mux.lock().await;
            if self.closed.load(Ordering::Acquire) {
                bail!("vector::session::TlsManager: shutting down");
            }
            reserve_mux(&mut pool, Some(flow_id))?
        };
        let handle = pending
            .0
            .handle
            .get_or_try_init(|| self.connect_mux(pending.0.clone()))
            .await;
        let handle = match handle {
            Ok(handle) => handle.clone(),
            Err(error) => {
                let pool = self.mux.lock().await;
                let Some(handle) = pool
                    .iter()
                    .filter_map(|carrier| carrier.handle.get())
                    .filter(|handle| handle.can_open_flow(flow_id))
                    .min_by_key(|handle| (handle.pressure(), handle.active_streams()))
                    .cloned()
                else {
                    return Err(error);
                };
                if self.closed.load(Ordering::Acquire) {
                    bail!("vector::session::TlsManager: shutting down");
                }
                let stream = handle.prepare_stream(flow_id)?;
                drop(pending);
                drop(pool);
                return handle
                    .open_prepared(stream)
                    .await
                    .map(OpenedTls::Mux)
                    .map_err(Into::into);
            }
        };
        if self.closed.load(Ordering::Acquire) {
            bail!("vector::session::TlsManager: shutting down");
        }
        let pool = self.mux.lock().await;
        let stream = handle.prepare_stream(flow_id)?;
        drop(pending);
        drop(pool);
        handle
            .open_prepared(stream)
            .await
            .map(OpenedTls::Mux)
            .map_err(Into::into)
    }

    async fn connect_mux(self: &Arc<Self>, slot: Arc<TlsMux>) -> Result<MuxHandle> {
        let TlsLane {
            mut stream,
            pending_auth,
            _link,
            latency,
        } = self.connect_lane().await?;
        stream
            .write_all(&pending_auth.expect("new TLS carrier has pending auth"))
            .await
            .context("vector::session::TlsManager: failed to authenticate mux carrier")?;
        stream
            .write_u8(crate::common::MUX_MARKER)
            .await
            .context("vector::session::TlsManager: failed to mark mux carrier")?;
        stream.flush().await?;
        let (handle, incoming) = MuxHandle::start(stream, MuxConfig::default())?;
        drop(incoming);
        let manager = self.clone();
        let lifetime = handle.clone();
        let mut monitors = self.mux_monitors.lock().await;
        while monitors.try_join_next().is_some() {}
        if self.closed.load(Ordering::Acquire) {
            handle.close();
            bail!("vector::session::TlsManager: shutting down");
        }
        let close = CloseMuxOnDrop(lifetime.clone());
        monitors.spawn(async move {
            let _close = close;
            manager
                .monitor_mux(slot, lifetime, _link, latency, MUX_IDLE_TIMEOUT)
                .await;
        });
        Ok(handle)
    }

    async fn monitor_mux(
        self: Arc<Self>,
        slot: Arc<TlsMux>,
        carrier: MuxHandle,
        _link: LinkGuard,
        _latency: LatencyGuard,
        idle_timeout: Duration,
    ) {
        loop {
            tokio::select! {
                _ = carrier.closed() => break,
                idle = carrier.idle_for(idle_timeout) => { if !idle { break; } }
            }
            let mut pool = self.mux.lock().await;
            if carrier.active_streams() != 0 || slot.pending.load(Ordering::Relaxed) != 0 {
                continue;
            }
            pool.retain(|candidate| !Arc::ptr_eq(candidate, &slot));
            carrier.close_with_reason(MuxCloseReason::IdleTimeout);
            break;
        }
        let reason = carrier.close_reason().await;
        self.telemetry.emit_runtime(RuntimeEvent::new(
            RuntimeLevel::Info,
            RuntimeKind::Mux,
            format!("TLS mux carrier disconnected: {}", reason.diagnostic()),
        ));
        self.mux
            .lock()
            .await
            .retain(|candidate| !Arc::ptr_eq(candidate, &slot));
    }

    pub(in crate::vector) async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let carriers = std::mem::take(&mut *self.mux.lock().await);
        for carrier in &carriers {
            if let Some(handle) = carrier.handle.get() {
                handle.close();
            }
        }
        drop(carriers);

        let mut monitors = self.mux_monitors.lock().await;
        monitors.abort_all();
        while monitors.join_next().await.is_some() {}
    }

    async fn connect_lane(&self) -> Result<TlsLane> {
        let (endpoint, family) = self
            .endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("vector::session::TlsManager: TCP carrier is not configured"))?;
        let (stream, exporter) = self
            .tls
            .connect_tcp(endpoint, &self.dial_policy, *family)
            .await?;
        let latency = self.latency.register();
        latency.update_tcp(stream.get_ref().0.get_ref());
        let auth = encode_auth_frame(
            self.auth_key,
            AuthTransport::TlsTcp,
            &exporter,
            self.session_id,
        );
        Ok(TlsLane {
            stream,
            pending_auth: Some(auth),
            _link: LinkGuard::new(self.stats.clone(), self.telemetry.clone(), false),
            latency,
        })
    }
}

struct CloseMuxOnDrop(MuxHandle);

impl Drop for CloseMuxOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

fn reserve_mux(pool: &mut Vec<Arc<TlsMux>>, flow_id: Option<u32>) -> std::io::Result<PendingMux> {
    pool.retain(|carrier| !carrier.handle.get().is_some_and(MuxHandle::is_closed));
    let selected = pool
        .iter()
        .filter(|carrier| {
            flow_id.is_none_or(|flow_id| {
                carrier
                    .handle
                    .get()
                    .is_none_or(|handle| handle.can_open_flow(flow_id))
            })
        })
        .map(|carrier| {
            let handle = carrier.handle.get();
            let active = carrier.pending.load(Ordering::Relaxed)
                + handle.map_or(0, MuxHandle::active_streams);
            let pressure = handle.map_or(0, MuxHandle::pressure);
            (carrier, active, pressure)
        })
        .min_by_key(|(_, active, pressure)| (*active != 0, *pressure, *active));
    let carrier = match selected {
        Some((carrier, active, _)) if active == 0 || pool.len() >= TLS_MUX_MAX_CARRIERS => {
            carrier.clone()
        }
        _ if pool.len() < TLS_MUX_MAX_CARRIERS => {
            let carrier = Arc::new(TlsMux::default());
            pool.push(carrier.clone());
            carrier
        }
        _ => {
            let index = pool.iter().position(|carrier| {
                carrier.pending.load(Ordering::Relaxed) == 0
                    && carrier
                        .handle
                        .get()
                        .is_some_and(|handle| handle.active_streams() == 0)
            });
            let Some(index) = index else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "no eligible TLS Mux carrier available",
                ));
            };
            let retired = pool.remove(index);
            retired
                .handle
                .get()
                .expect("idle carrier initialized")
                .close();
            let carrier = Arc::new(TlsMux::default());
            pool.push(carrier.clone());
            carrier
        }
    };
    carrier.pending.fetch_add(1, Ordering::Relaxed);
    Ok(PendingMux(carrier))
}

#[cfg(test)]
#[path = "../../tests/vector/session_tls.rs"]
mod tests;
