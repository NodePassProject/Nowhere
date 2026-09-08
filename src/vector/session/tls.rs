// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::OnceCell;

pub(in crate::vector) struct TlsManager {
    endpoint: Option<(String, crate::common::AddressFamily)>,
    dialer_ip: String,
    tls: ClientTls,
    auth_key: AuthKey,
    session_id: SessionId,
    stats: Arc<Stats>,
    telemetry: Arc<TelemetryHub>,
    latency: Arc<LatencyTracker>,
    mux: Mutex<Vec<Arc<TlsMux>>>,
    mux_enabled: bool,
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
            dialer_ip: config.dialer_ip.clone(),
            tls,
            auth_key: credentials.auth_key,
            session_id,
            stats: signals.stats,
            telemetry: signals.telemetry,
            latency: signals.latency,
            mux: Mutex::new(Vec::new()),
            mux_enabled: config.mux.enabled(),
        })
    }

    pub(in crate::vector) async fn open(self: &Arc<Self>, flow_id: u32) -> Result<OpenedTls> {
        if !self.mux_enabled {
            return self
                .connect_lane()
                .await
                .map(Box::new)
                .map(OpenedTls::Dedicated);
        }
        let pending = reserve_mux(&mut *self.mux.lock().await);
        // Reservations include connecting slots, avoiding a cold-start stampede
        // onto the first handshake to finish. OnceCell shares one initializer;
        // cancellation lets another waiter retry without leaking a pool slot.
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
                    .filter(|handle| !handle.is_closed())
                    .min_by_key(|handle| (handle.pressure(), handle.active_streams()))
                    .cloned()
                else {
                    return Err(error);
                };
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
        // Registration and reservation release exclude idle retirement.
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
        // No await after start until ownership is handed to the lifetime task.
        let manager = self.clone();
        let lifetime = handle.clone();
        tokio::spawn(async move {
            manager.monitor_mux(slot, lifetime, _link, latency).await;
        });
        Ok(handle)
    }

    async fn monitor_mux(
        self: Arc<Self>,
        slot: Arc<TlsMux>,
        carrier: MuxHandle,
        _link: LinkGuard,
        _latency: LatencyGuard,
    ) {
        loop {
            tokio::select! {
                _ = carrier.closed() => break,
                idle = carrier.idle_for(MUX_IDLE_TIMEOUT) => { if !idle { break; } }
            }
            let mut pool = self.mux.lock().await;
            if carrier.active_streams() != 0 || slot.pending.load(Ordering::Relaxed) != 0 {
                continue;
            }
            pool.retain(|candidate| !Arc::ptr_eq(candidate, &slot));
            carrier.close();
            return;
        }
        self.mux
            .lock()
            .await
            .retain(|candidate| !Arc::ptr_eq(candidate, &slot));
    }

    async fn connect_lane(&self) -> Result<TlsLane> {
        let (endpoint, family) = self
            .endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("vector::session::TlsManager: TCP carrier is not configured"))?;
        let (stream, exporter) = self
            .tls
            .connect_tcp(endpoint, &self.dialer_ip, *family)
            .await?;
        let latency = self.latency.register();
        latency.update_tcp(stream.get_ref().0);
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

fn reserve_mux(pool: &mut Vec<Arc<TlsMux>>) -> PendingMux {
    pool.retain(|carrier| !carrier.handle.get().is_some_and(MuxHandle::is_closed));
    let selected = pool
        .iter()
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
        _ => {
            let carrier = Arc::new(TlsMux::default());
            pool.push(carrier.clone());
            carrier
        }
    };
    carrier.pending.fetch_add(1, Ordering::Relaxed);
    PendingMux(carrier)
}

#[cfg(test)]
#[path = "../../tests/vector/session/tls.rs"]
mod tests;
