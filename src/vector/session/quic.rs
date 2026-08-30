// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

/// Lazily created, reconnecting shared QUIC session.
pub(in crate::vector) struct QuicManager {
    config: PortalClientConfig,
    tls: ClientTls,
    auth_key: AuthKey,
    session_id: SessionId,
    stats: Arc<Stats>,
    telemetry: Arc<TelemetryHub>,
    latency: Arc<LatencyTracker>,
    state: Mutex<Option<Arc<QuicSession>>>,
    connect_lock: Mutex<()>,
    retry_after: Mutex<Option<Instant>>,
    shutdown: CancellationToken,
    queue_bytes: usize,
}

impl QuicManager {
    pub(in crate::vector) fn new(
        config: PortalClientConfig,
        tls: ClientTls,
        credentials: &Credentials,
        session_id: SessionId,
        signals: ClientSignals,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            tls,
            auth_key: credentials.auth_key,
            session_id,
            stats: signals.stats,
            telemetry: signals.telemetry,
            latency: signals.latency,
            state: Mutex::new(None),
            connect_lock: Mutex::new(()),
            retry_after: Mutex::new(None),
            shutdown,
            queue_bytes: crate::common::env_int("NOW_QUIC_UDP_QUEUE_BYTES", 4 * 1024 * 1024)
                .clamp(2, i32::MAX) as usize,
        })
    }

    pub(in crate::vector) async fn get(&self) -> Result<Arc<QuicSession>> {
        if let Some(session) = self.live_session().await {
            return Ok(session);
        }
        let _connecting = self.connect_lock.lock().await;
        if let Some(session) = self.live_session().await {
            return Ok(session);
        }
        if let Some(retry_after) = *self.retry_after.lock().await {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    bail!("vector::session::QuicManager: shutting down")
                }
                _ = tokio::time::sleep_until(retry_after) => {}
            }
        }
        let session = match self.connect().await {
            Ok(session) => {
                *self.retry_after.lock().await = None;
                session
            }
            Err(error) => {
                *self.retry_after.lock().await = Some(Instant::now() + service_cooldown());
                return Err(error);
            }
        };
        *self.state.lock().await = Some(session.clone());
        Ok(session)
    }

    async fn live_session(&self) -> Option<Arc<QuicSession>> {
        self.state
            .lock()
            .await
            .as_ref()
            .filter(|session| session.connection.close_reason().is_none())
            .cloned()
    }

    async fn connect(&self) -> Result<Arc<QuicSession>> {
        let resolved = timeout(
            handshake_timeout(),
            lookup_host((self.config.remote_host.as_str(), self.config.remote_port)),
        )
        .await
        .map_err(|_| anyhow!("vector::session::QuicManager::connect: Portal DNS timeout"))?
        .context("vector::session::QuicManager::connect: Portal DNS failed")?;
        let addresses = filter_addrs(resolved, parse_local_ip(&self.config.dialer_ip));
        if addresses.is_empty() {
            bail!("vector::session::QuicManager::connect: no Portal address resolved");
        }
        let mut last_error = None;
        for address in addresses {
            match self.connect_address(address).await {
                Ok(session) => return Ok(session),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("vector::session::QuicManager::connect failed")))
    }

    async fn connect_address(&self, address: SocketAddr) -> Result<Arc<QuicSession>> {
        let bind = match parse_local_ip(&self.config.dialer_ip) {
            Some(ip) => SocketAddr::new(ip, 0),
            None if address.is_ipv4() => {
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }
            None => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        };
        let mut endpoint = Endpoint::client(bind)
            .with_context(|| format!("vector::session::QuicManager: bind {bind} failed"))?;
        let mut client_config = self.tls.quic_client_config()?;
        configure_quic_transport(
            &mut client_config,
            udp_idle_timeout(),
            Duration::from_secs(15),
        )?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(address, &self.tls.quic_server_name())
            .context("vector::session::QuicManager: invalid QUIC endpoint")?;
        let connection = timeout(handshake_timeout(), connecting)
            .await
            .map_err(|_| anyhow!("vector::session::QuicManager: QUIC handshake timeout"))?
            .context("vector::session::QuicManager: QUIC handshake failed")?;
        let version = quic_protocol_version(&connection)?;
        let mut exporter = [0u8; crate::protocol::TLS_EXPORTER_LEN];
        connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
            .map_err(|error| anyhow!("vector::session::QuicManager: exporter failed: {error:?}"))?;
        let (auth_send, auth_recv) = timeout(handshake_timeout(), connection.open_bi())
            .await
            .map_err(|_| anyhow!("vector::session::QuicManager: auth stream open timeout"))?
            .context("vector::session::QuicManager: failed to open auth stream")?;
        let auth = encode_auth_frame(
            self.auth_key,
            AuthTransport::Quic,
            &exporter,
            self.session_id,
        );
        let reassembly_config = ReassemblyConfig {
            max_slots: 64,
            max_bytes: self.queue_bytes,
            ttl: Duration::from_secs(10),
        };
        let latency = self.latency.register();
        latency.update(connection.rtt());
        let session = Arc::new(QuicSession {
            _endpoint: endpoint,
            connection,
            first_stream: Mutex::new(Some((auth_send, auth_recv, auth))),
            routes: StdMutex::new(HashMap::new()),
            reassembler: StdMutex::new(DatagramReassembler::new(reassembly_config)),
            queue_budget: Arc::new(Semaphore::new(self.queue_bytes)),
            _link: LinkGuard::new(self.stats.clone(), self.telemetry.clone(), true),
            latency,
            version,
        });
        spawn_datagram_loop(Arc::downgrade(&session), self.shutdown.clone());
        Ok(session)
    }

    pub(in crate::vector) async fn close(&self, deadline: Instant) {
        if let Some(session) = self.state.lock().await.take() {
            session.connection.close(VarInt::from_u32(0), b"");
            let _ = timeout_at(deadline, session.connection.closed()).await;
        }
    }

    pub(in crate::vector) async fn refresh_latency(&self) {
        if let Some(session) = self.live_session().await {
            session.latency.update(session.connection.rtt());
        }
    }
}

pub(in crate::vector) struct QuicSession {
    _endpoint: Endpoint,
    pub(in crate::vector) connection: Connection,
    first_stream: Mutex<Option<(SendStream, RecvStream, AuthFrame)>>,
    routes: StdMutex<HashMap<FlowId, UdpRoute>>,
    reassembler: StdMutex<DatagramReassembler<OwnedSemaphorePermit>>,
    queue_budget: Arc<Semaphore>,
    _link: LinkGuard,
    latency: LatencyGuard,
    pub(in crate::vector) version: ProtocolVersion,
}

pub(in crate::vector) type QueuedDatagram = BudgetedDatagram;

struct UdpRoute {
    sender: mpsc::Sender<QueuedDatagram>,
    ready: bool,
}

impl QuicSession {
    pub(in crate::vector) async fn open_bi(
        &self,
    ) -> Result<(SendStream, RecvStream, Option<AuthFrame>)> {
        if let Some((send, recv, auth)) = self.first_stream.lock().await.take() {
            return Ok((send, recv, Some(auth)));
        }
        let (send, recv) = timeout(handshake_timeout(), self.connection.open_bi())
            .await
            .map_err(|_| anyhow!("vector::session::QuicSession: stream open timeout"))?
            .context("vector::session::QuicSession: failed to open stream")?;
        Ok((send, recv, None))
    }

    pub(in crate::vector) fn register_udp(
        &self,
        flow_id: FlowId,
    ) -> Result<mpsc::Receiver<QueuedDatagram>> {
        let (sender, receiver) = mpsc::channel(64);
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        match routes.entry(flow_id) {
            Entry::Vacant(route) => {
                route.insert(UdpRoute {
                    sender,
                    ready: false,
                });
            }
            Entry::Occupied(_) => {
                bail!("vector::session::QuicSession: duplicate UDP flow");
            }
        }
        Ok(receiver)
    }

    pub(in crate::vector) fn activate_udp(&self, flow_id: FlowId) -> Result<()> {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let route = routes.get_mut(&flow_id).ok_or_else(|| {
            anyhow!("vector::session::QuicSession: UDP route closed before READY")
        })?;
        route.ready = true;
        Ok(())
    }

    pub(in crate::vector) fn remove_udp(&self, flow_id: FlowId) {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        routes.remove(&flow_id);
        reassembler.remove_flow(flow_id);
    }

    fn clear_udp(&self) {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        routes.clear();
        reassembler.clear();
    }

    pub(in crate::vector) async fn send_udp(
        &self,
        flow_id: FlowId,
        packet_id: &mut u32,
        payload: &[u8],
    ) -> Result<UdpDatagramSend> {
        send_quic_udp_packet(&self.connection, flow_id, packet_id, payload).await
    }

    pub(in crate::vector) fn close_udp(&self, flow_id: FlowId) {
        self.remove_udp(flow_id);
        if let Ok(frame) = encode_udp_close(flow_id) {
            let _ = self
                .connection
                .send_datagram(Bytes::copy_from_slice(&frame));
        }
    }

    fn receive_data(&self, flow_id: FlowId, payload: Bytes) {
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let Some(route) = routes.get(&flow_id).filter(|route| route.ready) else {
            return;
        };
        let Some(permit) = reserve_udp_budget(self.queue_budget.clone(), payload.len()) else {
            return;
        };
        let queued = QueuedDatagram::new(payload, permit);
        if let Err(TrySendError::Closed(_)) = route.sender.try_send(queued) {
            routes.remove(&flow_id);
            self.reassembler
                .lock()
                .unwrap_or_else(|lock| lock.into_inner())
                .remove_flow(flow_id);
        }
    }

    fn receive_fragment(&self, flow_id: FlowId, fragment: OwnedUdpFragment) {
        // Every operation touching both maps takes routes first. Keeping this
        // guard through insertion prevents remove_udp from leaving a stale
        // partial packet after the route has been removed.
        let mut routes = self.routes.lock().unwrap_or_else(|lock| lock.into_inner());
        let Some(route) = routes.get(&flow_id).filter(|route| route.ready) else {
            return;
        };
        let mut reassembler = self
            .reassembler
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        let outcome =
            reassembler.push_with(flow_id, fragment, std::time::Instant::now(), |packet_len| {
                reserve_udp_budget(self.queue_budget.clone(), usize::from(packet_len))
            });
        if let ReassemblyOutcome::Complete {
            payload,
            reservation,
            ..
        } = outcome
        {
            let queued = QueuedDatagram::new(payload, reservation);
            if let Err(TrySendError::Closed(_)) = route.sender.try_send(queued) {
                routes.remove(&flow_id);
                reassembler.remove_flow(flow_id);
            }
        }
    }
}

fn spawn_datagram_loop(session: Weak<QuicSession>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let session = loop {
            let Some(session) = session.upgrade() else {
                return;
            };
            tokio::select! {
                _ = shutdown.cancelled() => break session,
                _ = cleanup.tick() => {
                    session.reassembler.lock().unwrap_or_else(|lock| lock.into_inner())
                        .expire(std::time::Instant::now());
                }
                datagram = session.connection.read_datagram() => {
                    let Ok(datagram) = datagram else { break session; };
                    match decode_udp_frame_owned(datagram) {
                        Ok(OwnedUdpFrame::Data { flow_id, payload }) => {
                            session.receive_data(flow_id, payload);
                        }
                        Ok(OwnedUdpFrame::Fragment { flow_id, fragment }) => {
                            session.receive_fragment(flow_id, fragment);
                        }
                        Ok(OwnedUdpFrame::Close { flow_id }) => session.remove_udp(flow_id),
                        Err(_) => {}
                    }
                }
            }
        };
        session.clear_udp();
    });
}

fn configure_quic_transport(
    config: &mut quinn::ClientConfig,
    idle_timeout: Duration,
    keepalive_interval: Duration,
) -> Result<()> {
    let flow_control = quic_flow_control()?;
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_BUFFER_SIZE));
    transport.datagram_send_buffer_size(QUIC_DATAGRAM_BUFFER_SIZE);
    transport.stream_receive_window(VarInt::from_u32(flow_control.stream_receive_window));
    transport.receive_window(VarInt::from_u32(flow_control.connection_receive_window));
    transport.send_window(flow_control.send_window);
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(idle_timeout)?));
    transport.keep_alive_interval(Some(keepalive_interval));
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    config.transport_config(Arc::new(transport));
    Ok(())
}
