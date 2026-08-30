// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP tunnel setup and bidirectional relay.

use super::*;

pub(crate) struct TcpTunnel {
    reader: BoxReader,
    writer: BoxWriter,
    _lanes: Vec<PhysicalLane>,
    _lease: Option<FlowLease>,
    uplink: Carrier,
    downlink: Carrier,
    version: ProtocolVersion,
    _flow_permit: Option<OwnedSemaphorePermit>,
}

pub(crate) struct TcpTunnelGuard {
    _lanes: Vec<PhysicalLane>,
    _lease: Option<FlowLease>,
    _flow_permit: Option<OwnedSemaphorePermit>,
}

impl TcpTunnel {
    pub(in crate::vector) fn socks_reply(&self) -> u8 {
        REPLY_SUCCEEDED
    }

    pub(crate) fn carriers(&self) -> (Carrier, Carrier) {
        (self.uplink, self.downlink)
    }

    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub(crate) fn into_parts(self) -> (BoxReader, BoxWriter, TcpTunnelGuard) {
        let Self {
            reader,
            writer,
            _lanes,
            _lease,
            uplink: _,
            downlink: _,
            version: _,
            _flow_permit,
        } = self;
        (
            reader,
            writer,
            TcpTunnelGuard {
                _lanes,
                _lease,
                _flow_permit,
            },
        )
    }
}

impl AsyncRead for TcpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.reader.as_mut().poll_read(cx, buffer)
    }
}

impl AsyncWrite for TcpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writer.as_mut().poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_shutdown(cx)
    }
}

pub(crate) async fn open_tcp(
    client: Arc<PortalClient>,
    target: &Target,
    hops: u8,
) -> std::result::Result<TcpTunnel, OpenFlowError> {
    let flow_permit = client
        .tcp_flow_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| OpenFlowError::Setup(SetupResult::FlowLimit))?;
    let lease = client
        .flow_ids
        .allocate()
        .map_err(OpenFlowError::Protocol)?;
    let flow_id = lease.id();
    let uplink = carrier(client.config.up);
    let downlink = carrier(client.config.down);

    if uplink == downlink {
        let mut lane = open_lane(client.clone(), client.config.up, flow_id, MuxDirection::Up)
            .await
            .map_err(OpenFlowError::Transport)?;
        let header = FlowHeader {
            role: FlowRole::Duplex,
            flow_id,
            kind: FlowKind::Tcp,
            uplink,
            downlink,
            hops,
        };
        let version = lane.version;
        let pending_auth = lane.take_pending_auth();
        write_open_request(
            lane.writer.as_mut().expect("lane writer"),
            pending_auth,
            header,
            target,
        )
        .await
        .map_err(OpenFlowError::Transport)?;
        lane.mark_auth_sent();
        read_ready(lane.reader.as_mut().expect("lane reader"))
            .await
            .map_err(OpenFlowError::Setup)?;
        let reader = lane.take_reader();
        let writer = lane.take_writer();
        return Ok(TcpTunnel {
            reader,
            writer,
            _lanes: vec![lane],
            _lease: Some(lease),
            uplink,
            downlink,
            version,
            _flow_permit: Some(flow_permit),
        });
    }

    let (uplink_result, downlink_result) = tokio::join!(
        open_lane(client.clone(), client.config.up, flow_id, MuxDirection::Up,),
        open_lane(
            client.clone(),
            client.config.down,
            flow_id,
            MuxDirection::Down,
        ),
    );
    let mut uplink_lane = uplink_result.map_err(OpenFlowError::Transport)?;
    let mut downlink_lane = downlink_result.map_err(OpenFlowError::Transport)?;
    if uplink_lane.version != downlink_lane.version {
        return Err(OpenFlowError::Protocol(anyhow!(
            "vector::flow::open_tcp: split carriers negotiated different protocol versions"
        )));
    }
    let version = uplink_lane.version;
    let open_header = FlowHeader {
        role: FlowRole::Open,
        flow_id,
        kind: FlowKind::Tcp,
        uplink,
        downlink,
        hops,
    };
    let attach_header = FlowHeader {
        role: FlowRole::Attach,
        ..open_header
    };
    let pending_auth = uplink_lane.take_pending_auth();
    write_open_request(
        uplink_lane.writer.as_mut().expect("uplink writer"),
        pending_auth,
        open_header,
        target,
    )
    .await
    .map_err(OpenFlowError::Transport)?;
    uplink_lane.mark_auth_sent();
    let pending_auth = downlink_lane.take_pending_auth();
    write_header(
        downlink_lane.writer.as_mut().expect("downlink writer"),
        pending_auth,
        attach_header,
    )
    .await
    .map_err(OpenFlowError::Transport)?;
    downlink_lane.mark_auth_sent();
    read_ready(downlink_lane.reader.as_mut().expect("downlink reader"))
        .await
        .map_err(OpenFlowError::Setup)?;

    let writer = uplink_lane.take_writer();
    let reader = downlink_lane.take_reader();
    Ok(TcpTunnel {
        reader,
        writer,
        _lanes: vec![uplink_lane, downlink_lane],
        _lease: Some(lease),
        uplink,
        downlink,
        version,
        _flow_permit: Some(flow_permit),
    })
}

pub(in crate::vector) async fn relay_tcp(
    vector: Arc<VectorInner>,
    client: TcpStream,
    mut tunnel: TcpTunnel,
    client_peer: std::net::SocketAddr,
    target: &SocksAddress,
    access: AccessSpan,
) -> Result<()> {
    vector.stats.add_session(false);
    let _session = SessionGuard::new(vector.stats.clone(), false);
    vector.logger.debug(format_args!(
        "vector::flow::relay_tcp: exchange starting: UP[{}] {client_peer} -> {} -> {} -> {target} | DOWN[{}] {target} -> {} -> {} -> {client_peer}",
        carrier_name(tunnel.uplink),
        vector.config.socks.endpoint(),
        vector.config.portal_endpoint(),
        carrier_name(tunnel.downlink),
        vector.config.portal_endpoint(),
        vector.config.socks.endpoint(),
    ));

    let result = {
        let (mut client_read, mut client_write) = client.into_split();
        let mut up_buffer = vector.buffers.get_tcp_buffer();
        let mut down_buffer = vector.buffers.get_tcp_buffer();
        let uplink = tunnel.uplink;
        let downlink = tunnel.downlink;
        let client_to_portal = async {
            loop {
                let read = client_read.read(&mut up_buffer).await?;
                if read == 0 {
                    tunnel.writer.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                if let Some(rate) = &vector.rate_limiter {
                    rate.wait_read(read as i64).await;
                }
                tunnel.writer.write_all(&up_buffer[..read]).await?;
                if uplink == Carrier::Quic && downlink == Carrier::TlsTcp {
                    // A continuously writable QUIC stream can otherwise keep
                    // this relay hot long enough to delay the opposite Mux
                    // reader and its WINDOW returns.
                    tokio::task::yield_now().await;
                }
                access.add_upload(read as u64);
                vector
                    .stats
                    .tcp_rx
                    .fetch_add(read as u64, Ordering::Relaxed);
                carrier_counter(&vector, uplink, true).fetch_add(read as u64, Ordering::Relaxed);
            }
        };
        let portal_to_client = async {
            loop {
                let read = tunnel.reader.read(&mut down_buffer).await?;
                if read == 0 {
                    client_write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                if let Some(rate) = &vector.rate_limiter {
                    rate.wait_write(read as i64).await;
                }
                client_write.write_all(&down_buffer[..read]).await?;
                access.add_download(read as u64);
                vector
                    .stats
                    .tcp_tx
                    .fetch_add(read as u64, Ordering::Relaxed);
                carrier_counter(&vector, downlink, false).fetch_add(read as u64, Ordering::Relaxed);
            }
        };
        tokio::pin!(client_to_portal);
        tokio::pin!(portal_to_client);
        tokio::select! {
            result = &mut client_to_portal => match result {
                Ok(()) => timeout(tcp_read_timeout(), &mut portal_to_client).await.unwrap_or(Ok(())),
                Err(error) => Err(error),
            },
            result = &mut portal_to_client => match result {
                Ok(()) => timeout(tcp_read_timeout(), &mut client_to_portal).await.unwrap_or(Ok(())),
                Err(error) => Err(error),
            },
        }
    };
    vector.logger.debug(format_args!(
        "vector::flow::relay_tcp: exchange complete: {}",
        match &result {
            Ok(()) => "EOF".to_owned(),
            Err(error) => error.to_string(),
        }
    ));
    match &result {
        Ok(()) => access.finish(AccessOutcome::Success, None),
        Err(error) => {
            let error = error.to_string();
            access.finish(access_error_outcome(&error), Some(error));
        }
    }
    result
}
