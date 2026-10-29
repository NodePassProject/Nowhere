// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated QUIC connection setup, first flows, and connection reuse.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::time::{Instant, timeout, timeout_at};

use crate::protocol::{
    AuthTransport, FlowKind, SetupResult, Target, encode_auth_frame, encode_flow_request_into,
};
use crate::transport::QuicConnection;
use crate::vector::tls::{ClientTls, EXPORTER_LABEL, require_quic_nw3};

use super::{OpenFlowError, PortalClient, PortalClientConfig, QuicFlow};

struct ConnectionAttempt(Option<Arc<QuicConnection>>);

impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        if let Some(q) = &self.0 {
            q.close();
        }
    }
}

impl PortalClient {
    pub(crate) async fn open_quic_flow(
        &self,
        kind: FlowKind,
        target: &Target,
    ) -> std::result::Result<QuicFlow, OpenFlowError> {
        let deadline = Instant::now() + self.flow_setup_timeout;
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => Err(OpenFlowError::Cancelled),
            result = timeout_at(deadline, self.open_quic_flow_inner(kind, target)) => {
                result.map_err(|error| OpenFlowError::Transport(error.into()))?
            },
        }
    }

    async fn open_quic_flow_inner(
        &self,
        kind: FlowKind,
        target: &Target,
    ) -> std::result::Result<QuicFlow, OpenFlowError> {
        let mut state = self.quic.lock().await;
        if let Some(q) = state
            .as_ref()
            .filter(|(_, q)| {
                q.connection.close_reason().is_none()
                    && !q.cancel.is_cancelled()
                    && !q.draining.is_cancelled()
            })
            .map(|(_, q)| q.clone())
        {
            drop(state);
            let (flow, result) = self.start_quic_flow(&q, kind, target, None).await?;
            return ready_quic_flow(flow, result);
        }
        let (endpoint, connection) = connect_quic(&self.config, &self.tls)
            .await
            .map_err(OpenFlowError::Transport)?;
        let mut exporter = [0; 32];
        connection
            .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
            .map_err(|e| OpenFlowError::Transport(anyhow!("exporter failed: {e:?}")))?;
        let auth = encode_auth_frame(self.credentials.vector_key, AuthTransport::Quic, &exporter);
        let q = QuicConnection::new(connection, false, self.udp_queue_bytes);
        let mut attempt = ConnectionAttempt(Some(q.clone()));
        let (flow, result) = self.start_quic_flow(&q, kind, target, Some(auth)).await?;
        let limits =
            crate::transport::transport_flow_control().map_err(OpenFlowError::Transport)?;
        q.connection
            .set_receive_window(limits.connection_receive_window.into());
        q.connection.set_max_concurrent_bi_streams(1024u32.into());
        let monitor = q.clone();
        tokio::spawn(async move {
            if monitor.connection.accept_bi().await.is_ok() {
                monitor
                    .connection
                    .close(1u32.into(), b"role direction violation");
            }
        });
        *state = Some((endpoint, q));
        attempt.0 = None;
        ready_quic_flow(flow, result)
    }

    async fn start_quic_flow(
        &self,
        q: &Arc<QuicConnection>,
        kind: FlowKind,
        target: &Target,
        auth: Option<[u8; 16]>,
    ) -> std::result::Result<(QuicFlow, SetupResult), OpenFlowError> {
        let (mut send, mut recv) = timeout(self.config.handshake_timeout, q.connection.open_bi())
            .await
            .map_err(|e| OpenFlowError::Transport(e.into()))?
            .map_err(|e| OpenFlowError::Transport(e.into()))?;
        let id = q
            .flow_id(u64::from(send.id()))
            .map_err(OpenFlowError::Protocol)?;
        let udp = if kind == FlowKind::Udp {
            Some(q.register(id).map_err(OpenFlowError::Transport)?)
        } else {
            None
        };
        let mut bytes = [0; crate::protocol::TARGET_MAX_ENCODED_LEN + 17];
        let prefix = if let Some(auth) = auth {
            bytes[..16].copy_from_slice(&auth);
            16
        } else {
            0
        };
        let size = encode_flow_request_into(kind, target, &mut bytes[prefix..])
            .map_err(OpenFlowError::Protocol)?;
        send.write_all(&bytes[..prefix + size])
            .await
            .map_err(|e| OpenFlowError::Transport(e.into()))?;
        let result = crate::protocol::read_flow_result(&mut recv)
            .await
            .map_err(OpenFlowError::Protocol)?;
        Ok((QuicFlow { send, recv, udp }, SetupResult::from(result)))
    }
}

fn ready_quic_flow(
    flow: QuicFlow,
    result: SetupResult,
) -> std::result::Result<QuicFlow, OpenFlowError> {
    if result == SetupResult::Ready {
        Ok(flow)
    } else {
        Err(OpenFlowError::Setup(result))
    }
}

pub(crate) async fn connect_quic(
    config: &PortalClientConfig,
    tls: &ClientTls,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let remote = config.udp_endpoint().context("QUIC endpoint missing")?;
    let resolved = timeout(
        config.handshake_timeout,
        tokio::net::lookup_host((config.host(), remote.port)),
    )
    .await
    .context("Portal DNS timeout")??;
    let addresses =
        crate::common::filter_addrs_for_family(resolved, &config.dial_policy, remote.family);
    let mut last = anyhow!("Portal DNS returned no address");
    for address in addresses {
        let result = async {
            let bind = std::net::SocketAddr::new(
                if address.is_ipv4() {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                },
                0,
            );
            let socket = std::net::UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            let runtime = quinn::default_runtime().context("QUIC runtime missing")?;
            let socket = crate::transport::wrap_morph_udp_socket(
                runtime.wrap_udp_socket(socket)?,
                config.morph_keys.clone(),
                crate::transport::UdpRole::Client,
            )?;
            let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
                crate::transport::morph_endpoint_config(config.morph)?,
                None,
                socket,
                runtime,
            )?;
            let mut client = tls.quic_client_config()?;
            let mut transport = quinn::TransportConfig::default();
            let limits = crate::transport::transport_flow_control()?;
            transport
                .stream_receive_window(limits.stream_receive_window.into())
                .receive_window((64 * 1024u32).into())
                .send_window(limits.send_window)
                .max_concurrent_bidi_streams(1u32.into())
                .max_concurrent_uni_streams(0u32.into())
                .datagram_receive_buffer_size(Some(4 * 1024 * 1024))
                .datagram_send_buffer_size(4 * 1024 * 1024)
                .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
                .max_idle_timeout(Some(crate::common::udp_idle_timeout().try_into()?))
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            crate::transport::configure_morph_mtu(&mut transport, config.morph);
            client.transport_config(Arc::new(transport));
            endpoint.set_default_client_config(client);
            let connection = timeout(
                config.handshake_timeout,
                endpoint.connect(address, &tls.quic_server_name())?,
            )
            .await
            .context("QUIC handshake timeout")??;
            require_quic_nw3(&connection)?;
            Ok::<_, anyhow::Error>((endpoint, connection))
        }
        .await;
        match result {
            Ok(pair) => return Ok(pair),
            Err(error) => last = error,
        }
    }
    Err(last)
}
