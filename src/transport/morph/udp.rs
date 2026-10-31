// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph packet masking for QUIC UDP socket I/O.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use super::policy::{PreludePolicy, UDP_PRELUDE_ENV};
use super::udp_socket::ClientUdpSocket;
use super::{MorphKeyBytes, MorphKeys, NONCE_LEN, UDP_PRELUDE_LEN, exhausted};

const QUINN_DEFAULT_MTU_UPPER_BOUND: u16 = 1452;
pub(super) const UDP_NONCE_STREAM_LIMIT: u64 = (1u64 << 38) - 64;

#[derive(Clone, Copy)]
pub(crate) enum UdpRole {
    Client,
    Server,
}

pub(crate) fn wrap_morph_client_udp_socket(
    socket: std::net::UdpSocket,
    keys: Option<MorphKeys>,
    runtime: &dyn quinn::Runtime,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    if keys.is_none() {
        return runtime.wrap_udp_socket(socket);
    }
    wrap_morph_udp_socket(
        Arc::new(ClientUdpSocket::new(socket)?),
        keys,
        UdpRole::Client,
    )
}

pub(crate) fn wrap_morph_udp_socket(
    inner: Arc<dyn AsyncUdpSocket>,
    keys: Option<MorphKeys>,
    role: UdpRole,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    match keys {
        Some(keys) => {
            let (c2s, s2c) = keys.udp_keys();
            let (tx_key, rx_key) = match role {
                UdpRole::Client => (c2s, s2c),
                UdpRole::Server => (s2c, c2s),
            };
            Ok(Arc::new(MorphUdpSocket {
                inner,
                tx_key,
                rx_key,
                role,
                send: Mutex::new(UdpSendState::new(role)?),
                receive: Mutex::new(UdpReceiveState::new()),
            }))
        }
        None => Ok(inner),
    }
}

pub(crate) fn validate_udp_prelude_env() -> io::Result<()> {
    PreludePolicy::from_env(UDP_PRELUDE_ENV).map(|_| ())
}

pub(super) struct UdpSendState {
    send: Vec<u8>,
    prelude: Option<[u8; UDP_PRELUDE_LEN]>,
    pub(super) nonce_generator: UdpNonceGenerator,
}

impl UdpSendState {
    fn new(role: UdpRole) -> io::Result<Self> {
        let mut state = Self::from_seed(random_seed()?);
        if matches!(role, UdpRole::Client) {
            state.prelude = Some(PreludePolicy::from_env(UDP_PRELUDE_ENV)?.generate_udp()?);
        }
        Ok(state)
    }

    pub(super) fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            send: Vec::new(),
            prelude: None,
            nonce_generator: UdpNonceGenerator::from_seed(seed),
        }
    }
}

pub(super) struct UdpReceiveState {
    receive: [Vec<u8>; quinn::udp::BATCH_SIZE],
}

impl UdpReceiveState {
    pub(super) fn new() -> Self {
        Self {
            receive: std::array::from_fn(|_| Vec::new()),
        }
    }
}

pub(super) struct UdpNonceGenerator {
    cipher: ChaCha20,
    pub(super) generated: u64,
}

impl UdpNonceGenerator {
    pub(super) fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20::new((&seed).into(), (&[0u8; NONCE_LEN]).into()),
            generated: 0,
        }
    }

    pub(super) fn generate(&mut self, nonce: &mut [u8; NONCE_LEN]) -> io::Result<()> {
        self.generate_with_reseed(nonce, random_seed)
    }

    pub(super) fn generate_with_reseed(
        &mut self,
        nonce: &mut [u8; NONCE_LEN],
        reseed: impl FnOnce() -> io::Result<[u8; 32]>,
    ) -> io::Result<()> {
        if UDP_NONCE_STREAM_LIMIT.saturating_sub(self.generated) < NONCE_LEN as u64 {
            let seed = reseed()?;
            *self = Self::from_seed(seed);
        }
        nonce.fill(0);
        self.cipher
            .try_apply_keystream(nonce)
            .map_err(|_| io::Error::other("Morph UDP nonce generator exhausted"))?;
        self.generated += NONCE_LEN as u64;
        Ok(())
    }
}

fn random_seed() -> io::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(io::Error::other)?;
    Ok(seed)
}

pub(crate) fn morph_endpoint_config(enabled: bool) -> anyhow::Result<quinn::EndpointConfig> {
    let mut config = quinn::EndpointConfig::default();
    if enabled {
        let maximum = config
            .get_max_udp_payload_size()
            .checked_sub(NONCE_LEN as u64)
            .expect("Quinn UDP payload limit exceeds Morph overhead");
        config.max_udp_payload_size(maximum as u16)?;
    }
    Ok(config)
}

pub(crate) fn configure_morph_mtu(transport: &mut quinn::TransportConfig, enabled: bool) {
    if enabled {
        let mut discovery = quinn::MtuDiscoveryConfig::default();
        discovery.upper_bound(QUINN_DEFAULT_MTU_UPPER_BOUND - NONCE_LEN as u16);
        transport.mtu_discovery_config(Some(discovery));
    }
}

pub(super) struct MorphUdpSocket {
    pub(super) inner: Arc<dyn AsyncUdpSocket>,
    pub(super) tx_key: MorphKeyBytes,
    pub(super) rx_key: MorphKeyBytes,
    pub(super) role: UdpRole,
    pub(super) send: Mutex<UdpSendState>,
    pub(super) receive: Mutex<UdpReceiveState>,
}

impl fmt::Debug for MorphUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MorphUdpSocket")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for MorphUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let plain_stride = transmit.segment_size.unwrap_or(transmit.contents.len());
        if plain_stride == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty UDP datagram",
            ));
        }
        let segments = transmit.contents.len().div_ceil(plain_stride);
        let wire_len = transmit
            .contents
            .len()
            .checked_add(
                segments
                    .checked_mul(NONCE_LEN)
                    .ok_or_else(|| io::Error::other("Morph UDP datagram length overflow"))?,
            )
            .ok_or_else(|| io::Error::other("Morph UDP datagram length overflow"))?;
        let mut state = self.send.lock().unwrap_or_else(|lock| lock.into_inner());
        if let Some(prelude) = &state.prelude {
            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: prelude,
                segment_size: None,
                src_ip: transmit.src_ip,
            })?;
            state.prelude = None;
        }
        let UdpSendState {
            send,
            nonce_generator,
            ..
        } = &mut *state;
        if send.len() < wire_len {
            send.resize(wire_len, 0);
        }
        let mut wire_offset = 0;
        for plain in transmit.contents.chunks(plain_stride) {
            let wire_end = wire_offset + NONCE_LEN + plain.len();
            let (nonce, payload) = send[wire_offset..wire_end].split_at_mut(NONCE_LEN);
            let nonce: &mut [u8; NONCE_LEN] = nonce.try_into().expect("fixed nonce prefix");
            nonce_generator.generate(nonce)?;
            let mut cipher = ChaCha20::new((&self.tx_key).into(), (&*nonce).into());
            cipher
                .try_apply_keystream_b2b(plain, payload)
                .map_err(|_| exhausted())?;
            wire_offset = wire_end;
        }
        debug_assert_eq!(wire_offset, wire_len);
        let wire_stride = transmit
            .segment_size
            .map(|size| {
                size.checked_add(NONCE_LEN)
                    .ok_or_else(|| io::Error::other("Morph UDP segment length overflow"))
            })
            .transpose()?;
        let wire = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &send[..wire_len],
            segment_size: wire_stride,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wire)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let receive_count = bufs.len().min(meta.len()).min(quinn::udp::BATCH_SIZE);
        if receive_count == 0 {
            return Poll::Ready(Ok(0));
        }
        let max_segments = self.inner.max_receive_segments().max(1);
        let mut state = self.receive.lock().unwrap_or_else(|lock| lock.into_inner());
        let Some(nonce_overhead) = NONCE_LEN.checked_mul(max_segments) else {
            return Poll::Ready(Err(io::Error::other(
                "Morph UDP receive buffer length overflow",
            )));
        };
        let mut wire_lengths = [0; quinn::udp::BATCH_SIZE];
        for index in 0..receive_count {
            let Some(wire_len) = bufs[index].len().checked_add(nonce_overhead) else {
                return Poll::Ready(Err(io::Error::other(
                    "Morph UDP receive buffer length overflow",
                )));
            };
            wire_lengths[index] = wire_len;
            if state.receive[index].len() < wire_len {
                state.receive[index].resize(wire_len, 0);
            }
        }
        let receive = state.receive.each_mut();
        let mut index = 0;
        let mut wire_bufs = receive.map(|value| {
            let wire_len = wire_lengths[index];
            index += 1;
            IoSliceMut::new(&mut value[..wire_len])
        });
        let received = match self.inner.poll_recv(
            cx,
            &mut wire_bufs[..receive_count],
            &mut meta[..receive_count],
        ) {
            Poll::Ready(Ok(received)) => received.min(receive_count),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        let mut output = 0;
        for index in 0..received {
            let wire_meta = meta[index];
            let wire_stride = wire_meta.stride;
            let storage = &state.receive[index];
            if wire_meta.len == 0
                || wire_meta.len > wire_lengths[index]
                || wire_stride <= NONCE_LEN
                || wire_stride > wire_meta.len
            {
                continue;
            }
            let segment_count = wire_meta.len.div_ceil(wire_stride);
            let Some(nonce_bytes) = segment_count.checked_mul(NONCE_LEN) else {
                continue;
            };
            let Some(expected_len) = wire_meta.len.checked_sub(nonce_bytes) else {
                continue;
            };
            let final_wire_len = wire_meta.len % wire_stride;
            if expected_len == 0
                || expected_len > bufs[output].len()
                || (final_wire_len != 0 && final_wire_len <= NONCE_LEN)
            {
                continue;
            }
            let target = &mut bufs[output];
            let decoded_stride = wire_stride - NONCE_LEN;
            let mut decoded_len = 0;
            for wire in storage[..wire_meta.len].chunks(wire_stride) {
                let (nonce, encrypted) = wire.split_at(NONCE_LEN);
                let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("fixed nonce prefix");
                let mut cipher = ChaCha20::new((&self.rx_key).into(), nonce.into());
                let end = decoded_len + encrypted.len();
                cipher
                    .try_apply_keystream_b2b(encrypted, &mut target[decoded_len..end])
                    .map_err(|_| exhausted())?;
                if matches!(self.role, UdpRole::Server)
                    && !supported_quic_packet(&target[decoded_len..end])
                {
                    continue;
                }
                decoded_len = end;
            }
            if decoded_len == 0 {
                continue;
            }
            meta[output] = RecvMeta {
                len: decoded_len,
                stride: decoded_stride.min(decoded_len),
                ..wire_meta
            };
            output += 1;
        }
        if output != 0 {
            return Poll::Ready(Ok(output));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn supported_quic_packet(packet: &[u8]) -> bool {
    match packet.first() {
        Some(first) if first & 0x80 == 0 => true,
        Some(_) => packet.get(1..5).is_some_and(|version| {
            quinn_proto::DEFAULT_SUPPORTED_VERSIONS.contains(&u32::from_be_bytes(
                version.try_into().expect("version length"),
            ))
        }),
        None => false,
    }
}

#[cfg(test)]
#[path = "../../tests/transport/morph/udp.rs"]
mod tests;
