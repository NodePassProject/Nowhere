// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::fmt;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use super::{MorphKey, NONCE_LEN, exhausted};

const QUINN_DEFAULT_MTU_UPPER_BOUND: u16 = 1452;
const MAX_INVALID_RECEIVE_BATCHES: usize = 32;

pub(crate) fn wrap_morph_udp_socket(
    inner: Arc<dyn AsyncUdpSocket>,
    key: Option<MorphKey>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    match key {
        Some(key) => Ok(Arc::new(MorphUdpSocket {
            inner,
            key,
            buffers: Mutex::new(UdpBuffers::new()?),
        })),
        None => Ok(inner),
    }
}

pub(super) struct UdpBuffers {
    send: Vec<u8>,
    receive: [Vec<u8>; quinn::udp::BATCH_SIZE],
    pub(super) nonce_cipher: ChaCha20,
}

impl UdpBuffers {
    fn new() -> io::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(io::Error::other)?;
        Ok(Self::from_seed(seed))
    }

    pub(super) fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            send: Vec::new(),
            receive: std::array::from_fn(|_| Vec::new()),
            nonce_cipher: ChaCha20::new((&seed).into(), (&[0u8; NONCE_LEN]).into()),
        }
    }
}

pub(super) fn generate_nonce(cipher: &mut ChaCha20, nonce: &mut [u8; NONCE_LEN]) -> io::Result<()> {
    nonce.fill(0);
    cipher
        .try_apply_keystream(nonce)
        .map_err(|_| io::Error::other("Morph UDP nonce generator exhausted"))
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
    pub(super) key: MorphKey,
    pub(super) buffers: Mutex<UdpBuffers>,
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
        let mut buffers = self.buffers.lock().unwrap_or_else(|lock| lock.into_inner());
        let UdpBuffers {
            send, nonce_cipher, ..
        } = &mut *buffers;
        send.clear();
        send.reserve(transmit.contents.len() + segments * NONCE_LEN);
        for plain in transmit.contents.chunks(plain_stride) {
            let start = send.len();
            send.resize(start + NONCE_LEN + plain.len(), 0);
            let (nonce, payload) = send[start..].split_at_mut(NONCE_LEN);
            let nonce: &mut [u8; NONCE_LEN] = nonce.try_into().expect("fixed nonce prefix");
            generate_nonce(nonce_cipher, nonce)?;
            payload.copy_from_slice(plain);
            let mut cipher = ChaCha20::new((&self.key).into(), (&*nonce).into());
            cipher
                .try_apply_keystream(payload)
                .map_err(|_| exhausted())?;
        }
        let wire_stride = transmit.segment_size.map(|size| size + NONCE_LEN);
        let wire = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: send,
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
        let max_segments = self.inner.max_receive_segments().max(1);
        let mut buffers = self.buffers.lock().unwrap_or_else(|lock| lock.into_inner());
        for (storage, target) in buffers.receive.iter_mut().zip(bufs.iter()) {
            storage.resize(target.len() + NONCE_LEN * max_segments, 0);
        }
        for _ in 0..MAX_INVALID_RECEIVE_BATCHES {
            let receive = buffers.receive.each_mut();
            let mut wire_bufs = receive.map(|value| IoSliceMut::new(value));
            let received = match self.inner.poll_recv(cx, &mut wire_bufs[..bufs.len()], meta) {
                Poll::Ready(Ok(received)) => received,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            let mut output = 0;
            for index in 0..received {
                let wire_meta = meta[index];
                let wire_stride = wire_meta.stride.max(1);
                let storage = &mut buffers.receive[index];
                let target = &mut bufs[output];
                let decoded_stride = wire_stride.saturating_sub(NONCE_LEN);
                let mut decoded_len = 0;
                for wire in storage[..wire_meta.len].chunks_mut(wire_stride) {
                    if wire.len() <= NONCE_LEN {
                        continue;
                    }
                    let (nonce, encrypted) = wire.split_at_mut(NONCE_LEN);
                    let nonce: &[u8; NONCE_LEN] = (&*nonce).try_into().expect("fixed nonce prefix");
                    let mut cipher = ChaCha20::new((&self.key).into(), nonce.into());
                    cipher
                        .try_apply_keystream(encrypted)
                        .map_err(|_| exhausted())?;
                    let end = decoded_len + encrypted.len();
                    if end > target.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Morph UDP receive buffer overflow",
                        )));
                    }
                    target[decoded_len..end].copy_from_slice(encrypted);
                    decoded_len = end;
                }
                if decoded_len == 0 {
                    continue;
                }
                meta[output] = RecvMeta {
                    len: decoded_len,
                    stride: decoded_stride,
                    ..wire_meta
                };
                output += 1;
            }
            if output != 0 {
                return Poll::Ready(Ok(output));
            }
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
