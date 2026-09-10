// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Mutex as StdMutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use super::super::udp::{UDP_NONCE_STREAM_LIMIT, UdpNonceGenerator};
use super::super::*;

#[test]
fn udp_nonce_generator_fills_batches_from_one_stream() {
    let mut buffers = UdpBuffers::from_seed([3; 32]);
    let mut first = [0; NONCE_LEN];
    let mut second = [0; NONCE_LEN];
    buffers.nonce_generator.generate(&mut first).unwrap();
    buffers.nonce_generator.generate(&mut second).unwrap();

    assert_ne!(first, [0; NONCE_LEN]);
    assert_ne!(second, first);
}

#[test]
fn udp_nonce_generator_reseeds_before_exhaustion_and_retries_failures() {
    let mut generator = UdpNonceGenerator::from_seed([3; 32]);
    generator.generated = UDP_NONCE_STREAM_LIMIT;
    let mut nonce = [9; NONCE_LEN];

    let error = generator
        .generate_with_reseed(&mut nonce, || Err(io::Error::other("no entropy")))
        .unwrap_err();
    assert_eq!(error.to_string(), "no entropy");
    assert_eq!(generator.generated, UDP_NONCE_STREAM_LIMIT);
    assert_eq!(nonce, [9; NONCE_LEN]);

    generator
        .generate_with_reseed(&mut nonce, || Ok([4; 32]))
        .unwrap();
    assert_eq!(generator.generated, NONCE_LEN as u64);
    let mut expected = [0; NONCE_LEN];
    UdpNonceGenerator::from_seed([4; 32])
        .generate_with_reseed(&mut expected, || panic!("fresh stream must not reseed"))
        .unwrap();
    assert_eq!(nonce, expected);
}

#[test]
fn morph_endpoint_reserves_the_udp_nonce_overhead() {
    let plain = morph_endpoint_config(false).unwrap();
    let morph = morph_endpoint_config(true).unwrap();

    assert_eq!(
        morph.get_max_udp_payload_size() + NONCE_LEN as u64,
        plain.get_max_udp_payload_size()
    );
}

#[derive(Debug, Default)]
struct FakeUdpSocket {
    sent: StdMutex<Vec<(Vec<u8>, Option<usize>)>>,
    receive: StdMutex<VecDeque<(Vec<u8>, RecvMeta)>>,
    receive_lengths: StdMutex<Vec<usize>>,
}

#[derive(Debug)]
struct ReadyPoller;

impl std::future::Future for ReadyPoller {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(()))
    }
}

impl UdpPoller for ReadyPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for FakeUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ReadyPoller)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((transmit.contents.to_vec(), transmit.segment_size));
        Ok(())
    }

    fn poll_recv(
        &self,
        _cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some((packet, packet_meta)) = self.receive.lock().unwrap().pop_front() else {
            return Poll::Pending;
        };
        self.receive_lengths.lock().unwrap().push(bufs[0].len());
        bufs[0][..packet.len()].copy_from_slice(&packet);
        meta[0] = packet_meta;
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok("127.0.0.1:1".parse().unwrap())
    }

    fn max_transmit_segments(&self) -> usize {
        2
    }

    fn max_receive_segments(&self) -> usize {
        2
    }
}

#[tokio::test]
async fn udp_preserves_gso_datagram_boundaries() {
    let key = MorphKeys::derive(b"shared").udp_key();
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = MorphUdpSocket {
        inner: raw.clone(),
        key,
        buffers: Mutex::new(UdpBuffers::from_seed([1; 32])),
    };
    for plain in [
        b"abcdef".as_slice(),
        b"abcde".as_slice(),
        b"ghijkl".as_slice(),
    ] {
        socket
            .try_send(&Transmit {
                destination: "127.0.0.1:2".parse().unwrap(),
                ecn: None,
                contents: plain,
                segment_size: Some(3),
                src_ip: None,
            })
            .unwrap();
        let (wire, stride) = raw.sent.lock().unwrap().pop().unwrap();
        assert_eq!(stride, Some(15));
        assert_eq!(wire.len(), plain.len() + 2 * NONCE_LEN);
        assert_ne!(&wire[..NONCE_LEN], &wire[15..15 + NONCE_LEN]);

        let wire_len = wire.len();
        raw.receive.lock().unwrap().push_back((
            wire,
            RecvMeta {
                addr: "127.0.0.1:2".parse().unwrap(),
                len: wire_len,
                stride: 15,
                ecn: None,
                dst_ip: None,
            },
        ));
        let mut output = [0xa7; 6];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [RecvMeta::default()];
        let count = poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(&output[..plain.len()], plain);
        assert!(output[plain.len()..].iter().all(|byte| *byte == 0xa7));
        assert_eq!(meta[0].len, plain.len());
        assert_eq!(meta[0].stride, 3);
    }
}

#[tokio::test]
async fn udp_discards_invalid_wire_datagrams_before_returning_valid_data() {
    let key = MorphKeys::derive(b"shared").udp_key();
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = MorphUdpSocket {
        inner: raw.clone(),
        key,
        buffers: Mutex::new(UdpBuffers::from_seed([2; 32])),
    };
    let packet_meta = |len| RecvMeta {
        addr: "127.0.0.1:2".parse().unwrap(),
        len,
        stride: len,
        ecn: None,
        dst_ip: None,
    };
    raw.receive
        .lock()
        .unwrap()
        .push_back((vec![0; NONCE_LEN], packet_meta(NONCE_LEN)));

    socket
        .try_send(&Transmit {
            destination: "127.0.0.1:2".parse().unwrap(),
            ecn: None,
            contents: b"oversized",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let (oversized, _) = raw.sent.lock().unwrap().pop().unwrap();
    let oversized_len = oversized.len();
    raw.receive
        .lock()
        .unwrap()
        .push_back((oversized, packet_meta(oversized_len)));

    raw.receive
        .lock()
        .unwrap()
        .push_back((vec![0; NONCE_LEN], packet_meta(5 + NONCE_LEN * 2 + 1)));

    socket
        .try_send(&Transmit {
            destination: "127.0.0.1:2".parse().unwrap(),
            ecn: None,
            contents: b"valid",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let (wire, _) = raw.sent.lock().unwrap().pop().unwrap();
    let wire_len = wire.len();
    raw.receive
        .lock()
        .unwrap()
        .push_back((wire, packet_meta(wire_len)));

    let mut output = [0u8; 5];
    let mut bufs = [IoSliceMut::new(&mut output)];
    let mut meta = [RecvMeta::default()];
    let count = poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(&output, b"valid");
    assert_eq!(meta[0].len, 5);
}

#[tokio::test]
async fn udp_reuses_buffers_without_relaxing_current_receive_bounds() {
    let key = MorphKeys::derive(b"shared").udp_key();
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = MorphUdpSocket {
        inner: raw.clone(),
        key,
        buffers: Mutex::new(UdpBuffers::from_seed([5; 32])),
    };
    let destination = "127.0.0.1:2".parse().unwrap();
    let packet_meta = |len| RecvMeta {
        addr: destination,
        len,
        stride: len,
        ecn: None,
        dst_ip: None,
    };

    socket
        .try_send(&Transmit {
            destination,
            ecn: None,
            contents: &[0x5a; 32],
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let (large_wire, _) = raw.sent.lock().unwrap().pop().unwrap();
    let large_wire_len = large_wire.len();
    raw.receive
        .lock()
        .unwrap()
        .push_back((large_wire, packet_meta(large_wire_len)));
    let mut large_output = [0; 32];
    let mut large_bufs = [IoSliceMut::new(&mut large_output)];
    let mut large_meta = [RecvMeta::default()];
    poll_fn(|cx| socket.poll_recv(cx, &mut large_bufs, &mut large_meta))
        .await
        .unwrap();
    assert_eq!(large_output, [0x5a; 32]);

    socket
        .try_send(&Transmit {
            destination,
            ecn: None,
            contents: b"x",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let (small_wire, _) = raw.sent.lock().unwrap().pop().unwrap();
    assert_eq!(small_wire.len(), NONCE_LEN + 1);
    // Three one-byte GRO payloads would fit the decoded target, but the
    // claimed wire length exceeds this call's receive slice (4 + 2 * 12).
    raw.receive.lock().unwrap().push_back((
        vec![0; NONCE_LEN],
        RecvMeta {
            len: 3 * (NONCE_LEN + 1),
            stride: NONCE_LEN + 1,
            ..packet_meta(0)
        },
    ));
    let small_wire_len = small_wire.len();
    raw.receive
        .lock()
        .unwrap()
        .push_back((small_wire, packet_meta(small_wire_len)));
    let mut small_output = [0xa7; 4];
    let mut small_bufs = [IoSliceMut::new(&mut small_output)];
    let mut small_meta = [RecvMeta::default()];
    poll_fn(|cx| socket.poll_recv(cx, &mut small_bufs, &mut small_meta))
        .await
        .unwrap();
    assert_eq!(small_meta[0].len, 1);
    assert_eq!(small_output, [b'x', 0xa7, 0xa7, 0xa7]);

    socket
        .try_send(&Transmit {
            destination,
            ecn: None,
            contents: &[0xa5; 48],
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let (larger_wire, _) = raw.sent.lock().unwrap().pop().unwrap();
    assert_eq!(larger_wire.len(), NONCE_LEN + 48);
    let larger_wire_len = larger_wire.len();
    raw.receive
        .lock()
        .unwrap()
        .push_back((larger_wire, packet_meta(larger_wire_len)));
    let mut larger_output = [0; 48];
    let mut larger_bufs = [IoSliceMut::new(&mut larger_output)];
    let mut larger_meta = [RecvMeta::default()];
    poll_fn(|cx| socket.poll_recv(cx, &mut larger_bufs, &mut larger_meta))
        .await
        .unwrap();
    assert_eq!(larger_output, [0xa5; 48]);
    assert_eq!(
        *raw.receive_lengths.lock().unwrap(),
        [
            32 + 2 * NONCE_LEN,
            4 + 2 * NONCE_LEN,
            4 + 2 * NONCE_LEN,
            48 + 2 * NONCE_LEN
        ]
    );
}
