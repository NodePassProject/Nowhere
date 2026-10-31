// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph UDP masking and segmented packet I/O tests.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Mutex as StdMutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use super::*;

#[test]
fn udp_nonce_generator_fills_batches_from_one_stream() {
    let mut state = UdpSendState::from_seed([3; 32]);
    let mut first = [0; NONCE_LEN];
    let mut second = [0; NONCE_LEN];
    state.nonce_generator.generate(&mut first).unwrap();
    state.nonce_generator.generate(&mut second).unwrap();

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
    outcomes: StdMutex<VecDeque<Option<io::ErrorKind>>>,
    attempts: StdMutex<Vec<Vec<u8>>>,
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
        self.attempts
            .lock()
            .unwrap()
            .push(transmit.contents.to_vec());
        if let Some(Some(kind)) = self.outcomes.lock().unwrap().pop_front() {
            return Err(io::Error::from(kind));
        }
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
        let mut receive = self.receive.lock().unwrap();
        let mut count = 0;
        for (buf, output_meta) in bufs.iter_mut().zip(meta) {
            let Some((packet, packet_meta)) = receive.pop_front() else {
                break;
            };
            self.receive_lengths.lock().unwrap().push(buf.len());
            buf[..packet.len()].copy_from_slice(&packet);
            *output_meta = packet_meta;
            count += 1;
        }
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
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
    let key = MorphKeys::derive(b"shared").udp_c2s;
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = MorphUdpSocket {
        inner: raw.clone(),
        tx_key: key,
        rx_key: key,
        role: UdpRole::Client,
        send: Mutex::new(UdpSendState::from_seed([1; 32])),
        receive: Mutex::new(UdpReceiveState::new()),
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
    let key = MorphKeys::derive(b"shared").udp_c2s;
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = MorphUdpSocket {
        inner: raw.clone(),
        tx_key: key,
        rx_key: key,
        role: UdpRole::Client,
        send: Mutex::new(UdpSendState::from_seed([2; 32])),
        receive: Mutex::new(UdpReceiveState::new()),
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
    let key = MorphKeys::derive(b"shared").udp_c2s;
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = MorphUdpSocket {
        inner: raw.clone(),
        tx_key: key,
        rx_key: key,
        role: UdpRole::Client,
        send: Mutex::new(UdpSendState::from_seed([5; 32])),
        receive: Mutex::new(UdpReceiveState::new()),
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

#[test]
fn quic_version_filter_uses_quinn_versions_and_only_reads_long_header_versions() {
    assert!(!supported_quic_packet(&[]));
    for first in 0..=0x7f {
        assert!(supported_quic_packet(&[first]));
    }
    for first in [0x80, 0xc0, 0xf0, 0xff] {
        for version in quinn_proto::DEFAULT_SUPPORTED_VERSIONS {
            let mut packet = vec![first];
            packet.extend_from_slice(&version.to_be_bytes());
            assert!(supported_quic_packet(&packet));
            for len in 1..5 {
                assert!(!supported_quic_packet(&packet[..len]));
            }
        }
        for version in [0u32, 2, 0x0a1a_2a3a, u32::MAX] {
            let mut packet = vec![first];
            packet.extend_from_slice(&version.to_be_bytes());
            assert!(!supported_quic_packet(&packet));
        }
    }
}

fn filter_socket(raw: Arc<FakeUdpSocket>, role: UdpRole) -> MorphUdpSocket {
    let key = MorphKeys::derive(b"shared").udp_c2s;
    MorphUdpSocket {
        inner: raw,
        tx_key: key,
        rx_key: key,
        role,
        send: Mutex::new(UdpSendState::from_seed([7; 32])),
        receive: Mutex::new(UdpReceiveState::new()),
    }
}

fn queue_segments(raw: &FakeUdpSocket, plain: &[u8], stride: usize, addr: &str) {
    let key = MorphKeys::derive(b"shared").udp_c2s;
    let mut wire = Vec::new();
    for (index, segment) in plain.chunks(stride).enumerate() {
        let nonce = [index as u8; NONCE_LEN];
        wire.extend_from_slice(&nonce);
        let start = wire.len();
        wire.extend_from_slice(segment);
        ChaCha20::new((&key).into(), (&nonce).into()).apply_keystream(&mut wire[start..]);
    }
    let len = wire.len();
    raw.receive.lock().unwrap().push_back((
        wire,
        RecvMeta {
            addr: addr.parse().unwrap(),
            len,
            stride: (stride + NONCE_LEN).min(len),
            ecn: Some(quinn::udp::EcnCodepoint::Ect0),
            dst_ip: Some("127.0.0.9".parse().unwrap()),
        },
    ));
}

#[tokio::test]
async fn server_filters_each_gro_segment_and_preserves_metadata_and_short_tails() {
    let mut accepted = vec![0xc0];
    accepted.extend_from_slice(&quinn_proto::DEFAULT_SUPPORTED_VERSIONS[0].to_be_bytes());
    accepted.extend_from_slice(&[1, 2, 3]);
    let rejected = [0xc0, 0xff, 0xff, 0xff, 0xff, 4, 5, 6];
    for (plain, expected) in [
        ([rejected.as_slice(), &accepted].concat(), accepted.clone()),
        ([accepted.as_slice(), &rejected].concat(), accepted.clone()),
        (
            [accepted.as_slice(), &accepted].concat(),
            [accepted.as_slice(), &accepted].concat(),
        ),
        (
            [rejected.as_slice(), &[0x40, 7, 8]].concat(),
            vec![0x40, 7, 8],
        ),
        (
            [accepted.as_slice(), &[0xc0, 0, 0]].concat(),
            accepted.clone(),
        ),
        (
            [accepted.as_slice(), &[0x40, 7, 8]].concat(),
            [accepted.as_slice(), &[0x40, 7, 8]].concat(),
        ),
    ] {
        let raw = Arc::new(FakeUdpSocket::default());
        let socket = filter_socket(raw.clone(), UdpRole::Server);
        for _ in 0..2 {
            queue_segments(&raw, &plain, 8, "127.0.0.2:2345");
            let mut output = [0xa7; 16];
            let mut bufs = [IoSliceMut::new(&mut output)];
            let mut meta = [RecvMeta::default()];
            assert_eq!(
                poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(&output[..expected.len()], expected);
            assert_eq!(meta[0].len, expected.len());
            assert_eq!(meta[0].stride, 8.min(expected.len()));
            assert_eq!(meta[0].addr, "127.0.0.2:2345".parse().unwrap());
            assert_eq!(meta[0].ecn, Some(quinn::udp::EcnCodepoint::Ect0));
            assert_eq!(meta[0].dst_ip, Some("127.0.0.9".parse().unwrap()));
        }
    }
}

#[tokio::test]
async fn server_compacts_receive_batches_and_wakes_after_discarding_all_segments() {
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = filter_socket(raw.clone(), UdpRole::Server);
    let rejected = [0xc0, 0xff, 0xff, 0xff, 0xff];
    queue_segments(&raw, &rejected.repeat(2), 5, "127.0.0.2:2");
    queue_segments(&raw, &rejected, 5, "127.0.0.3:3");
    let mut output = [[0; 16]; 2];
    let mut bufs = output.each_mut().map(|buf| IoSliceMut::new(buf));
    let mut meta = [RecvMeta::default(); 2];
    let wakes = Arc::new(TestWake(std::sync::atomic::AtomicUsize::new(0)));
    let waker = std::task::Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(socket.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
    assert_eq!(wakes.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    queue_segments(&raw, &rejected, 5, "127.0.0.2:2");
    queue_segments(&raw, b"valid", 5, "127.0.0.3:3");
    assert_eq!(
        poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap(),
        1
    );
    assert_eq!(&bufs[0][..5], b"valid");
    assert_eq!(meta[0].addr, "127.0.0.3:3".parse().unwrap());
}

struct TestWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for TestWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tokio::test]
async fn client_passes_unsupported_versions_and_native_socket_is_not_wrapped() {
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = filter_socket(raw.clone(), UdpRole::Client);
    let plain = [0xc0, 0xff, 0xff, 0xff, 0xff];
    queue_segments(&raw, &plain, 5, "127.0.0.2:2");
    let mut output = [0; 5];
    let mut bufs = [IoSliceMut::new(&mut output)];
    let mut meta = [RecvMeta::default()];
    assert_eq!(
        poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap(),
        1
    );
    assert_eq!(output, plain);
    for role in [UdpRole::Server, UdpRole::Client] {
        let inner: Arc<dyn AsyncUdpSocket> = raw.clone();
        assert!(Arc::ptr_eq(
            &inner,
            &wrap_morph_udp_socket(inner.clone(), None, role).unwrap()
        ));
    }
}

#[test]
fn udp_prelude_retries_only_until_success_and_preserves_normal_datagrams() {
    for outcomes in [
        vec![
            Some(io::ErrorKind::WouldBlock),
            Some(io::ErrorKind::WouldBlock),
        ],
        vec![None, Some(io::ErrorKind::WouldBlock)],
        vec![Some(io::ErrorKind::PermissionDenied)],
        vec![None, Some(io::ErrorKind::PermissionDenied)],
    ] {
        let raw = Arc::new(FakeUdpSocket::default());
        raw.outcomes
            .lock()
            .unwrap()
            .extend(outcomes.iter().copied());
        let socket = filter_socket(raw.clone(), UdpRole::Client);
        let prelude = [0x41; UDP_PRELUDE_LEN];
        socket.send.lock().unwrap().prelude = Some(prelude);
        let transmit = Transmit {
            destination: "127.0.0.1:443".parse().unwrap(),
            ecn: None,
            contents: b"original QUIC packet",
            segment_size: None,
            src_ip: None,
        };
        for kind in outcomes.into_iter().flatten() {
            assert_eq!(socket.try_send(&transmit).unwrap_err().kind(), kind);
        }
        socket.try_send(&transmit).unwrap();
        socket.try_send(&transmit).unwrap();
        let attempts = raw.attempts.lock().unwrap();
        assert!(
            attempts
                .iter()
                .filter(|data| data.len() == UDP_PRELUDE_LEN)
                .all(|data| data == &prelude)
        );
        let sent = raw.sent.lock().unwrap();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0], (prelude.to_vec(), None));
        for (wire, _) in &sent[1..] {
            let (nonce, encrypted) = wire.split_at(NONCE_LEN);
            let nonce: &[u8; NONCE_LEN] = nonce.try_into().unwrap();
            let mut plain = encrypted.to_vec();
            ChaCha20::new((&socket.tx_key).into(), nonce.into()).apply_keystream(&mut plain);
            assert_eq!(plain, transmit.contents);
        }
        assert!(socket.send.lock().unwrap().prelude.is_none());
    }
}

#[test]
fn udp_prelude_is_once_per_socket_under_concurrent_sends() {
    for _ in 0..2 {
        let raw = Arc::new(FakeUdpSocket::default());
        let socket = Arc::new(filter_socket(raw.clone(), UdpRole::Client));
        socket.send.lock().unwrap().prelude = Some([0x41; UDP_PRELUDE_LEN]);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    socket
                        .try_send(&Transmit {
                            destination: "127.0.0.1:443".parse().unwrap(),
                            ecn: None,
                            contents: b"packet",
                            segment_size: None,
                            src_ip: None,
                        })
                        .unwrap()
                });
            }
        });
        let sent = raw.sent.lock().unwrap();
        assert_eq!(sent.len(), 9);
        assert_eq!(sent[0].0.len(), UDP_PRELUDE_LEN);
        assert!(
            sent[1..]
                .iter()
                .all(|(wire, _)| wire.len() == NONCE_LEN + 6)
        );
    }
}

#[test]
fn udp_server_and_disabled_morph_do_not_send_preludes() {
    for (keys, role) in [
        (None, UdpRole::Client),
        (None, UdpRole::Server),
        (Some(MorphKeys::derive(b"shared")), UdpRole::Server),
    ] {
        let raw = Arc::new(FakeUdpSocket::default());
        let socket = wrap_morph_udp_socket(raw.clone(), keys.clone(), role).unwrap();
        socket
            .try_send(&Transmit {
                destination: "127.0.0.1:443".parse().unwrap(),
                ecn: None,
                contents: b"packet",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let sent = raw.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].0.len(),
            6 + if keys.is_some() { NONCE_LEN } else { 0 }
        );
        if keys.is_none() {
            assert_eq!(sent[0].0, b"packet");
        }
    }
}

#[test]
fn wrapped_client_generates_a_prelude_before_its_first_quic_packet() {
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = wrap_morph_udp_socket(
        raw.clone(),
        Some(MorphKeys::derive(b"shared")),
        UdpRole::Client,
    )
    .unwrap();
    for _ in 0..2 {
        socket
            .try_send(&Transmit {
                destination: "127.0.0.1:443".parse().unwrap(),
                ecn: None,
                contents: b"packet",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
    }
    let sent = raw.sent.lock().unwrap();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[0].0.len(), UDP_PRELUDE_LEN);
    assert_eq!(sent[0].1, None);
    assert_eq!(sent[1].0.len(), NONCE_LEN + 6);
}

#[tokio::test]
async fn server_silently_discards_udp_prelude_then_receives_normal_morph_packet() {
    let raw = Arc::new(FakeUdpSocket::default());
    let socket = filter_socket(raw.clone(), UdpRole::Server);
    for size in 0..=UDP_PRELUDE_LEN {
        raw.receive.lock().unwrap().push_back((
            vec![0x41; size],
            RecvMeta {
                addr: "127.0.0.1:443".parse().unwrap(),
                len: size,
                stride: size,
                ..RecvMeta::default()
            },
        ));
    }
    queue_segments(&raw, &[0x40, 1, 2, 3], 4, "127.0.0.1:443");
    let mut bytes = [0u8; 64];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let mut meta = [RecvMeta::default()];
    let received = poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
        .await
        .unwrap();
    assert_eq!(received, 1);
    assert_eq!(&bufs[0][..meta[0].len], &[0x40, 1, 2, 3]);
    assert!(raw.sent.lock().unwrap().is_empty());
}
