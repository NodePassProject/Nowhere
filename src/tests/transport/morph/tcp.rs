// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph TCP masking and partial I/O tests.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::*;

impl super::MorphWriteReady for tokio::io::DuplexStream {
    fn poll_morph_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn apply_at(
    key: &super::super::MorphKeyBytes,
    nonce: &[u8; NONCE_LEN],
    offset: u64,
    bytes: &mut [u8],
) -> io::Result<()> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.try_seek(offset).map_err(|_| exhausted())?;
    cipher.try_apply_keystream(bytes).map_err(|_| exhausted())
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn chacha20_starts_at_block_zero() {
    let mut block = [0u8; 64];
    apply_at(&[0; 32], &[0; 12], 0, &mut block).unwrap();
    assert_eq!(
        block,
        hex(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        )
    );
}

#[test]
fn tcp_empty_io_is_immediately_ready_after_bootstrap() {
    let keys = MorphKeys::derive(b"shared");
    let (_client_io, server_io) = tokio::io::duplex(64);
    let mut server = MorphTcpStream::initialized_for_test(server_io, &keys, [1; NONCE_LEN], false);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut empty = [];
    let mut read_buf = ReadBuf::new(&mut empty);

    assert!(matches!(
        Pin::new(&mut server).poll_read(&mut context, &mut read_buf),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        Pin::new(&mut server).poll_write(&mut context, &[]),
        Poll::Ready(Ok(0))
    ));
}

#[tokio::test]
async fn tcp_limits_each_cipher_direction_without_touching_the_other() {
    let keys = MorphKeys::derive(b"shared");
    let nonce = [17; NONCE_LEN];
    let (client_io, mut peer) = tokio::io::duplex(64);
    let mut client = MorphTcpStream::initialized_for_test(client_io, &keys, nonce, true);
    let state = client.morph.as_mut().unwrap();
    state.write_offset = TCP_STREAM_LIMIT - 3;
    state.write_cipher.try_seek(state.write_offset).unwrap();
    state.read_offset = TCP_STREAM_LIMIT - 5;
    state.read_cipher.try_seek(state.read_offset).unwrap();

    assert_eq!(client.write(b"request").await.unwrap(), 3);
    let mut wire = [0; 3];
    peer.read_exact(&mut wire).await.unwrap();
    apply_at(&keys.tcp_c2s, &nonce, TCP_STREAM_LIMIT - 3, &mut wire).unwrap();
    assert_eq!(&wire, b"req");
    assert_eq!(
        client.write(b"x").await.unwrap_err().kind(),
        exhausted().kind()
    );
    assert_eq!(client.write(&[]).await.unwrap(), 0);

    let mut response = *b"reply";
    apply_at(&keys.tcp_s2c, &nonce, TCP_STREAM_LIMIT - 5, &mut response).unwrap();
    peer.write_all(&response).await.unwrap();
    let mut received = [0; 8];
    assert_eq!(client.read(&mut received).await.unwrap(), 5);
    assert_eq!(&received[..5], b"reply");
    assert_eq!(
        client.read(&mut received).await.unwrap_err().kind(),
        exhausted().kind()
    );
    assert_eq!(client.read(&mut []).await.unwrap(), 0);
}

#[tokio::test]
async fn tcp_partial_reads_at_the_cipher_limit_preserve_existing_buffer_contents() {
    let keys = MorphKeys::derive(b"shared");
    let nonce = [18; NONCE_LEN];
    let (client_io, mut peer) = tokio::io::duplex(64);
    let mut client = MorphTcpStream::initialized_for_test(client_io, &keys, nonce, true);
    let state = client.morph.as_mut().unwrap();
    state.read_offset = TCP_STREAM_LIMIT - 5;
    state.read_cipher.try_seek(state.read_offset).unwrap();
    let mut response = *b"reply";
    apply_at(&keys.tcp_s2c, &nonce, TCP_STREAM_LIMIT - 5, &mut response).unwrap();
    peer.write_all(&response).await.unwrap();

    let mut received = [0xa5; 9];
    let mut buffer = ReadBuf::new(&mut received);
    buffer.put_slice(b"head");
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    assert!(matches!(
        Pin::new(&mut client).poll_read(&mut context, &mut buffer),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buffer.filled(), b"headreply");
    assert_eq!(client.write(b"independent").await.unwrap(), 11);
    let mut wire = [0; 11];
    peer.read_exact(&mut wire).await.unwrap();
    apply_at(&keys.tcp_c2s, &nonce, 0, &mut wire).unwrap();
    assert_eq!(&wire, b"independent");
}

#[derive(Debug)]
struct PendingWriteStream {
    ready: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
    written: Arc<std::sync::Mutex<Vec<u8>>>,
    outcomes: std::sync::Mutex<VecDeque<WriteOutcome>>,
}

#[derive(Debug)]
enum WriteOutcome {
    Accept(usize),
    Pending,
    Error(io::ErrorKind),
}

impl AsyncRead for PendingWriteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingWriteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let outcome = self.outcomes.lock().unwrap().pop_front();
        match outcome.unwrap_or(WriteOutcome::Accept(input.len())) {
            WriteOutcome::Accept(limit) => {
                let count = input.len().min(limit);
                self.written
                    .lock()
                    .unwrap()
                    .extend_from_slice(&input[..count]);
                Poll::Ready(Ok(count))
            }
            WriteOutcome::Pending => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            WriteOutcome::Error(kind) => Poll::Ready(Err(kind.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl super::MorphWriteReady for PendingWriteStream {
    fn poll_morph_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ready.load(Ordering::Relaxed) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[tokio::test]
async fn tcp_emits_fixed_authenticated_prelude_nonce_and_ciphertext_vector() {
    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inner = PendingWriteStream {
        ready: Arc::new(AtomicBool::new(true)),
        writes: Arc::new(AtomicUsize::new(0)),
        written: written.clone(),
        outcomes: Default::default(),
    };
    let keys = MorphKeys::derive(b"shared");
    let prelude = [0x7f; TCP_PRELUDE_LEN];
    let nonce = [0x23; NONCE_LEN];
    let authentication = AuthenticatedPrelude {
        identity: 1,
        counter: 1,
    };
    let mut stream = MorphTcpStream::connect_authenticated_for_test(
        inner,
        keys.clone(),
        prelude,
        nonce,
        authentication,
    )
    .await
    .unwrap();
    let mut expected_prelude = prelude;
    keys.encode_prelude(&mut expected_prelude, &nonce, authentication);
    stream.write_all(b"hello").await.unwrap();

    let wire = written.lock().unwrap();
    assert_eq!(&wire[..TCP_PRELUDE_LEN], &expected_prelude);
    assert_eq!(&wire[TCP_PRELUDE_LEN..TCP_PRELUDE_LEN + NONCE_LEN], &nonce);
    let mut expected = b"hello".to_vec();
    apply_at(&keys.tcp_c2s, &nonce, 0, &mut expected).unwrap();
    assert_eq!(&wire[TCP_PRELUDE_LEN + NONCE_LEN..], expected);
}

#[tokio::test]
async fn fade_bootstrap_preserves_wire_layout_and_order_across_partial_writes() {
    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inner = PendingWriteStream {
        ready: Arc::new(AtomicBool::new(true)),
        writes: Arc::new(AtomicUsize::new(0)),
        written: written.clone(),
        outcomes: std::sync::Mutex::new(VecDeque::from([
            WriteOutcome::Accept(3),
            WriteOutcome::Pending,
            WriteOutcome::Accept(61),
            WriteOutcome::Accept(2),
            WriteOutcome::Pending,
            WriteOutcome::Accept(10),
        ])),
    };
    let keys = MorphKeys::derive(b"shared");
    let prelude = PreludePolicy::Fade.generate_tcp().unwrap();
    let nonce = [0x23; NONCE_LEN];
    let authentication = AuthenticatedPrelude {
        identity: 1,
        counter: 1,
    };
    let mut stream = MorphTcpStream::connect_authenticated_for_test(
        inner,
        keys.clone(),
        prelude,
        nonce,
        authentication,
    )
    .await
    .unwrap();
    let mut expected_prelude = prelude;
    keys.encode_prelude(&mut expected_prelude, &nonce, authentication);
    {
        let wire = written.lock().unwrap();
        assert_eq!(wire.len(), TCP_PRELUDE_LEN + NONCE_LEN);
        assert_eq!(&wire[..TCP_PRELUDE_LEN], &expected_prelude);
        assert_eq!(&wire[TCP_PRELUDE_LEN..], &nonce);
    }
    stream.write_all(b"hello").await.unwrap();
    let wire = written.lock().unwrap();
    let mut expected = b"hello".to_vec();
    apply_at(&keys.tcp_c2s, &nonce, 0, &mut expected).unwrap();
    assert_eq!(&wire[TCP_PRELUDE_LEN + NONCE_LEN..], expected);
}

#[test]
fn tcp_waits_for_write_readiness_before_copying_or_xoring() {
    let ready = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inner = PendingWriteStream {
        ready: ready.clone(),
        writes: writes.clone(),
        written: written.clone(),
        outcomes: Default::default(),
    };
    let keys = MorphKeys::derive(b"shared");
    let mut client = MorphTcpStream::initialized_for_test(inner, &keys, [11; NONCE_LEN], true);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"initial"),
        Poll::Pending
    ));
    assert_eq!(writes.load(Ordering::Relaxed), 0);
    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"payload"),
        Poll::Pending
    ));
    assert_eq!(writes.load(Ordering::Relaxed), 0);
    assert!(client.morph.as_ref().unwrap().write_buffer.is_empty());

    ready.store(true, Ordering::Relaxed);
    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"changed"),
        Poll::Ready(Ok(7))
    ));
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    let mut payload = written.lock().unwrap().to_vec();
    apply_at(&keys.tcp_c2s, &[11; NONCE_LEN], 0, &mut payload).unwrap();
    assert_eq!(&payload, b"changed");
}

#[test]
fn tcp_retries_changed_input_after_short_write_pending_and_error() {
    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inner = PendingWriteStream {
        ready: Arc::new(AtomicBool::new(true)),
        writes: Arc::new(AtomicUsize::new(0)),
        written: written.clone(),
        outcomes: std::sync::Mutex::new(VecDeque::from([
            WriteOutcome::Accept(3),
            WriteOutcome::Pending,
            WriteOutcome::Error(io::ErrorKind::Interrupted),
            WriteOutcome::Accept(usize::MAX),
        ])),
    };
    let keys = MorphKeys::derive(b"shared");
    let mut client = MorphTcpStream::initialized_for_test(inner, &keys, [12; NONCE_LEN], true);
    let mut context = Context::from_waker(Waker::noop());

    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"abc-unaccepted"),
        Poll::Ready(Ok(3))
    ));
    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"pending input"),
        Poll::Pending
    ));
    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"error input"),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted
    ));
    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"z"),
        Poll::Ready(Ok(1))
    ));
    let wire = written.lock().unwrap();
    let mut payload = wire.to_vec();
    apply_at(&keys.tcp_c2s, &[12; NONCE_LEN], 0, &mut payload).unwrap();
    assert_eq!(&payload, b"abcz");
}

#[tokio::test]
async fn tcp_uses_one_client_nonce_and_independent_directions() {
    let keys = MorphKeys::derive(b"shared");
    let (client_io, server_io) = tokio::io::duplex(4096);
    let (client, server) = tokio::join!(
        MorphTcpStream::connect_current_for_test(client_io, Some(keys.clone())),
        MorphTcpStream::accept(server_io, Some(keys)),
    );
    let mut client = client.unwrap();
    let mut server = server.unwrap();

    client.write_all(b"client hello").await.unwrap();
    let mut request = [0; 12];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"client hello");

    server.write_all(b"server reply").await.unwrap();
    let mut response = [0; 12];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"server reply");
}

#[tokio::test]
async fn tcp_bootstrap_finishes_before_either_side_is_exposed() {
    let keys = MorphKeys::derive(b"shared");
    let (client_io, server_io) = tokio::io::duplex(4096);
    let (client, server) = tokio::join!(
        MorphTcpStream::connect_current_for_test(client_io, Some(keys.clone())),
        MorphTcpStream::accept(server_io, Some(keys)),
    );
    let mut client = client.unwrap();
    let server = server.unwrap();
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    server_writer.write_all(b"reply").await.unwrap();
    let mut response = [0; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"reply");

    client.write_all(b"hello").await.unwrap();
    let mut request = [0; 5];
    server_reader.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"hello");
}

#[tokio::test]
async fn tcp_preserves_offsets_across_small_io_chunks() {
    let keys = MorphKeys::derive(b"shared");
    let (client_io, server_io) = tokio::io::duplex(1024);
    let (client, server) = tokio::join!(
        MorphTcpStream::connect_current_for_test(client_io, Some(keys.clone())),
        MorphTcpStream::accept(server_io, Some(keys)),
    );
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    let payload = vec![0x5a; 65_537];
    let expected = payload.clone();

    let writer = tokio::spawn(async move { client.write_all(&payload).await });
    let mut received = vec![0; expected.len()];
    server.read_exact(&mut received).await.unwrap();
    writer.await.unwrap().unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn tcp_write_processes_the_full_available_buffer() {
    let keys = MorphKeys::derive(b"shared");
    let (client_io, _peer_io) = tokio::io::duplex(256 * 1024);
    let mut client = MorphTcpStream::initialized_for_test(client_io, &keys, [10; NONCE_LEN], true);
    let payload = vec![0x5a; 128 * 1024];

    assert_eq!(client.write(&payload).await.unwrap(), payload.len());
    let buffer_len = client.morph.as_ref().unwrap().write_buffer.len();
    assert_eq!(client.write(b"x").await.unwrap(), 1);
    assert_eq!(
        client.morph.as_ref().unwrap().write_buffer.len(),
        buffer_len
    );
}

#[tokio::test]
async fn authenticated_bootstrap_roundtrips_without_changing_ciphertext() {
    let keys = MorphKeys::derive(b"shared");
    for policy in [
        PreludePolicy::Fade,
        PreludePolicy::Full8,
        PreludePolicy::Low7,
    ] {
        let prelude = policy.generate_tcp().unwrap();
        let nonce = [0x23; NONCE_LEN];
        let authentication = AuthenticatedPrelude {
            identity: 0x0123_4567_89ab_cdef,
            counter: 0x1234_5678_9abc,
        };
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client, server) = tokio::join!(
            MorphTcpStream::connect_authenticated_for_test(
                client_io,
                keys.clone(),
                prelude,
                nonce,
                authentication
            ),
            MorphTcpStream::accept_bootstrap(server_io, Some(keys.clone())),
        );
        let mut client = client.unwrap();
        let (mut server, token) = server.unwrap();
        assert!(token == Some(authentication));
        client.write_all(b"hello").await.unwrap();
        let mut received = [0; 5];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello");
        server.write_all(b"reply").await.unwrap();
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"reply");
        let mut encoded = prelude;
        keys.encode_prelude(&mut encoded, &nonce, authentication);
        assert_eq!(encoded[..32], prelude[..32]);
        for (encoded, original) in encoded.iter().zip(prelude) {
            assert_eq!(encoded & 0x80, original & 0x80);
        }
    }
}

#[tokio::test]
async fn cancelled_and_failed_bootstrap_never_return_counter() {
    let keys = MorphKeys::derive(b"shared");
    let identity = ClientPrelude::for_test(42, 0);
    let (inner, _peer) = tokio::io::duplex(1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            MorphTcpStream::connect(inner, Some(keys.clone()), &identity)
        )
        .await
        .is_err()
    );
    assert_eq!(identity.allocated_for_test(), 1);
    let (inner, peer) = tokio::io::duplex(76);
    drop(peer);
    assert!(
        MorphTcpStream::connect(inner, Some(keys.clone()), &identity)
            .await
            .is_err()
    );
    assert_eq!(identity.allocated_for_test(), 2);
    let (inner, peer) = tokio::io::duplex(76);
    let (_, accepted) = tokio::join!(
        MorphTcpStream::connect(inner, Some(keys.clone()), &identity),
        MorphTcpStream::accept_bootstrap(peer, Some(keys)),
    );
    assert_eq!(accepted.unwrap().1.unwrap().counter, 3);
}

#[tokio::test]
async fn disabled_morph_does_not_initialize_identity() {
    let identity = ClientPrelude::default();
    let (inner, _peer) = tokio::io::duplex(76);
    MorphTcpStream::connect(inner, None, &identity)
        .await
        .unwrap();
    assert_eq!(identity.allocated_for_test(), 0);
}

#[test]
fn randomized_prelude_policies_preserve_prefix_and_high_bits_after_authentication() {
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef");
    for policy in [
        PreludePolicy::Fade,
        PreludePolicy::Full8,
        PreludePolicy::Low7,
    ] {
        let mut counts = [0usize; 128];
        let mut high = 0;
        for counter in 1..=2048 {
            let mut prelude = policy.generate_tcp().unwrap();
            let original = prelude;
            let mut nonce = [0; 12];
            getrandom::fill(&mut nonce).unwrap();
            let mut identity = [0; 8];
            getrandom::fill(&mut identity).unwrap();
            let authentication = AuthenticatedPrelude {
                identity: u64::from_be_bytes(identity),
                counter,
            };
            keys.encode_prelude(&mut prelude, &nonce, authentication);
            assert!(keys.decode_prelude(&prelude, &nonce) == Some(authentication));
            assert_eq!(prelude[..32], original[..32]);
            for index in 32..64 {
                assert_eq!(prelude[index] & 0x80, original[index] & 0x80);
                counts[usize::from(prelude[index] & 0x7f)] += 1;
                high += usize::from(prelude[index] >> 7);
            }
        }
        assert!(counts.iter().all(|&count| (350..700).contains(&count)));
        if policy == PreludePolicy::Low7 {
            assert_eq!(high, 0);
        } else {
            assert!((30_000..35_500).contains(&high));
        }
    }
}

#[tokio::test]
async fn invalid_bootstrap_returns_original_stream_without_reading_tls() {
    let keys = MorphKeys::derive(b"shared");
    for invalid_counter in [false, true] {
        let mut prelude = [0x55; TCP_PRELUDE_LEN];
        let nonce = [0x23; NONCE_LEN];
        keys.encode_prelude(
            &mut prelude,
            &nonce,
            AuthenticatedPrelude {
                identity: 1,
                counter: if invalid_counter { 0 } else { 1 },
            },
        );
        if !invalid_counter {
            prelude[0] ^= 1;
        }
        let (mut sender, receiver) = tokio::io::duplex(128);
        sender.write_all(&prelude).await.unwrap();
        sender.write_all(&nonce).await.unwrap();
        sender.write_all(b"unparsed TLS").await.unwrap();
        let (error, mut receiver) = MorphTcpStream::accept_bootstrap(receiver, Some(keys.clone()))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut unread = [0; 12];
        receiver.read_exact(&mut unread).await.unwrap();
        assert_eq!(&unread, b"unparsed TLS");
    }
}
