// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use chacha20::ChaCha20;
use chacha20::cipher::KeyIvInit;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::super::*;

impl super::super::tcp::MorphWriteReady for tokio::io::DuplexStream {
    fn poll_morph_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

fn set_tcp_nonce<S>(stream: &mut MorphTcpStream<S>, nonce: [u8; NONCE_LEN]) {
    let state = stream.morph.as_mut().unwrap();
    state.prefix = nonce;
    state.read_cipher = Some(ChaCha20::new(
        (&state.read_key).into(),
        (&state.prefix).into(),
    ));
    state.write_cipher = Some(ChaCha20::new(
        (&state.write_key).into(),
        (&state.prefix).into(),
    ));
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
fn tcp_empty_io_does_not_wait_for_the_nonce() {
    let keys = MorphKeys::derive(b"shared");
    let (_client_io, server_io) = tokio::io::duplex(64);
    let mut server = MorphTcpStream::server(server_io, Some(keys));
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

#[derive(Debug)]
struct PendingWriteStream {
    writes: Arc<AtomicUsize>,
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
        _cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl super::super::tcp::MorphWriteReady for PendingWriteStream {
    fn poll_morph_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[test]
fn tcp_waits_for_write_readiness_before_copying_or_xoring() {
    let writes = Arc::new(AtomicUsize::new(0));
    let inner = PendingWriteStream {
        writes: writes.clone(),
    };
    let keys = MorphKeys::derive(b"shared");
    let mut client = MorphTcpStream::client(inner, Some(keys)).unwrap();
    set_tcp_nonce(&mut client, [11; NONCE_LEN]);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"payload"),
        Poll::Pending
    ));
    // Only the nonce prefix reaches the underlying stream.
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut context, b"payload"),
        Poll::Pending
    ));
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    assert!(client.morph.as_ref().unwrap().write_buffer.is_empty());
}

#[tokio::test]
async fn tcp_uses_one_client_nonce_and_independent_directions() {
    let keys = MorphKeys::derive(b"shared");
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = MorphTcpStream::client(client_io, Some(keys.clone())).unwrap();
    set_tcp_nonce(&mut client, [7; NONCE_LEN]);
    let mut server = MorphTcpStream::server(server_io, Some(keys));

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
async fn tcp_server_waits_for_the_client_nonce_before_writing() {
    let keys = MorphKeys::derive(b"shared");
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = MorphTcpStream::client(client_io, Some(keys.clone())).unwrap();
    set_tcp_nonce(&mut client, [8; NONCE_LEN]);
    let server = MorphTcpStream::server(server_io, Some(keys));
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let reply = tokio::spawn(async move { server_writer.write_all(b"reply").await });
    tokio::task::yield_now().await;
    assert!(!reply.is_finished());

    client.write_all(b"hello").await.unwrap();
    let mut request = [0; 5];
    server_reader.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"hello");
    reply.await.unwrap().unwrap();

    let mut response = [0; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"reply");
}

#[tokio::test]
async fn tcp_preserves_offsets_across_small_io_chunks() {
    let keys = MorphKeys::derive(b"shared");
    let (client_io, server_io) = tokio::io::duplex(1024);
    let mut client = MorphTcpStream::client(client_io, Some(keys.clone())).unwrap();
    set_tcp_nonce(&mut client, [9; NONCE_LEN]);
    let mut server = MorphTcpStream::server(server_io, Some(keys));
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
    let mut client = MorphTcpStream::client(client_io, Some(keys)).unwrap();
    set_tcp_nonce(&mut client, [10; NONCE_LEN]);
    let payload = vec![0x5a; 128 * 1024];

    assert_eq!(client.write(&payload).await.unwrap(), payload.len());
}
