// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use chacha20::ChaCha20;
use chacha20::cipher::KeyIvInit;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::*;

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
