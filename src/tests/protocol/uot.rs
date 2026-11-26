// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UDP-over-stream packet framing tests.

use crate::protocol::test_support::{encode_udp_packet, read_udp_packet, read_udp_packet_into};

use super::*;

#[test]
fn packet_codec_contains_only_u16_length_and_payload() {
    assert_eq!(encode_udp_packet(b"").unwrap(), [0, 0]);
    assert_eq!(encode_udp_packet(b"abc").unwrap(), [0, 3, b'a', b'b', b'c']);
    assert_eq!(encode_udp_packet_header(0x1234).unwrap(), [0x12, 0x34]);
    assert!(encode_udp_packet_header(UOT_PACKET_MAX + 1).is_err());
    assert!(encode_udp_packet(&vec![0; UOT_PACKET_MAX + 1]).is_err());
}

#[tokio::test]
async fn reads_zero_maximum_and_consecutive_packets() {
    let maximum = vec![0x5a; UOT_PACKET_MAX];
    let mut wire = encode_udp_packet(&[]).unwrap();
    wire.extend_from_slice(&encode_udp_packet(b"abc").unwrap());
    wire.extend_from_slice(&encode_udp_packet(&maximum).unwrap());
    let mut input = wire.as_slice();

    assert_eq!(read_udp_packet(&mut input).await.unwrap(), Some(Vec::new()));
    assert_eq!(
        read_udp_packet(&mut input).await.unwrap(),
        Some(b"abc".to_vec())
    );
    assert_eq!(read_udp_packet(&mut input).await.unwrap(), Some(maximum));
    assert_eq!(read_udp_packet(&mut input).await.unwrap(), None);
}

#[tokio::test]
async fn reusable_reader_retains_capacity_across_packets() {
    let mut wire = encode_udp_packet(&vec![1; 4096]).unwrap();
    wire.extend_from_slice(&encode_udp_packet(b"small").unwrap());
    wire.extend_from_slice(&encode_udp_packet(&[]).unwrap());
    let mut input = wire.as_slice();
    let mut buffer = Vec::new();

    assert_eq!(
        read_udp_packet_into(&mut input, &mut buffer).await.unwrap(),
        Some(4096)
    );
    let capacity = buffer.capacity();
    assert_eq!(
        read_udp_packet_into(&mut input, &mut buffer).await.unwrap(),
        Some(5)
    );
    assert_eq!(&buffer, b"small");
    assert!(buffer.capacity() >= capacity);
    assert_eq!(
        read_udp_packet_into(&mut input, &mut buffer).await.unwrap(),
        Some(0)
    );
    assert!(buffer.is_empty());
    assert_eq!(
        read_udp_packet_into(&mut input, &mut buffer).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn writer_does_not_add_a_type_byte() {
    let mut output = Vec::new();
    write_udp_packet(&mut output, b"payload").await.unwrap();
    assert_eq!(output, encode_udp_packet(b"payload").unwrap());
}

#[tokio::test]
async fn distinguishes_clean_eof_from_truncated_length_and_payload() {
    assert_eq!(read_udp_packet(&mut &[][..]).await.unwrap(), None);
    assert!(read_udp_packet(&mut &[0][..]).await.is_err());
    assert!(read_udp_packet(&mut &[0, 3, b'a', b'b'][..]).await.is_err());
}

#[tokio::test]
async fn handles_a_reader_that_returns_partial_chunks() {
    let wire = encode_udp_packet(b"chunked").unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let write = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        writer.write_all(&wire).await.unwrap();
    });
    assert_eq!(
        read_udp_packet(&mut reader).await.unwrap(),
        Some(b"chunked".to_vec())
    );
    write.await.unwrap();
}
