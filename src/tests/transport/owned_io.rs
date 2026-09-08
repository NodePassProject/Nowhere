use super::*;
use crate::mux::{MuxConfig, MuxHandle};

#[tokio::test]
async fn owned_bytes_enter_mux_without_a_borrowed_payload_copy() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let stream = client.open_stream(901).await.unwrap();
    let (_reader, writer) = stream.into_split();
    let mut writer: Pin<Box<dyn AsyncWriteAny>> = Box::pin(writer);
    let mut peer = incoming.accept().await.unwrap().unwrap();
    client.reset_borrowed_write_copies();

    write_owned(
        &mut writer,
        RelayChunk::Bytes(Bytes::from_static(b"owned payload")),
    )
    .await
    .unwrap();
    let mut received = [0; 13];
    peer.read_exact(&mut received).await.unwrap();

    assert_eq!(&received, b"owned payload");
    assert_eq!(client.borrowed_write_copies(), 0);
}

#[tokio::test]
async fn generic_reads_use_a_pool_owned_chunk() {
    let buffers = Buffers::new(FRAME_BYTES, 1);
    let mut reader = &b"pooled"[..];
    let chunk = read_owned_from(&mut reader, &buffers)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(chunk.as_ref(), b"pooled");
    let allocation = chunk.as_ref().as_ptr();
    drop(chunk);
    let reused = buffers.get_tcp_buffer();
    assert_eq!(reused.as_ptr(), allocation);
}
