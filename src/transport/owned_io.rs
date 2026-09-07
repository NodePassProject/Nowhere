// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Owned payload handoff for relay paths that terminate in TLS Mux.

use std::any::Any;
use std::io;
use std::pin::Pin;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::mux::{FRAME_BYTES, FlowReader, FlowWriter, MuxChunk};

pub(crate) trait AsyncReadAny: AsyncRead + Send + Unpin {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: AsyncRead + Send + Unpin + 'static> AsyncReadAny for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub(crate) trait AsyncWriteAny: AsyncWrite + Send + Unpin {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: AsyncWrite + Send + Unpin + 'static> AsyncWriteAny for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub(crate) enum RelayChunk {
    Mux(MuxChunk),
    Bytes(Bytes),
}

impl RelayChunk {
    pub(crate) fn len(&self) -> usize {
        self.as_ref().len()
    }
}

impl AsRef<[u8]> for RelayChunk {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Mux(chunk) => chunk.as_ref(),
            Self::Bytes(bytes) => bytes,
        }
    }
}

pub(crate) async fn read_owned(
    reader: &mut Pin<Box<dyn AsyncReadAny>>,
) -> io::Result<Option<RelayChunk>> {
    let any = reader.as_mut().get_mut().as_any_mut();
    if let Some(reader) = any.downcast_mut::<FlowReader>() {
        return reader
            .recv_chunk()
            .await
            .map(|chunk| chunk.map(RelayChunk::Mux));
    }
    if let Some(reader) = any.downcast_mut::<BufReader<FlowReader>>()
        && reader.buffer().is_empty()
    {
        return reader
            .get_mut()
            .recv_chunk()
            .await
            .map(|chunk| chunk.map(RelayChunk::Mux));
    }
    read_owned_from(reader).await
}

pub(crate) async fn read_owned_from<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<RelayChunk>> {
    let mut payload = BytesMut::with_capacity(FRAME_BYTES);
    let count = reader.read_buf(&mut payload).await?;
    if count == 0 {
        Ok(None)
    } else {
        Ok(Some(RelayChunk::Bytes(payload.freeze())))
    }
}

pub(crate) async fn write_owned(
    writer: &mut Pin<Box<dyn AsyncWriteAny>>,
    chunk: RelayChunk,
) -> io::Result<()> {
    if let Some(writer) = writer
        .as_mut()
        .get_mut()
        .as_any_mut()
        .downcast_mut::<FlowWriter>()
    {
        let chunk = match chunk {
            RelayChunk::Mux(chunk) => chunk,
            RelayChunk::Bytes(bytes) => MuxChunk::from_bytes(bytes),
        };
        return writer.send_chunk(chunk).await;
    }
    writer.write_all(chunk.as_ref()).await
}

pub(crate) async fn write_owned_to<W: AsyncWrite + Unpin>(
    writer: &mut W,
    chunk: RelayChunk,
) -> io::Result<()> {
    writer.write_all(chunk.as_ref()).await
}

#[cfg(test)]
mod tests {
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
}
