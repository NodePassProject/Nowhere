// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Owned payload handoff for relay paths that terminate in TLS Mux.

use std::any::Any;
use std::io;
use std::pin::Pin;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::mux::{FRAME_BYTES, FlowReader, FlowWriter, MuxChunk};

use super::Buffers;

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
    buffers: &Buffers,
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
    read_owned_from(reader, buffers).await
}

pub(crate) async fn read_owned_from<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffers: &Buffers,
) -> io::Result<Option<RelayChunk>> {
    let mut payload = buffers.get_tcp_buffer();
    let capacity = payload.len().min(FRAME_BYTES);
    let count = reader.read(&mut payload[..capacity]).await?;
    if count == 0 {
        Ok(None)
    } else {
        Ok(Some(RelayChunk::Bytes(
            Bytes::from_owner(payload).slice(..count),
        )))
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
#[path = "../tests/transport/owned_io.rs"]
mod tests;
