// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Directional Morph masking for asynchronous TCP streams.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::cipher::TcpCipher;
use super::policy::{PreludePolicy, TCP_PRELUDE_ENV};
use super::{
    AuthenticatedPrelude, ClientPrelude, MorphGrade, MorphKeys, NONCE_LEN, TCP_PRELUDE_LEN,
};

pub(crate) fn validate_tcp_prelude_env() -> io::Result<()> {
    PreludePolicy::from_env(TCP_PRELUDE_ENV).map(|_| ())
}

pub(super) struct TcpMorph {
    pub(super) read_cipher: TcpCipher,
    pub(super) write_cipher: TcpCipher,
    read_record: Option<RecordState>,
    write_record: Option<RecordState>,
    read_offset: u64,
    write_offset: u64,
    pub(super) write_buffer: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
struct RecordState {
    header: [u8; 5],
    header_len: usize,
    payload_left: usize,
    skip_payload: bool,
}

impl RecordState {
    fn span(self, available: usize) -> (usize, bool) {
        if self.payload_left == 0 {
            (available.min(self.header.len() - self.header_len), true)
        } else {
            (available.min(self.payload_left), !self.skip_payload)
        }
    }

    fn advance(&mut self, plain: &[u8]) {
        if self.payload_left != 0 {
            self.payload_left -= plain.len();
            return;
        }
        let end = self.header_len + plain.len();
        self.header[self.header_len..end].copy_from_slice(plain);
        self.header_len = end;
        if end == self.header.len() {
            self.header_len = 0;
            self.payload_left = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            self.skip_payload = self.header[..3] == [23, 3, 3] && self.payload_left <= 18432;
        }
    }

    fn apply(
        &mut self,
        cipher: &mut TcpCipher,
        mut offset: u64,
        data: &mut [u8],
        opening: bool,
    ) -> io::Result<()> {
        let mut position = None;
        let mut rest = data;
        while !rest.is_empty() {
            let (count, mask) = self.span(rest.len());
            let (part, next) = rest.split_at_mut(count);
            if !opening {
                self.advance(part);
            }
            if mask {
                if position != Some(offset) {
                    cipher.try_seek(offset)?;
                }
                cipher.try_apply_keystream(part)?;
                position = Some(offset + count as u64);
            }
            if opening {
                self.advance(part);
            }
            rest = next;
            offset += count as u64;
        }
        Ok(())
    }
}

pub(crate) struct MorphTcpStream<S> {
    inner: S,
    pub(super) morph: Option<TcpMorph>,
}

impl<S> fmt::Debug for MorphTcpStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MorphTcpStream")
            .field("inner", &self.inner)
            .field("enabled", &self.morph.is_some())
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> MorphTcpStream<S> {
    pub(crate) async fn connect(
        inner: S,
        keys: Option<MorphKeys>,
        identity: &ClientPrelude,
    ) -> io::Result<Self> {
        let Some(keys) = keys else {
            return Ok(Self { inner, morph: None });
        };
        let mut prelude = PreludePolicy::from_env(TCP_PRELUDE_ENV)?.generate_tcp()?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        keys.encode_prelude(&mut prelude, &nonce, identity.allocate()?);
        Self::connect_with_bootstrap(inner, keys, prelude, nonce).await
    }

    async fn connect_with_bootstrap(
        mut inner: S,
        keys: MorphKeys,
        prelude: [u8; TCP_PRELUDE_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> io::Result<Self> {
        inner.write_all(&prelude).await?;
        inner.write_all(&nonce).await?;
        Ok(Self::initialized(inner, &keys, nonce, true))
    }

    pub(crate) async fn accept_bootstrap(
        mut inner: S,
        keys: Option<MorphKeys>,
    ) -> Result<(Self, Option<AuthenticatedPrelude>), (io::Error, S)> {
        let Some(keys) = keys else {
            return Ok((Self { inner, morph: None }, None));
        };
        let mut prelude = [0u8; TCP_PRELUDE_LEN];
        if let Err(error) = inner.read_exact(&mut prelude).await {
            return Err((error, inner));
        }
        let mut nonce = [0u8; NONCE_LEN];
        if let Err(error) = inner.read_exact(&mut nonce).await {
            return Err((error, inner));
        }
        let Some(authentication) = keys
            .decode_prelude(&prelude, &nonce)
            .filter(|authentication| authentication.is_valid())
        else {
            return Err((
                io::Error::new(io::ErrorKind::InvalidData, "invalid Morph prelude"),
                inner,
            ));
        };
        Ok((
            Self::initialized(inner, &keys, nonce, false),
            Some(authentication),
        ))
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
    }

    fn initialized(inner: S, keys: &MorphKeys, nonce: [u8; NONCE_LEN], client: bool) -> Self {
        let (read_key, write_key) = if client {
            (&keys.tcp_s2c, &keys.tcp_c2s)
        } else {
            (&keys.tcp_c2s, &keys.tcp_s2c)
        };
        Self {
            inner,
            morph: Some(TcpMorph {
                read_cipher: TcpCipher::new(keys.cipher, read_key, &nonce),
                write_cipher: TcpCipher::new(keys.cipher, write_key, &nonce),
                read_record: (keys.grade == MorphGrade::Core).then(RecordState::default),
                write_record: (keys.grade == MorphGrade::Core).then(RecordState::default),
                read_offset: 0,
                write_offset: 0,
                write_buffer: Vec::new(),
            }),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MorphTcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.morph.is_none() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let state = self.morph.as_ref().unwrap();
        let remaining = state.read_cipher.limit().saturating_sub(state.read_offset);
        if remaining == 0 && buf.remaining() != 0 {
            return Poll::Ready(Err(state.read_cipher.exhausted()));
        }
        let before = buf.filled().len();
        let allowed = usize::try_from(remaining.min(buf.remaining() as u64)).unwrap();
        let unfilled = buf.initialize_unfilled_to(allowed);
        let mut inner_buf = ReadBuf::new(unfilled);
        match Pin::new(&mut self.inner).poll_read(cx, &mut inner_buf) {
            Poll::Ready(Ok(())) => {
                let count = inner_buf.filled().len();
                let state = self.morph.as_mut().unwrap();
                let data = inner_buf.filled_mut();
                if let Some(record) = &mut state.read_record {
                    record.apply(&mut state.read_cipher, state.read_offset, data, true)?;
                } else {
                    state.read_cipher.try_apply_keystream(data)?;
                }
                state.read_offset += count as u64;
                buf.advance(count);
                debug_assert_eq!(buf.filled().len(), before + count);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

pub(crate) trait MorphWriteReady {
    fn poll_morph_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl MorphWriteReady for tokio::net::TcpStream {
    fn poll_morph_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_ready(cx)
    }
}

impl<S: AsyncWrite + MorphWriteReady + Unpin> AsyncWrite for MorphTcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.morph.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, input);
        }
        let this = self.as_mut().get_mut();
        let state = this.morph.as_ref().unwrap();
        let remaining = state
            .write_cipher
            .limit()
            .saturating_sub(state.write_offset);
        if remaining == 0 {
            return Poll::Ready(Err(state.write_cipher.exhausted()));
        }
        let count = usize::try_from(remaining.min(input.len() as u64))
            .expect("count is bounded by usize input length");
        match this.inner.poll_morph_write_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let state = this.morph.as_mut().unwrap();
        if state.write_buffer.len() < count {
            state.write_buffer.resize(count, 0);
        }
        let output = &mut state.write_buffer[..count];
        let mut next_record = state.write_record;
        if let Some(record) = &mut next_record {
            output.copy_from_slice(&input[..count]);
            record.apply(&mut state.write_cipher, state.write_offset, output, false)?;
        } else {
            state
                .write_cipher
                .try_apply_keystream_b2b(&input[..count], output)?;
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, output);
        if let Some(record) = &mut state.write_record {
            return match result {
                Poll::Ready(Ok(0)) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    if n == count {
                        state.write_record = next_record;
                    } else {
                        let mut written = &input[..n];
                        while !written.is_empty() {
                            let (span, _) = record.span(written.len());
                            record.advance(&written[..span]);
                            written = &written[span..];
                        }
                    }
                    state.write_offset += n as u64;
                    Poll::Ready(Ok(n))
                }
                other => other,
            };
        }
        match result {
            Poll::Ready(Ok(0)) => {
                state.write_cipher.try_seek(state.write_offset)?;
                Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(n)) => {
                state.write_offset += n as u64;
                if n != count {
                    state.write_cipher.try_seek(state.write_offset)?;
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => {
                state.write_cipher.try_seek(state.write_offset)?;
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                state.write_cipher.try_seek(state.write_offset)?;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "../../tests/transport/morph/tcp_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "../../tests/transport/morph/tcp.rs"]
mod tests;
