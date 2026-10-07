// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Directional Morph masking for asynchronous TCP streams.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{MorphKeys, NONCE_LEN, TCP_PRELUDE_LEN, exhausted};

const TCP_STREAM_LIMIT: u64 = (1u64 << 38) - 64;
const TCP_PRELUDE_ENV: &str = "NOW_MORPH_TCP_PRELUDE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpPreludePolicy {
    Low7,
    Full8,
}

impl TcpPreludePolicy {
    fn from_env() -> io::Result<Self> {
        Self::parse(std::env::var(TCP_PRELUDE_ENV))
    }

    fn parse(value: Result<String, std::env::VarError>) -> io::Result<Self> {
        match value {
            Ok(value) if value == "low7" => Ok(Self::Low7),
            Ok(value) if value == "full8" => Ok(Self::Full8),
            Err(std::env::VarError::NotPresent) => Ok(Self::Full8),
            Ok(_) | Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{TCP_PRELUDE_ENV} must be low7 or full8"),
            )),
        }
    }

    fn generate(self) -> io::Result<[u8; TCP_PRELUDE_LEN]> {
        let mut prelude = [0u8; TCP_PRELUDE_LEN];
        getrandom::fill(&mut prelude).map_err(io::Error::other)?;
        self.apply(&mut prelude);
        Ok(prelude)
    }

    fn apply(self, prelude: &mut [u8; TCP_PRELUDE_LEN]) {
        match self {
            Self::Low7 => {
                for byte in prelude {
                    *byte &= 0x7f;
                }
            }
            Self::Full8 => {}
        }
    }
}

pub(super) struct TcpMorph {
    pub(super) read_cipher: ChaCha20,
    pub(super) write_cipher: ChaCha20,
    read_offset: u64,
    write_offset: u64,
    pub(super) write_buffer: Vec<u8>,
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
    pub(crate) async fn connect(inner: S, keys: Option<MorphKeys>) -> io::Result<Self> {
        let Some(keys) = keys else {
            return Ok(Self { inner, morph: None });
        };
        let prelude = TcpPreludePolicy::from_env()?.generate()?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
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

    pub(crate) async fn accept(mut inner: S, keys: Option<MorphKeys>) -> io::Result<Self> {
        let Some(keys) = keys else {
            return Ok(Self { inner, morph: None });
        };
        let mut prelude = [0u8; TCP_PRELUDE_LEN];
        inner.read_exact(&mut prelude).await?;
        let mut nonce = [0u8; NONCE_LEN];
        inner.read_exact(&mut nonce).await?;
        Ok(Self::initialized(inner, &keys, nonce, false))
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
                read_cipher: ChaCha20::new(read_key.into(), (&nonce).into()),
                write_cipher: ChaCha20::new(write_key.into(), (&nonce).into()),
                read_offset: 0,
                write_offset: 0,
                write_buffer: Vec::new(),
            }),
        }
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
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
        let remaining = TCP_STREAM_LIMIT.saturating_sub(self.morph.as_ref().unwrap().read_offset);
        if remaining == 0 && buf.remaining() != 0 {
            return Poll::Ready(Err(exhausted()));
        }
        let before = buf.filled().len();
        let allowed = usize::try_from(remaining.min(buf.remaining() as u64)).unwrap();
        let unfilled = buf.initialize_unfilled_to(allowed);
        let mut inner_buf = ReadBuf::new(unfilled);
        match Pin::new(&mut self.inner).poll_read(cx, &mut inner_buf) {
            Poll::Ready(Ok(())) => {
                let count = inner_buf.filled().len();
                let state = self.morph.as_mut().unwrap();
                state
                    .read_cipher
                    .try_apply_keystream(&mut inner_buf.filled_mut()[..count])
                    .map_err(|_| exhausted())?;
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
        let remaining = TCP_STREAM_LIMIT.saturating_sub(this.morph.as_ref().unwrap().write_offset);
        if remaining == 0 {
            return Poll::Ready(Err(exhausted()));
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
        state
            .write_cipher
            .try_apply_keystream_b2b(&input[..count], &mut state.write_buffer[..count])
            .map_err(|_| exhausted())?;
        match Pin::new(&mut this.inner).poll_write(cx, &state.write_buffer[..count]) {
            Poll::Ready(Ok(0)) => {
                state
                    .write_cipher
                    .try_seek(state.write_offset)
                    .map_err(|_| exhausted())?;
                Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(n)) => {
                state.write_offset += n as u64;
                if n != count {
                    state
                        .write_cipher
                        .try_seek(state.write_offset)
                        .map_err(|_| exhausted())?;
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => {
                state
                    .write_cipher
                    .try_seek(state.write_offset)
                    .map_err(|_| exhausted())?;
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                state
                    .write_cipher
                    .try_seek(state.write_offset)
                    .map_err(|_| exhausted())?;
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
