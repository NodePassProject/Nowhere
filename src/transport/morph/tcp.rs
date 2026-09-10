// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{MorphKey, MorphKeys, NONCE_LEN, exhausted};

const TCP_STREAM_LIMIT: u64 = (1u64 << 38) - 64;

#[derive(Clone, Copy)]
enum TcpRole {
    Client,
    Server,
}

pub(super) struct TcpMorph {
    pub(super) read_key: MorphKey,
    pub(super) write_key: MorphKey,
    pub(super) read_cipher: Option<ChaCha20>,
    pub(super) write_cipher: Option<ChaCha20>,
    read_offset: u64,
    write_offset: u64,
    pub(super) prefix: [u8; NONCE_LEN],
    read_prefix_pos: usize,
    write_prefix_pos: usize,
    write_waiter: Option<Waker>,
    pub(super) write_buffer: Vec<u8>,
}

pub(crate) struct MorphTcpStream<S> {
    inner: S,
    keys: Option<MorphKeys>,
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
            .field("enabled", &self.keys.is_some())
            .finish()
    }
}

impl<S> MorphTcpStream<S> {
    pub(crate) fn client(inner: S, keys: Option<MorphKeys>) -> io::Result<Self> {
        let mut stream = Self {
            inner,
            keys,
            morph: None,
        };
        if stream.keys.is_some() {
            let mut nonce = [0u8; NONCE_LEN];
            getrandom::fill(&mut nonce).map_err(io::Error::other)?;
            stream.morph = Some(stream.new_state(nonce, TcpRole::Client));
        }
        Ok(stream)
    }

    pub(crate) fn server(inner: S, keys: Option<MorphKeys>) -> Self {
        let mut stream = Self {
            inner,
            keys,
            morph: None,
        };
        if stream.keys.is_some() {
            stream.morph = Some(stream.new_state([0; NONCE_LEN], TcpRole::Server));
        }
        stream
    }

    fn new_state(&self, nonce: [u8; NONCE_LEN], role: TcpRole) -> TcpMorph {
        let keys = self.keys.as_ref().expect("Morph state requires keys");
        let (read_key, write_key) = match role {
            TcpRole::Client => (&keys.tcp_s2c, &keys.tcp_c2s),
            TcpRole::Server => (&keys.tcp_c2s, &keys.tcp_s2c),
        };
        TcpMorph {
            read_key: *read_key,
            write_key: *write_key,
            read_cipher: match role {
                TcpRole::Client => Some(ChaCha20::new(read_key.into(), (&nonce).into())),
                TcpRole::Server => None,
            },
            write_cipher: match role {
                TcpRole::Client => Some(ChaCha20::new(write_key.into(), (&nonce).into())),
                TcpRole::Server => None,
            },
            read_offset: 0,
            write_offset: 0,
            prefix: nonce,
            read_prefix_pos: match role {
                TcpRole::Client => NONCE_LEN,
                TcpRole::Server => 0,
            },
            write_prefix_pos: match role {
                TcpRole::Client => 0,
                TcpRole::Server => NONCE_LEN,
            },
            write_waiter: None,
            write_buffer: Vec::new(),
        }
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
    }
}

#[cfg(test)]
pub(super) fn apply_at(
    key: &MorphKey,
    nonce: &[u8; NONCE_LEN],
    offset: u64,
    bytes: &mut [u8],
) -> io::Result<()> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.try_seek(offset).map_err(|_| exhausted())?;
    cipher.try_apply_keystream(bytes).map_err(|_| exhausted())
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
        if self.keys.is_none() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if self.morph.as_ref().unwrap().read_prefix_pos < NONCE_LEN {
            while self.morph.as_ref().unwrap().read_prefix_pos < NONCE_LEN {
                let filled = self.morph.as_ref().unwrap().read_prefix_pos;
                let mut scratch = [0u8; NONCE_LEN];
                let mut nonce_buf = ReadBuf::new(&mut scratch[..NONCE_LEN - filled]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut nonce_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if nonce_buf.filled().is_empty() => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Morph TCP nonce",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        let count = nonce_buf.filled().len();
                        let state = self.morph.as_mut().unwrap();
                        state.prefix[filled..filled + count].copy_from_slice(nonce_buf.filled());
                        state.read_prefix_pos += count;
                    }
                }
            }
            if let Some(waiter) = self.morph.as_mut().unwrap().write_waiter.take() {
                waiter.wake();
            }
            let state = self.morph.as_mut().unwrap();
            state.read_cipher = Some(ChaCha20::new(
                (&state.read_key).into(),
                (&state.prefix).into(),
            ));
            state.write_cipher = Some(ChaCha20::new(
                (&state.write_key).into(),
                (&state.prefix).into(),
            ));
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
                    .as_mut()
                    .expect("Morph read cipher initialized")
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

#[cfg(test)]
impl MorphWriteReady for tokio::io::DuplexStream {
    fn poll_morph_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
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
        if self.keys.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, input);
        }
        let this = self.as_mut().get_mut();
        if this
            .morph
            .as_ref()
            .expect("Morph state initialized")
            .read_prefix_pos
            < NONCE_LEN
        {
            this.morph.as_mut().unwrap().write_waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let prefix_pos = this
            .morph
            .as_ref()
            .expect("Morph state initialized")
            .write_prefix_pos;
        if prefix_pos < NONCE_LEN {
            let prefix = this.morph.as_ref().unwrap().prefix;
            match Pin::new(&mut this.inner).poll_write(cx, &prefix[prefix_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => this.morph.as_mut().unwrap().write_prefix_pos += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            if this.morph.as_ref().unwrap().write_prefix_pos < NONCE_LEN {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
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
        state.write_buffer.clear();
        state.write_buffer.extend_from_slice(&input[..count]);
        state
            .write_cipher
            .as_mut()
            .expect("Morph write cipher initialized")
            .try_apply_keystream(&mut state.write_buffer)
            .map_err(|_| exhausted())?;
        match Pin::new(&mut this.inner).poll_write(cx, &state.write_buffer) {
            Poll::Ready(Ok(0)) => {
                state
                    .write_cipher
                    .as_mut()
                    .unwrap()
                    .try_seek(state.write_offset)
                    .map_err(|_| exhausted())?;
                Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(n)) => {
                state.write_offset += n as u64;
                if n != count {
                    state
                        .write_cipher
                        .as_mut()
                        .expect("Morph write cipher initialized")
                        .try_seek(state.write_offset)
                        .map_err(|_| exhausted())?;
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => {
                state
                    .write_cipher
                    .as_mut()
                    .unwrap()
                    .try_seek(state.write_offset)
                    .map_err(|_| exhausted())?;
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                state
                    .write_cipher
                    .as_mut()
                    .unwrap()
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
