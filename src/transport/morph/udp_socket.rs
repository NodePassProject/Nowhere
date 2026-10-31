// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Tokio Morph client socket with strict Prelude send errors.

use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::Interest;
use tokio_util::sync::ReusableBoxFuture;

use super::UDP_PRELUDE_LEN;

#[derive(Debug)]
pub(super) struct ClientUdpSocket {
    io: tokio::net::UdpSocket,
    state: UdpSocketState,
}

impl ClientUdpSocket {
    async fn writable(self: Arc<Self>) -> io::Result<()> {
        self.io.writable().await
    }

    pub(super) fn new(socket: std::net::UdpSocket) -> io::Result<Self> {
        Ok(Self {
            state: UdpSocketState::new((&socket).into())?,
            io: tokio::net::UdpSocket::from_std(socket)?,
        })
    }
}

impl AsyncUdpSocket for ClientUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ClientUdpPoller {
            writable: ReusableBoxFuture::new(self.clone().writable()),
            socket: self,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            if transmit.contents.len() == UDP_PRELUDE_LEN && transmit.segment_size.is_none() {
                self.state.try_send((&self.io).into(), transmit)
            } else {
                self.state.send((&self.io).into(), transmit)
            }
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(result) = self.io.try_io(Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(result));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }
}

struct ClientUdpPoller {
    socket: Arc<ClientUdpSocket>,
    writable: ReusableBoxFuture<'static, io::Result<()>>,
}

impl std::fmt::Debug for ClientUdpPoller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientUdpPoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for ClientUdpPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = ready!(self.writable.poll(cx));
        let next = self.socket.clone().writable();
        self.writable.set(next);
        Poll::Ready(result)
    }
}

#[cfg(test)]
#[path = "../../tests/transport/morph/udp_socket.rs"]
mod tests;
