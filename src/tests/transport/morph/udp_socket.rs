// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Real socket Prelude error propagation and normal packet compatibility.

use std::future::poll_fn;

use crate::transport::MorphKeys;
use crate::transport::morph::udp::wrap_morph_client_udp_socket;

use super::*;

#[tokio::test]
async fn prelude_errors_are_not_swallowed_by_the_runtime_adapter() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let runtime = quinn::TokioRuntime;
    let socket =
        wrap_morph_client_udp_socket(socket, Some(MorphKeys::derive(b"shared")), &runtime).unwrap();
    let mut poller = socket.clone().create_io_poller();
    let transmit = Transmit {
        destination: "[::1]:443".parse().unwrap(),
        ecn: None,
        contents: b"original packet",
        segment_size: None,
        src_ip: None,
    };
    for _ in 0..2 {
        poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let error = socket.try_send(&transmit).unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::WouldBlock);
    }
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .try_send(&Transmit {
            destination: receiver.local_addr().unwrap(),
            ..transmit
        })
        .unwrap();
    let mut buf = [0; 1500];
    assert_eq!(receiver.recv(&mut buf).await.unwrap(), UDP_PRELUDE_LEN);
    assert_eq!(
        receiver.recv(&mut buf).await.unwrap(),
        12 + transmit.contents.len()
    );
}

#[tokio::test]
async fn ordinary_morph_packets_keep_quinn_send_error_semantics() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let socket = Arc::new(ClientUdpSocket::new(socket).unwrap());
    let mut poller = socket.clone().create_io_poller();
    poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .unwrap();
    socket
        .try_send(&Transmit {
            destination: "[::1]:443".parse().unwrap(),
            ecn: None,
            contents: &[0; UDP_PRELUDE_LEN + 1],
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
}
