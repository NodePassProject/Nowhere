// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS UDP payload ownership and receive storage release through forwarding.

use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};

use crate::common::{
    COMMAND_UDP_ASSOCIATE, DialPolicy, OutboundDialer, REPLY_SUCCEEDED, SocksAddress, SocksConfig,
    authenticate, encode_udp_packet_into, read_request, write_reply,
};

use super::*;

#[tokio::test]
async fn socks_target_receiver_copies_only_payload_and_releases_storage_before_waiting() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let config = SocksConfig::from_url(
            &url::Url::parse(&format!("portal://key@127.0.0.1:2000?out={}", listener.local_addr().unwrap())).unwrap(),
        ).unwrap();
        let proxy = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            authenticate(&mut control, None).await.unwrap();
            assert_eq!(read_request(&mut control).await.unwrap().command, COMMAND_UDP_ASSOCIATE);
            write_reply(&mut control, REPLY_SUCCEEDED, &SocksAddress::Ip(relay_address)).await.unwrap();
            let mut request = [0; 64];
            let (_, client) = relay.recv_from(&mut request).await.unwrap();
            let mut frame = Vec::new();
            for payload in [b"payload".as_slice(), b""] {
                encode_udp_packet_into(&mut frame, &SocksAddress::Ip("192.0.2.1:53".parse().unwrap()), payload).unwrap();
                relay.send_to(&frame, client).await.unwrap();
            }
            control
        });
        let socket = OutboundDialer::new(DialPolicy::default(), config)
            .dial_udp_target(&Target::domain("example.com", 53).unwrap(), Duration::from_secs(1))
            .await.unwrap();
        socket.send(b"request", &mut Vec::new()).await.unwrap();
        let _control = proxy.await.unwrap();
        let mut receiver = TargetReceiver::Network(&socket);
        let mut buffer = Vec::with_capacity(u16::MAX as usize + 262);
        for expected in [b"payload".as_slice(), b""] {
            let packet = receiver.recv(&mut buffer).await.unwrap().unwrap();
            assert!(matches!(&packet, crate::vector::ReceivedUdpPacket::Buffered(range) if range.start == 0));
            assert_eq!(packet.payload(&buffer), expected);
            assert_eq!(buffer.len(), expected.len());
            assert_eq!(buffer.capacity(), expected.len());
        }
        let mut receiving = Box::pin(receiver.recv(&mut buffer));
        std::future::poll_fn(|cx| {
            assert!(receiving.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        }).await;
        drop(receiving);
        assert_eq!(buffer.capacity(), 0);
    }).await.unwrap();
}

#[tokio::test]
async fn blocked_download_retains_only_the_payload_and_still_cancels_or_times_out() {
    for timeout in [false, true] {
        let portal = crate::Portal::new(
            url::Url::parse("portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000").unwrap(),
            crate::common::Logger,
        )
        .unwrap();
        let mut inner = portal.inner;
        let forward =
            std::sync::Arc::get_mut(&mut std::sync::Arc::get_mut(&mut inner).unwrap().forward)
                .unwrap();
        forward.runtime.udp_idle_timeout = Duration::from_millis(100);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(peer.local_addr().unwrap()).await.unwrap();
        peer.connect(socket.local_addr().unwrap()).await.unwrap();
        let mut target = UdpTarget::Network(OutboundUdpSocket::Direct(socket));
        let (stream, mut downstream) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(stream);
        let mut input = UdpTunnel::stream(
            Box::pin(reader),
            Box::pin(writer),
            crate::vector::TcpTunnelGuard { _flow: None },
            forward.stats.clone(),
            false,
            forward.runtime.handshake_timeout,
        );
        let cancel = CancellationToken::new();
        let mut buffer = Vec::new();
        peer.send(&[42; 8000]).await.unwrap();
        let input_cancel = input.cancellation();
        let mut relay = Box::pin(relay_udp(
            forward,
            &mut input,
            &mut target,
            cancel.clone(),
            input_cancel,
            CancellationToken::new(),
            &mut buffer,
        ));
        if timeout {
            tokio::time::timeout(Duration::from_secs(1), &mut relay)
                .await
                .unwrap()
                .unwrap();
        } else {
            let mut header = [0; 1];
            tokio::time::timeout(Duration::from_secs(1), async {
                tokio::select! {
                    result = &mut relay => panic!("relay exited before blocked write: {result:?}"),
                    result = tokio::io::AsyncReadExt::read_exact(&mut downstream, &mut header) => { result.unwrap(); }
                }
            }).await.unwrap();
            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(1), &mut relay)
                .await
                .unwrap()
                .unwrap();
        }
        drop(relay);
        assert_eq!(buffer.len(), 8000);
        assert_eq!(buffer.capacity(), 8000);
        assert_eq!(forward.stats.udp_download_bytes.load(Ordering::Relaxed), 0);
    }
}
