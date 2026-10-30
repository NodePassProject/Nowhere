// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS ingress forwarding and association cleanup across carriers.

use crate::common::{SocksAddress, decode_udp_packet, encode_udp_packet_into};

use super::*;

async fn request(
    endpoint: std::net::SocketAddr,
    command: u8,
    port: u16,
) -> (tokio::net::TcpStream, std::net::SocketAddr) {
    let mut stream = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(stream) = tokio::net::TcpStream::connect(endpoint).await {
                break stream;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let [hi, lo] = port.to_be_bytes();
    stream
        .write_all(&[5, command, 0, 1, 127, 0, 0, 1, hi, lo])
        .await
        .unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let address = std::net::SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    (stream, address)
}

#[tokio::test]
async fn socks_ingress_tcp_half_close_and_udp_reuse_across_carriers_and_morph() {
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    let tcp_port = match tcp {
        Target::Ip(address) => address.port(),
        _ => unreachable!(),
    };
    let udp_address = match udp {
        Target::Ip(address) => address,
        _ => unreachable!(),
    };
    for morph in [false, true] {
        let h = Harness::new("direct", morph).await;
        for net in ["tcp", "udp"] {
            let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = reservation.local_addr().unwrap();
            let mut url = h.url("vector", net, morph);
            url.query_pairs_mut()
                .append_pair("in", &endpoint.to_string())
                .append_pair("rate", "8")
                .append_pair("etar", "8");
            let vector = crate::Vector::new(url, Logger).unwrap();
            drop(reservation);
            let serving = tokio::spawn(vector.run());
            let (mut stream, _) = request(endpoint, 1, tcp_port).await;
            let payload = vec![42; 131072];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, payload);
            drop(stream);
            tokio::time::timeout(Duration::from_secs(3), async {
                while h
                    .inner
                    .forward
                    .stats
                    .tcp_active
                    .load(std::sync::atomic::Ordering::Relaxed)
                    != 0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();

            let (control, relay) = request(endpoint, 3, 0).await;
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = SocksAddress::Ip(udp_address);
            let mut packet = Vec::new();
            let mut reply = vec![0; 65535];
            for size in udp_sizes().into_iter().chain([1, 8000]) {
                let payload = vec![size as u8; size];
                encode_udp_packet_into(&mut packet, &target, &payload).unwrap();
                socket.send_to(&packet, relay).await.unwrap();
                let (n, source) =
                    tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut reply))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(source, relay);
                let (decoded, fragment, received) = decode_udp_packet(&reply[..n]).unwrap();
                assert_eq!(decoded, target);
                assert_eq!(fragment, 0);
                assert_eq!(received, payload);
            }
            drop(control);
            tokio::time::timeout(Duration::from_secs(3), async {
                while h
                    .inner
                    .forward
                    .stats
                    .udp_active
                    .load(std::sync::atomic::Ordering::Relaxed)
                    != 0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let released = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Ok(socket) = tokio::net::UdpSocket::bind(relay).await {
                        break socket;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("SOCKS UDP relay socket was not released on control EOF");
            drop(released);
            serving.abort();
            assert!(serving.await.unwrap_err().is_cancelled());
        }
        h.close().await;
    }
    tcp_task.abort();
    udp_task.abort();
}
