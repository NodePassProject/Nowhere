use super::*;

#[tokio::test]
async fn ipv6_sockets_are_v6_only_and_allow_ipv4_on_the_same_port() {
    let udp = bind_quic_socket("[::]:0".parse().unwrap()).unwrap();
    assert!(socket2::SockRef::from(&udp).only_v6().unwrap());
    let udp4 = std::net::UdpSocket::bind(("0.0.0.0", udp.local_addr().unwrap().port())).unwrap();
    let tcp = listen_tcp("[::]:0".parse().unwrap())
        .unwrap()
        .into_std()
        .unwrap();
    assert!(socket2::SockRef::from(&tcp).only_v6().unwrap());
    let tcp4 = std::net::TcpListener::bind(("0.0.0.0", tcp.local_addr().unwrap().port())).unwrap();
    drop((udp, udp4, tcp, tcp4));
}
