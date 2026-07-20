use super::*;
use std::time::Duration;

use crate::common::{LogLevel, Logger};
use crate::vector::Vector;
use url::Url;

#[test]
fn source_request_rejects_other_ips_and_domains() {
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        validate_udp_source_request(&SocksAddress::Ip("127.0.0.2:1234".parse().unwrap()), peer,)
            .is_err()
    );
    assert!(
        validate_udp_source_request(&SocksAddress::Domain("localhost".into(), 1234), peer).is_err()
    );
}

#[test]
fn source_endpoint_locks_first_port() {
    let endpoint = StdMutex::new(None);
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1000".parse().unwrap()
    ));
    assert!(accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1000".parse().unwrap()
    ));
    assert!(!accept_udp_source(
        &endpoint,
        peer,
        "127.0.0.1:1001".parse().unwrap()
    ));
}

#[tokio::test]
async fn pending_target_setup_does_not_block_control_shutdown() {
    let portal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let portal_addr = portal.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let portal_task = tokio::spawn(async move {
        let (stream, _) = portal.accept().await.unwrap();
        let _ = accepted_tx.send(());
        let _stream = stream;
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let vector = Vector::new(
        Url::parse(&format!(
            "vector://secret@{portal_addr}?up=tcp&down=tcp&pool=0&socks=127.0.0.1:1080"
        ))
        .unwrap(),
        Logger::new(LogLevel::None, false),
    )
    .unwrap();

    let controls = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connecting = TcpStream::connect(controls.local_addr().unwrap());
    let (accepted, client) = tokio::join!(controls.accept(), connecting);
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let association = tokio::spawn(run_udp_association(
        vector.inner.clone(),
        server,
        peer,
        SocksAddress::unspecified(),
        CancellationToken::new(),
    ));

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, REPLY_SUCCEEDED, 0, 1]);
    let udp_endpoint = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let local_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = Vec::new();
    encode_udp_packet_into(
        &mut packet,
        &SocksAddress::Ip("192.0.2.1:53".parse().unwrap()),
        b"request",
    )
    .unwrap();
    local_udp.send_to(&packet, udp_endpoint).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), accepted_rx)
        .await
        .unwrap()
        .unwrap();

    drop(client);
    tokio::time::timeout(Duration::from_millis(500), association)
        .await
        .expect("association stayed blocked on target setup")
        .unwrap()
        .unwrap();
    portal_task.abort();
}
