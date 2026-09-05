use super::{bind_carrier, io_error_is_family_unavailable};
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, TcpListener};

#[tokio::test]
async fn dns_listener_binds_every_unique_resolved_address() {
    use std::net::ToSocketAddrs;
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    let portal = super::Portal::new(
        url::Url::parse(&format!("portal://secret@localhost/tcp:{port}")).unwrap(),
        crate::common::Logger::new(crate::common::LogLevel::None, false),
    )
    .unwrap();
    let mut expected = ("localhost", port)
        .to_socket_addrs()
        .unwrap()
        .collect::<Vec<_>>();
    expected.sort_unstable();
    expected.dedup();
    drop(reservation);
    let listeners = portal.listen_tcp_listeners().unwrap();
    let mut actual = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect::<Vec<_>>();
    actual.sort_unstable();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn tcp_startup_failure_releases_already_opened_quic_socket() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = occupied.local_addr().unwrap().port();
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let portal = super::Portal::new(
        url::Url::parse(&format!(
            "portal://secret@127.0.0.1/tcp4:{tcp_port}/udp4:{}",
            address.port()
        ))
        .unwrap(),
        crate::common::Logger::new(crate::common::LogLevel::None, false),
    )
    .unwrap();
    drop(reservation);
    assert!(portal.run().await.is_err());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            match std::net::UdpSocket::bind(address) {
                Ok(socket) => {
                    drop(socket);
                    break;
                }
                Err(error) if error.kind() == ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("unexpected rebind error: {error}"),
            }
        }
    })
    .await
    .expect("QUIC socket leaked after TCP startup failure");
}

#[test]
fn injected_family_failure_warns_only_when_degradation_is_allowed() {
    let addresses: [SocketAddr; 2] = [
        "0.0.0.0:2000".parse().unwrap(),
        "[::]:2000".parse().unwrap(),
    ];
    for allow in [false, true] {
        let mut warnings = Vec::new();
        let result = bind_carrier(
            &addresses,
            allow,
            |addr| {
                if addr.is_ipv6() {
                    Err(
                        Error::new(ErrorKind::AddrNotAvailable, "injected unavailable family")
                            .into(),
                    )
                } else {
                    Ok(addr)
                }
            },
            |addr, _| warnings.push(addr),
        );
        assert_eq!(result.is_ok(), allow);
        assert_eq!(warnings.len(), usize::from(allow));
        if let Ok(bound) = result {
            assert_eq!(bound, [addresses[0]]);
        }
    }
    assert!(
        bind_carrier::<()>(
            &addresses,
            true,
            |_| Err(Error::new(ErrorKind::AddrNotAvailable, "unavailable").into()),
            |_, _| {}
        )
        .is_err()
    );
}

#[test]
fn fatal_bind_failure_releases_preceding_socket_even_with_degradation_enabled() {
    for kind in [ErrorKind::AddrInUse, ErrorKind::PermissionDenied] {
        let mut bound = None;
        let addresses = ["127.0.0.1:0".parse().unwrap(); 2];
        let result = bind_carrier(
            &addresses,
            true,
            |addr| {
                if bound.is_some() {
                    return Err(Error::new(kind, "injected fatal failure").into());
                }
                let socket = TcpListener::bind(addr)?;
                bound = Some(socket.local_addr()?);
                Ok(socket)
            },
            |_, _| panic!("fatal errors must not degrade"),
        );
        assert!(result.is_err());
        let rebound = TcpListener::bind(bound.unwrap()).expect("preceding listener leaked");
        drop(rebound);
    }
}

#[test]
fn classifies_portable_and_platform_family_errors() {
    assert!(io_error_is_family_unavailable(&std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "family unavailable",
    )));
    #[cfg(unix)]
    let codes = [libc::EAFNOSUPPORT];
    #[cfg(windows)]
    let codes = [10047];
    for code in codes {
        assert!(io_error_is_family_unavailable(
            &std::io::Error::from_raw_os_error(code)
        ));
    }
    assert!(!io_error_is_family_unavailable(&std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "occupied",
    )));
}
