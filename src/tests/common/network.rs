// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Network helper tests.

use super::*;

#[test]
fn bind_udp_addrs_handles_wildcard_and_ip_literals() {
    assert_eq!(
        bind_udp_addrs("", 8080).unwrap(),
        vec![
            SocketAddr::from(([0, 0, 0, 0], 8080)),
            SocketAddr::from(([0u16; 8], 8080)),
        ]
    );
    assert_eq!(
        bind_udp_addrs("0.0.0.0", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("::", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("[::]", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("127.0.0.1", 8080).unwrap(),
        vec![SocketAddr::from(([127, 0, 0, 1], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("::1", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("[::1]", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
}

#[test]
fn filter_addrs_matches_local_ip_family() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 443)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
    ];

    assert_eq!(filter_addrs(addrs.into_iter(), None), addrs);
    assert_eq!(
        filter_addrs(addrs.into_iter(), Some("127.0.0.1".parse().unwrap())),
        [addrs[0]]
    );
    assert_eq!(
        filter_addrs(addrs.into_iter(), Some("::1".parse().unwrap())),
        [addrs[1]]
    );
}

#[test]
fn carrier_bind_resolution_expands_wildcards_and_filters_dns() {
    let v4 = CarrierEndpoint {
        port: 8080,
        family: AddressFamily::V4,
    };
    let v6 = CarrierEndpoint {
        port: 9090,
        family: AddressFamily::V6,
    };
    assert_eq!(
        resolve_bind_addrs("*", v4).unwrap(),
        [SocketAddr::from(([0, 0, 0, 0], 8080))]
    );
    assert_eq!(
        resolve_bind_addrs("*", v6).unwrap(),
        [SocketAddr::from(([0u16; 8], 9090))]
    );
    assert!(resolve_bind_addrs("127.0.0.1", v6).is_err());

    let localhost = resolve_bind_addrs("localhost", v4).unwrap();
    assert!(!localhost.is_empty());
    assert!(localhost.iter().all(SocketAddr::is_ipv4));
    assert!(localhost.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn carrier_and_local_bind_family_filters_are_both_enforced() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 443)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
    ];
    assert_eq!(
        filter_addrs_for_family(addrs.into_iter(), None, AddressFamily::V6),
        [addrs[1]]
    );
    assert!(
        filter_addrs_for_family(
            addrs.into_iter(),
            Some("127.0.0.1".parse().unwrap()),
            AddressFamily::V6,
        )
        .is_empty()
    );
}
