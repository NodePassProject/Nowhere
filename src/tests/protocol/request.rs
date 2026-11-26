// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Target address codecs and request validation tests.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::io::AsyncReadExt;

use crate::protocol::test_support::{encode_target, write_request, write_request_frame};

use super::*;

#[test]
fn flow_requests_encode_all_targets_into_the_supplied_buffer() {
    for target in [
        Target::try_from("127.0.0.1:80").unwrap(),
        Target::try_from("[2001:db8::5]:65535").unwrap(),
        Target::domain("example.com", 443).unwrap(),
        Target::domain(
            format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61)
            ),
            1,
        )
        .unwrap(),
    ] {
        for kind in [FlowKind::Tcp, FlowKind::Udp] {
            let mut buffer = [0xa5; TARGET_MAX_ENCODED_LEN + 2];
            let length = encode_flow_request_into(kind, &target, &mut buffer).unwrap();
            assert_eq!(buffer[0], kind as u8);
            let (decoded, consumed) = decode_target(&buffer[1..length]).unwrap();
            assert_eq!(decoded, target);
            assert_eq!(consumed + 1, length);
            assert!(buffer[length..].iter().all(|&byte| byte == 0xa5));
            assert!(encode_flow_request_into(kind, &target, &mut buffer[..length - 1]).is_err());
        }
    }
    assert!(
        encode_flow_request_into(
            FlowKind::Tcp,
            &Target::Ip("127.0.0.1:80".parse().unwrap()),
            &mut []
        )
        .is_err()
    );
}

#[test]
fn ipv4_ipv6_and_domain_match_socks5_address_vectors() {
    let ipv4 = Target::Ip(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(192, 0, 2, 1),
        443,
    )));
    assert_eq!(
        encode_target(&ipv4).unwrap(),
        [0x01, 192, 0, 2, 1, 0x01, 0xbb]
    );

    let ipv6 = Target::Ip(SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
        53,
        0,
        0,
    )));
    assert_eq!(
        encode_target(&ipv6).unwrap(),
        [
            0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53,
        ]
    );

    let domain = Target::domain("xn--bcher-kva.example", 8080).unwrap();
    let mut expected = vec![0x03, 21];
    expected.extend_from_slice(b"xn--bcher-kva.example");
    expected.extend_from_slice(&8080u16.to_be_bytes());
    assert_eq!(encode_target(&domain).unwrap(), expected);
}

#[test]
fn all_target_variants_round_trip_and_preserve_trailing_payload() {
    for target in [
        Target::try_from("127.0.0.1:80").unwrap(),
        Target::try_from("[2001:db8::5]:65535").unwrap(),
        Target::try_from("example.com:443").unwrap(),
    ] {
        let mut encoded = encode_target(&target).unwrap();
        let consumed = encoded.len();
        encoded.extend_from_slice(b"initial payload");
        let (decoded, actual_consumed) = decode_target(&encoded).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(actual_consumed, consumed);
        assert_eq!(&encoded[actual_consumed..], b"initial payload");
        assert_eq!(Target::try_from(target.to_string()).unwrap(), target);
    }
}

#[test]
fn maximum_domain_is_accepted_without_a_large_generic_target_buffer() {
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253);
    let target = Target::domain(host.clone(), 1).unwrap();
    let encoded = encode_target(&target).unwrap();
    assert_eq!(encoded.len(), TARGET_MAX_ENCODED_LEN);
    assert_eq!(encoded[0], TARGET_ATYP_DOMAIN);
    assert_eq!(encoded[1], 253);
    assert_eq!(decode_target(&encoded).unwrap().0, target);

    assert!(Target::domain(format!("{host}a"), 1).is_err());
}

#[test]
fn target_constructors_reject_empty_illegal_or_ambiguous_values() {
    for value in [
        "",
        "example.com",
        "example.com:0",
        ":443",
        "bücher.example:443",
        "bad host:443",
        "bad/host:443",
        "bad@host:443",
        "-bad.example:443",
        "bad-.example:443",
        "bad..example:443",
        "example.com.:443",
        "bad:host:443",
        "[example.com]:443",
        "2001:db8::1:443",
    ] {
        assert!(Target::try_from(value).is_err(), "accepted {value:?}");
    }
    assert!(Target::ip("127.0.0.1:0".parse().unwrap()).is_err());
    assert!(Target::domain("example.com", 0).is_err());
    assert!(Target::domain("bad[host]", 443).is_err());
    assert!(Target::domain(format!("{}.example", "a".repeat(64)), 443).is_err());
}

#[test]
fn public_enum_cannot_bypass_encoder_validation() {
    assert!(
        encode_target(&Target::Domain {
            host: String::new(),
            port: 443,
        })
        .is_err()
    );
    assert!(encode_target(&Target::Ip("127.0.0.1:0".parse().unwrap())).is_err());
    let mut short = [0; 6];
    assert!(encode_target_into(&Target::try_from("127.0.0.1:80").unwrap(), &mut short).is_err());
}

#[test]
fn decoder_rejects_unknown_empty_zero_port_and_truncated_inputs() {
    for input in [
        vec![],
        vec![0x00],
        vec![0x02, 1, 2, 3, 4, 0, 80],
        vec![0x01],
        vec![0x01, 127, 0, 0, 1, 0],
        vec![0x01, 127, 0, 0, 1, 0, 0],
        vec![0x04; 18],
        vec![0x03],
        vec![0x03, 0, 0, 80],
        vec![0x03, 3, b'a', b'b', 0, 80],
        vec![0x03, 1, 0xff, 0, 80],
        vec![0x03, 1, b'a', 0, 0],
    ] {
        assert!(decode_target(&input).is_err(), "accepted {input:?}");
    }
}

#[tokio::test]
async fn async_read_and_write_leave_initial_payload_untouched() {
    let target = Target::try_from("example.com:443").unwrap();
    let mut wire = Vec::new();
    write_request(&mut wire, &target).await.unwrap();
    assert_eq!(wire, write_request_frame(&target).unwrap());
    wire.extend_from_slice(b"hello");

    let mut input = wire.as_slice();
    assert_eq!(read_request(&mut input).await.unwrap(), target);
    let mut payload = Vec::new();
    input.read_to_end(&mut payload).await.unwrap();
    assert_eq!(payload, b"hello");
}

#[test]
fn honest_address_accessors_distinguish_ip_and_domain() {
    let ip = Target::try_from("127.0.0.1:80").unwrap();
    assert_eq!(ip.ip_addr(), Some(Ipv4Addr::LOCALHOST.into()));
    assert_eq!(ip.domain_name(), None);
    let domain = Target::try_from("example.com:80").unwrap();
    assert_eq!(domain.ip_addr(), None);
    assert_eq!(domain.domain_name(), Some("example.com"));
    assert_eq!(domain.port(), 80);
    assert_eq!(domain.socket_addr(), None);
}
