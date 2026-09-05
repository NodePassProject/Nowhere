use super::*;

fn parse(raw: &str, wildcard: bool) -> Result<ServiceEndpoint> {
    ServiceEndpoint::parse(&Url::parse(raw)?, wildcard, "test")
}

#[test]
fn parses_compact_and_explicit_endpoints() {
    let compact = parse("portal://key@*:2077", true).unwrap();
    assert_eq!(compact.canonical(), "*:2077");
    assert_eq!(compact.tcp.unwrap().port, 2077);
    assert_eq!(compact.udp.unwrap().port, 2077);

    let explicit = parse("portal://key@*/udp6:3088/tcp4:2077", true).unwrap();
    assert_eq!(explicit.canonical(), "*/tcp4:2077/udp6:3088");
    assert_eq!(explicit.tcp.unwrap().family, AddressFamily::V4);
    assert_eq!(explicit.udp.unwrap().family, AddressFamily::V6);
}

#[test]
fn accepts_every_declared_carrier_token() {
    for (carrier, family, is_tcp) in [
        ("tcp", AddressFamily::Any, true),
        ("tcp4", AddressFamily::V4, true),
        ("tcp6", AddressFamily::V6, true),
        ("udp", AddressFamily::Any, false),
        ("udp4", AddressFamily::V4, false),
        ("udp6", AddressFamily::V6, false),
    ] {
        let endpoint = parse(&format!("portal://key@*/{carrier}:2077"), true).unwrap();
        let parsed = if is_tcp { endpoint.tcp } else { endpoint.udp }.unwrap();
        assert_eq!(parsed.family, family, "carrier={carrier}");
        assert_eq!(parsed.port, 2077, "carrier={carrier}");
    }
}

#[test]
fn accepts_port_boundaries_and_canonicalizes_leading_zeroes() {
    for (raw_port, expected_port) in [("1", 1), ("00001", 1), ("65535", 65535)] {
        let endpoint = parse(&format!("portal://key@*/tcp:{raw_port}"), true).unwrap();
        assert_eq!(endpoint.tcp.unwrap().port, expected_port);
        assert_eq!(endpoint.canonical(), format!("*/tcp:{expected_port}"));
    }
}

#[test]
fn rejects_invalid_carrier_names_and_port_representations() {
    for carrier in ["", "TCP", "Udp", "quic", "tcp7", "tcp%20"] {
        let raw = format!("portal://key@*/{carrier}:2077");
        let error = parse(&raw, true).unwrap_err().to_string();
        assert!(
            error.contains("unknown carrier"),
            "{raw} returned {error:?}"
        );
    }
    for port in [
        "", "0", "-1", "+1", "1.0", "1%20", "%201", "0x50", "65536", "999999", "１２",
    ] {
        let raw = format!("portal://key@*/tcp:{port}");
        assert!(parse(&raw, true).is_err(), "accepted {raw}");
    }
}

#[test]
fn rejects_every_duplicate_transport_pair() {
    for carriers in [["tcp", "tcp4", "tcp6"], ["udp", "udp4", "udp6"]] {
        for first in carriers {
            for second in carriers {
                let raw = format!("portal://key@*/{first}:2077/{second}:3088");
                let error = parse(&raw, true).unwrap_err().to_string();
                assert!(
                    error.contains("carrier is declared more than once"),
                    "{raw} returned {error:?}"
                );
            }
        }
    }
}

#[test]
fn formats_ipv6_and_single_carriers() {
    assert_eq!(
        parse("vector://key@[2001:db8::1]/udp:3088", false)
            .unwrap()
            .canonical(),
        "[2001:db8::1]/udp:3088"
    );
    assert_eq!(
        parse("vector://key@example.com/tcp:2077", false)
            .unwrap()
            .canonical(),
        "example.com/tcp:2077"
    );
}

#[test]
fn rejects_invalid_grammar_and_family_mismatches() {
    for (raw, expected) in [
        ("portal://key@*:2077/tcp:2077", "choose either HOST:PORT"),
        ("portal://key@*/", "must not contain empty segments"),
        ("portal://key@*/tcp:2077/", "trailing slash"),
        ("portal://key@*/tcp:2077//udp:2077", "empty segments"),
        ("portal://key@*/tcp", "must use CARRIER:PORT"),
        ("portal://key@*/tcp:1:2", "decimal digits only"),
        ("portal://key@*/tcp:abc", "decimal digits only"),
        ("portal://key@*/tcp:-1", "decimal digits only"),
        ("portal://key@*/tcp:+2077", "decimal digits only"),
        ("portal://key@*/tcp:", "decimal digits only"),
        ("portal://key@*/tcp:0", "1..=65535"),
        ("portal://key@*/tcp:65536", "1..=65535"),
        ("portal://key@*/TCP:2077", "unknown carrier"),
        ("portal://key@*/sctp:2077", "unknown carrier"),
        (
            "portal://key@*/tcp:2077/tcp6:3088",
            "TCP carrier is declared more than once",
        ),
        (
            "portal://key@*/udp4:2077/udp:3088",
            "UDP carrier is declared more than once",
        ),
        (
            "portal://key@192.0.2.1/tcp6:2077",
            "address family does not match",
        ),
        (
            "portal://key@[2001:db8::1]/udp4:2077",
            "address family does not match",
        ),
    ] {
        let error = parse(raw, true).unwrap_err().to_string();
        assert!(error.contains(expected), "{raw} returned {error:?}");
    }
    let error = parse("vector://key@*:2077", false).unwrap_err().to_string();
    assert!(error.contains("wildcard host is only valid for Portal listeners"));
}

#[test]
fn raw_input_validation_rejects_dot_segments_before_url_normalization() {
    for raw in [
        "portal://key@*/tcp:2077/../udp:3088",
        "portal://key@*/tcp:2077/./udp:3088",
        "portal://key@*/tcp:2077/%2e%2e/udp:3088",
        "vector://key@example.com/%2E./tcp:2077?socks=:1080",
    ] {
        let error = validate_endpoint_url_input(raw, "test")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("must not contain '.' or '..' segments"),
            "{raw}: {error}"
        );
    }
}
