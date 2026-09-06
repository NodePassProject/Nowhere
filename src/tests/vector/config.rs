use super::*;

fn parse(raw: &str) -> Result<VectorConfig> {
    VectorConfig::from_url(&Url::parse(raw)?)
}

#[test]
fn dual_carrier_endpoint_defaults_to_tcp_without_mux() {
    let config = parse("vector://secret@example.com:2000?socks=:1080").unwrap();
    assert_eq!(config.up, CarrierMode::Tcp);
    assert_eq!(config.down, CarrierMode::Tcp);
    assert_eq!(config.mux, MuxMode::Disabled);
    assert_eq!(config.sni, None);
    assert_eq!(config.pin, None);
    assert_eq!(config.socks.host, "");
    assert_eq!(config.socks.port, 1080);
}

#[test]
fn explicit_endpoints_select_ports_families_and_single_carrier_defaults() {
    let tcp = parse("vector://secret@example.com/tcp4:2006?socks=:1080").unwrap();
    assert_eq!(tcp.up, CarrierMode::Tcp);
    assert_eq!(tcp.down, CarrierMode::Tcp);
    assert_eq!(tcp.portal_endpoint(), "example.com/tcp4:2006");

    let udp = parse("vector://secret@example.com/udp6:2017?socks=:1080").unwrap();
    assert_eq!(udp.up, CarrierMode::Udp);
    assert_eq!(udp.down, CarrierMode::Udp);
    assert_eq!(udp.mux, MuxMode::Disabled);

    let mixed = parse("vector://secret@example.com/udp6:2017/tcp4:2006?socks=:1080").unwrap();
    assert_eq!(mixed.portal_endpoint(), "example.com/tcp4:2006/udp6:2017");
    assert_eq!(mixed.remote.tcp.unwrap().port, 2006);
    assert_eq!(mixed.remote.udp.unwrap().port, 2017);
    assert_eq!(mixed.up, CarrierMode::Tcp);
    assert_eq!(mixed.down, CarrierMode::Tcp);
    assert_eq!(mixed.mux, MuxMode::Disabled);
}

#[test]
fn policy_must_use_declared_carriers() {
    for raw in [
        "vector://secret@example.com/tcp:2006?up=udp&socks=:1080",
        "vector://secret@example.com/udp:2017?down=tcp&socks=:1080",
        "vector://secret@example.com/tcp:2006?up=mix&socks=:1080",
    ] {
        assert!(parse(raw).is_err(), "accepted {raw}");
    }
}

#[test]
fn tcp_pair_defaults_to_dedicated_lanes() {
    let config =
        parse("vector://secret@example.com:2000?up=tcp&down=tcp&socks=127.0.0.1:1080").unwrap();
    assert_eq!(config.checkpoint_mode(), 0);
    assert_eq!(config.mux, MuxMode::Disabled);
}

#[test]
fn parses_all_route_policies_and_preserves_checkpoint_modes() {
    let cases = [
        ("tcp", "tcp", 0),
        ("tcp", "udp", 1),
        ("udp", "tcp", 2),
        ("udp", "udp", 3),
        ("mix", "tcp", 4),
        ("mix", "udp", 5),
        ("tcp", "mix", 6),
        ("udp", "mix", 7),
        ("mix", "mix", 8),
    ];
    for (up, down, mode) in cases {
        let config = parse(&format!(
            "vector://secret@example.com:2000?up={up}&down={down}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.up.to_string(), up);
        assert_eq!(config.down.to_string(), down);
        assert_eq!(config.checkpoint_mode(), mode);
        assert!(
            config
                .effective_url()
                .contains(&format!("up={up}&down={down}"))
        );
    }
}

#[test]
fn mux_is_available_for_tcp_or_mix_and_normalized_for_pure_udp() {
    for (up, down) in [
        ("tcp", "tcp"),
        ("tcp", "udp"),
        ("udp", "tcp"),
        ("mix", "tcp"),
        ("mix", "udp"),
        ("tcp", "mix"),
        ("udp", "mix"),
        ("mix", "mix"),
    ] {
        let config = parse(&format!(
            "vector://secret@example.com:2000?up={up}&down={down}&mux=1&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.mux, MuxMode::Enabled, "up={up} down={down}");
    }

    let config =
        parse("vector://secret@example.com:2000?up=udp&down=udp&mux=1&socks=:1080").unwrap();
    assert_eq!(config.mux, MuxMode::Disabled);
    assert!(config.effective_url().contains("up=udp&down=udp"));
    assert!(config.effective_url().contains("&mux=0&"));
}

#[test]
fn parses_authenticated_socks_and_preserves_plus() {
    let config = parse(
        "vector://secret@example.com:2000?socks=user%2Bname:p%40ss%3Aword@%5B%3A%3A1%5D:1080",
    )
    .unwrap();
    let credentials = config.socks.credentials.unwrap();
    assert_eq!(credentials.as_pair(), ("user+name", "p@ss:word"));
    assert_eq!(config.socks.host, "::1");
}

#[test]
fn rejects_missing_or_empty_socks() {
    assert!(parse("vector://secret@example.com:2000").is_err());
    assert!(parse("vector://secret@example.com:2000?socks=").is_err());
}

#[test]
fn ignores_unknown_values_and_keeps_the_first_duplicate() {
    let config = parse(
        "vector://secret@example.com:2000?wat=1&%FF=x&alpn=private/2&pool=8&up=tcp&up=udp&down=tcp&socks=:1080&socks=:1081",
    )
    .unwrap();
    assert_eq!(config.up, CarrierMode::Tcp);
    assert_eq!(config.down, CarrierMode::Tcp);
    assert_eq!(config.socks.port, 1080);
    assert!(!config.effective_url().contains("alpn="));
    assert!(!config.effective_url().contains("pool="));
}

#[test]
fn rejects_invalid_selected_values_but_accepts_disabled_identity_options() {
    assert!(parse("vector://secret@example.com:2000?socks=:1080&up=auto").is_err());
    assert!(parse("vector://secret@example.com:2000?socks=:1080&rate=-1").is_err());
    for sni in ["", "none"] {
        let config = parse(&format!(
            "vector://secret@example.com:2000?sni={sni}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.sni, None);
        assert!(config.effective_url().contains("&sni=none&"));
    }
    for pin in ["", "none"] {
        let config = parse(&format!(
            "vector://secret@example.com:2000?pin={pin}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.pin, None);
        assert!(config.effective_url().contains("&pin=none&"));
    }

    let config = parse("vector://secret@example.com:2000?pin&socks=:1080").unwrap();
    assert_eq!(config.pin, None);
}

#[test]
fn effective_url_uses_canonical_order_and_prints_identity_options() {
    let config = parse(
        "vector://secret@example.com:2000?log=debug&alpn=private&mux=1&pool=8&down=tcp&up=tcp&sni=relay.example&pin=abc&etar=2&rate=1&socks=:1080",
    )
    .unwrap();
    assert_eq!(
        config.effective_url(),
        "vector://example.com:2000?up=tcp&down=tcp&mux=1&sni=relay.example&pin=abc&rate=1&etar=2&socks=:1080"
    );
}

#[test]
fn ignores_removed_alpn_and_validates_mux_inputs() {
    for raw in [
        "vector://secret@example.com:2000?socks=:1080&mux=",
        "vector://secret@example.com:2000?socks=:1080&mux=2",
        "vector://secret@example.com:2000?socks=:1080&mux=true",
        "vector://secret@example.com:2000?socks=:1080&mux=-1",
    ] {
        assert!(parse(raw).is_err(), "URL unexpectedly accepted: {raw}");
    }
    for alpn in [String::new(), "a".repeat(256)] {
        let config = parse(&format!(
            "vector://secret@example.com:2000?socks=:1080&alpn={alpn}"
        ))
        .unwrap();
        assert!(!config.effective_url().contains("alpn="));
    }
}

#[test]
fn preserves_pin_without_early_validation() {
    for pin in ["abc", "ABCDEF", "not-a-fingerprint"] {
        let config = parse(&format!(
            "vector://secret@example.com:2000?pin={pin}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.pin.as_deref(), Some(pin));
    }
}

#[test]
fn rejects_invalid_authority_shape() {
    assert!(parse("vector://example.com:2000?socks=:1080").is_err());
    assert!(parse("vector://secret:password@example.com:2000?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com:2000/?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com:2000/path?socks=:1080").is_err());
}

#[test]
fn normalizes_ipv6_portal_authority() {
    let config = parse("vector://secret@[::1]:2000?socks=127.0.0.1:1080").unwrap();
    assert_eq!(config.remote.host, "::1");
    assert_eq!(config.portal_endpoint(), "[::1]:2000");
}

#[test]
fn upstream_authority_decodes_reserved_key_bytes_and_ipv6() {
    let query = HashMap::from([
        ("up".to_owned(), "tcp".to_owned()),
        ("down".to_owned(), "tcp".to_owned()),
    ]);
    let (config, credentials) =
        PortalClientConfig::from_upstream_authority("part%40key@[::1]:2080", &query, "::2")
            .unwrap();

    assert_eq!(config.endpoint(), "[::1]:2080");
    assert_eq!(config.dialer_ip, "::2");
    assert_eq!(
        credentials,
        crate::protocol::Credentials::from_shared_key(b"part@key").unwrap()
    );
}

#[test]
fn upstream_authority_decodes_the_shared_key_exactly_once() {
    let query = HashMap::new();
    let (_, credentials) = PortalClientConfig::from_upstream_authority(
        "part%2540key@origin.example/udp:2080",
        &query,
        "auto",
    )
    .unwrap();
    assert_eq!(
        credentials,
        crate::protocol::Credentials::from_shared_key(b"part%40key").unwrap()
    );
}

#[test]
fn upstream_authority_accepts_explicit_carriers() {
    let query = HashMap::new();
    let (config, _) = PortalClientConfig::from_upstream_authority(
        "secret@origin.example/tcp6:2006",
        &query,
        "auto",
    )
    .unwrap();
    assert_eq!(config.endpoint(), "origin.example/tcp6:2006");
    assert_eq!(config.up, CarrierMode::Tcp);
    assert_eq!(config.down, CarrierMode::Tcp);
}

#[test]
fn upstream_authority_requires_unambiguous_key_endpoint_separator() {
    let query = HashMap::new();
    for authority in [
        "missing-separator.example:2080",
        "part@key@origin.example:2080",
        "secret@origin.example",
        "@origin.example:2080",
    ] {
        assert!(
            PortalClientConfig::from_upstream_authority(authority, &query, "auto").is_err(),
            "authority accepted: {authority}"
        );
    }
}

#[test]
fn upstream_authority_rejects_every_invalid_endpoint_shape() {
    let query = HashMap::new();
    for (authority, expected) in [
        ("secret@*:2000", "wildcard host is only valid"),
        (
            "secret@origin.example:2000/tcp:2006",
            "choose either HOST:PORT",
        ),
        ("secret@origin.example/tcp:2006/", "trailing slash"),
        (
            "secret@origin.example/tcp:2006/tcp6:2006",
            "TCP carrier is declared more than once",
        ),
        ("secret@origin.example/udp:0", "1..=65535"),
        ("secret@origin.example/sctp:2000", "unknown carrier"),
        (
            "secret@192.0.2.1/udp6:2017",
            "address family does not match",
        ),
        (
            "secret@origin.example/tcp:2006?inner=1",
            "expected shared-key and one endpoint",
        ),
        (
            "secret@origin.example/tcp:2006#fragment",
            "expected shared-key and one endpoint",
        ),
        ("bad%GG@origin.example/tcp:2006", "malformed percent escape"),
    ] {
        let error = PortalClientConfig::from_upstream_authority(authority, &query, "auto")
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{authority} returned {error:?}");
        assert!(
            !error.contains("secret@"),
            "error leaked the next shared key"
        );
    }
}
