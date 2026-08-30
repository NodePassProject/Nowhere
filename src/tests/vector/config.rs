use super::*;

fn parse(raw: &str) -> Result<VectorConfig> {
    VectorConfig::from_url(&Url::parse(raw)?)
}

#[test]
fn defaults_to_quic_both_directions() {
    let config = parse("vector://secret@example.com:2077?socks=:1080").unwrap();
    assert_eq!(config.up, CarrierMode::Udp);
    assert_eq!(config.down, CarrierMode::Udp);
    assert_eq!(config.mux, MuxMode::Disabled);
    assert_eq!(config.sni, None);
    assert_eq!(config.pin, None);
    assert_eq!(config.socks.host, "");
    assert_eq!(config.socks.port, 1080);
}

#[test]
fn tcp_pair_defaults_to_dedicated_lanes() {
    let config =
        parse("vector://secret@example.com:2077?up=tcp&down=tcp&socks=127.0.0.1:1080").unwrap();
    assert_eq!(config.checkpoint_mode(), 0);
    assert_eq!(config.mux, MuxMode::Disabled);
}

#[test]
fn parses_authenticated_socks_and_preserves_plus() {
    let config = parse(
        "vector://secret@example.com:2077?socks=user%2Bname:p%40ss%3Aword@%5B%3A%3A1%5D:1080",
    )
    .unwrap();
    let credentials = config.socks.credentials.unwrap();
    assert_eq!(credentials.as_pair(), ("user+name", "p@ss:word"));
    assert_eq!(config.socks.host, "::1");
}

#[test]
fn rejects_missing_or_empty_socks() {
    assert!(parse("vector://secret@example.com:2077").is_err());
    assert!(parse("vector://secret@example.com:2077?socks=").is_err());
}

#[test]
fn ignores_unknown_values_and_keeps_the_first_duplicate() {
    let config = parse(
        "vector://secret@example.com:2077?wat=1&%FF=x&alpn=private/2&pool=8&up=tcp&up=udp&down=tcp&socks=:1080&socks=:1081",
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
    assert!(parse("vector://secret@example.com:2077?socks=:1080&up=mix").is_err());
    assert!(parse("vector://secret@example.com:2077?socks=:1080&rate=-1").is_err());
    for sni in ["", "none"] {
        let config = parse(&format!(
            "vector://secret@example.com:2077?sni={sni}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.sni, None);
        assert!(config.effective_url().contains("&sni=none&"));
    }
    for pin in ["", "none"] {
        let config = parse(&format!(
            "vector://secret@example.com:2077?pin={pin}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.pin, None);
        assert!(config.effective_url().contains("&pin=none&"));
    }

    let config = parse("vector://secret@example.com:2077?pin&socks=:1080").unwrap();
    assert_eq!(config.pin, None);
}

#[test]
fn effective_url_uses_canonical_order_and_prints_identity_options() {
    let config = parse(
        "vector://secret@example.com:2077?log=debug&alpn=private&mux=1&pool=8&down=tcp&up=tcp&sni=relay.example&pin=abc&etar=2&rate=1&socks=:1080",
    )
    .unwrap();
    assert_eq!(
        config.effective_url(),
        "vector://example.com:2077?up=tcp&down=tcp&mux=1&sni=relay.example&pin=abc&rate=1&etar=2&socks=:1080"
    );
}

#[test]
fn ignores_removed_alpn_and_validates_mux_inputs() {
    for raw in [
        "vector://secret@example.com:2077?socks=:1080&mux=",
        "vector://secret@example.com:2077?socks=:1080&mux=2",
        "vector://secret@example.com:2077?socks=:1080&mux=true",
        "vector://secret@example.com:2077?socks=:1080&mux=-1",
    ] {
        assert!(parse(raw).is_err(), "URL unexpectedly accepted: {raw}");
    }
    for alpn in [String::new(), "a".repeat(256)] {
        let config = parse(&format!(
            "vector://secret@example.com:2077?socks=:1080&alpn={alpn}"
        ))
        .unwrap();
        assert!(!config.effective_url().contains("alpn="));
    }
}

#[test]
fn preserves_pin_without_early_validation() {
    for pin in ["abc", "ABCDEF", "not-a-fingerprint"] {
        let config = parse(&format!(
            "vector://secret@example.com:2077?pin={pin}&socks=:1080"
        ))
        .unwrap();
        assert_eq!(config.pin.as_deref(), Some(pin));
    }
}

#[test]
fn rejects_invalid_authority_shape() {
    assert!(parse("vector://example.com:2077?socks=:1080").is_err());
    assert!(parse("vector://secret:password@example.com:2077?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com:2077/?socks=:1080").is_err());
    assert!(parse("vector://secret@example.com:2077/path?socks=:1080").is_err());
}

#[test]
fn normalizes_ipv6_portal_authority() {
    let config = parse("vector://secret@[::1]:2077?socks=127.0.0.1:1080").unwrap();
    assert_eq!(config.remote_host, "::1");
    assert_eq!(config.portal_endpoint(), "[::1]:2077");
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
