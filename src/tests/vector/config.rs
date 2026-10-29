// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector carrier selection, defaults, query validation, and effective configuration tests.

use super::*;

fn parse(query: &str) -> Result<VectorConfig> {
    VectorConfig::from_url(
        &Url::parse(&format!(
            "vector://0123456789abcdef0123456789abcdef@localhost:2000?in=127.0.0.1:1080&{query}"
        ))
        .unwrap(),
    )
}

#[test]
fn defaults_and_unknown_options_are_ignored() {
    let config = parse("unused=garbage&net=%ZZ&unknown=%ZZ").unwrap();
    assert_eq!(config.net, CarrierMode::Tcp);
    let effective = Url::parse(&config.effective_url()).unwrap();
    assert_eq!(effective.scheme(), "vector");
    assert!(effective.username().is_empty());
    assert!(effective.password().is_none());
    assert_eq!(effective.host_str(), Some("localhost"));
    assert_eq!(effective.port(), Some(2000));
    let values = effective.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(effective.query_pairs().count(), values.len());
    assert_eq!(
        values,
        HashMap::from([
            ("in".into(), "127.0.0.1:1080".into()),
            ("sni".into(), "localhost".into()),
            ("pin".into(), "none".into()),
            ("morph".into(), "1".into()),
            ("rate".into(), "0".into()),
            ("etar".into(), "0".into()),
        ])
    );
    assert_eq!(parse("net=udp&net=bad").unwrap().net, CarrierMode::Tcp);
    assert!(parse("net=bad&net=udp").is_ok());
}

#[test]
fn recognized_invalid_values_and_missing_ingress_fail() {
    for query in ["morph=2", "rate=-1", "etar=no", "pin=bad"] {
        assert!(parse(query).is_err(), "{query}");
    }
    let url = Url::parse("vector://0123456789abcdef0123456789abcdef@localhost:2000").unwrap();
    assert!(VectorConfig::from_url(&url).is_err());
    assert!(PortalClientConfig::from_probe_url(&url).is_ok());
}

#[test]
fn endpoint_selects_one_carrier_and_address_family() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    for (endpoint, mode, family) in [
        (
            "localhost:2000",
            CarrierMode::Tcp,
            crate::common::AddressFamily::Any,
        ),
        (
            "localhost/tcp:2000",
            CarrierMode::Tcp,
            crate::common::AddressFamily::Any,
        ),
        (
            "localhost/tcp4:2000",
            CarrierMode::Tcp,
            crate::common::AddressFamily::V4,
        ),
        (
            "localhost/tcp6:2000",
            CarrierMode::Tcp,
            crate::common::AddressFamily::V6,
        ),
        (
            "localhost/udp:2000",
            CarrierMode::Udp,
            crate::common::AddressFamily::Any,
        ),
        (
            "localhost/udp4:2000",
            CarrierMode::Udp,
            crate::common::AddressFamily::V4,
        ),
        (
            "localhost/udp6:2000",
            CarrierMode::Udp,
            crate::common::AddressFamily::V6,
        ),
    ] {
        let url = Url::parse(&format!(
            "vector://{KEY}@{endpoint}?in=127.0.0.1:1080&net=invalid"
        ))
        .unwrap();
        let config = VectorConfig::from_url(&url).unwrap();
        assert_eq!(config.net, mode, "{endpoint}");
        let carrier = if mode == CarrierMode::Tcp {
            config.tcp_endpoint()
        } else {
            config.udp_endpoint()
        }
        .unwrap();
        assert_eq!(carrier.family, family);
        assert_eq!(config.endpoint(), endpoint);
        assert!(!config.effective_url().contains("net="));
    }
    let url = Url::parse(&format!("vector://{KEY}@localhost/tcp:2000/udp:2001")).unwrap();
    let error = PortalClientConfig::from_probe_url(&url).unwrap_err();
    assert!(error.to_string().contains("exactly one carrier"));
}

#[test]
fn ingress_credentials_split_before_single_decode_and_are_redacted() {
    let url = Url::parse(
        "vector://0123456789abcdef0123456789abcdef@localhost:2000?in=a%3Ab:p%2540ss@127.0.0.1:1080",
    )
    .unwrap();
    let config = VectorConfig::from_url(&url).unwrap();
    assert_eq!(
        config.socks.credentials.as_ref().unwrap().as_pair(),
        ("a:b", "p%40ss")
    );
    assert!(!config.effective_url().contains("p%40ss"));
}

#[test]
fn morph_defaults_on_and_honors_explicit_values() {
    for scheme in ["vector", "egress", "nowhere"] {
        for (query, enabled) in [("", true), ("morph=0", false), ("morph=1", true)] {
            let url = Url::parse(&format!(
                "{scheme}://0123456789abcdef0123456789abcdef@localhost:2000?{query}"
            ))
            .unwrap();
            let query = query_first(&url, &["morph"]).unwrap();
            let config = PortalClientConfig::parse(&url, &query).unwrap();
            assert_eq!(config.morph, enabled, "{url}");
            assert_eq!(config.morph_keys.is_some(), enabled, "{url}");
        }
    }
}

#[test]
fn handshake_timeout_is_saved_per_vector_and_inherited_by_probe_and_fingerprint() {
    let mut instances = Vec::new();
    for (key, milliseconds) in [
        ("0123456789abcdef0123456789abcdef", 9100),
        ("fedcba9876543210fedcba9876543210", 24700),
    ] {
        let expected = Duration::from_millis(milliseconds);
        for carrier in ["tcp", "udp"] {
            for morph in [0, 1] {
                let url = Url::parse(&format!(
                    "vector://{key}@127.0.0.1/{carrier}:2000?in=127.0.0.1:1080&morph={morph}&pin={}",
                    "0".repeat(64)
                ))
                .unwrap();
                let (probe, _) = PortalClientConfig::from_probe_url(&url).unwrap();
                let share = Url::parse(&format!(
                    "nowhere://{key}@127.0.0.1:2000?net={carrier}&morph={morph}"
                ))
                .unwrap();
                let fingerprint = PortalClientConfig::from_fingerprint_url(&share).unwrap();
                assert_eq!(probe.handshake_timeout, expected);
                assert_eq!(fingerprint.handshake_timeout, expected);
                let vector = crate::Vector::new(url, crate::Logger).unwrap();
                instances.push((vector, expected));
            }
        }
    }
    for (vector, expected) in instances {
        assert_eq!(vector.runtime.inner.config.handshake_timeout, expected);
        assert_eq!(
            vector.runtime.inner.client.config.handshake_timeout,
            expected
        );
    }
}

#[test]
fn probe_and_fingerprint_reject_invalid_shared_keys_without_leaking_them() {
    for key in [
        "a".repeat(31),
        "A".repeat(32),
        "%2561".repeat(32),
        "0123456789abcdef0123456789abcdef:do-not-print-password".to_owned(),
    ] {
        for morph in [0, 1] {
            for scheme in ["vector", "nowhere"] {
                let url =
                    Url::parse(&format!("{scheme}://{key}@localhost:2000?morph={morph}")).unwrap();
                let error = if scheme == "vector" {
                    PortalClientConfig::from_probe_url(&url).map(|(config, _)| config)
                } else {
                    PortalClientConfig::from_fingerprint_url(&url)
                }
                .unwrap_err();
                let message = format!("{error:#}");
                assert!(message.contains("use nowhere generate-key"), "{message}");
                assert!(!message.contains(&key), "{message}");
                assert!(!message.contains("do-not-print-password"), "{message}");
                assert!(!message.contains("localhost"), "{message}");
            }
        }
    }
}

#[test]
fn probe_and_fingerprint_use_decoded_key_bytes() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    let encoded: String = KEY.bytes().map(|byte| format!("%{byte:02X}")).collect();
    let probe = Url::parse(&format!("vector://{encoded}@localhost:2000?morph=1")).unwrap();
    let share = Url::parse(&format!(
        "nowhere://{encoded}@localhost:2000?morph=1#Display%20Name"
    ))
    .unwrap();
    let (probe, credentials) = PortalClientConfig::from_probe_url(&probe).unwrap();
    let fingerprint = PortalClientConfig::from_fingerprint_url(&share).unwrap();
    assert_eq!(
        credentials,
        crate::protocol::Credentials::from_shared_key(KEY.as_bytes()).unwrap()
    );
    for config in [probe, fingerprint] {
        assert_eq!(config.handshake_timeout, Duration::from_millis(9100));
        assert_eq!(
            config.morph_keys.unwrap().udp_keys(),
            MorphKeys::derive(KEY.as_bytes()).udp_keys()
        );
    }
}
