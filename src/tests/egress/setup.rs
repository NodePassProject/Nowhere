// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress configuration defaults, target dial policy, and credential redaction tests.

use std::collections::HashMap;

use crate::common::DialPolicy;

use super::*;

#[test]
fn endpoint_accepts_one_carrier_or_a_compact_quic_port() {
    const KEY: &str = "0123456789abcdef0123456789abcdef";
    for endpoint in ["localhost:2000", "localhost/udp6:2000"] {
        let egress = Egress::new(
            Url::parse(&format!("egress://{KEY}@{endpoint}")).unwrap(),
            Logger,
        )
        .unwrap();
        assert_eq!(egress.config.net, crate::vector::config::CarrierMode::Udp);
        assert_eq!(egress.config.endpoint(), endpoint);
    }
    let tls = Egress::new(
        Url::parse(&format!("egress://{KEY}@localhost/tcp:2000")).unwrap(),
        Logger,
    )
    .unwrap();
    assert_eq!(tls.config.net, crate::vector::config::CarrierMode::Tcp);
    {
        let endpoint = "localhost/tcp:2000/udp:2001";
        let error = Egress::new(
            Url::parse(&format!("egress://{KEY}@{endpoint}")).unwrap(),
            Logger,
        )
        .err()
        .unwrap();
        assert!(
            error.to_string().contains("exactly one carrier"),
            "{endpoint}: {error}"
        );
    }
}

#[test]
fn fixed_quic_and_effective_defaults_ignore_unknown_options_and_hide_credentials() {
    let egress = Egress::new(
        Url::parse(
            "egress://0123456789abcdef0123456789abcdef@localhost:2000?net=tcp&unknown=bad&unused=secret&dial4=192.0.2.254",
        )
        .unwrap(),
        Logger,
    )
    .unwrap();
    assert_eq!(egress.config.net, crate::vector::config::CarrierMode::Udp);
    assert_eq!(egress.config.dial_policy, DialPolicy::default());
    let effective = Url::parse(&egress.effective).unwrap();
    assert_eq!(effective.scheme(), "egress");
    assert!(effective.username().is_empty());
    assert!(effective.password().is_none());
    assert_eq!(effective.host_str(), Some("localhost"));
    assert_eq!(effective.port(), Some(2000));
    let values = effective.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(effective.query_pairs().count(), values.len());
    assert_eq!(
        values,
        HashMap::from([
            ("sni".into(), "localhost".into()),
            ("pin".into(), "none".into()),
            ("dial4".into(), "192.0.2.254".into()),
            ("dial6".into(), "auto".into()),
            ("morph".into(), "1".into()),
            ("rate".into(), "0".into()),
            ("etar".into(), "0".into()),
        ])
    );
}

#[test]
fn tls_pool_max_requires_a_positive_bounded_integer() {
    assert_eq!(parse_tls_pool_max("1").unwrap(), 1);
    assert_eq!(parse_tls_pool_max("128").unwrap(), 128);
    for value in ["0", "invalid", "999999999999999999999999999"] {
        assert!(parse_tls_pool_max(value).is_err());
    }
}

#[test]
fn handshake_timeout_is_shared_by_egress_connection_and_forwarding_per_instance() {
    let mut instances = Vec::new();
    for (key, milliseconds) in [
        ("0123456789abcdef0123456789abcdef", 9100),
        ("fedcba9876543210fedcba9876543210", 24700),
    ] {
        for carrier in ["tcp", "udp"] {
            for morph in [0, 1] {
                let egress = Egress::new(
                    Url::parse(&format!(
                        "egress://{key}@127.0.0.1/{carrier}:2000?morph={morph}&pin={}",
                        "0".repeat(64)
                    ))
                    .unwrap(),
                    Logger,
                )
                .unwrap();
                let expected = if std::env::var_os("NOW_TEST_HANDSHAKE_OVERRIDE").is_some() {
                    std::time::Duration::from_secs(45)
                } else {
                    std::time::Duration::from_millis(milliseconds)
                };
                instances.push((egress, expected));
            }
        }
    }
    for (egress, expected) in instances {
        assert_eq!(egress.config.handshake_timeout, expected);
        assert_eq!(egress.forward.runtime.handshake_timeout, expected);
    }
}
