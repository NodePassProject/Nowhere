// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal effective configuration, outlet selection, defaults, and credential redaction tests.

use std::collections::HashMap;

use super::*;

#[test]
fn startup_url_preserves_effective_values_and_omits_credentials() {
    for (query, expected) in [
        (
            "",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=1&rate=0&etar=0",
        ),
        (
            "?net=%ZZ&socks=%FF&unknown=%ZZ",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=1&rate=0&etar=0",
        ),
        (
            "?etar=20&rate=10&dial4=127.0.0.1&morph=1&out=a%3Ab:p%40ss@localhost:1080",
            "portal://127.0.0.1:2000?out=localhost:1080&tls=1&dial4=127.0.0.1&dial6=auto&morph=1&rate=10&etar=20",
        ),
        (
            "?out=egress&unknown=secret",
            "portal://127.0.0.1:2000?out=egress&tls=1&morph=1&rate=0&etar=0",
        ),
        (
            "?morph=0",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=0&rate=0&etar=0",
        ),
    ] {
        let portal = Portal::new(
            Url::parse(&format!(
                "portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000{query}"
            ))
            .unwrap(),
            Logger,
        )
        .unwrap();
        let actual = Url::parse(&portal.inner.effective).unwrap();
        let expected = Url::parse(expected).unwrap();
        assert_eq!(actual.scheme(), expected.scheme());
        assert_eq!(actual.host_str(), expected.host_str());
        assert_eq!(actual.port(), expected.port());
        assert!(actual.username().is_empty());
        assert!(actual.password().is_none());
        assert_eq!(actual.query_pairs().count(), expected.query_pairs().count());
        assert_eq!(
            actual.query_pairs().collect::<HashMap<_, _>>(),
            expected.query_pairs().collect::<HashMap<_, _>>()
        );
        assert_eq!(
            portal.inner.morph_keys.is_some(),
            !query.contains("morph=0")
        );
    }
}

#[test]
fn egress_output_accepts_tcp_only_udp_only_and_dual_listeners() {
    for endpoint in [
        "127.0.0.1/tcp:2000",
        "127.0.0.1/udp:2000",
        "127.0.0.1/tcp:2000/udp:2001",
    ] {
        let url = Url::parse(&format!(
            "portal://0123456789abcdef0123456789abcdef@{endpoint}?out=egress"
        ))
        .unwrap();
        let portal = Portal::new(url, Logger).unwrap();
        assert!(portal.inner.egress_registry.is_some());
        assert_eq!(
            !portal.inner.tcp_bind_addrs.is_empty(),
            endpoint.contains("/tcp:")
        );
        assert_eq!(
            !portal.inner.udp_bind_addrs.is_empty(),
            endpoint.contains("/udp:")
        );
    }
}

#[test]
fn handshake_timeout_is_saved_per_portal_key_across_carriers_and_morph() {
    let mut instances = Vec::new();
    for (key, milliseconds) in [
        ("0123456789abcdef0123456789abcdef", 9100),
        ("fedcba9876543210fedcba9876543210", 24700),
    ] {
        for carrier in ["tcp", "udp"] {
            for morph in [0, 1] {
                let portal = Portal::new(
                    Url::parse(&format!(
                        "portal://{key}@127.0.0.1/{carrier}:2000?morph={morph}"
                    ))
                    .unwrap(),
                    Logger,
                )
                .unwrap();
                instances.push((portal, std::time::Duration::from_millis(milliseconds)));
            }
        }
    }
    for (portal, expected) in instances {
        assert_eq!(portal.inner.runtime.handshake_timeout, expected);
        assert_eq!(portal.inner.forward.runtime.handshake_timeout, expected);
    }
}
