// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal construction and formatting tests.

use super::*;
use crate::common::{LogLevel, Logger};
use tokio::net::TcpListener;
use url::Url;

fn test_logger() -> Logger {
    Logger::new(LogLevel::None, false)
}

#[test]
fn empty_host_listens_on_both_wildcard_families() {
    let portal = Portal::new_with_listen_host(
        Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@localhost:2000?dial=127.0.0.1").unwrap(),
        Some(""),
        test_logger(),
    )
    .unwrap();

    assert_eq!(portal.inner.endpoint_addr, "*:2000");
    assert_eq!(
        portal.inner.tcp_bind_addrs,
        vec![
            SocketAddr::from(([0, 0, 0, 0], 2000)),
            SocketAddr::from(([0u16; 8], 2000)),
        ]
    );
    assert_eq!(portal.inner.udp_bind_addrs, portal.inner.tcp_bind_addrs);
    assert_eq!(
        portal.inner.outbound.dial_policy().to_string(),
        "dial=127.0.0.1"
    );
    assert_eq!(portal.inner.network_mode, NetworkMode::Mix);
    assert_eq!(
        portal.effective_url(),
        "portal://*:2000?tls=1&rate=0&etar=0&dial=127.0.0.1&morph=0&socks=none&next=none"
    );
}

#[test]
fn explicit_wildcard_host_selects_one_address_family() {
    let ipv4 = Portal::new(
        Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@0.0.0.0:2000?dial=auto").unwrap(),
        test_logger(),
    )
    .unwrap();
    let ipv6 = Portal::new(
        Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@[::]:2000?dial=::1").unwrap(),
        test_logger(),
    )
    .unwrap();

    assert_eq!(ipv4.inner.endpoint_addr, "0.0.0.0:2000");
    assert_eq!(
        ipv4.inner.tcp_bind_addrs,
        vec![SocketAddr::from(([0, 0, 0, 0], 2000))]
    );
    assert_eq!(ipv4.inner.outbound.dial_policy().to_string(), "dial=auto");

    assert_eq!(ipv6.inner.endpoint_addr, "[::]:2000");
    assert_eq!(
        ipv6.inner.tcp_bind_addrs,
        vec![SocketAddr::from(([0u16; 8], 2000))]
    );
    assert_eq!(ipv6.inner.outbound.dial_policy().to_string(), "dial=::1");
}

#[test]
fn explicit_carriers_have_independent_ports_and_families() {
    let portal = Portal::new(
        Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@*/tcp4:2006/udp6:2017").unwrap(),
        test_logger(),
    )
    .unwrap();

    assert_eq!(portal.inner.endpoint_addr, "*/tcp4:2006/udp6:2017");
    assert_eq!(
        portal.inner.tcp_bind_addrs,
        vec![SocketAddr::from(([0, 0, 0, 0], 2006))]
    );
    assert_eq!(
        portal.inner.udp_bind_addrs,
        vec![SocketAddr::from(([0u16; 8], 2017))]
    );
    assert_eq!(portal.inner.network_mode, NetworkMode::Mix);
}

#[test]
fn carrier_paths_select_network_mode_and_net_is_ignored() {
    let cases = [
        (
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000",
            NetworkMode::Mix,
        ),
        (
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?net=tcp",
            NetworkMode::Mix,
        ),
        (
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1/tcp:2006",
            NetworkMode::Tcp,
        ),
        (
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1/udp:2017",
            NetworkMode::Udp,
        ),
    ];

    for (raw, expected) in cases {
        let portal = Portal::new(Url::parse(raw).unwrap(), test_logger()).unwrap();
        assert_eq!(portal.inner.network_mode, expected);
    }
}

#[test]
fn net_is_an_ignored_unknown_parameter() {
    let portal = Portal::new(
        Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?net=auto").unwrap(),
        test_logger(),
    )
    .unwrap();

    assert_eq!(portal.inner.network_mode, NetworkMode::Mix);
    assert!(!portal.effective_url().contains("net="));
}

#[test]
fn socks_configuration_is_validated_and_redacted_in_effective_url() {
    let portal = Portal::new(
        Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?log=none&socks=user:p%40ss@proxy.test:1080")
            .unwrap(),
        test_logger(),
    )
    .unwrap();
    let effective = portal.effective_url();
    assert!(effective.contains("socks=proxy.test:1080"));
    assert!(!effective.contains("user"));
    assert!(!effective.contains("p@ss"));

    let duplicate = Portal::new(
        Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?socks=proxy.test:1080&socks=other.test:1080")
            .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert!(duplicate.effective_url().contains("socks=proxy.test:1080"));
}

#[test]
fn native_next_defaults_to_tcp_without_mux_and_redacts_the_shared_key() {
    let portal = Portal::new(
        Url::parse("portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?next=%323456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@relay.example:2080")
            .unwrap(),
        test_logger(),
    )
    .unwrap();

    assert_eq!(portal.inner.outbound.next_endpoint(), "relay.example:2080");
    assert_eq!(
        portal.inner.outbound.next_transport().as_deref(),
        Some("up=tcp down=tcp mux=0 sni=none pin=none morph=0")
    );
    let effective = portal.effective_url();
    assert!(effective.contains("next=relay.example:2080"));
    assert!(
        !effective.contains("23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01")
    );
    assert_eq!(portal.inner.outbound.ping_ms(), 0);
}

#[test]
fn native_next_omitted_directions_keep_independent_tcp_defaults_and_explicit_mux() {
    for endpoint in ["origin.example:2000", "origin.example/udp6:2017/tcp4:2006"] {
        for (query, up, down) in [
            ("", "tcp", "tcp"),
            ("&up=udp", "udp", "tcp"),
            ("&down=udp", "tcp", "udp"),
            ("&up=mix", "mix", "tcp"),
            ("&down=mix", "tcp", "mix"),
        ] {
            for (mux_query, mux) in [("", 0), ("&mux=1", 1)] {
                let raw = format!(
                    "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@*/udp4:2017?next=23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@{endpoint}{query}{mux_query}"
                );
                let portal = Portal::new(Url::parse(&raw).unwrap(), test_logger()).unwrap();
                assert_eq!(portal.inner.network_mode, NetworkMode::Udp);
                assert_eq!(
                    portal.inner.outbound.next_transport().as_deref(),
                    Some(
                        format!("up={up} down={down} mux={mux} sni=none pin=none morph=0").as_str()
                    ),
                    "{raw}"
                );
                assert!(
                    portal
                        .effective_url()
                        .contains(&format!("&up={up}&down={down}&mux={mux}&")),
                    "{raw}"
                );
            }
        }
    }
}

#[test]
fn native_next_uses_shared_endpoint_grammar_and_single_carrier_defaults() {
    let portal = Portal::new(
        Url::parse("portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@*/tcp4:2006?next=23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@relay.example/udp6:2017")
            .unwrap(),
        test_logger(),
    )
    .unwrap();

    assert_eq!(portal.inner.network_mode, NetworkMode::Tcp);
    assert_eq!(
        portal.inner.outbound.next_endpoint(),
        "relay.example/udp6:2017"
    );
    assert_eq!(
        portal.inner.outbound.next_transport().as_deref(),
        Some("up=udp down=udp mux=0 sni=none pin=none morph=0")
    );
}

#[test]
fn native_next_reuses_transport_identity_and_source_binding() {
    let portal = Portal::new(
        Url::parse(
            "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?dial=127.0.0.2&alpn=private/2&next=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@[::1]:2080&up=tcp&down=tcp&mux=1&sni=origin.example&pin=abc",
        )
        .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert_eq!(
        portal.inner.outbound.dial_policy().to_string(),
        "dial=127.0.0.2"
    );
    assert_eq!(portal.inner.outbound.next_endpoint(), "[::1]:2080");
    assert_eq!(
        portal.inner.outbound.next_transport().as_deref(),
        Some("up=tcp down=tcp mux=1 sni=origin.example pin=abc morph=0")
    );
    assert!(
        portal
            .effective_url()
            .contains("&up=tcp&down=tcp&mux=1&sni=origin.example&pin=abc")
    );
}

#[test]
fn native_next_and_socks_are_mutually_exclusive() {
    let result = Portal::new(
        Url::parse(
            "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?next=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@origin.example:2080&socks=127.0.0.1:1080",
        )
        .unwrap(),
        test_logger(),
    );
    assert!(result.is_err());

    let disabled_socks = Portal::new(
        Url::parse("portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?next=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@origin.example:2080&socks=none")
            .unwrap(),
        test_logger(),
    );
    assert!(disabled_socks.is_ok());
}

#[test]
fn disabled_next_ignores_all_native_upstream_options() {
    for suffix in [
        "up=mix&down=invalid&mux=2&sni=127.0.0.1&pin=anything",
        "next=none&up=mix&down=invalid&mux=true&sni=127.0.0.1&pin=anything",
        "next=none&up=%GG&mux=%GG&pin=%FF",
    ] {
        let portal = Portal::new(
            Url::parse(&format!("portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?{suffix}")).unwrap(),
            test_logger(),
        )
        .unwrap();
        assert_eq!(portal.inner.outbound.next_endpoint(), "none");
        assert_eq!(portal.inner.outbound.next_transport(), None);
        assert!(!portal.effective_url().contains("mux="));
    }
}

#[test]
fn enabled_next_validates_only_effective_upstream_options() {
    for suffix in [
        "up=auto",
        "down=tls",
        "mux=",
        "mux=2",
        "mux=true",
        "sni=127.0.0.1",
    ] {
        let result = Portal::new(
            Url::parse(&format!(
                "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?next=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@origin.example:2080&{suffix}"
            ))
            .unwrap(),
            test_logger(),
        );
        assert!(result.is_err(), "upstream options accepted: {suffix}");
    }
}

#[test]
fn native_next_accepts_mix_and_normalizes_pure_udp_mux() {
    for (up, down, mux) in [
        ("mix", "tcp", 1),
        ("mix", "udp", 1),
        ("tcp", "mix", 1),
        ("udp", "mix", 1),
        ("mix", "mix", 1),
        ("udp", "udp", 0),
    ] {
        let portal = Portal::new(
            Url::parse(&format!(
                "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?next=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@origin.example:2080&up={up}&down={down}&mux=1"
            ))
            .unwrap(),
            test_logger(),
        )
        .unwrap();
        assert_eq!(
            portal.inner.outbound.next_transport().as_deref(),
            Some(format!("up={up} down={down} mux={mux} sni=none pin=none morph=0").as_str()),
        );
        assert!(
            portal
                .effective_url()
                .contains(&format!("&up={up}&down={down}&mux={mux}"))
        );
    }
}

#[test]
fn next_uses_first_duplicate_and_rejects_empty_value() {
    let portal = Portal::new(
        Url::parse(
            "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?next=456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123@one.example:2080&next=ignored-invalid-key@two.example:2081",
        )
        .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert_eq!(portal.inner.outbound.next_endpoint(), "one.example:2080");

    assert!(
        Portal::new(
            Url::parse("portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000?next=").unwrap(),
            test_logger(),
        )
        .is_err()
    );
}

#[test]
fn direct_portal_reports_exact_zero_ping() {
    let portal = Portal::new(
        Url::parse("portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@127.0.0.1:2000").unwrap(),
        test_logger(),
    )
    .unwrap();
    assert_eq!(portal.inner.outbound.ping_ms(), 0);
}

#[test]
fn all_network_modes_reject_tls_zero() {
    for mode in ["mix", "tcp", "udp"] {
        let portal = Portal::new(
            Url::parse(&format!("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?tls=0&net={mode}")).unwrap(),
            test_logger(),
        );
        assert!(portal.is_err());
    }
}

#[tokio::test]
async fn network_mode_binds_only_selected_transports() {
    for (path, expected_tcp, expected_udp) in [("", 1, 1), ("/tcp:PORT", 1, 0), ("/udp:PORT", 0, 1)]
    {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let portal = Portal::new(
            Url::parse(&if path.is_empty() {
                format!("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:{port}")
            } else {
                format!(
                    "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1{}",
                    path.replace("PORT", &port.to_string())
                )
            })
            .unwrap(),
            test_logger(),
        )
        .unwrap();

        let endpoints = portal.listen_endpoints().unwrap();
        let listeners = portal.listen_tcp_listeners().unwrap();
        assert_eq!(listeners.len(), expected_tcp);
        assert_eq!(endpoints.len(), expected_udp);
    }
}

#[test]
fn portal_url_contract_rejects_invalid_structure_and_selected_values() {
    for raw in [
        "vector://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000",
        "portal://secret:password@127.0.0.1:2000",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000/tcp:2006",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1/not-a-carrier:2000",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000#fragment",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?socks=",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?rate=-1",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?dial=not-an-ip",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?morph=",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?morph=2",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:0",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1",
    ] {
        assert!(
            Portal::new(Url::parse(raw).unwrap(), test_logger()).is_err(),
            "URL unexpectedly accepted: {raw}"
        );
    }
}

#[test]
fn outer_morph_controls_local_and_next_carriers() {
    let portal = Portal::new(
        Url::parse(
            "portal://3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012@127.0.0.1:2000?morph=1&next=23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@origin.example:2080",
        )
        .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert!(portal.inner.morph_keys.is_some());
    assert_eq!(
        portal.inner.outbound.next_transport().as_deref(),
        Some("up=tcp down=tcp mux=0 sni=none pin=none morph=1")
    );
    assert!(portal.effective_url().contains("&morph=1&"));
}

#[test]
fn portal_ignores_unknown_parameters_and_keeps_first_duplicate() {
    let portal = Portal::new(
        Url::parse(
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?unknown=value&spec=ignored&alpn=private/2&mux=2&pool=8&net=tcp&net=udp&rate=1&rate=2",
        )
        .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert_eq!(portal.inner.network_mode, NetworkMode::Mix);
    assert_eq!(portal.inner.rate_limit, 1);
    assert!(portal.effective_url().contains("?tls=1&"));
    assert!(!portal.effective_url().contains("net="));
    assert!(!portal.effective_url().contains("alpn="));
    assert!(!portal.effective_url().contains("mux="));
    assert!(!portal.effective_url().contains("pool="));
}

#[test]
fn portal_mux_is_ignored_without_next() {
    for value in ["", "0", "1", "2", "true"] {
        let portal = Portal::new(
            Url::parse(&format!(
                "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?alpn=private/2&mux={value}"
            ))
            .unwrap(),
            test_logger(),
        )
        .unwrap();
        assert!(!portal.effective_url().contains("alpn="));
        assert!(!portal.effective_url().contains("mux="));
    }
}

#[test]
fn certificate_parameters_are_tied_to_ca_trusted_mode() {
    for raw in [
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?crt=cert.pem",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?key=key.pem",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?crt=cert.pem&key=key.pem",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?tls=2&crt=cert.pem",
        "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?tls=2&key=key.pem",
    ] {
        assert!(Portal::new(Url::parse(raw).unwrap(), test_logger()).is_err());
    }
}

#[tokio::test]
async fn listener_bind_failure_moves_lifecycle_to_stopped() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let portal = Portal::new(
        Url::parse(&format!(
            "portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:{port}?net=tcp&log=none"
        ))
        .unwrap(),
        test_logger(),
    )
    .unwrap();
    let lifecycle = portal.inner.telemetry.lifecycle_receiver();

    assert!(portal.run().await.is_err());
    assert_eq!(lifecycle.borrow().state, "STOPPED");
}

#[test]
fn telemetry_metadata_retains_portal_and_upstream_configuration_without_credentials() {
    let portal = Portal::new(
        Url::parse("portal://3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012@0.0.0.0:2077?tls=1&rate=50&etar=80&morph=1&next=23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@relay.example:3077&up=udp&down=tcp&mux=1&sni=relay.example").unwrap(),
        test_logger(),
    ).unwrap();
    let descriptor = portal.inner.telemetry.descriptor();
    assert_eq!(descriptor.endpoint, "0.0.0.0:2077");
    for option in [
        "listen=0.0.0.0:2077",
        "tls=1",
        "rate=50",
        "etar=80",
        "morph=1",
        "socks=none",
        "next=relay.example:3077",
        "next.up=udp",
        "next.down=tcp",
        "next.mux=1",
        "next.sni=relay.example",
        "next.pin=none",
        "next.morph=1",
    ] {
        assert!(
            descriptor
                .config_summary
                .split_whitespace()
                .any(|value| value == option),
            "missing {option}: {}",
            descriptor.config_summary
        );
    }
    let encoded = serde_json::to_string(descriptor).unwrap();
    for secret in [
        "3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
        "23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
        "user",
        "password",
    ] {
        assert!(!encoded.contains(secret));
    }
}

#[test]
fn telemetry_metadata_retains_portal_socks_endpoint_without_credentials() {
    let portal = Portal::new(
        Url::parse("portal://3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012@0.0.0.0:2077?socks=user:password@127.0.0.1:1080")
            .unwrap(),
        test_logger(),
    )
    .unwrap();
    assert!(
        portal
            .inner
            .telemetry
            .descriptor()
            .config_summary
            .contains("socks=127.0.0.1:1080")
    );
    let encoded = serde_json::to_string(portal.inner.telemetry.descriptor()).unwrap();
    for secret in [
        "3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
        "user",
        "password",
    ] {
        assert!(!encoded.contains(secret));
    }
}

#[test]
fn dual_stack_sources_are_validated_and_rendered_for_every_outbound_path() {
    for (query, summary) in [
        ("dial4=127.0.0.1", "dial4=127.0.0.1 dial6=auto"),
        ("dial6=%3A%3A1", "dial4=auto dial6=::1"),
        ("dial4=auto&dial6=auto", "dial4=auto dial6=auto"),
        (
            "dial4=127.0.0.1&dial4=bad&dial6=::1",
            "dial4=127.0.0.1 dial6=::1",
        ),
    ] {
        for route in [
            "",
            "&socks=localhost:1080",
            "&next=23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@localhost/tcp4:2080",
            "&next=23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01@localhost/udp6:2080",
        ] {
            let portal = Portal::new(
                Url::parse(&format!("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?{query}{route}")).unwrap(),
                test_logger(),
            )
            .unwrap();
            assert_eq!(portal.inner.outbound.dial_policy().to_string(), summary);
            let output = portal.effective_url();
            assert!(output.contains(&summary.replace(' ', "&")), "{output}");
            assert!(!output.contains("&dial="), "{output}");
            assert!(
                portal
                    .inner
                    .telemetry
                    .descriptor()
                    .config_summary
                    .contains(summary)
            );
            assert!(
                !output
                    .contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            );
        }
    }
    for query in [
        "dial=auto&dial4=auto",
        "dial6=auto&dial=::1",
        "dial4=",
        "dial6=127.0.0.1",
        "dial6=::ffff:192.0.2.1",
    ] {
        assert!(
            Portal::new(
                Url::parse(&format!("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?{query}")).unwrap(),
                test_logger()
            )
            .is_err(),
            "{query}"
        );
    }
    assert!(
        Portal::new(
            Url::parse("portal://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:2000?dial4=192.0.2.254&dial6=2001:db8::1")
                .unwrap(),
            test_logger()
        )
        .is_ok()
    );
}

#[test]
fn generated_and_percent_encoded_portal_keys_preserve_text_derivation() {
    let mut keys = vec![crate::toolbox::generate_key().unwrap()];
    keys.extend(
        [32, 33, 35, 63, 64]
            .into_iter()
            .map(|length| "a".repeat(length)),
    );
    for key in keys {
        let encoded: String = key.bytes().map(|byte| format!("%{byte:02X}")).collect();
        for value in [&key, &encoded] {
            for morph in [0, 1] {
                let portal = Portal::new(
                    Url::parse(&format!("portal://{value}@127.0.0.1:2000?morph={morph}&next={value}@origin.example:2080&pin={}&log=none", "0".repeat(64))).unwrap(),
                    test_logger(),
                ).unwrap();
                assert_eq!(
                    portal.inner.credentials,
                    Credentials::from_shared_key(key.as_bytes()).unwrap()
                );
                if morph == 1 {
                    assert_eq!(
                        portal.inner.morph_keys.as_ref().unwrap().udp_keys(),
                        MorphKeys::derive(key.as_bytes()).udp_keys()
                    );
                } else {
                    assert!(portal.inner.morph_keys.is_none());
                }
            }
        }
    }
}

#[test]
fn invalid_listener_and_next_keys_fail_before_tls_dns_or_listening() {
    let valid = "0123456789abcdef".repeat(4);
    let invalid = [
        String::new(),
        "secret".to_owned(),
        "a".repeat(31),
        "a".repeat(65),
        "A".repeat(64),
        format!("A{}", "a".repeat(63)),
        "g".repeat(64),
        format!("%20{}", "a".repeat(63)),
        format!("{}%20", "a".repeat(63)),
        format!("%2530{}", "a".repeat(31)),
        "bad%GG".to_owned(),
        "bad%".to_owned(),
        "bad%1".to_owned(),
        "%FF".to_owned(),
    ];
    for key in invalid {
        for morph in [0, 1] {
            for next in [false, true] {
                let (listener_key, upstream) = if next {
                    (
                        valid.as_str(),
                        format!("&next={key}@unresolvable.invalid:2080"),
                    )
                } else {
                    (key.as_str(), String::new())
                };
                let raw = format!(
                    "portal://{listener_key}@unresolvable.invalid:2000?tls=2&crt=missing-certificate.pem&key=missing-private-key.pem&morph={morph}{upstream}"
                );
                let error = Portal::new(Url::parse(&raw).unwrap(), test_logger())
                    .err()
                    .unwrap();
                let message = format!("{error:#}");
                assert!(
                    message.contains(if next {
                        "Portal next endpoint"
                    } else {
                        "Portal listener"
                    }),
                    "{message}"
                );
                assert!(message.contains("nowhere generate-key"), "{message}");
                assert!(!message.contains(&raw));
                assert!(!message.contains("unresolvable.invalid"));
                assert!(!message.contains("missing-certificate.pem"));
                assert!(!message.contains("missing-private-key.pem"));
                if !key.is_empty() {
                    assert!(!message.contains(&key), "{message}");
                }
            }
        }
    }
}
