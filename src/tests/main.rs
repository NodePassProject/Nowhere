// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! CLI help and version behavior tests.

use super::*;

#[test]
fn help_text_documents_usage_and_configuration_surface() {
    for expected in [
        "Usage:",
        "nowhere tui",
        "nowhere <portal-or-vector-url>",
        "-h, --help",
        "-v, --version",
        "portal://<shared-key>@<listen-host>:<listen-port>",
        "vector://<shared-key>@<portal-host>:<portal-port>",
        "tls=1|2",
        "net=mix|tcp|udp",
        "socks=<listener>",
        "next=<portal>",
        "sni=<name|none>",
        "pin=<sha256|none>",
        "mux=0|1",
        "Use TLS Mux for the native upstream.",
        "UDP ASSOCIATE",
        "rate=<mbps>",
        "etar=<mbps>",
        "UDP-over-TCP (UoT)",
        "NOW_MAX_TCP_FLOWS",
        "NOW_MAX_UDP_FLOWS",
        "NOW_QUIC_UDP_QUEUE_BYTES",
        "NOW_QUIC_MEMORY_PROFILE",
        "NOW_MAX_PENDING_PAIRS",
        "NOW_FLOW_PAIR_TIMEOUT",
        "NOW_FLOW_SETUP_TIMEOUT",
        "NOW_HANDSHAKE_TIMEOUT",
        "NOW_TELEMETRY_INTERVAL",
        "NOW_SERVICE_COOLDOWN",
        "Password credentials are not supported.",
        "tls=0 is not supported.",
        "BIND is not supported.",
    ] {
        assert!(
            HELP_TEXT.contains(expected),
            "missing help text: {expected}"
        );
    }
    for removed in ["alpn=<value>", "pool=<number>", "NOW_QUIC_MAX_UDP_FLOWS"] {
        assert!(
            !HELP_TEXT.contains(removed),
            "removed help option: {removed}"
        );
    }
}

#[test]
fn parse_command_url_keeps_vector_remote_host() {
    let parsed = parse_command_url(
        "vector://secret@relay.example:2077?up=udp&down=tcp&socks=127.0.0.1:1080",
    )
    .unwrap();
    assert_eq!(parsed.url.scheme(), "vector");
    assert_eq!(parsed.url.host_str(), Some("relay.example"));
    assert_eq!(parsed.url.port(), Some(2077));
    assert_eq!(parsed.listen_host, None);
}

#[test]
fn logger_rejects_unknown_or_empty_levels() {
    assert!(init_logger(Some("verbose")).is_err());
    assert!(init_logger(Some("")).is_err());
    assert!(init_logger(None).is_ok());
    assert!(init_logger(Some("event")).is_ok());
}

#[test]
fn parse_command_url_accepts_empty_listen_host() {
    let parsed = parse_command_url("portal://secret@:2077?log=none&dial=::1").unwrap();

    assert_eq!(parsed.url.scheme(), "portal");
    assert_eq!(parsed.url.username(), "secret");
    assert_eq!(parsed.url.port(), Some(2077));
    assert_eq!(parsed.listen_host.as_deref(), Some(""));
    assert_eq!(
        parsed
            .url
            .query_pairs()
            .find(|(key, _)| key == "dial")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some("::1")
    );
}

#[test]
fn parse_command_url_accepts_empty_listen_host_without_userinfo() {
    let parsed = parse_command_url("portal://:2077").unwrap();

    assert_eq!(parsed.url.scheme(), "portal");
    assert_eq!(parsed.url.username(), "");
    assert_eq!(parsed.url.port(), Some(2077));
    assert_eq!(parsed.listen_host.as_deref(), Some(""));
}

#[test]
fn parse_command_url_keeps_normal_hosts() {
    let parsed = parse_command_url("portal://secret@[::]:2077?dial=auto").unwrap();

    assert_eq!(parsed.url.host_str(), Some("[::]"));
    assert_eq!(parsed.url.port(), Some(2077));
    assert_eq!(parsed.listen_host, None);
}
