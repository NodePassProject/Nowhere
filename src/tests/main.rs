// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! CLI help and version behavior tests.

use super::*;

#[test]
fn help_text_documents_usage_and_configuration_surface() {
    for expected in [
        "Usage:",
        "nowhere <portal-url>",
        "-h, --help",
        "-v, --version",
        "portal://<shared-key>@<listen-host>:<listen-port>",
        "tls=1|2",
        "net=mix|tcp|udp",
        "socks=<proxy>",
        "UDP ASSOCIATE",
        "rate=<mbps>",
        "etar=<mbps>",
        "UDP-over-TCP (UoT)",
        "NOW_QUIC_MAX_STREAMS",
        "NOW_QUIC_MAX_UDP_FLOWS",
        "NOW_QUIC_UDP_QUEUE_BYTES",
        "NOW_TCP_IDLE_POOL_CONNS",
        "NOW_MAX_PENDING_PAIRS",
        "NOW_HANDSHAKE_TIMEOUT",
        "Password credentials are not supported.",
        "tls=0 is not supported.",
    ] {
        assert!(
            HELP_TEXT.contains(expected),
            "missing help text: {expected}"
        );
    }
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
