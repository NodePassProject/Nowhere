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
        "<carrier>:<port>",
        "vector://<shared-key>@<portal-host>:<portal-port>",
        "tls=1|2",
        "tcp4, udp4",
        "tcp6, udp6",
        "socks=<listener>",
        "next=<portal>",
        "sni=<name|none>",
        "pin=<sha256|none>",
        "mux=0|1",
        "up=tcp|udp|mix",
        "down=tcp|udp|mix",
        "Use TLS Mux when the native route can select TCP.",
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
        "NOW_MIX_FALLBACK_TIMEOUT",
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
fn parse_command_url_rejects_empty_host_for_explicit_carriers() {
    assert!(parse_command_url("portal://secret@/tcp:2077").is_err());
}

#[test]
fn parse_command_url_keeps_normal_hosts() {
    let parsed = parse_command_url("portal://secret@[::]:2077?dial=auto").unwrap();

    assert_eq!(parsed.url.host_str(), Some("[::]"));
    assert_eq!(parsed.url.port(), Some(2077));
    assert_eq!(parsed.listen_host, None);
}

#[tokio::test]
async fn invalid_configuration_urls_fail_before_service_startup_with_safe_errors() {
    const SECRET: &str = "do-not-print-this-secret";
    for (raw, expected) in [
        ("not-a-url".to_owned(), "invalid configuration URL"),
        (
            format!("ftp://{SECRET}@example.com:2077"),
            "scheme must be portal or vector",
        ),
        ("portal://@*:2077?log=none".to_owned(), "missing shared key"),
        (
            format!("portal://{SECRET}@*:abc?log=none"),
            "invalid port number",
        ),
        (
            format!("portal://{SECRET}@*:0?log=none"),
            "compact endpoint requires a port in 1..=65535",
        ),
        (
            format!("portal://{SECRET}@/tcp:2077?log=none"),
            "empty host",
        ),
        (
            format!("portal://{SECRET}@*/tcp?log=none"),
            "must use CARRIER:PORT",
        ),
        (
            format!("portal://{SECRET}@*/tcp:2077/../udp:3088?log=none"),
            "must not contain '.' or '..' segments",
        ),
        (
            format!("portal://{SECRET}@*:2077/tcp:3088?log=none"),
            "choose either HOST:PORT",
        ),
        (
            format!("portal://{SECRET}@*/udp:2077/udp6:3088?log=none"),
            "UDP carrier is declared more than once",
        ),
        (
            format!("portal://{SECRET}@*/tcp:65536?log=none"),
            "carrier port must be in 1..=65535",
        ),
        (
            format!("portal://{SECRET}@192.0.2.1/tcp6:2077?log=none"),
            "address family does not match",
        ),
        (
            format!("portal://{SECRET}@*:2077?log=verbose"),
            "log must be none, debug, info, warn, error, or event",
        ),
        (
            format!("portal://{SECRET}@*:2077?rate=-1&log=none"),
            "rate must be a non-negative integer",
        ),
        (
            format!("portal://{SECRET}@*:2077?socks=bad&log=none"),
            "invalid socks endpoint: expected HOST:PORT",
        ),
        (
            format!("portal://{SECRET}@unresolvable.invalid:2077?rate=-1&log=none"),
            "rate must be a non-negative integer",
        ),
        (
            format!("vector://{SECRET}@*/tcp:2077?socks=:1080&log=none"),
            "wildcard host is only valid for Portal listeners",
        ),
        (
            "vector://@example.com:2077?socks=:1080&log=none".to_owned(),
            "missing shared key",
        ),
        (
            format!("vector://{SECRET}@example.com?socks=:1080&log=none"),
            "compact endpoint requires a port in 1..=65535",
        ),
        (
            format!("vector://{SECRET}@example.com:2077?log=none"),
            "socks parameter is required",
        ),
        (
            format!("vector://{SECRET}@example.com/udp:2077?up=tcp&socks=:1080&log=none"),
            "up selects a carrier not declared by the endpoint",
        ),
        (
            format!(
                "portal://outer@*:2077?next={SECRET}@origin.example/tcp:2077/../udp:3088&log=none"
            ),
            "must not contain '.' or '..' segments",
        ),
        (
            format!("portal://outer@*:2077?next={SECRET}@*/tcp:2077&log=none"),
            "wildcard host is only valid for Portal listeners",
        ),
        (
            format!("portal://outer@*:2077?next={SECRET}@origin.example/tcp:2077?inner=1&log=none"),
            "expected shared-key and one endpoint",
        ),
    ] {
        let args = vec!["nowhere".to_owned(), raw];
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), start(args))
            .await
            .expect("invalid configuration attempted to run a service")
            .unwrap_err();
        let message = format_start_error(&error);
        assert!(message.starts_with("error: "));
        assert!(message.contains(expected), "response was {message:?}");
        assert!(
            !message.contains("::"),
            "response exposed internal names: {message:?}"
        );
        assert!(!message.contains(SECRET), "response leaked the shared key");
    }
}
