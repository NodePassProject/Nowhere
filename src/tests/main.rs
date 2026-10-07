// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! CLI help and version behavior tests.

use super::*;

#[test]
fn probe_results_use_the_panel_as_the_only_error_output() {
    let error = anyhow::Error::new(ProbeFailed);
    assert!(!should_print_start_error(&error));
    assert!(should_print_start_error(&anyhow::anyhow!("invalid URL")));
}

#[tokio::test]
async fn commands_reject_extra_arguments() {
    for command in [
        "help",
        "--help",
        "version",
        "--version",
        "tui",
        "status",
        "generate-key",
    ] {
        let error = start(vec![
            "nowhere".to_owned(),
            command.to_owned(),
            "extra".to_owned(),
        ])
        .await
        .unwrap_err();
        assert!(error.to_string().starts_with("usage:"));
    }
}

#[tokio::test]
async fn fingerprint_requires_exactly_one_share_link() {
    for arguments in [
        vec!["nowhere", "fingerprint"],
        vec![
            "nowhere",
            "fingerprint",
            "nowhere://secret@localhost:2000#My%20Portal",
            "extra",
        ],
    ] {
        let error = start(arguments.into_iter().map(str::to_owned).collect())
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "usage: nowhere fingerprint <nowhere-url>"
        );
    }
}

#[tokio::test]
async fn fingerprint_rejects_invalid_raw_share_links_before_network_access() {
    for raw in [
        "nowhere://secret@localhost/tcp:2006/../udp:2017",
        "nowhere://secret@localhost/tcp:2006/%2e%2e/udp:2017#Name",
        "nowhere://secret@localhost/tcp:secret",
        "portal://secret@localhost:2000",
        "vector://secret@localhost:2000",
    ] {
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            start(vec![
                "nowhere".to_owned(),
                "fingerprint".to_owned(),
                raw.to_owned(),
            ]),
        )
        .await
        .expect("invalid share link attempted network access")
        .unwrap_err();
        let message = format_start_error(&error);
        assert!(message.contains("invalid Nowhere share link"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[tokio::test]
async fn probe_requires_exactly_a_url_and_target() {
    for arguments in [
        vec!["nowhere", "probe"],
        vec!["nowhere", "probe", "vector://secret@localhost:2000"],
        vec![
            "nowhere",
            "probe",
            "vector://secret@localhost:2000",
            "example.com:443",
            "extra",
        ],
    ] {
        let error = start(arguments.into_iter().map(str::to_owned).collect())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "usage: nowhere probe <URL> <TARGET>");
    }
}

#[tokio::test]
async fn toolbox_errors_do_not_expose_configuration_values() {
    for (url, expected) in [
        (
            "vector://secret@localhost:2000?up=secret",
            "up must be tcp, udp, or mix",
        ),
        (
            "vector://secret@localhost/tcp:secret",
            "carrier port must contain decimal digits only",
        ),
    ] {
        let error = start(vec![
            "nowhere".to_owned(),
            "probe".to_owned(),
            url.to_owned(),
            "example.com:443".to_owned(),
        ])
        .await
        .unwrap_err();
        let message = format_start_error(&error);
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

#[test]
fn help_text_documents_usage_and_configuration_surface() {
    assert!(!HELP_TEXT.contains('\''));
    for expected in [
        "Usage:",
        "nowhere tui",
        "nowhere probe <vector-url> <target>",
        "nowhere status",
        "nowhere generate-key",
        "nowhere fingerprint <nowhere-url>",
        "nowhere <portal-url>",
        "nowhere <vector-url>",
        "-h | --help",
        "-v | --version",
        "portal://<key>@<listen-host>:<port>",
        "<carrier>:<port>",
        "vector://<key>@<portal-host>:<port>",
        "nowhere://<key>@<portal-host>:<port>",
        "tls=1|2",
        "tcp4, udp4",
        "tcp6, udp6",
        "socks=<listener>",
        "next=<portal>",
        "sni=<name|none>",
        "pin=<sha256|none>",
        "mux=0|1",
        "morph=0|1",
        "up=tcp|udp|mix",
        "down=tcp|udp|mix",
        "Both peers on each hop",
        "rate=<mbps>",
        "etar=<mbps>",
        "NOW_MORPH_TCP_PRELUDE",
        "NOW_TRANSPORT_MEMORY_PROFILE",
        "low7 (default) or full8",
        "https://github.com/NodePassProject/Nowhere/tree/main/docs",
    ] {
        assert!(
            HELP_TEXT.contains(expected),
            "missing help text: {expected}"
        );
    }
    for removed in [
        "nowhere check",
        "nowhere dial",
        "NOW_MAX_TCP_FLOWS",
        "NOW_MAX_UDP_FLOWS",
        "NOW_MAX_PENDING_PAIRS",
        "alpn=<value>",
        "pool=<number>",
        "NOW_QUIC_MAX_UDP_FLOWS",
    ] {
        assert!(
            !HELP_TEXT.contains(removed),
            "removed help option: {removed}"
        );
    }
}

#[test]
fn parse_command_url_keeps_vector_remote_host() {
    let parsed = parse_command_url(
        "vector://secret@relay.example:2000?up=udp&down=tcp&socks=127.0.0.1:1080",
    )
    .unwrap();
    assert_eq!(parsed.scheme(), "vector");
    assert_eq!(parsed.host_str(), Some("relay.example"));
    assert_eq!(parsed.port(), Some(2000));
}

#[test]
fn logger_rejects_unknown_or_empty_levels() {
    assert!(init_logger(Some("verbose")).is_err());
    assert!(init_logger(Some("")).is_err());
    assert!(init_logger(None).is_ok());
    assert!(init_logger(Some("event")).is_err());
}

#[test]
fn parse_command_url_normalizes_legacy_empty_listen_host() {
    let parsed = parse_command_url("portal://secret@:2000?log=none&dial=::1").unwrap();

    assert_eq!(parsed.scheme(), "portal");
    assert_eq!(parsed.username(), "secret");
    assert_eq!(parsed.host_str(), Some("*"));
    assert_eq!(parsed.port(), Some(2000));
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "dial")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some("::1")
    );
}

#[test]
fn parse_command_url_normalizes_legacy_empty_host_without_userinfo() {
    let parsed = parse_command_url("portal://:2000").unwrap();

    assert_eq!(parsed.scheme(), "portal");
    assert_eq!(parsed.username(), "");
    assert_eq!(parsed.host_str(), Some("*"));
    assert_eq!(parsed.port(), Some(2000));
}

#[test]
fn parse_command_url_rejects_empty_host_for_explicit_carriers() {
    assert!(parse_command_url("portal://secret@/tcp:2006").is_err());
}

#[test]
fn parse_command_url_keeps_normal_hosts() {
    let parsed = parse_command_url("portal://secret@[::]:2000?dial=auto").unwrap();

    assert_eq!(parsed.host_str(), Some("[::]"));
    assert_eq!(parsed.port(), Some(2000));
}

#[tokio::test]
async fn invalid_configuration_urls_fail_before_service_startup_with_safe_errors() {
    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    for (raw, expected) in [
        ("not-a-url".to_owned(), "invalid configuration URL"),
        (
            format!("ftp://{SECRET}@example.com:2000"),
            "scheme must be portal or vector",
        ),
        ("portal://@*:2000?log=none".to_owned(), "missing shared key"),
        (
            format!("portal://{SECRET}@*:abc?log=none"),
            "invalid port number",
        ),
        (
            format!("portal://{SECRET}@*:0?log=none"),
            "compact endpoint requires a port in 1..=65535",
        ),
        (
            format!("portal://{SECRET}@/tcp:2006?log=none"),
            "empty host",
        ),
        (
            format!("portal://{SECRET}@*/tcp?log=none"),
            "must use CARRIER:PORT",
        ),
        (
            format!("portal://{SECRET}@*/tcp:2006/../udp:2017?log=none"),
            "must not contain '.' or '..' segments",
        ),
        (
            format!("portal://{SECRET}@*:2000/tcp:2006?log=none"),
            "choose either HOST:PORT",
        ),
        (
            format!("portal://{SECRET}@*/udp:2017/udp6:2017?log=none"),
            "UDP carrier is declared more than once",
        ),
        (
            format!("portal://{SECRET}@*/tcp:65536?log=none"),
            "carrier port must be in 1..=65535",
        ),
        (
            format!("portal://{SECRET}@192.0.2.1/tcp6:2006?log=none"),
            "address family does not match",
        ),
        (
            format!("portal://{SECRET}@*:2000?log=verbose"),
            "log must be none, debug, info, warn, or error",
        ),
        (
            format!("portal://{SECRET}@*:2000?rate=-1&log=none"),
            "rate must be a non-negative integer",
        ),
        (
            format!("portal://{SECRET}@*:2000?socks=bad&log=none"),
            "invalid socks endpoint: expected HOST:PORT",
        ),
        (
            format!("portal://{SECRET}@unresolvable.invalid:2000?rate=-1&log=none"),
            "rate must be a non-negative integer",
        ),
        (
            format!("vector://{SECRET}@*/tcp:2006?socks=:1080&log=none"),
            "wildcard host is only valid for Portal listeners",
        ),
        (
            "vector://@example.com:2000?socks=:1080&log=none".to_owned(),
            "missing shared key",
        ),
        (
            format!("vector://{SECRET}@example.com?socks=:1080&log=none"),
            "compact endpoint requires a port in 1..=65535",
        ),
        (
            format!("vector://{SECRET}@example.com:2000?log=none"),
            "socks parameter is required",
        ),
        (
            format!("vector://{SECRET}@example.com/udp:2017?up=tcp&socks=:1080&log=none"),
            "up selects a carrier not declared by the endpoint",
        ),
        (
            format!(
                "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@*:2000?next={SECRET}@origin.example/tcp:2006/../udp:2017&log=none"
            ),
            "must not contain '.' or '..' segments",
        ),
        (
            format!(
                "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@*:2000?next={SECRET}@*/tcp:2006&log=none"
            ),
            "wildcard host is only valid for Portal listeners",
        ),
        (
            format!(
                "portal://123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0@*:2000?next={SECRET}@origin.example/tcp:2006?inner=1&log=none"
            ),
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

#[tokio::test]
async fn portal_key_rejections_identify_the_endpoint_without_starting_a_service() {
    const VALID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const INVALID: &str = "do-not-print-this-secret";
    for morph in [0, 1] {
        for (raw, context) in [
            (
                format!("portal://{INVALID}@unresolvable.invalid:2000?log=none&morph={morph}"),
                "Portal listener",
            ),
            (
                format!(
                    "portal://{VALID}@unresolvable.invalid:2000?next={INVALID}@origin.invalid:2080&log=none&morph={morph}"
                ),
                "Portal next endpoint",
            ),
        ] {
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                start(vec!["nowhere".to_owned(), raw.clone()]),
            )
            .await
            .expect("invalid key attempted service startup")
            .unwrap_err();
            let message = format_start_error(&error);
            assert!(message.contains(context), "{message}");
            assert!(message.contains("nowhere generate-key"), "{message}");
            assert!(!message.contains(INVALID));
            assert!(!message.contains(VALID));
            assert!(!message.contains(&raw));
        }
    }
}
