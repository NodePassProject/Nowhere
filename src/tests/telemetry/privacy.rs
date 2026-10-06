// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry pseudonyms, redaction, and schema privacy tests.

use super::*;
#[test]
fn aliases_are_short_and_category_separated() {
    let p = Privacy::new().unwrap();
    assert_eq!(p.alias("client", "10.0.0.1:1234"), "C001");
    assert_eq!(p.alias("client", "10.0.0.1:5678"), "C001");
    assert_eq!(p.alias("client", "10.0.0.2:5678"), "C002");
    assert_eq!(p.alias("peer", "10.0.0.1:1234"), "P001");
    assert_eq!(p.alias("peer", "10.0.0.1:5678"), "P002");
    assert_eq!(
        Privacy::new().unwrap().alias("client", "10.0.0.2:5678"),
        "C001"
    );
}

#[test]
fn alias_memory_is_bounded_and_evicted_numbers_are_not_reused() {
    let p = Privacy::new().unwrap();
    for n in 0..=ALIAS_CAPACITY {
        p.alias("client", &format!("client{n}"));
    }
    assert_eq!(p.clients.lock().unwrap().values.len(), ALIAS_CAPACITY);
    assert_eq!(
        p.alias("client", "client0"),
        format!("C{}", ALIAS_CAPACITY + 2)
    );
}

#[test]
fn targets_keep_endpoints_but_reject_credentials_and_control_characters() {
    for value in ["example.com:443", "203.0.113.8:8443", "[2001:db8::1]:443"] {
        assert_eq!(target(value), value);
    }
    for value in [
        "https://key@example.com:443/path?token=secret",
        "key@example.com:443",
        "example.com:443\x1b[31m",
        "example.com/path:443",
    ] {
        assert_eq!(target(value), "<redacted>");
    }
}

#[test]
fn diagnostic_templates_never_publish_arbitrary_error_text() {
    let raw = "TLS carrier connection failed: secret-key at /private/key.pem: Connection refused (os error 111)\x1b[31m";
    let message = runtime_message(RuntimeKind::Carrier, RuntimeLevel::Warn, raw);
    assert_eq!(message, "TLS carrier connection failed: connection refused");
    assert_eq!(
        runtime_message(RuntimeKind::Carrier, RuntimeLevel::Warn, &message),
        message
    );
    assert_eq!(
        runtime_message(
            RuntimeKind::Carrier,
            RuntimeLevel::Warn,
            "QUIC carrier connected secret-key"
        ),
        "Carrier warning"
    );
    assert_eq!(
        error_reason("InvalidCertificate(Expired) secret-key"),
        "certificate expired"
    );
    assert_eq!(
        error_reason("certificate expired secret-key"),
        "certificate expired"
    );
    assert_eq!(
        error_reason("DNS lookup failed for secret.example"),
        "DNS lookup failed"
    );
    assert_eq!(error_reason("secret-key"), "operation failed");
    assert_eq!(error_reason("application closed"), "application closed");
    assert_eq!(error_reason("idle timeout"), "idle timeout");
    assert_eq!(error_reason("mux reader failure"), "mux reader failure");
    assert_eq!(error_reason("mux writer failure"), "mux writer failure");
    assert_eq!(
        error_reason("flow setup rejected: dial failed"),
        "target connection failed"
    );
    assert_eq!(
        error_reason("flow setup rejected: flow limit"),
        "resource limit reached"
    );
}

#[test]
fn mux_close_reasons_survive_runtime_sanitization() {
    for reason in [
        "application closed",
        "idle timeout",
        "unexpected EOF",
        "mux reader failure",
        "mux writer failure",
        "protocol error",
    ] {
        let message = format!("TLS mux carrier disconnected: {reason}");
        assert_eq!(
            runtime_message(RuntimeKind::Mux, RuntimeLevel::Info, &message),
            message
        );
    }
}

#[test]
fn contract_reasons_survive_constructor_and_publisher_sanitization() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/telemetry/schema.json")).unwrap();
    for value in schema["$defs"]["access_finish"]["properties"]["error"]["anyOf"][0]["enum"]
        .as_array()
        .unwrap()
    {
        let reason = value.as_str().unwrap();
        assert_eq!(error_reason(reason), reason);
        let message = format!("TLS carrier connection failed: {reason}");
        assert_eq!(
            runtime_message(RuntimeKind::Carrier, RuntimeLevel::Warn, &message),
            message
        );
    }
}

#[test]
fn nested_transport_causes_are_classified_without_exposing_context() {
    let error = anyhow::anyhow!("Connection refused (os error 111)")
        .context("vector::tls::connect_tcp: failed to dial private.example:443");
    let raw = format!("TLS carrier connection failed: {error:#}");
    assert_eq!(
        runtime_message(RuntimeKind::Carrier, RuntimeLevel::Warn, &raw),
        "TLS carrier connection failed: connection refused"
    );
    assert_eq!(
        error_reason("vector::tls::connect_tcp: failed to dial private.example:443"),
        "operation failed"
    );
    let error = anyhow::anyhow!("invalid peer certificate: certificate has expired")
        .context("vector::tls::connect_tcp: TLS handshake failed");
    assert_eq!(error_reason(&format!("{error:#}")), "certificate expired");
}

#[test]
fn lifecycle_reasons_remain_useful_and_safe_across_publication() {
    for reason in ["START_FAILED", "CLEANUP_COMPLETE", "STATE_CHANGED"] {
        let message = format!("STOPPED: {reason}");
        assert_eq!(
            runtime_message(RuntimeKind::Lifecycle, RuntimeLevel::Info, &message),
            message
        );
    }
    assert_eq!(
        runtime_message(
            RuntimeKind::Lifecycle,
            RuntimeLevel::Info,
            "STOPPED: secret-key"
        ),
        "STOPPED: STATE_CHANGED"
    );
}

#[test]
fn operator_metadata_preserves_ports_and_effective_options_without_secrets() {
    for address in [
        ":2077",
        "0.0.0.0:2077",
        "[::1]:2077",
        "relay.example/tcp4:2077/udp6:3077",
        "*/tcp:2077",
    ] {
        assert_eq!(endpoint(address), address);
    }
    for address in [
        "key@relay.example:2077",
        "relay.example:2077?key=secret",
        "relay.example:2077/private",
        "relay.example/tcp:2077/../tcp:3000",
        "relay.example:2077\x1b[31m",
        "relay.example:2077#secret",
    ] {
        assert_eq!(endpoint(address), "<redacted>", "{address}");
    }
    assert_eq!(
        config_summary(
            "listen=0.0.0.0:2077 tls=1 rate=100 etar=-1 dial=0.0.0.0 morph=1 socks=127.0.0.1:1080 next=relay.example:3077 next.up=udp next.down=mix next.mux=1 next.sni=relay.example next.pin=012345secret key=secret crt=/private/cert socks_password=secret secret"
        ),
        "listen=0.0.0.0:2077 tls=1 rate=100 etar=-1 dial=0.0.0.0 morph=1 socks=127.0.0.1:1080 next=relay.example:3077 next.up=udp next.down=mix next.mux=1 next.sni=relay.example next.pin=present"
    );
    assert_eq!(
        config_summary("socks=user:password@127.0.0.1:1080 sni=bad\x1b[31m mux=secret"),
        "socks=<redacted>"
    );
}

#[test]
fn dual_stack_source_summary_retains_only_valid_family_values() {
    assert_eq!(
        config_summary("dial4=127.0.0.1 dial6=::1 key=secret"),
        "dial4=127.0.0.1 dial6=::1"
    );
    assert_eq!(
        config_summary("dial4=auto dial6=auto"),
        "dial4=auto dial6=auto"
    );
    assert_eq!(
        config_summary("dial4=0.0.0.0 dial6=::"),
        "dial4=0.0.0.0 dial6=::"
    );
    assert_eq!(
        config_summary("dial4=::1 dial6=127.0.0.1 dial6=::ffff:192.0.2.1 dial4=secret dial6=bad"),
        ""
    );
}
