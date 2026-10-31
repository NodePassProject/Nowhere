// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Configuration parsing tests.

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use url::Url;

use super::*;

#[test]
fn query_first_ignores_unknown_parameters_and_keeps_first_duplicate() {
    let parsed = Url::parse("portal://key@localhost:2000?mode=first&label=now%2F1").unwrap();
    let values = query_first(&parsed, &["mode", "label"]).unwrap();
    assert_eq!(values["mode"], "first");
    assert_eq!(values["label"], "now/1");

    let duplicate = Url::parse("portal://key@localhost:2000?mode=first&mode=second").unwrap();
    assert_eq!(query_first(&duplicate, &["mode"]).unwrap()["mode"], "first");
    let unknown = Url::parse("portal://key@localhost:2000?typo=value&%FF=value").unwrap();
    assert!(query_first(&unknown, &["mode"]).unwrap().is_empty());
}

#[test]
fn query_first_preserves_literal_slash_and_plus_and_validates_the_selected_value() {
    let protocol = Url::parse("portal://key@localhost:2000?label=private/2").unwrap();
    assert_eq!(
        query_first(&protocol, &["label"]).unwrap()["label"],
        "private/2"
    );

    let parsed = Url::parse("portal://key@localhost:2000?label=now+private").unwrap();
    assert_eq!(
        query_first(&parsed, &["label"]).unwrap()["label"],
        "now+private"
    );

    let bad = Url::parse("portal://key@localhost:2000?label=%GG").unwrap();
    assert!(query_first(&bad, &["label"]).is_err());

    let ignored_bad_duplicate =
        Url::parse("portal://key@localhost:2000?label=now%2F1&label=%GG").unwrap();
    assert_eq!(
        query_first(&ignored_bad_duplicate, &["label"]).unwrap()["label"],
        "now/1"
    );
}

#[test]
fn rate_limit_converts_mbps_to_bytes_per_second() {
    assert_eq!(rate_limit_bytes_per_second(-1), 0);
    assert_eq!(rate_limit_bytes_per_second(0), 0);
    assert_eq!(rate_limit_bytes_per_second(1), 125_000);
    assert_eq!(rate_limit_bytes_per_second(8), 1_000_000);
}

#[test]
fn duration_defaults_overrides_and_invalid_values() {
    assert_eq!(
        read_duration(
            &mut |_| Ok(None),
            "NOW_FLOW_SETUP_TIMEOUT",
            Duration::from_secs(20)
        )
        .unwrap(),
        Duration::from_secs(20)
    );
    assert_eq!(
        read_duration(
            &mut |_| Ok(Some("750ms".into())),
            "NOW_FLOW_SETUP_TIMEOUT",
            Duration::from_secs(20)
        )
        .unwrap(),
        Duration::from_millis(750)
    );
    for raw in [
        "0s",
        "-1s",
        "invalid",
        "",
        "999999999999999999999999h",
        "18446744073709551615s",
    ] {
        let error = validate_timeouts(&mut |_| Ok(Some(raw.into()))).unwrap_err();
        assert!(format!("{error:#}").contains("NOW_TCP_DIAL_TIMEOUT"));
    }
    assert!(
        read_duration(
            &mut |_| Ok(Some("5000000000000000s".into())),
            "NOW_UDP_IDLE_TIMEOUT",
            Duration::from_secs(120)
        )
        .is_err()
    );
}

#[test]
fn quic_udp_queue_bytes_defaults_and_bounds_are_strict() {
    assert_eq!(
        read_quic_udp_queue_bytes(&mut |_| Ok(None)).unwrap(),
        4 * 1024 * 1024
    );
    let max = Semaphore::MAX_PERMITS.min(u32::MAX as usize);
    for bytes in [1, 8192, max] {
        assert_eq!(
            read_quic_udp_queue_bytes(&mut |name| {
                assert_eq!(name, "NOW_QUIC_UDP_QUEUE_BYTES");
                Ok(Some(bytes.to_string()))
            })
            .unwrap(),
            bytes
        );
    }
    for raw in [
        "0",
        "-1",
        "",
        "invalid",
        "1.5",
        " 8",
        "999999999999999999999999",
        &(max + 1).to_string(),
    ] {
        let error = read_quic_udp_queue_bytes(&mut |_| Ok(Some(raw.into()))).unwrap_err();
        assert!(format!("{error:#}").contains("NOW_QUIC_UDP_QUEUE_BYTES"));
    }
}

#[test]
fn invalid_quic_udp_queue_bytes_is_rejected_by_each_service_at_startup() {
    for role in ["portal", "vector", "egress"] {
        for raw in ["0", "-1", "invalid", "999999999999999999999999"] {
            assert_invalid_startup(role, "NOW_QUIC_UDP_QUEUE_BYTES", std::ffi::OsStr::new(raw));
        }
    }
}

#[test]
fn invalid_duration_is_rejected_by_each_service_at_startup() {
    for role in ["portal", "vector", "egress"] {
        for name in [
            "NOW_TCP_DIAL_TIMEOUT",
            "NOW_UDP_DIAL_TIMEOUT",
            "NOW_TCP_READ_TIMEOUT",
            "NOW_UDP_IDLE_TIMEOUT",
            "NOW_HANDSHAKE_TIMEOUT",
            "NOW_FLOW_SETUP_TIMEOUT",
            "NOW_SHUTDOWN_TIMEOUT",
            "NOW_RELOAD_INTERVAL",
            "NOW_SERVICE_COOLDOWN",
        ] {
            assert_invalid_startup(role, name, std::ffi::OsStr::new("invalid"));
        }
    }
    for role in ["probe", "fingerprint"] {
        assert_invalid_startup(
            role,
            "NOW_HANDSHAKE_TIMEOUT",
            std::ffi::OsStr::new("invalid"),
        );
    }
}

fn assert_invalid_startup(role: &str, name: &str, raw: &std::ffi::OsStr) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "common::config::tests::invalid_duration_startup_child",
            "--nocapture",
        ])
        .env("NOW_TEST_TIMEOUT_ROLE", role)
        .env("NOW_TEST_TIMEOUT_NAME", name)
        .env(name, raw)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{role} {name}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn non_unicode_duration_is_a_startup_error() {
    let raw = std::ffi::OsString::from_vec(vec![0xff]);
    for role in ["probe", "fingerprint"] {
        assert_invalid_startup(role, "NOW_HANDSHAKE_TIMEOUT", &raw);
    }
    for role in ["portal", "vector", "egress"] {
        assert_invalid_startup(role, "NOW_HANDSHAKE_TIMEOUT", &raw);
        assert_invalid_startup(role, "NOW_FLOW_SETUP_TIMEOUT", &raw);
        assert_invalid_startup(role, "NOW_QUIC_UDP_QUEUE_BYTES", &raw);
    }
}

#[test]
fn invalid_duration_startup_child() {
    let Ok(role) = std::env::var("NOW_TEST_TIMEOUT_ROLE") else {
        return;
    };
    let name = std::env::var("NOW_TEST_TIMEOUT_NAME").unwrap();
    let scheme = match role.as_str() {
        "probe" => "vector",
        "fingerprint" => "nowhere",
        _ => &role,
    };
    let url = Url::parse(&format!(
        "{scheme}://0123456789abcdef0123456789abcdef@127.0.0.1:2000?morph=0"
    ))
    .unwrap();
    let error = match role.as_str() {
        "portal" => crate::Portal::new(url, crate::Logger).err(),
        "vector" => crate::Vector::new(url, crate::Logger).err(),
        "egress" => crate::Egress::new(url, crate::Logger).err(),
        "probe" => crate::vector::PortalClientConfig::from_probe_url(&url).err(),
        "fingerprint" => crate::vector::PortalClientConfig::from_fingerprint_url(&url).err(),
        _ => panic!("invalid test role"),
    }
    .expect("invalid configuration did not stop startup");
    assert!(format!("{error:#}").contains(&name), "{error:#}");
}

#[test]
fn handshake_timeout_reference_vectors_cover_ascii_keys_and_range_endpoints() {
    for (key, milliseconds) in [
        ("0123456789abcdef0123456789abcdef", 9100),
        ("fedcba9876543210fedcba9876543210", 24700),
        ("00000000000000000000000000000000", 18600),
        ("ffffffffffffffffffffffffffffffff", 24300),
        ("00000000000000000000000000000005", 3000),
        ("0000000000000000000000000000002a", 30000),
    ] {
        assert_eq!(
            derive_handshake_timeout(key.as_bytes()),
            Duration::from_millis(milliseconds)
        );
    }
}

#[test]
fn handshake_timeout_uses_decoded_ascii_and_explicit_values_take_precedence() {
    let url = Url::parse("portal://%30123456789abcdef0123456789abcdef@localhost:2000").unwrap();
    let mut reads = 0;
    let timeout = read_handshake_timeout(
        &mut |name| {
            assert_eq!(name, "NOW_HANDSHAKE_TIMEOUT");
            reads += 1;
            Ok(None)
        },
        &url,
    )
    .unwrap();
    assert_eq!(timeout, Duration::from_millis(9100));
    assert_eq!(reads, 1);

    let missing_key = Url::parse("portal://localhost:2000").unwrap();
    for (raw, expected) in [("1500ms", 1500), ("45s", 45000)] {
        assert_eq!(
            read_handshake_timeout(&mut |_| Ok(Some(raw.into())), &missing_key).unwrap(),
            Duration::from_millis(expected)
        );
    }
    for raw in [
        "",
        "0s",
        "-1s",
        "invalid",
        "999999999999999999999999h",
        "18446744073709551615s",
    ] {
        let error = read_handshake_timeout(&mut |_| Ok(Some(raw.into())), &url).unwrap_err();
        assert!(format!("{error:#}").contains("NOW_HANDSHAKE_TIMEOUT"));
    }
}

#[test]
fn explicit_handshake_timeout_overrides_each_service_instance() {
    for test in [
        "portal::setup::tests::handshake_timeout_is_saved_per_portal_key_across_carriers_and_morph",
        "egress::setup::tests::handshake_timeout_is_shared_by_egress_connection_and_forwarding_per_instance",
        "vector::config::tests::handshake_timeout_is_saved_per_vector_and_inherited_by_probe_and_fingerprint",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("NOW_HANDSHAKE_TIMEOUT", "45s")
            .env("NOW_TEST_HANDSHAKE_OVERRIDE", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("running 1 test"),
            "{test}: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn tcp_buffer_defaults_bounds_and_vector_startup_are_strict() {
    assert_eq!(read_tcp_data_buf_size(&mut |_| Ok(None)).unwrap(), 32768);
    for value in [1, 4096, isize::MAX as usize] {
        assert_eq!(
            read_tcp_data_buf_size(&mut |_| Ok(Some(value.to_string()))).unwrap(),
            value
        );
    }
    for raw in [
        "0",
        "-1",
        "",
        "bad",
        "1.5",
        "999999999999999999999999",
        &(isize::MAX as u128 + 1).to_string(),
    ] {
        assert!(read_tcp_data_buf_size(&mut |_| Ok(Some(raw.into()))).is_err());
        assert_invalid_startup("vector", "NOW_TCP_DATA_BUF_SIZE", std::ffi::OsStr::new(raw));
    }
    #[cfg(unix)]
    assert_invalid_startup(
        "vector",
        "NOW_TCP_DATA_BUF_SIZE",
        &std::ffi::OsString::from_vec(vec![0xff]),
    );
}

#[test]
fn morph_prelude_is_validated_only_by_tcp_morph_clients_at_startup() {
    for raw in [
        None,
        Some("fade"),
        Some("full8"),
        Some("low7"),
        Some("bad"),
        Some(""),
    ] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "common::config::tests::morph_prelude_startup_child",
                "--nocapture",
            ])
            .env("NOW_TEST_PRELUDE_CHILD", "1")
            .env_remove("NOW_MORPH_TCP_PRELUDE")
            .env_remove("NOW_MORPH_UDP_PRELUDE");
        if let Some(raw) = raw {
            child.env("NOW_MORPH_TCP_PRELUDE", raw);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{raw:?}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(unix)]
    {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "common::config::tests::morph_prelude_startup_child",
                "--nocapture",
            ])
            .env("NOW_TEST_PRELUDE_CHILD", "1")
            .env(
                "NOW_MORPH_TCP_PRELUDE",
                std::ffi::OsString::from_vec(vec![0xff]),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn morph_prelude_startup_child() {
    if std::env::var_os("NOW_TEST_PRELUDE_CHILD").is_none() {
        return;
    }
    let invalid = !matches!(
        std::env::var("NOW_MORPH_TCP_PRELUDE"),
        Err(std::env::VarError::NotPresent)
    ) && !matches!(
        std::env::var("NOW_MORPH_TCP_PRELUDE").as_deref(),
        Ok("fade" | "full8" | "low7")
    );
    for role in ["vector", "egress"] {
        for (carrier, morph) in [("tcp", 1), ("tcp", 0), ("udp", 1)] {
            let url = Url::parse(&format!("{role}://0123456789abcdef0123456789abcdef@127.0.0.1/{carrier}:2000?in=127.0.0.1:1080&morph={morph}&pin={}", "0".repeat(64))).unwrap();
            let error = if role == "vector" {
                crate::Vector::new(url, crate::Logger).err()
            } else {
                crate::Egress::new(url, crate::Logger).err()
            };
            assert_eq!(
                error.is_some(),
                invalid && carrier == "tcp" && morph == 1,
                "{role}/{carrier}/{morph}: {error:?}"
            );
            if let Some(error) = error {
                assert!(format!("{error:#}").contains("NOW_MORPH_TCP_PRELUDE"));
            }
        }
    }
}

#[test]
fn udp_prelude_configuration_is_isolated_by_role_carrier_and_morph() {
    let values = [
        None,
        Some("fade"),
        Some("full8"),
        Some("low7"),
        Some(""),
        Some("FADE"),
        Some("bad"),
    ];
    for tcp in values {
        for udp in values {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "common::config::tests::udp_prelude_configuration_child",
                ])
                .env("NOW_TEST_UDP_PRELUDE_CHILD", "1")
                .env_remove("NOW_MORPH_TCP_PRELUDE")
                .env_remove("NOW_MORPH_UDP_PRELUDE");
            if let Some(value) = tcp {
                child.env("NOW_MORPH_TCP_PRELUDE", value);
            }
            if let Some(value) = udp {
                child.env("NOW_MORPH_UDP_PRELUDE", value);
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "tcp={tcp:?} udp={udp:?}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    #[cfg(unix)]
    {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "common::config::tests::udp_prelude_configuration_child",
            ])
            .env("NOW_TEST_UDP_PRELUDE_CHILD", "1")
            .env_remove("NOW_MORPH_TCP_PRELUDE")
            .env(
                "NOW_MORPH_UDP_PRELUDE",
                std::ffi::OsString::from_vec(vec![0xff]),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn udp_prelude_configuration_child() {
    if std::env::var_os("NOW_TEST_UDP_PRELUDE_CHILD").is_none() {
        return;
    }
    for role in ["vector", "egress"] {
        for carrier in ["tcp", "udp"] {
            for morph in [0, 1] {
                let env = if carrier == "tcp" {
                    "NOW_MORPH_TCP_PRELUDE"
                } else {
                    "NOW_MORPH_UDP_PRELUDE"
                };
                let invalid = !matches!(std::env::var(env), Err(std::env::VarError::NotPresent))
                    && !matches!(std::env::var(env).as_deref(), Ok("fade" | "full8" | "low7"));
                let url = Url::parse(&format!("{role}://0123456789abcdef0123456789abcdef@127.0.0.1/{carrier}:2000?in=127.0.0.1:1080&morph={morph}&pin={}", "0".repeat(64))).unwrap();
                let error = if role == "vector" {
                    crate::Vector::new(url, crate::Logger).err()
                } else {
                    crate::Egress::new(url, crate::Logger).err()
                };
                assert_eq!(
                    error.is_some(),
                    invalid && morph == 1,
                    "{role}/{carrier}/{morph}: {error:?}"
                );
                if let Some(error) = error {
                    assert!(format!("{error:#}").contains(env));
                }
            }
        }
    }
    let url = Url::parse("portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000").unwrap();
    assert!(crate::Portal::new(url, crate::Logger).is_ok());
}
