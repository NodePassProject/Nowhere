// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Independent role-key and authentication-tag vectors and credential parsing tests.

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn fixed_role_keys_and_tags_match_independent_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    assert_eq!(
        AUTH_EXPORTER_LABEL,
        fixture["exporter_label"].as_str().unwrap().as_bytes()
    );
    let credentials =
        Credentials::from_shared_key(fixture["shared_key_text"].as_str().unwrap().as_bytes())
            .unwrap();
    let exporter = std::array::from_fn(|i| i as u8);
    for vector in fixture["auth"].as_array().unwrap() {
        let key = if vector["role"] == "vector" {
            credentials.vector_key
        } else {
            credentials.egress_key
        };
        assert_eq!(hex(&key), vector["role_key_hex"]);
        let transport = if vector["transport"] == 1 {
            AuthTransport::TlsTcp
        } else {
            AuthTransport::Quic
        };
        let frame = encode_auth_frame(key, transport, &exporter);
        assert_eq!(frame.len(), 16);
        assert_eq!(hex(&frame), vector["auth_frame_hex"]);
    }
}

#[test]
fn replay_transport_role_and_truncation_fail() {
    let creds = Credentials::from_shared_key(b"0123456789abcdef0123456789abcdef").unwrap();
    let exporter = [7; 32];
    let frame = encode_auth_frame(creds.vector_key, AuthTransport::TlsTcp, &exporter);
    assert_eq!(
        validate_auth_frame(&frame, &creds, AuthTransport::TlsTcp, &exporter).unwrap(),
        ConnectionRole::Vector
    );
    assert!(validate_auth_frame(&frame, &creds, AuthTransport::Quic, &exporter).is_err());
    assert!(validate_auth_frame(&frame, &creds, AuthTransport::TlsTcp, &[8; 32]).is_err());
    for n in 0..16 {
        assert!(
            validate_auth_frame(&frame[..n], &creds, AuthTransport::TlsTcp, &exporter).is_err()
        );
    }
    for index in 0..16 {
        let mut changed = frame;
        changed[index] ^= 1;
        assert!(validate_auth_frame(&changed, &creds, AuthTransport::TlsTcp, &exporter).is_err());
    }
    let egress = encode_auth_frame(creds.egress_key, AuthTransport::TlsTcp, &exporter);
    assert_eq!(
        validate_auth_frame(&egress, &creds, AuthTransport::TlsTcp, &exporter).unwrap(),
        ConnectionRole::Egress
    );
    assert!(validate_auth_frame(&egress, &creds, AuthTransport::Quic, &exporter).is_err());
}

#[test]
fn percent_decoding_is_once_and_text_is_not_hex_decoded() {
    let url = Url::parse("vector://a%2520b@localhost:2000").unwrap();
    assert_eq!(Credentials::decode_shared_key(&url).unwrap(), b"a%20b");
    assert_ne!(
        Credentials::from_shared_key(b"abcd").unwrap(),
        Credentials::from_shared_key(&[0xab, 0xcd]).unwrap()
    );
    for key in [
        "",
        "ABCDEF0123456789ABCDEF0123456789AB",
        "abcdef",
        "g123456789abcdef0123456789abcdef",
    ] {
        let url = Url::parse(&format!("portal://{key}@localhost:2000")).unwrap();
        assert!(Credentials::for_service(&url, "test").is_err());
    }
}

#[test]
fn service_roles_share_key_validation_and_decode_only_once() {
    for role in ["portal", "vector", "egress"] {
        let key = "0123456789abcdef0123456789abcdef";
        let encoded: String = key.bytes().map(|byte| format!("%{byte:02X}")).collect();
        for text in [key, &encoded] {
            let url = Url::parse(&format!("{role}://{text}@localhost:2000")).unwrap();
            assert_eq!(
                Credentials::new(&url).unwrap(),
                Credentials::from_shared_key(key.as_bytes()).unwrap()
            );
        }
        for key in [
            "".to_owned(),
            "a".repeat(31),
            "a".repeat(33),
            "a".repeat(64),
            "a".repeat(65),
            "a".repeat(256),
            "é".repeat(16),
            "%61".repeat(31),
            "%61".repeat(33),
            "%61".repeat(64),
            "A".repeat(32),
            "g".repeat(32),
            "%2561".repeat(32),
            "%FF".repeat(32),
            "%ZZ".repeat(32),
            "a".repeat(31) + "%00",
            "a".repeat(31) + "%20",
        ] {
            let url = Url::parse(&format!("{role}://{key}@localhost:2000")).unwrap();
            let error = Credentials::new(&url).unwrap_err().to_string();
            assert!(error.contains("use nowhere generate-key"), "{error}");
            if !key.is_empty() {
                assert!(!error.contains(&key), "{error}");
            }
        }
        let url = Url::parse(&format!(
            "{role}://{}:password@localhost:2000",
            "a".repeat(32)
        ))
        .unwrap();
        assert!(Credentials::new(&url).is_err());
    }
}
