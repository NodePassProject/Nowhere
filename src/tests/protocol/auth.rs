// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use tokio::io::AsyncReadExt;
use url::Url;

use super::*;

const EXPORTER: TlsExporter = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const SESSION: SessionId = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[test]
fn hkdf_and_auth_frames_match_fixed_vectors() {
    let key = derive_auth_key(b"secret");
    assert_eq!(
        hex(&key),
        "8de7e08dd22134ac5acc57902658a36b7f6f9d219987ed49b934a7529a4d24c5"
    );
    assert_eq!(
        hex(&encode_auth_frame(
            key,
            AuthTransport::TlsTcp,
            &EXPORTER,
            SESSION
        )),
        "000102030405060708090a0b0c0d0e0f91f3033378b001f0de171717c027be00"
    );
    assert_eq!(
        hex(&encode_auth_frame(
            key,
            AuthTransport::Quic,
            &EXPORTER,
            SESSION
        )),
        "000102030405060708090a0b0c0d0e0f97d0be56bda8a0ee7596775b35efbf68"
    );
}

#[test]
fn credentials_decode_username_and_reject_ambiguous_inputs() {
    let plain = Credentials::new(&Url::parse("portal://sec%20ret@127.0.0.1:443").unwrap()).unwrap();
    assert_eq!(plain, Credentials::from_shared_key(b"sec ret").unwrap());
    assert!(
        Credentials::new(&Url::parse("portal://secret:password@127.0.0.1:443").unwrap()).is_err()
    );
    assert!(Credentials::new(&Url::parse("portal://127.0.0.1:443").unwrap()).is_err());
    assert!(Credentials::from_shared_key(&vec![1; 256]).is_err());
    for url in [
        "portal://bad%GG@127.0.0.1:443",
        "portal://bad%@127.0.0.1:443",
        "portal://bad%1@127.0.0.1:443",
    ] {
        assert!(Credentials::new(&Url::parse(url).unwrap()).is_err());
    }
}

#[test]
fn frame_round_trip_is_bound_to_every_authenticated_input() {
    let key = derive_auth_key(b"secret");
    let frame = encode_auth_frame(key, AuthTransport::TlsTcp, &EXPORTER, SESSION);
    assert_eq!(frame.len(), AUTH_FRAME_LEN);
    assert_eq!(
        validate_auth_frame(&frame, key, AuthTransport::TlsTcp, &EXPORTER).unwrap(),
        SESSION
    );

    let mut wrong_exporter = EXPORTER;
    wrong_exporter[0] ^= 1;
    assert!(validate_auth_frame(&frame, key, AuthTransport::TlsTcp, &wrong_exporter).is_err());
    assert!(validate_auth_frame(&frame, key, AuthTransport::Quic, &EXPORTER).is_err());
    assert!(
        validate_auth_frame(
            &frame,
            derive_auth_key(b"other"),
            AuthTransport::TlsTcp,
            &EXPORTER
        )
        .is_err()
    );

    let mut changed_session = frame;
    changed_session[0] ^= 1;
    assert!(validate_auth_frame(&changed_session, key, AuthTransport::TlsTcp, &EXPORTER).is_err());
    let mut changed_tag = frame;
    changed_tag[AUTH_FRAME_LEN - 1] ^= 1;
    assert!(validate_auth_frame(&changed_tag, key, AuthTransport::TlsTcp, &EXPORTER).is_err());
}

#[test]
fn captured_frame_cannot_be_replayed_on_another_connection() {
    let key = derive_auth_key(b"secret");
    let first_exporter = [7; TLS_EXPORTER_LEN];
    let second_exporter = [8; TLS_EXPORTER_LEN];
    let frame = encode_auth_frame(key, AuthTransport::Quic, &first_exporter, SESSION);

    assert!(validate_auth_frame(&frame, key, AuthTransport::Quic, &first_exporter).is_ok());
    assert!(validate_auth_frame(&frame, key, AuthTransport::Quic, &second_exporter).is_err());
}

#[test]
fn decoder_rejects_truncated_and_trailing_frames() {
    let key = derive_auth_key(b"secret");
    let frame = encode_auth_frame(key, AuthTransport::TlsTcp, &EXPORTER, SESSION);
    assert!(
        validate_auth_frame(
            &frame[..AUTH_FRAME_LEN - 1],
            key,
            AuthTransport::TlsTcp,
            &EXPORTER
        )
        .is_err()
    );
    let mut trailing = frame.to_vec();
    trailing.push(0);
    assert!(validate_auth_frame(&trailing, key, AuthTransport::TlsTcp, &EXPORTER).is_err());
}

#[tokio::test]
async fn async_reader_leaves_the_first_flow_on_the_same_stream() {
    let key = derive_auth_key(b"secret");
    let mut input = encode_auth_frame(key, AuthTransport::Quic, &EXPORTER, SESSION).to_vec();
    input.extend_from_slice(b"flow");
    let mut input = input.as_slice();

    assert_eq!(
        read_auth_frame(&mut input, key, AuthTransport::Quic, &EXPORTER)
            .await
            .unwrap(),
        SESSION
    );
    let mut following = Vec::new();
    input.read_to_end(&mut following).await.unwrap();
    assert_eq!(following, b"flow");
}

#[tokio::test]
async fn async_reader_rejects_a_truncated_frame() {
    let key = derive_auth_key(b"secret");
    let frame = encode_auth_frame(key, AuthTransport::TlsTcp, &EXPORTER, SESSION);
    assert!(
        read_auth_frame(
            &mut &frame[..AUTH_FRAME_LEN - 1],
            key,
            AuthTransport::TlsTcp,
            &EXPORTER
        )
        .await
        .is_err()
    );
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
