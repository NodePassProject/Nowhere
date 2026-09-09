// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::super::*;

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn derives_fixed_hkdf_sha256_keys() {
    let keys = MorphKeys::derive(b"test portal key");
    assert_eq!(
        keys.tcp_c2s,
        hex("90df47db82553ab6b0489ea77a085593475a70c6a61e957ad3ffe0824bd2126a")
    );
    assert_eq!(
        keys.tcp_s2c,
        hex("20bc17a22d08469e60efd4c6bdda76f190c33946599a0797bab2d52007b97e27")
    );
    assert_eq!(
        keys.udp,
        hex("484b5f06a66e566099da4886e3bb2ec342aedee0ebcd7ea426d68ece4f3f8ea2")
    );
}
