// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph root-domain key derivation and fixed interoperability vectors tests.

use super::*;

impl MorphKeys {
    pub(crate) fn core_aes(shared_key: &[u8]) -> Self {
        Self {
            grade: MorphGrade::Core,
            cipher: MorphCipher::Aes,
            ..Self::derive(shared_key)
        }
    }
}

pub(super) fn hex<const N: usize>(value: &str) -> [u8; N] {
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
        hex("f3d2fabc455a59c400d09d400b5a0b9b221e2b157589fc87674b902111ea1014")
    );
    assert_eq!(
        keys.tcp_s2c,
        hex("190cfc4c689b24d4bfc8431f46d9f2d1bcbf6222eed612a3ea12d04ff4e4af8c")
    );
    assert_eq!(
        keys.udp_c2s,
        hex("20221bde5d70b44211a22c7e62967945d7d85bcde0d17a3b28d1fa686f8e5c1f")
    );
    assert_eq!(
        keys.udp_s2c,
        hex("78938ee9245028e7de63ac27b0ab64c68df2961a2cf39da1394f0f242bf8b389")
    );
}
