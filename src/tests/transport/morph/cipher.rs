// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! AES TCP and UDP interoperability vector tests.

use super::super::MorphKeys;
use super::super::tests::hex;
use super::*;

#[test]
fn aes_matches_tcp_and_udp_vectors() {
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef");
    let nonce = std::array::from_fn(|index| index as u8);
    let plain = std::array::from_fn::<_, 37, _>(|index| index as u8);

    for (key, offset, expected) in [
        (
            &keys.tcp_c2s,
            0,
            "8e59faa695f33a1a5ffc8369938132d677a1536e730205de8b4767a560fd155b7ed13833e3",
        ),
        (
            &keys.tcp_s2c,
            0,
            "17a4869bfb790fa12b676b42a6ad4f40f8eaff0566051e81313ca1a59486b0f766ba989ce2",
        ),
        (
            &keys.tcp_c2s,
            (1 << 40) + 19,
            "dda378cb6a89ab5e74c5081119eb5fe3a06c0ee6563feacd15afa86af9b77425f0519188a2",
        ),
    ] {
        let mut cipher = TcpCipher::new(MorphCipher::Aes, key, &nonce);
        cipher.try_seek(offset).unwrap();
        let mut actual = plain;
        let (first, second) = actual.split_at_mut(21);
        cipher.try_apply_keystream(first).unwrap();
        cipher.try_apply_keystream(second).unwrap();
        assert_eq!(actual, hex(expected));
    }

    for (key, expected) in [
        (
            &keys.udp_c2s,
            "4378463322b3680c1d1ad62068c536c0fc5e1eac063187dcb2cf48d0ab609405aa9f4fea6b",
        ),
        (
            &keys.udp_s2c,
            "2813cf0312ebdcc2beb4ff955b4667eb3ab282761d5d5ecc3b1b111d8531262cb6ea62744a",
        ),
    ] {
        let mut actual = [0; 37];
        MorphCipher::Aes
            .apply_datagram(
                super::MorphGrade::Full,
                false,
                key,
                &nonce,
                &plain,
                &mut actual,
            )
            .unwrap();
        assert_eq!(actual, hex(expected));
    }
}

#[test]
fn core_datagram_masks_the_expected_ranges_at_absolute_offsets() {
    let key = [12; 32];
    let nonce = [5; 12];
    for cipher in [MorphCipher::ChaCha, MorphCipher::Aes] {
        for first in [0x40, 0xc0] {
            for len in [1, 40, 41, 42, 139] {
                let mut plain = vec![0x27; len];
                plain[0] = first;
                let mut full = vec![0; len];
                cipher
                    .apply_datagram(MorphGrade::Full, false, &key, &nonce, &plain, &mut full)
                    .unwrap();
                let mut core = vec![0; len];
                cipher
                    .apply_datagram(MorphGrade::Core, false, &key, &nonce, &plain, &mut core)
                    .unwrap();
                if first & 0x80 == 0 && len > 41 {
                    full[25..len - 16].copy_from_slice(&plain[25..len - 16]);
                }
                assert_eq!(core, full);
                let mut opened = vec![0; len];
                cipher
                    .apply_datagram(MorphGrade::Core, true, &key, &nonce, &core, &mut opened)
                    .unwrap();
                assert_eq!(opened, plain);
            }
        }
    }
}
