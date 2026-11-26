// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph traffic cipher selection and AES counter initialization.

use std::io;

use aes::Aes128;
use anyhow::bail;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherError, StreamCipherSeek};
use ctr::Ctr128BE;

use super::{MorphGrade, MorphKeyBytes, NONCE_LEN, exhausted, hmac_sha256};

type AesCtr = Ctr128BE<Aes128>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MorphCipher {
    ChaCha,
    Aes,
}

impl MorphCipher {
    pub(crate) fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value {
            None | Some("chacha") => Ok(Self::ChaCha),
            Some("aes") => Ok(Self::Aes),
            Some(_) => bail!("cipher must be chacha or aes"),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha => "chacha",
            Self::Aes => "aes",
        }
    }

    pub(super) fn apply_datagram(
        self,
        grade: MorphGrade,
        opening: bool,
        key: &MorphKeyBytes,
        nonce: &[u8; NONCE_LEN],
        input: &[u8],
        output: &mut [u8],
    ) -> io::Result<()> {
        match self {
            Self::ChaCha => mask_datagram(
                ChaCha20::new(key.into(), nonce.into()),
                grade,
                opening,
                input,
                output,
            )
            .map_err(|_| exhausted()),
            Self::Aes => {
                let mut counter = [0; 16];
                counter[..NONCE_LEN].copy_from_slice(nonce);
                let cipher = AesCtr::new_from_slices(&key[..16], &counter)
                    .expect("fixed AES key and counter lengths");
                mask_datagram(cipher, grade, opening, input, output)
                    .map_err(|_| io::Error::other("Morph AES datagram keystream exhausted"))
            }
        }
    }
}

fn mask_datagram(
    mut cipher: impl StreamCipher + StreamCipherSeek,
    grade: MorphGrade,
    opening: bool,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), StreamCipherError> {
    if input.len() != output.len() {
        return Err(StreamCipherError);
    }
    if grade == MorphGrade::Full || input.len() <= 41 || (!opening && input[0] & 0x80 != 0) {
        return cipher.try_apply_keystream_b2b(input, output);
    }
    cipher.try_apply_keystream_b2b(&input[..25], &mut output[..25])?;
    if opening && output[0] & 0x80 != 0 {
        return cipher.try_apply_keystream_b2b(&input[25..], &mut output[25..]);
    }
    let tail = input.len() - 16;
    output[25..tail].copy_from_slice(&input[25..tail]);
    cipher.try_seek(tail)?;
    cipher.try_apply_keystream_b2b(&input[tail..], &mut output[tail..])
}

pub(super) enum TcpCipher {
    ChaCha(ChaCha20),
    Aes(Box<AesCtr>),
}

impl TcpCipher {
    pub(super) fn new(cipher: MorphCipher, key: &MorphKeyBytes, nonce: &[u8; NONCE_LEN]) -> Self {
        match cipher {
            MorphCipher::ChaCha => Self::ChaCha(ChaCha20::new(key.into(), nonce.into())),
            MorphCipher::Aes => {
                let key = hmac_sha256(key, nonce);
                Self::Aes(Box::new(
                    AesCtr::new_from_slices(&key[..16], &[0; 16])
                        .expect("fixed AES key and counter lengths"),
                ))
            }
        }
    }

    pub(super) fn limit(&self) -> u64 {
        match self {
            Self::ChaCha(_) => (1 << 38) - 64,
            Self::Aes(_) => 1 << 48,
        }
    }

    pub(super) fn exhausted(&self) -> io::Error {
        match self {
            Self::ChaCha(_) => exhausted(),
            Self::Aes(_) => io::Error::other("Morph AES TCP keystream exhausted"),
        }
    }

    pub(super) fn try_apply_keystream(&mut self, data: &mut [u8]) -> io::Result<()> {
        match self {
            Self::ChaCha(cipher) => cipher.try_apply_keystream(data),
            Self::Aes(cipher) => cipher.try_apply_keystream(data),
        }
        .map_err(|_| self.exhausted())
    }

    pub(super) fn try_apply_keystream_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> io::Result<()> {
        match self {
            Self::ChaCha(cipher) => cipher.try_apply_keystream_b2b(input, output),
            Self::Aes(cipher) => cipher.try_apply_keystream_b2b(input, output),
        }
        .map_err(|_| self.exhausted())
    }

    pub(super) fn try_seek(&mut self, offset: u64) -> io::Result<()> {
        match self {
            Self::ChaCha(cipher) => cipher.try_seek(offset),
            Self::Aes(cipher) => cipher.try_seek(offset),
        }
        .map_err(|_| self.exhausted())
    }
}

#[cfg(test)]
#[path = "../../tests/transport/morph/cipher.rs"]
mod tests;
