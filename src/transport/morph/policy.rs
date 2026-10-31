// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared Morph TCP and UDP Prelude generation policies.

use std::io;

use super::{TCP_PRELUDE_LEN, UDP_PRELUDE_LEN};

pub(super) const TCP_PRELUDE_ENV: &str = "NOW_MORPH_TCP_PRELUDE";

pub(super) const UDP_PRELUDE_ENV: &str = "NOW_MORPH_UDP_PRELUDE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PreludePolicy {
    Fade,
    Full8,
    Low7,
}

impl PreludePolicy {
    pub(super) fn from_env(env: &str) -> io::Result<Self> {
        Self::parse(env, std::env::var(env))
    }

    pub(super) fn parse(env: &str, value: Result<String, std::env::VarError>) -> io::Result<Self> {
        match value {
            Ok(value) if value == "fade" => Ok(Self::Fade),
            Ok(value) if value == "full8" => Ok(Self::Full8),
            Ok(value) if value == "low7" => Ok(Self::Low7),
            Err(std::env::VarError::NotPresent) => Ok(Self::Fade),
            Ok(_) | Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{env} must be fade, full8 or low7"),
            )),
        }
    }

    pub(super) fn generate_tcp(self) -> io::Result<[u8; TCP_PRELUDE_LEN]> {
        self.generate_tcp_with(|bytes| getrandom::fill(bytes).map_err(io::Error::other))
    }

    pub(super) fn generate_tcp_with(
        self,
        fill: impl FnMut(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<[u8; TCP_PRELUDE_LEN]> {
        self.generate_with(fill)
    }

    pub(super) fn generate_udp(self) -> io::Result<[u8; UDP_PRELUDE_LEN]> {
        self.generate_with(|bytes| getrandom::fill(bytes).map_err(io::Error::other))
    }

    fn generate_with<const N: usize>(
        self,
        mut fill: impl FnMut(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<[u8; N]> {
        let mut prelude = [0u8; N];
        fill(&mut prelude)?;
        match self {
            Self::Fade => {
                let (a, b) = if N == TCP_PRELUDE_LEN {
                    let mut boundaries = [0u8; 2];
                    fill(&mut boundaries)?;
                    (
                        8 + usize::from(sample_below(boundaries[0], 5, &mut fill)?),
                        16 + usize::from(sample_below(boundaries[1], 17, &mut fill)?),
                    )
                } else {
                    (2, 10)
                };
                for byte in &mut prelude[..a] {
                    *byte = 0x20 + sample_below(*byte, 95, &mut fill)?;
                }
                for byte in &mut prelude[a..b] {
                    *byte &= 0x7f;
                }
            }
            Self::Full8 => {}
            Self::Low7 => {
                for byte in &mut prelude {
                    *byte &= 0x7f;
                }
            }
        }
        Ok(prelude)
    }
}

fn sample_below(
    mut byte: u8,
    upper: u8,
    fill: &mut impl FnMut(&mut [u8]) -> io::Result<()>,
) -> io::Result<u8> {
    let limit = 256u16 - 256 % u16::from(upper);
    while u16::from(byte) >= limit {
        fill(std::slice::from_mut(&mut byte))?;
    }
    Ok(byte % upper)
}

#[cfg(test)]
#[path = "../../tests/transport/morph/policy.rs"]
mod tests;
