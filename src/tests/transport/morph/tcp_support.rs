// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph TCP constructors used by internal tests.

use super::*;

#[test]
fn prelude_policy_defaults_to_fade_and_rejects_invalid_settings() {
    use std::env::VarError;

    assert_eq!(
        PreludePolicy::parse(TCP_PRELUDE_ENV, Err(VarError::NotPresent)).unwrap(),
        PreludePolicy::Fade
    );
    for (value, expected) in [
        ("fade", PreludePolicy::Fade),
        ("full8", PreludePolicy::Full8),
        ("low7", PreludePolicy::Low7),
    ] {
        assert_eq!(
            PreludePolicy::parse(TCP_PRELUDE_ENV, Ok(value.into())).unwrap(),
            expected
        );
    }
    for value in [
        "", "FULL8", "FADE", " full8", " fade", "low7 ", "fade ", "other",
    ] {
        let error = PreludePolicy::parse(TCP_PRELUDE_ENV, Ok(value.into())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(TCP_PRELUDE_ENV));
    }
    assert!(
        PreludePolicy::parse(
            TCP_PRELUDE_ENV,
            Err(VarError::NotUnicode(std::ffi::OsString::new()))
        )
        .is_err()
    );
}

#[tokio::test]
async fn server_accepts_authenticated_preludes_for_every_base_policy() {
    let mut preludes = vec![[0xff; TCP_PRELUDE_LEN], [0; TCP_PRELUDE_LEN]];
    for policy in [
        PreludePolicy::Fade,
        PreludePolicy::Full8,
        PreludePolicy::Low7,
    ] {
        preludes.push(policy.generate_tcp().unwrap());
    }
    for prelude in preludes {
        let keys = MorphKeys::derive(b"shared");
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client, server) = tokio::join!(
            MorphTcpStream::connect_authenticated_for_test(
                client_io,
                keys.clone(),
                prelude,
                [9; NONCE_LEN],
                AuthenticatedPrelude {
                    identity: 1,
                    counter: 1
                },
            ),
            MorphTcpStream::accept(server_io, Some(keys)),
        );
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut payload = [0; 5];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        server.write_all(b"reply").await.unwrap();
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"reply");
    }
}

#[tokio::test]
async fn server_rejects_unauthenticated_preludes_for_every_base_policy() {
    let keys = MorphKeys::derive(b"shared");
    for policy in [
        PreludePolicy::Fade,
        PreludePolicy::Full8,
        PreludePolicy::Low7,
    ] {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client, server) = tokio::join!(
            MorphTcpStream::connect_with_bootstrap(
                client_io,
                keys.clone(),
                policy.generate_tcp().unwrap(),
                [9; NONCE_LEN],
            ),
            MorphTcpStream::accept_bootstrap(server_io, Some(keys.clone())),
        );
        let _client = client.unwrap();
        let (error, _stream) = server.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn base_prelude_policies_preserve_every_input_byte_mapping() {
    for value in 0..=u8::MAX {
        for policy in [PreludePolicy::Full8, PreludePolicy::Low7] {
            let mut calls = 0;
            let prelude = policy
                .generate_tcp_with(|bytes| {
                    calls += 1;
                    bytes.fill(value);
                    Ok(())
                })
                .unwrap();
            assert_eq!(calls, 1);
            let expected = if policy == PreludePolicy::Low7 {
                value & 0x7f
            } else {
                value
            };
            assert_eq!(prelude, [expected; TCP_PRELUDE_LEN]);
        }
    }
}

#[test]
fn fade_covers_all_boundary_pairs_and_exact_segment_ranges() {
    for a in 8..=12 {
        for b in 16..=32 {
            let mut input = vec![255; TCP_PRELUDE_LEN];
            input.extend([a as u8 - 8, b as u8 - 16]);
            input.extend((0..a).map(|index| if index % 2 == 0 { 0 } else { 94 }));
            let mut input = input.into_iter();
            let prelude = PreludePolicy::Fade
                .generate_tcp_with(|bytes| {
                    for byte in bytes {
                        *byte = input.next().unwrap();
                    }
                    Ok(())
                })
                .unwrap();
            assert!(input.next().is_none());
            assert_eq!(prelude.len(), 64);
            for (index, &byte) in prelude[..a].iter().enumerate() {
                assert_eq!(byte, if index % 2 == 0 { 0x20 } else { 0x7e });
            }
            assert!(prelude[a..b].iter().all(|&byte| byte == 0x7f));
            assert!(prelude[b..].iter().all(|&byte| byte == 0xff));
        }
    }
}

#[test]
fn fade_preserves_uniform_low7_and_full8_byte_mappings() {
    let mut ascii_counts = [0; 95];
    let mut low7_counts = [0; 128];
    let mut full8_counts = [0; 256];
    for input in 0..=u8::MAX {
        let mut calls = 0;
        let prelude = PreludePolicy::Fade
            .generate_tcp_with(|bytes| {
                calls += 1;
                bytes.fill(if calls == 1 { input } else { 0 });
                Ok(())
            })
            .unwrap();
        if input < 190 {
            ascii_counts[usize::from(prelude[0] - 0x20)] += 1;
        }
        low7_counts[usize::from(prelude[8])] += 1;
        full8_counts[usize::from(prelude[16])] += 1;
    }
    assert_eq!(ascii_counts, [2; 95]);
    assert_eq!(low7_counts, [2; 128]);
    assert_eq!(full8_counts, [1; 256]);
}

#[test]
fn fade_uses_fresh_secure_randomness_for_each_prelude() {
    let mut seen = std::collections::HashSet::new();
    let mut tail_has_high_bit = false;
    for _ in 0..1024 {
        let prelude = PreludePolicy::Fade.generate_tcp().unwrap();
        assert!(prelude[..8].iter().all(|byte| (0x20..=0x7e).contains(byte)));
        assert!(prelude[..16].iter().all(|&byte| byte <= 0x7f));
        tail_has_high_bit |= prelude[32..].iter().any(|&byte| byte > 0x7f);
        assert!(seen.insert(prelude));
    }
    assert!(tail_has_high_bit);
}

#[test]
fn fade_propagates_random_source_errors_at_every_generation_stage() {
    for fail_at in 1..=12 {
        let mut calls = 0;
        let error = PreludePolicy::Fade
            .generate_tcp_with(|bytes| {
                calls += 1;
                if calls == fail_at {
                    return Err(io::Error::other("random source failed"));
                }
                bytes.fill(if calls <= 2 { 255 } else { 0 });
                Ok(())
            })
            .unwrap_err();
        assert_eq!(calls, fail_at);
        assert_eq!(error.to_string(), "random source failed");
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> MorphTcpStream<S> {
    pub(crate) fn into_inner(self) -> S {
        self.inner
    }

    pub(crate) async fn connect_authenticated_for_test(
        inner: S,
        keys: MorphKeys,
        mut prelude: [u8; TCP_PRELUDE_LEN],
        nonce: [u8; NONCE_LEN],
        authentication: AuthenticatedPrelude,
    ) -> io::Result<Self> {
        keys.encode_prelude(&mut prelude, &nonce, authentication);
        Self::connect_with_bootstrap(inner, keys, prelude, nonce).await
    }

    pub(crate) async fn connect_current_for_test(
        inner: S,
        keys: Option<MorphKeys>,
    ) -> io::Result<Self> {
        Self::connect(inner, keys, &ClientPrelude::default()).await
    }

    pub(crate) async fn connect_legacy_for_test(inner: S, keys: MorphKeys) -> io::Result<Self> {
        let prelude = PreludePolicy::from_env(TCP_PRELUDE_ENV)?.generate_tcp()?;
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        Self::connect_with_bootstrap(inner, keys, prelude, nonce).await
    }

    pub(crate) async fn accept(inner: S, keys: Option<MorphKeys>) -> Result<Self, (io::Error, S)> {
        Self::accept_bootstrap(inner, keys)
            .await
            .map(|(stream, _)| stream)
    }

    pub(in crate::transport::morph) fn initialized_for_test(
        inner: S,
        keys: &MorphKeys,
        nonce: [u8; NONCE_LEN],
        client: bool,
    ) -> Self {
        Self::initialized(inner, keys, nonce, client)
    }
}
