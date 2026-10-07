// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph TCP constructors used by internal tests.

use super::*;

#[test]
fn prelude_policy_defaults_to_full8_and_rejects_invalid_settings() {
    use std::env::VarError;

    assert_eq!(
        TcpPreludePolicy::parse(Err(VarError::NotPresent)).unwrap(),
        TcpPreludePolicy::Full8
    );
    for (value, expected) in [
        ("low7", TcpPreludePolicy::Low7),
        ("full8", TcpPreludePolicy::Full8),
    ] {
        assert_eq!(TcpPreludePolicy::parse(Ok(value.into())).unwrap(), expected);
    }
    for value in ["", "FULL8", " full8", "low7 ", "other"] {
        let error = TcpPreludePolicy::parse(Ok(value.into())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(TCP_PRELUDE_ENV));
    }
    assert!(TcpPreludePolicy::parse(Err(VarError::NotUnicode(std::ffi::OsString::new()))).is_err());
}

#[tokio::test]
async fn server_accepts_both_prelude_policies_without_interpreting_bytes() {
    for policy in [TcpPreludePolicy::Low7, TcpPreludePolicy::Full8] {
        let mut prelude = [0xff; TCP_PRELUDE_LEN];
        policy.apply(&mut prelude);
        assert_eq!(
            prelude,
            [if policy == TcpPreludePolicy::Low7 {
                0x7f
            } else {
                0xff
            }; TCP_PRELUDE_LEN]
        );
        let keys = MorphKeys::derive(b"shared");
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client, server) = tokio::join!(
            MorphTcpStream::connect_for_test(client_io, keys.clone(), prelude, [9; NONCE_LEN]),
            MorphTcpStream::accept(server_io, Some(keys)),
        );
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut payload = [0; 5];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> MorphTcpStream<S> {
    pub(in crate::transport::morph) fn initialized_for_test(
        inner: S,
        keys: &MorphKeys,
        nonce: [u8; NONCE_LEN],
        client: bool,
    ) -> Self {
        Self::initialized(inner, keys, nonce, client)
    }

    pub(in crate::transport::morph) async fn connect_for_test(
        inner: S,
        keys: MorphKeys,
        prelude: [u8; TCP_PRELUDE_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> io::Result<Self> {
        Self::connect_with_bootstrap(inner, keys, prelude, nonce).await
    }
}
