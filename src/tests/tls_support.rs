// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Certificate pins for local TLS and QUIC test fixtures.

use std::io::Cursor;
use std::sync::Arc;

pub(crate) fn server_certificate_pin(server: &rustls::ServerConfig) -> String {
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    client_config.alpn_protocols = vec![crate::protocol::ALPN.to_vec()];
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut acceptor = rustls::server::Acceptor::default();
    acceptor.read_tls(&mut Cursor::new(hello)).unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    let key = server
        .cert_resolver
        .resolve(accepted.client_hello())
        .unwrap();
    crate::common::certificate_sha256(&key.cert[0])
}
