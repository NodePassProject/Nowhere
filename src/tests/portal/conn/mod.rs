// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared Portal connection fixtures and authenticated stream helpers.

mod auth;
mod egress;
mod flow;
mod prehello;
mod udp;
mod vn;

use crate::protocol::test_support::encode_target;
use crate::protocol::{AuthTransport, encode_auth_frame};

use super::*;

async fn connect(h: &Harness) -> (quinn::Endpoint, quinn::Connection) {
    let (config, _) = PortalClientConfig::from_probe_url(&h.url("vector", "udp", false)).unwrap();
    let tls = crate::vector::tls::ClientTls::new(&config).unwrap();
    crate::vector::client::connect_quic(&config, &tls)
        .await
        .unwrap()
}

fn tag(q: &quinn::Connection, egress: bool) -> [u8; 16] {
    let mut exporter = [0; 32];
    q.export_keying_material(&mut exporter, crate::protocol::AUTH_EXPORTER_LABEL, b"")
        .unwrap();
    let c = Credentials::from_shared_key(KEY.as_bytes()).unwrap();
    encode_auth_frame(
        if egress { c.egress_key } else { c.vector_key },
        AuthTransport::Quic,
        &exporter,
    )
}

async fn request(send: &mut quinn::SendStream, kind: u8, target: &Target) {
    let mut bytes = vec![kind];
    bytes.extend(encode_target(target).unwrap());
    send.write_all(&bytes).await.unwrap();
}

async fn result(recv: &mut quinn::RecvStream) -> SetupResult {
    SetupResult::from(
        tokio::time::timeout(
            Duration::from_secs(2),
            crate::protocol::read_flow_result(recv),
        )
        .await
        .unwrap()
        .unwrap(),
    )
}
