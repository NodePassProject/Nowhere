// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;

#[tokio::test]
async fn uot_flows_exceed_the_former_udp_limit_without_reserving_quic_credit() {
    let registry = registry(Duration::from_secs(60));
    let session = [6; SESSION_ID_LEN];
    let _guard = registry.register_tcp_link(session, Arc::new(Stats::default()));
    let mut held = Vec::new();
    for id in 1..=512 {
        let (up, _) = tokio::io::duplex(64);
        let (down, _) = tokio::io::duplex(64);
        held.push(
            registry
                .submit_udp(
                    session,
                    header(
                        FlowRole::Duplex,
                        id,
                        FlowKind::Udp,
                        Carrier::TlsTcp,
                        Carrier::TlsTcp,
                    ),
                    Some(target("target.test:53")),
                    tcp_half("uot"),
                    UdpHalf::Duplex {
                        uplink: UdpUp::TlsTcp(Box::pin(up)),
                        downlink: UdpDown::TlsTcp {
                            writer: Box::pin(down),
                            liveness: None,
                        },
                    },
                )
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(registry.claims.lock().unwrap().len(), 512);
    assert_eq!(registry.quic_stream_credit(session).into_inner(), 64);
    drop(held);
    assert!(registry.claims.lock().unwrap().is_empty());
}
