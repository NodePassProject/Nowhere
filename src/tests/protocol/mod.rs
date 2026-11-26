// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Deterministic parser mutation corpus for Targets, DATAGRAMs, reassembly, and URLs.

use std::time::Duration;

use url::Url;

use crate::protocol::test_support::{encode_target, encode_udp_data_fragments};

use super::*;

const KEY: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn deterministic_mutation_corpus_bounds_target_datagram_reassembly_and_urls() {
    use crate::protocol::{OwnedUdpFrame, ReassemblyConfig, ReassemblyOutcome};
    let mut random = 0x6e7733u64;
    let mut next = || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    let target = encode_target(&Target::domain("example.com", 443).unwrap()).unwrap();
    let frame = encode_udp_data_fragments(2, 1, b"fragmented payload", 16).unwrap();
    let mut assembly = crate::protocol::DatagramReassembler::new(ReassemblyConfig::default());
    let now = std::time::Instant::now();
    for i in 0..20000 {
        let mut bytes = if i % 3 == 0 {
            target.clone()
        } else if i % 3 == 1 {
            frame[0].to_vec()
        } else {
            vec![0; next() as usize % 512]
        };
        for _ in 0..(next() % 8 + 1) {
            if !bytes.is_empty() {
                let index = next() as usize % bytes.len();
                bytes[index] = next() as u8;
            }
        }
        if i % 5 == 0 {
            bytes.truncate(next() as usize % (bytes.len() + 1));
        }
        if let Ok((decoded, consumed)) = super::request::decode_target(&bytes) {
            assert!(consumed <= bytes.len());
            assert_eq!(
                super::request::decode_target(&encode_target(&decoded).unwrap())
                    .unwrap()
                    .0,
                decoded
            );
        }
        if let Ok(OwnedUdpFrame::Fragment { flow_id, fragment }) =
            crate::protocol::decode_udp_frame_owned(bytes::Bytes::from(bytes))
        {
            let _: ReassemblyOutcome<()> = assembly.push_with(flow_id, fragment, now, |_| Some(()));
        }
        assert!(assembly.slot_count() <= 64);
        assert!(assembly.reserved_bytes() <= 1024 * 1024);
        if i % 17 == 0 {
            assembly.clear();
        }
        let url = format!(
            "vector://{KEY}@127.0.0.1/{}:2000?in=127.0.0.1:1080&morph={}&unused={}&unknown=%{:02x}",
            if next() & 1 == 0 { "tcp" } else { "udp" },
            next() % 8,
            next(),
            next() as u8
        );
        if let Ok(url) = Url::parse(&url) {
            let _ = crate::vector::PortalClientConfig::from_probe_url(&url);
        }
    }
    assembly.expire(now + Duration::from_secs(11));
    assert_eq!(assembly.slot_count(), 0);
    assert_eq!(assembly.reserved_bytes(), 0);
}
