// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! QUIC UDP frame codec and fragmentation boundary tests.

use crate::protocol::MAX_FLOW_ID;
use crate::protocol::test_support::{encode_udp_data, encode_udp_data_fragments};

use super::*;

#[test]
fn packed_header_preserves_maximum_ids_and_all_type_bits() {
    let data = encode_udp_data(MAX_FLOW_ID, &[]).unwrap();
    assert_eq!(data, [0x3f, 0xff, 0xff, 0xff]);
    assert_eq!(
        decode_udp_frame(&data).unwrap(),
        UdpFrame::Data {
            flow_id: MAX_FLOW_ID,
            payload: &[]
        }
    );
    let close = encode_udp_close(MAX_FLOW_ID).unwrap();
    assert_eq!(close, [0xbf, 0xff, 0xff, 0xff]);
    assert_eq!(
        decode_udp_frame(&close).unwrap(),
        UdpFrame::Close {
            flow_id: MAX_FLOW_ID
        }
    );
    let mut fragment = encode_udp_fragment_header(MAX_FLOW_ID, u32::MAX, 0, 2, 2)
        .unwrap()
        .to_vec();
    assert_eq!(
        fragment,
        [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 2, 0, 2]
    );
    fragment.push(42);
    let UdpFrame::Fragment {
        flow_id,
        fragment: decoded,
    } = decode_udp_frame(&fragment).unwrap()
    else {
        panic!("expected fragment");
    };
    assert_eq!(flow_id, MAX_FLOW_ID);
    assert_eq!(decoded.packet_id, u32::MAX);
    for flow_id in [0, MAX_FLOW_ID + 1, u32::MAX] {
        assert!(encode_udp_data(flow_id, &[]).is_err());
        assert!(encode_udp_close(flow_id).is_err());
        assert!(encode_udp_fragment_header(flow_id, 1, 0, 2, 2).is_err());
    }
    for len in 0..UDP_HEADER_LEN {
        assert!(decode_udp_frame(&data[..len]).is_err());
    }
    for len in 0..=UDP_FRAGMENT_HEADER_LEN {
        assert!(decode_udp_frame(&fragment[..len]).is_err());
    }
}

#[test]
fn fragmentation_starts_exactly_above_the_new_data_capacity() {
    for max_size in [13, 64, 1200] {
        let exact = vec![0x5a; max_size - UDP_HEADER_LEN];
        let frames = encode_udp_data_fragments(1, 1, &exact, max_size).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), max_size);
        assert!(matches!(
            decode_udp_frame(&frames[0]).unwrap(),
            UdpFrame::Data { .. }
        ));

        let larger = vec![0x5a; exact.len() + 1];
        let frames = encode_udp_data_fragments(1, 1, &larger, max_size).unwrap();
        assert!(frames.len() >= 2);
        let mut recovered = Vec::new();
        for frame in frames {
            assert!(frame.len() <= max_size);
            let UdpFrame::Fragment { fragment, .. } = decode_udp_frame(&frame).unwrap() else {
                panic!("expected fragment");
            };
            recovered.extend_from_slice(fragment.payload);
        }
        assert_eq!(recovered, larger);
    }
}

#[test]
fn normal_data_and_close_have_exact_four_byte_headers() {
    assert_eq!(
        encode_udp_data(0x0102_0304, &[0xaa, 0xbb]).unwrap(),
        [1, 2, 3, 4, 0xaa, 0xbb]
    );
    assert_eq!(encode_udp_data(0x0102_0304, &[]).unwrap(), [1, 2, 3, 4]);
    assert_eq!(encode_udp_close(0x0102_0304).unwrap(), [0x81, 2, 3, 4]);
    assert_eq!(UDP_HEADER_LEN, 4);
}

#[test]
fn unfragmented_packets_never_carry_fragment_metadata() {
    for payload_len in [0, 1, 95] {
        let payload = vec![0x5a; payload_len];
        let frames = encode_udp_data_fragments(7, 11, &payload, 100).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), UDP_HEADER_LEN + payload_len);
        assert_eq!(
            decode_udp_frame(&frames[0]).unwrap(),
            UdpFrame::Data {
                flow_id: 7,
                payload: &payload,
            }
        );
    }
}

#[test]
fn fragmented_packets_use_exact_twelve_byte_headers() {
    let payload = vec![0x5a; 2500];
    let frames = encode_udp_data_fragments(0x0102_0304, 0x1122_3344, &payload, 1200).unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(UDP_FRAGMENT_HEADER_LEN, 12);
    assert_eq!(
        &frames[0][..UDP_FRAGMENT_HEADER_LEN],
        &[0x41, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 3, 0x09, 0xc4]
    );

    let mut assembled = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        assert!(frame.len() <= 1200);
        let UdpFrame::Fragment { flow_id, fragment } = decode_udp_frame(frame).unwrap() else {
            panic!("expected fragment");
        };
        assert_eq!(flow_id, 0x0102_0304);
        assert_eq!(fragment.packet_id, 0x1122_3344);
        assert_eq!(fragment.fragment_index as usize, index);
        assert_eq!(fragment.fragment_count, 3);
        assert_eq!(fragment.total_len, 2500);
        assembled.extend_from_slice(fragment.payload);
    }
    assert_eq!(assembled, payload);
}

#[test]
fn lazy_fragment_plan_materializes_only_requested_frames() {
    let payload = vec![0x6b; 2500];
    {
        let mut fragments = encode_udp_fragments(7, 9, &payload, 1200).unwrap();
        assert_eq!(fragments.len(), 3);

        let first = fragments.next().unwrap();
        assert_eq!(first.len(), 1200);
        assert_eq!(fragments.len(), 2);
        let UdpFrame::Fragment { fragment, .. } = decode_udp_frame(&first).unwrap() else {
            panic!("expected fragment");
        };
        assert_eq!(fragment.fragment_index, 0);
        assert_eq!(fragment.fragment_count, 3);
    }
    let collected = encode_udp_fragments(7, 9, &payload, 1200)
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(
        collected,
        encode_udp_data_fragments(7, 9, &payload, 1200).unwrap()
    );
}

#[test]
fn lazy_fragment_plan_enforces_two_to_255_fragments() {
    assert!(encode_udp_fragments(1, 1, &[0; 9], 13).is_err());
    let fragments = encode_udp_fragments(1, 1, &[0; 255], 13).unwrap();
    assert_eq!(fragments.len(), 255);
    assert!(encode_udp_fragments(1, 1, &[0; 256], 13).is_err());
    assert!(encode_udp_fragments(1, 0, &[0; 20], 13).is_err());
}

#[test]
fn decoder_round_trips_zero_length_data_and_close() {
    let data = encode_udp_data(5, &[]).unwrap();
    assert_eq!(
        decode_udp_frame(&data).unwrap(),
        UdpFrame::Data {
            flow_id: 5,
            payload: &[],
        }
    );
    let close = encode_udp_close(5).unwrap();
    assert_eq!(
        decode_udp_frame(&close).unwrap(),
        UdpFrame::Close { flow_id: 5 }
    );
}

#[test]
fn owned_decoder_slices_data_and_fragment_payloads_without_copying() {
    let data = Bytes::from(encode_udp_data(5, b"payload").unwrap());
    let data_payload_ptr = data.as_ptr().wrapping_add(UDP_HEADER_LEN);
    let OwnedUdpFrame::Data { flow_id, payload } = decode_udp_frame_owned(data).unwrap() else {
        panic!("expected owned UDP DATA");
    };
    assert_eq!(flow_id, 5);
    assert_eq!(payload, b"payload"[..]);
    assert_eq!(payload.as_ptr(), data_payload_ptr);

    let frame = Bytes::from(
        encode_udp_data_fragments(7, 9, &[0x5a; 100], 64)
            .unwrap()
            .remove(0),
    );
    let fragment_payload_ptr = frame.as_ptr().wrapping_add(UDP_FRAGMENT_HEADER_LEN);
    let OwnedUdpFrame::Fragment { flow_id, fragment } = decode_udp_frame_owned(frame).unwrap()
    else {
        panic!("expected owned UDP FRAGMENT");
    };
    assert_eq!(flow_id, 7);
    assert_eq!(fragment.payload.as_ptr(), fragment_payload_ptr);
    assert_eq!(fragment.payload, [0x5a; 52][..]);
}

#[test]
fn flow_ids_must_fit_thirty_bits_and_packet_ids_must_be_nonzero() {
    assert!(encode_udp_data(0, b"x").is_err());
    assert!(encode_udp_close(0).is_err());
    assert!(encode_udp_data_fragments(0, 1, b"x", 64).is_err());
    assert!(encode_udp_data(MAX_FLOW_ID, b"x").is_ok());
    assert!(encode_udp_data(MAX_FLOW_ID + 1, b"x").is_err());
    assert!(encode_udp_fragment_header(1, 0, 0, 2, 2).is_err());

    let mut fragment = encode_udp_data_fragments(1, 9, &[1; 100], 64)
        .unwrap()
        .remove(0);
    fragment[4..8].fill(0);
    assert!(decode_udp_frame(&fragment).is_err());
}

#[test]
fn decoder_rejects_short_unknown_and_close_payload_frames() {
    for input in [
        vec![],
        vec![0],
        vec![0, 0, 0, 0],
        vec![0xc0, 0, 0, 1],
        vec![0x80, 0, 0, 1, 0],
    ] {
        assert!(decode_udp_frame(&input).is_err(), "accepted {input:?}");
    }
}

#[test]
fn fragment_validation_rejects_every_invalid_metadata_shape() {
    assert!(encode_udp_fragment_header(1, 1, 0, 1, 1).is_err());
    assert!(encode_udp_fragment_header(1, 1, 2, 2, 1).is_err());
    assert!(encode_udp_fragment_header(1, 1, 0, 2, 0).is_err());
    assert!(encode_udp_fragment_header(1, 1, 0, 3, 2).is_err());

    let valid = encode_udp_data_fragments(1, 2, &[7; 100], 64)
        .unwrap()
        .remove(0);
    for mutate in [
        |frame: &mut Vec<u8>| frame[9] = 1,
        |frame: &mut Vec<u8>| frame[8] = frame[9],
        |frame: &mut Vec<u8>| frame[10..12].fill(0),
        |frame: &mut Vec<u8>| frame.truncate(11),
        |frame: &mut Vec<u8>| frame.truncate(12),
    ] {
        let mut frame = valid.clone();
        mutate(&mut frame);
        assert!(decode_udp_frame(&frame).is_err());
    }
}

#[test]
fn fragmentation_enforces_udp_and_fragment_count_limits() {
    assert!(encode_udp_data_fragments(1, 1, b"x", 4).is_err());
    assert!(encode_udp_data_fragments(1, 1, &[0; 20], UDP_FRAGMENT_HEADER_LEN).is_err());
    let oversized = vec![0; UDP_PACKET_MAX + 1];
    assert!(encode_udp_data_fragments(1, 1, &oversized, usize::MAX).is_err());
    assert!(encode_udp_data_fragments(1, 1, &[0; 256], UDP_FRAGMENT_HEADER_LEN + 1).is_err());
}
