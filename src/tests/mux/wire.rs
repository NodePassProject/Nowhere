use super::*;

#[test]
fn headers_have_stable_seven_byte_vectors() {
    let cases = [
        (
            FrameHeader::open(0x0102_0304, 0x0506).unwrap(),
            [1, 5, 6, 1, 2, 3, 4],
        ),
        (
            FrameHeader::data(0x0102_0304, 0x0506).unwrap(),
            [2, 5, 6, 1, 2, 3, 4],
        ),
        (
            FrameHeader::window(0, 0x0506).unwrap(),
            [3, 5, 6, 0, 0, 0, 0],
        ),
        (
            FrameHeader::close(0x0102_0304, CLOSE_FIN).unwrap(),
            [4, 0, 0, 1, 2, 3, 4],
        ),
        (
            FrameHeader::close(0x0102_0304, CLOSE_RESET).unwrap(),
            [5, 0, 0, 1, 2, 3, 4],
        ),
    ];
    for (header, encoded) in cases {
        assert_eq!(encode_header(header).unwrap(), encoded);
        assert_eq!(decode_header(&encoded).unwrap(), header);
    }
}

#[test]
fn only_window_accepts_zero_flow_id() {
    assert!(FrameHeader::window(0, 1).is_ok());
    assert!(FrameHeader::open(0, 1).is_err());
    assert!(FrameHeader::data(0, 1).is_err());
    assert!(FrameHeader::close(0, CLOSE_FIN).is_err());
}

#[test]
fn invalid_codes_and_values_are_rejected() {
    assert!(FrameHeader::data(1, 0).is_err());
    assert!(FrameHeader::window(1, 0).is_err());
    assert!(FrameHeader::close(1, CLOSE_FIN).is_ok());
    assert!(FrameHeader::close(1, CLOSE_RESET).is_ok());
    assert!(FrameHeader::close(1, 2).is_err());
}

#[test]
fn flow_ids_must_fit_the_shared_thirty_bit_space() {
    for kind in [
        FrameKind::Open,
        FrameKind::Data,
        FrameKind::Window,
        FrameKind::Fin,
        FrameKind::Reset,
    ] {
        let value = u16::from(matches!(kind, FrameKind::Data | FrameKind::Window));
        let header = FrameHeader {
            kind,
            value,
            flow_id: MAX_FLOW_ID,
        };
        let bytes = encode_header(header).unwrap();
        assert_eq!(decode_header(&bytes).unwrap(), header);
        for flow_id in [MAX_FLOW_ID + 1, u32::MAX] {
            assert!(encode_header(FrameHeader { flow_id, ..header }).is_err());
            let mut invalid = bytes;
            invalid[3..].copy_from_slice(&flow_id.to_be_bytes());
            assert!(decode_header(&invalid).is_err());
        }
        for len in 0..HEADER_LEN {
            assert!(decode_header(&bytes[..len]).is_err());
        }
    }
}

#[test]
fn decoder_rejects_unknown_types_and_nonzero_terminal_values() {
    for kind in [0, 6, 0xff] {
        assert!(decode_header(&[kind, 0, 0, 0, 0, 0, 1]).is_err());
    }
    for kind in [4, 5] {
        assert!(decode_header(&[kind, 0, 1, 0, 0, 0, 1]).is_err());
    }
}
