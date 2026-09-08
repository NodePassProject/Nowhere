use super::*;

#[test]
fn headers_have_stable_eight_byte_vectors() {
    let cases = [
        (
            FrameHeader::open(0x0102_0304, 0x0506).unwrap(),
            [1, 0, 5, 6, 1, 2, 3, 4],
        ),
        (
            FrameHeader::data(0x0102_0304, 0x0506).unwrap(),
            [2, 0, 5, 6, 1, 2, 3, 4],
        ),
        (
            FrameHeader::window(0, 0x0506).unwrap(),
            [3, 0, 5, 6, 0, 0, 0, 0],
        ),
        (
            FrameHeader::close(0x0102_0304, CLOSE_RESET).unwrap(),
            [4, 1, 0, 0, 1, 2, 3, 4],
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
