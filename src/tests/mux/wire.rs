use super::*;

#[test]
fn header_has_stable_eight_byte_vector() {
    let header = FrameHeader::stream(0x0102_0304, FLAG_SYN, 0x0506).unwrap();
    let encoded = encode_header(header).unwrap();
    assert_eq!(encoded, [1, FLAG_SYN, 0x05, 0x06, 1, 2, 3, 4]);
    assert_eq!(decode_header(&encoded).unwrap(), header);
}

#[test]
fn only_connection_window_accepts_zero_flow_id() {
    assert!(FrameHeader::window(0, 1).is_ok());
    assert!(FrameHeader::stream(0, 0, 1).is_err());
}

#[test]
fn reset_is_exclusive_and_empty() {
    assert!(FrameHeader::stream(1, FLAG_RST, 0).is_ok());
    assert!(FrameHeader::stream(1, FLAG_RST | FLAG_FIN, 0).is_err());
    assert!(FrameHeader::stream(1, FLAG_RST, 1).is_err());
}

#[test]
fn open_uses_value_for_initial_window_credit() {
    assert!(FrameHeader::stream(1, FLAG_SYN, 12 * 1024).is_ok());
    assert!(FrameHeader::stream(1, FLAG_SYN | FLAG_FIN, 0).is_err());
}
