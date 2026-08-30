use super::*;

#[test]
fn alpn_mapping_is_fixed_and_ordered_for_v2_preference() {
    assert_eq!(SUPPORTED_ALPNS, [b"nw2".as_slice(), b"now/1".as_slice()]);
    assert_eq!(
        ProtocolVersion::from_alpn(Some(V2_ALPN)).unwrap(),
        ProtocolVersion::V2
    );
    assert_eq!(
        ProtocolVersion::from_alpn(Some(V1_ALPN)).unwrap(),
        ProtocolVersion::V1
    );
    assert!(ProtocolVersion::from_alpn(Some(b"private/2")).is_err());
    assert!(ProtocolVersion::from_alpn(None).is_err());
}
