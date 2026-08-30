// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Fixed Nowhere wire codecs.

mod auth;
mod datagram;
mod flow;
mod request;
mod result;
mod uot;
mod util;
mod version;

pub use auth::{
    AUTH_FRAME_LEN, AUTH_TAG_LEN, AuthFrame, AuthKey, AuthTransport, Credentials, TLS_EXPORTER_LEN,
    TlsExporter, derive_auth_key, encode_auth_frame, read_auth_frame, validate_auth_frame,
};
pub use datagram::{
    BorrowedUdpFragment, DatagramReassembler, OwnedUdpFragment, OwnedUdpFrame, ReassemblyConfig,
    ReassemblyDropReason, ReassemblyOutcome, UDP_FRAGMENT_HEADER_LEN, UDP_FRAME_CLOSE,
    UDP_FRAME_DATA, UDP_FRAME_FRAGMENT, UDP_HEADER_LEN, UDP_PACKET_MAX, UdpFragment, UdpFragments,
    UdpFrame, decode_udp_frame, decode_udp_frame_owned, encode_udp_close, encode_udp_data,
    encode_udp_data_fragments, encode_udp_data_header, encode_udp_fragment_header,
    encode_udp_fragments,
};
pub use flow::{
    Carrier, FLOW_HEADER_LEN, FlowHeader, FlowId, FlowKind, FlowRole, MAX_PORTAL_HOPS,
    SESSION_ID_LEN, SessionId, decode_flow_header, encode_flow_header, read_flow_header,
    write_flow_header,
};
pub use request::{
    TARGET_ATYP_DOMAIN, TARGET_ATYP_IPV4, TARGET_ATYP_IPV6, TARGET_IPV4_LEN, TARGET_IPV6_LEN,
    TARGET_MAX_ENCODED_LEN, Target, decode_target, encode_target, encode_target_into, read_request,
    write_request, write_request_frame,
};
pub use result::{
    FlowErrorCode, FlowResult, SETUP_RESULT_LEN, SetupResult, decode_setup_result,
    encode_flow_result, encode_setup_result, read_flow_result, read_setup_result,
    write_flow_result, write_setup_result,
};
pub use uot::{
    UOT_HEADER_LEN, UOT_PACKET_MAX, encode_udp_packet, encode_udp_packet_header, read_udp_packet,
    read_udp_packet_into, write_udp_packet,
};
pub use version::{ProtocolVersion, SUPPORTED_ALPNS, V1_ALPN, V2_ALPN};
