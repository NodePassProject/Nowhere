// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use tokio::io::AsyncReadExt;

fn shard(handle: MuxHandle) -> TlsMux {
    TlsMux {
        handle,
        version: ProtocolVersion::V2,
    }
}

#[tokio::test]
async fn shard_selection_stops_at_four_active_flows() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (handle, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_peer, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let mut streams = Vec::new();
    let mut peers = Vec::new();

    for flow_id in 1..TLS_MUX_FLOWS_PER_SHARD as u32 {
        streams.push(handle.open_stream(flow_id).await.unwrap());
        peers.push(incoming.accept().await.unwrap().unwrap());
    }
    let shard = shard(handle.clone());
    assert!(
        select_available_mux(std::slice::from_ref(&shard))
            .unwrap()
            .handle
            .same_carrier(&handle)
    );

    streams.push(
        handle
            .open_stream(TLS_MUX_FLOWS_PER_SHARD as u32)
            .await
            .unwrap(),
    );
    peers.push(incoming.accept().await.unwrap().unwrap());
    assert!(select_available_mux(std::slice::from_ref(&shard)).is_none());
}

#[tokio::test]
async fn shard_selection_uses_the_least_loaded_carrier() {
    let (left_a, right_a) = tokio::io::duplex(1 << 20);
    let (handle_a, _) = MuxHandle::start(left_a, MuxConfig::default()).unwrap();
    let (_peer_a, mut incoming_a) = MuxHandle::start(right_a, MuxConfig::default()).unwrap();
    let (left_b, right_b) = tokio::io::duplex(1 << 20);
    let (handle_b, _) = MuxHandle::start(left_b, MuxConfig::default()).unwrap();
    let (_peer_b, mut incoming_b) = MuxHandle::start(right_b, MuxConfig::default()).unwrap();

    let _stream_a1 = handle_a.open_stream(1).await.unwrap();
    let _peer_a1 = incoming_a.accept().await.unwrap().unwrap();
    let _stream_a2 = handle_a.open_stream(2).await.unwrap();
    let _peer_a2 = incoming_a.accept().await.unwrap().unwrap();
    let _stream_b = handle_b.open_stream(3).await.unwrap();
    let _peer_b = incoming_b.accept().await.unwrap().unwrap();

    let selected = select_available_mux(&[shard(handle_a), shard(handle_b.clone())]).unwrap();
    assert!(selected.handle.same_carrier(&handle_b));
}

#[tokio::test]
async fn closing_one_shard_does_not_affect_another() {
    let (left_a, right_a) = tokio::io::duplex(1 << 20);
    let (handle_a, _) = MuxHandle::start(left_a, MuxConfig::default()).unwrap();
    let (_peer_a, mut incoming_a) = MuxHandle::start(right_a, MuxConfig::default()).unwrap();
    let (left_b, right_b) = tokio::io::duplex(1 << 20);
    let (handle_b, _) = MuxHandle::start(left_b, MuxConfig::default()).unwrap();
    let (_peer_b, mut incoming_b) = MuxHandle::start(right_b, MuxConfig::default()).unwrap();

    let mut stream_a = handle_a.open_stream(1).await.unwrap();
    let _peer_stream_a = incoming_a.accept().await.unwrap().unwrap();
    let mut stream_b = handle_b.open_stream(2).await.unwrap();
    let mut peer_stream_b = incoming_b.accept().await.unwrap().unwrap();

    handle_a.close();
    assert!(stream_a.write_all(b"closed").await.is_err());

    stream_b.write_all(b"live").await.unwrap();
    let mut payload = [0_u8; 4];
    peer_stream_b.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"live");
}
