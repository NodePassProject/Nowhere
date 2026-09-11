use super::wire::{CLOSE_FIN, CLOSE_RESET, FrameHeader, encode_header};
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn more_than_256_live_streams_transfer_and_half_close() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (left, right) = tokio::io::duplex(1 << 20);
        let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
        let (server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
        let mut streams = Vec::new();
        for id in 1..=1024 {
            let outgoing = client.open_stream(id).await.unwrap();
            let accepted = incoming.accept().await.unwrap().unwrap();
            streams.push((outgoing, accepted));
        }
        assert_eq!(client.active_streams(), 1024);
        for (mut outgoing, mut accepted) in streams {
            outgoing.write_all(b"ok").await.unwrap();
            drop(outgoing);
            let mut bytes = Vec::new();
            accepted.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"ok");
        }
        assert_eq!(client.active_streams(), 0);
        client.close();
        server.close();
    })
    .await
    .expect("stream admission must not depend on terminal queue capacity");
}

#[tokio::test]
async fn open_reset_churn_cannot_overflow_pending_incoming_admission() {
    let config = MuxConfig {
        active_stream_limit: 2,
        ..MuxConfig::default()
    };
    let (mut peer, carrier) = tokio::io::duplex(4096);
    let (server, incoming) = MuxHandle::start(carrier, config).unwrap();
    for flow_id in 1..=3 {
        peer.write_all(&encode_header(FrameHeader::open(flow_id, 0).unwrap()).unwrap())
            .await
            .unwrap();
        peer.write_all(&encode_header(FrameHeader::close(flow_id, CLOSE_RESET).unwrap()).unwrap())
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), server.closed())
        .await
        .expect("RESET must not bypass pending OPEN admission");
    assert_eq!(incoming.receiver.len(), 2);
    assert_eq!(server.active_streams(), 0);
}

#[tokio::test]
async fn remote_open_admission_closes_carrier_at_the_metadata_limit() {
    let config = MuxConfig {
        active_stream_limit: 2,
        ..MuxConfig::default()
    };
    let (mut peer, carrier) = tokio::io::duplex(4096);
    let (server, mut incoming) = MuxHandle::start(carrier, config).unwrap();
    let mut streams = Vec::new();

    for flow_id in 1..=2 {
        peer.write_all(&encode_header(FrameHeader::open(flow_id, 0).unwrap()).unwrap())
            .await
            .unwrap();
        let stream = incoming.accept().await.unwrap().unwrap();
        assert_eq!(stream.flow_id(), flow_id);
        streams.push(stream);
    }
    assert_eq!(server.active_streams(), 2);

    peer.write_all(&encode_header(FrameHeader::open(3, 0).unwrap()).unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), server.closed())
        .await
        .expect("OPEN beyond the metadata budget must close the carrier");
    assert_eq!(server.active_streams(), 0);
}

#[tokio::test]
async fn slow_small_packet_reader_does_not_block_other_flows() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (left, right) = tokio::io::duplex(1 << 20);
        let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
        let (server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
        let mut slow = client.open_stream(1).await.unwrap();
        let _slow_peer = incoming.accept().await.unwrap().unwrap();
        for _ in 0..1024 {
            slow.write_all(b"x").await.unwrap();
        }
        let mut fast = client.open_stream(2).await.unwrap();
        let mut fast_peer = incoming.accept().await.unwrap().unwrap();
        fast.write_all(b"ok").await.unwrap();
        let mut bytes = [0; 2];
        fast_peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        client.close();
        server.close();
    })
    .await
    .expect("per-flow queue must not stall the carrier reader");
}

#[test]
fn production_idle_timeout_remains_thirty_seconds() {
    assert_eq!(MUX_IDLE_TIMEOUT, Duration::from_secs(30));
}

#[tokio::test]
async fn abandoned_reader_returns_credit_without_closing_other_streams() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (left, right) = tokio::io::duplex(1 << 20);
        let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
        let (server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
        let outgoing = client.open_stream(1).await.unwrap();
        let mut accepted = incoming.accept().await.unwrap().unwrap();
        let (reader, _writer) = outgoing.into_split();
        drop(reader);
        accepted
            .write_all(&vec![0; 2 * MAX_CONNECTION_WINDOW_BYTES])
            .await
            .unwrap();
        let mut other = client.open_stream(2).await.unwrap();
        let mut peer = incoming.accept().await.unwrap().unwrap();
        other.write_all(b"ok").await.unwrap();
        let mut bytes = [0; 2];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        assert!(!client.is_closed());
        client.close();
        server.close();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_blocked_flow_cannot_fill_the_shared_send_queue() {
    let (left, _right) = tokio::io::duplex(1);
    let (handle, _incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let mut a = handle.open_stream(1).await.unwrap();
    let mut b = handle.open_stream(2).await.unwrap();
    a.write_all(b"queued").await.unwrap();
    let pending = tokio::spawn(async move { a.write_all(b"blocked").await });
    tokio::time::timeout(Duration::from_secs(1), b.write_all(b"other"))
        .await
        .unwrap()
        .unwrap();
    tokio::task::yield_now().await;
    assert!(!pending.is_finished());
    handle.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

async fn assert_raw_frame_closes_carrier(frame: &[u8]) {
    let (left, mut peer) = tokio::io::duplex(1 << 20);
    let (handle, _incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    peer.write_all(frame).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle.closed())
        .await
        .expect("invalid frame must close carrier");
}

#[tokio::test]
async fn invalid_kind_and_unknown_flow_data_close_carrier() {
    assert_raw_frame_closes_carrier(&[0xff, 0, 0, 0, 0, 0, 1]).await;

    let mut frame = encode_header(FrameHeader::data(99, 1).unwrap())
        .unwrap()
        .to_vec();
    frame.push(0);
    assert_raw_frame_closes_carrier(&frame).await;
}

#[tokio::test]
async fn invalid_prepared_id_does_not_reserve_a_stream_or_close_the_carrier() {
    let (left, _peer) = tokio::io::duplex(1024);
    let (handle, _incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    for id in [0, crate::protocol::MAX_FLOW_ID + 1, u32::MAX] {
        assert!(handle.prepare_stream(id).is_err());
        assert_eq!(handle.active_streams(), 0);
        assert!(!handle.is_closed());
    }
    let _stream = handle.prepare_stream(crate::protocol::MAX_FLOW_ID).unwrap();
    assert_eq!(handle.active_streams(), 1);
    handle.close();
}

#[tokio::test]
async fn duplicate_open_and_credit_overflow_close_carrier() {
    let open = encode_header(FrameHeader::open(7, 0).unwrap()).unwrap();
    let mut duplicate = open.to_vec();
    duplicate.extend_from_slice(&open);
    assert_raw_frame_closes_carrier(&duplicate).await;

    let overflow = encode_header(FrameHeader::window(0, u16::MAX as usize).unwrap()).unwrap();
    assert_raw_frame_closes_carrier(&overflow).await;
}

#[tokio::test]
async fn duplicate_close_and_late_stream_window_are_idempotent() {
    let (left, mut peer) = tokio::io::duplex(1 << 20);
    let (handle, mut incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    peer.write_all(&encode_header(FrameHeader::open(7, 0).unwrap()).unwrap())
        .await
        .unwrap();
    let stream = incoming.accept().await.unwrap().unwrap();
    let reset = encode_header(FrameHeader::close(7, CLOSE_RESET).unwrap()).unwrap();
    peer.write_all(&reset).await.unwrap();
    peer.write_all(&reset).await.unwrap();
    peer.write_all(&encode_header(FrameHeader::window(7, 1).unwrap()).unwrap())
        .await
        .unwrap();
    peer.write_all(&encode_header(FrameHeader::open(9, 0).unwrap()).unwrap())
        .await
        .unwrap();
    let next = tokio::time::timeout(Duration::from_secs(1), incoming.accept())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(next.flow_id(), 9);
    assert!(!handle.is_closed());
    drop(stream);
}

#[tokio::test]
async fn data_after_fin_closes_carrier() {
    let (left, mut peer) = tokio::io::duplex(1 << 20);
    let (handle, mut incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    peer.write_all(&encode_header(FrameHeader::open(8, 0).unwrap()).unwrap())
        .await
        .unwrap();
    let _stream = incoming.accept().await.unwrap().unwrap();
    peer.write_all(&encode_header(FrameHeader::close(8, CLOSE_FIN).unwrap()).unwrap())
        .await
        .unwrap();
    let mut data = encode_header(FrameHeader::data(8, 1).unwrap())
        .unwrap()
        .to_vec();
    data.push(0);
    peer.write_all(&data).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle.closed())
        .await
        .expect("DATA after FIN must close carrier");
}

#[tokio::test]
async fn idle_deadline_resets_when_a_stream_becomes_active() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let idle = {
        let client = client.clone();
        tokio::spawn(async move { client.idle_for(std::time::Duration::from_millis(80)).await })
    };

    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let outgoing = client.open_stream(1).await.unwrap();
    let accepted = incoming.accept().await.unwrap().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!idle.is_finished());
    drop(outgoing);
    drop(accepted);

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), idle)
            .await
            .unwrap()
            .unwrap()
    );
}

#[tokio::test]
async fn stream_round_trip_and_half_close() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _client_incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_server, mut server_incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let mut outgoing = client.open_stream(7).await.unwrap();
    outgoing.write_all(b"hello").await.unwrap();
    outgoing.shutdown().await.unwrap();
    let mut incoming = server_incoming.accept().await.unwrap().unwrap();
    let mut payload = Vec::new();
    incoming.read_to_end(&mut payload).await.unwrap();
    assert_eq!(payload, b"hello");
}

#[tokio::test]
async fn many_small_writes_cross_the_credit_window() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let mut outgoing = client.open_stream(8).await.unwrap();
    let mut accepted = incoming.accept().await.unwrap().unwrap();
    let packet = vec![0x5a; 1_202];
    let count = 1_024;
    let reader = tokio::spawn(async move {
        let mut received = vec![0; 1_202 * count];
        accepted.read_exact(&mut received).await.unwrap();
        received
    });

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for _ in 0..count {
            outgoing.write_all(&packet).await.unwrap();
        }
        outgoing.shutdown().await.unwrap();
    })
    .await
    .expect("small writes must continue after exhausting initial credit");

    let received = reader.await.unwrap();
    assert!(received.iter().all(|byte| *byte == 0x5a));
}

#[tokio::test]
async fn peers_with_different_profiles_exchange_beyond_the_base_window() {
    let memory = MuxConfig {
        stream_window_bytes: 4 * MIB,
        connection_window_bytes: 8 * MIB,
        ..MuxConfig::default()
    };
    let throughput = MuxConfig {
        stream_window_bytes: 16 * MIB,
        connection_window_bytes: 32 * MIB,
        ..MuxConfig::default()
    };
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, memory).unwrap();
    let (_server, mut incoming) = MuxHandle::start(right, throughput).unwrap();
    let mut outgoing = client.open_stream(81).await.unwrap();
    let mut accepted = incoming.accept().await.unwrap().unwrap();
    let sender = tokio::spawn(async move {
        let payload = vec![0x81; 12 * MIB];
        outgoing.write_all(&payload).await.unwrap();
        outgoing.shutdown().await.unwrap();
    });
    let mut received = 0;
    let mut buffer = vec![0; FRAME_BYTES];
    loop {
        let count = accepted.read(&mut buffer).await.unwrap();
        if count == 0 {
            break;
        }
        assert!(buffer[..count].iter().all(|byte| *byte == 0x81));
        received += count;
    }
    sender.await.unwrap();
    assert_eq!(received, 12 * MIB);
}

#[tokio::test]
async fn carrier_close_fails_every_flow() {
    let (left, right) = tokio::io::duplex(1024);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let mut outgoing = client.open_stream(9).await.unwrap();
    let _ = incoming.accept().await.unwrap().unwrap();
    server.close();
    let failed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if outgoing.write_all(b"closed").await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(failed.is_ok());
}

#[tokio::test]
async fn rapid_stream_drop_does_not_close_carrier() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();

    for flow_id in 1..=2_000 {
        let outgoing = client.open_stream(flow_id).await.unwrap();
        let accepted = incoming.accept().await.unwrap().unwrap();
        drop(outgoing);
        drop(accepted);
    }

    tokio::task::yield_now().await;
    assert!(!client.is_closed());
    assert!(!server.is_closed());
}

#[tokio::test]
async fn dropping_unused_writer_preserves_incoming_half() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();

    let outgoing = client.open_stream(11).await.unwrap();
    let (mut client_reader, client_writer) = outgoing.into_split();
    let accepted = incoming.accept().await.unwrap().unwrap();
    let (_server_reader, mut server_writer) = accepted.into_split();
    drop(client_writer);
    server_writer.write_all(b"response").await.unwrap();
    server_writer.shutdown().await.unwrap();

    let mut response = Vec::new();
    client_reader.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response");
}

#[tokio::test]
async fn stream_credit_does_not_shrink_with_active_stream_count() {
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let mut streams = Vec::new();
    let mut peers = Vec::new();

    for flow_id in 1..=128 {
        streams.push(client.open_stream(flow_id).await.unwrap());
        peers.push(incoming.accept().await.unwrap().unwrap());
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let all_ready = client.shared.flows.lock().unwrap().values().all(|flow| {
                flow.send_credit.available_permits()
                    == credit_units(MuxConfig::default().stream_window_bytes)
            });
            if all_ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    {
        let flows = client.shared.flows.lock().unwrap();
        assert!(flows.values().all(|flow| {
            flow.send_credit.available_permits()
                == credit_units(MuxConfig::default().stream_window_bytes)
        }));
    }

    let retained = streams.pop().unwrap();
    drop(streams);
    {
        let flows = client.shared.flows.lock().unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(
            flows
                .values()
                .next()
                .unwrap()
                .send_credit
                .available_permits(),
            credit_units(MuxConfig::default().stream_window_bytes)
        );
    }
    drop(retained);
    drop(peers);
}

#[tokio::test]
async fn concurrent_streams_cross_the_connection_window() {
    const FLOWS: u32 = 16;
    const BYTES_PER_FLOW: usize = 3 * MIB;
    let (left, right) = tokio::io::duplex(1 << 20);
    let (client, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let (_server, mut incoming) = MuxHandle::start(right, MuxConfig::default()).unwrap();
    let mut writers = Vec::new();
    let mut readers = Vec::new();
    for flow_id in 1..=FLOWS {
        writers.push(client.open_stream(flow_id).await.unwrap());
        readers.push(incoming.accept().await.unwrap().unwrap());
    }

    let mut tasks = writers
        .into_iter()
        .map(|mut stream| {
            tokio::spawn(async move {
                stream.write_all(&vec![0x5a; BYTES_PER_FLOW]).await.unwrap();
                stream.shutdown().await.unwrap();
            })
        })
        .collect::<Vec<_>>();
    tasks.extend(readers.into_iter().map(|mut stream| {
        tokio::spawn(async move {
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.len(), BYTES_PER_FLOW);
            assert!(received.iter().all(|byte| *byte == 0x5a));
        })
    }));
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn closing_carrier_wakes_exhausted_stream_credit() {
    let (left, right) = tokio::io::duplex(1024);
    let (handle, _) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let mut stream = handle.open_stream(501).await.unwrap();
    let credit = handle.shared.send_credit(501).unwrap();
    let permits = credit.available_permits();
    credit
        .clone()
        .acquire_many_owned(permits as u32)
        .await
        .unwrap()
        .forget();
    let write = tokio::spawn(async move { stream.write_all(b"blocked").await });
    tokio::task::yield_now().await;
    assert!(!write.is_finished());
    handle.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    drop(right);
}

#[tokio::test]
async fn closing_carrier_interrupts_blocked_io_and_releases_shared_state() {
    let (left, _right) = tokio::io::duplex(1);
    let (handle, incoming) = MuxHandle::start(left, MuxConfig::default()).unwrap();
    let weak = Arc::downgrade(&handle.shared);
    tokio::task::yield_now().await;
    handle.close();
    drop(handle);
    drop(incoming);
    tokio::time::timeout(Duration::from_secs(1), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("blocked I/O must release carrier state after close");
}

#[test]
fn profiles_outside_wire_window_limits_are_rejected() {
    for (stream, connection) in [
        (MIB, 8 * MIB),
        (4 * MIB, 4 * MIB),
        (32 * MIB, 32 * MIB),
        (4 * MIB + 1, 8 * MIB),
    ] {
        assert!(
            MuxConfig {
                stream_window_bytes: stream,
                connection_window_bytes: connection,
                ..MuxConfig::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        MuxConfig {
            active_stream_limit: 0,
            ..MuxConfig::default()
        }
        .validate()
        .is_err()
    );
}
