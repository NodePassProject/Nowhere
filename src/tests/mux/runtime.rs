use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    for flow_id in 1..=128 {
        streams.push(client.open_stream(flow_id).await.unwrap());
        let _ = incoming.accept().await.unwrap().unwrap();
    }
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
}
