// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use tokio::io::AsyncReadExt;

fn slot(handle: MuxHandle) -> Arc<TlsMux> {
    let slot = Arc::new(TlsMux::default());
    assert!(slot.handle.set(handle).is_ok());
    slot
}

async fn carrier(pressured: bool) -> (MuxHandle, MuxHandle, crate::mux::Incoming, Vec<MuxStream>) {
    let (left, right) = tokio::io::duplex(1 << 20);
    let config = MuxConfig {
        stream_window_bytes: 4 << 20,
        connection_window_bytes: 8 << 20,
        outbound_frames: 512,
        ..MuxConfig::default()
    };
    let (handle, _) = MuxHandle::start(left, config).unwrap();
    let (peer, mut incoming) = MuxHandle::start(right, config).unwrap();
    let mut streams = Vec::new();
    for id in 1..=2 {
        let mut stream = handle.open_stream(id).await.unwrap();
        streams.push(incoming.accept().await.unwrap().unwrap());
        if pressured {
            stream.write_all(&vec![1; 7 << 19]).await.unwrap();
            stream.flush().await.unwrap();
        }
        streams.push(stream);
    }
    (handle, peer, incoming, streams)
}

#[tokio::test]
async fn cold_reservations_balance_across_eight_connecting_slots() {
    let mut pool = Vec::new();
    let pending: Vec<_> = (0..16).map(|_| reserve_mux(&mut pool)).collect();
    assert_eq!(pool.len(), 8);
    assert!(
        pool.iter()
            .all(|slot| slot.pending.load(Ordering::Relaxed) == 2)
    );
    drop(pending);
    assert!(
        pool.iter()
            .all(|slot| slot.pending.load(Ordering::Relaxed) == 0)
    );
}

#[tokio::test]
async fn idle_carrier_is_reused_before_new_connections() {
    let (handle, peer, _incoming, streams) = carrier(false).await;
    drop(streams);
    let mut pool = vec![slot(handle.clone())];
    let selected = reserve_mux(&mut pool);
    assert_eq!(pool.len(), 1);
    assert!(selected.0.handle.get().unwrap().same_carrier(&handle));
    handle.close();
    peer.close();
}

#[tokio::test]
async fn full_pool_prefers_lower_pressure_and_still_transfers_new_flows() {
    let mut pool = Vec::new();
    let mut peers = Vec::new();
    let mut streams = Vec::new();
    let mut incoming = Vec::new();
    for index in 0..8 {
        let (handle, peer, receiver, held) = carrier(index != 7).await;
        pool.push(slot(handle));
        peers.push(peer);
        streams.extend(held);
        incoming.push(receiver);
    }
    let selected = reserve_mux(&mut pool);
    assert!(Arc::ptr_eq(&selected.0, &pool[7]));
    let handle = selected.0.handle.get().unwrap();
    let mut stream = handle.open_stream(99).await.unwrap();
    let mut accepted = incoming[7].accept().await.unwrap().unwrap();
    stream.write_all(b"new").await.unwrap();
    let mut bytes = [0; 3];
    accepted.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"new");
    assert_eq!(pool.len(), 8);
    for slot in &pool {
        slot.handle.get().unwrap().close();
    }
    for peer in &peers {
        peer.close();
    }
    drop((streams, stream));
}

#[tokio::test]
async fn cancelling_initializer_releases_reservation_and_allows_retry() {
    let mut pool = Vec::new();
    let pending = reserve_mux(&mut pool);
    let (started, ready) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _pending = pending;
        _pending
            .0
            .handle
            .get_or_try_init(|| async {
                let _ = started.send(());
                std::future::pending::<Result<MuxHandle>>().await
            })
            .await
            .map(|_| ())
    });
    ready.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(pool[0].pending.load(Ordering::Relaxed), 0);
    let retry = reserve_mux(&mut pool);
    assert_eq!(pool.len(), 1);
    let (handle, peer, _incoming, streams) = carrier(false).await;
    retry
        .0
        .handle
        .get_or_try_init(|| async { Ok::<_, anyhow::Error>(handle.clone()) })
        .await
        .unwrap();
    assert!(retry.0.handle.get().unwrap().same_carrier(&handle));
    handle.close();
    peer.close();
    drop(streams);
}

#[tokio::test]
async fn closed_carrier_is_replaced_with_a_reusable_slot() {
    let (handle, peer, _incoming, streams) = carrier(false).await;
    let mut pool = vec![slot(handle.clone())];
    let old = pool[0].clone();
    handle.close();
    let pending = reserve_mux(&mut pool);
    assert_eq!(pool.len(), 1);
    assert!(!Arc::ptr_eq(&pending.0, &old));
    peer.close();
    drop(streams);
}
