// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pairing registry tests.

use super::*;
use crate::protocol::{
    Carrier, FlowKind, FlowResult, FlowRole, SESSION_ID_LEN, Target, encode_flow_result,
    read_flow_result,
};
use crate::transport::Stats;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

impl PairingRegistry {
    fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }
}

fn registry(max_udp_flows: usize, timeout: Duration) -> Arc<PairingRegistry> {
    Arc::new(PairingRegistry {
        tcp: Mutex::new(HashMap::new()),
        udp: Mutex::new(HashMap::new()),
        links: StdMutex::new(HashMap::new()),
        claims: StdMutex::new(HashMap::new()),
        rejections: StdMutex::new(HashMap::new()),
        accepting: AtomicBool::new(true),
        next_quic_generation: AtomicU64::new(1),
        next_epoch: AtomicU64::new(1),
        max_pending: 16,
        timeout,
        max_udp_flows,
    })
}

#[tokio::test]
async fn drain_rejects_pending_and_new_flows_but_preserves_active_claims() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [0x5a; SESSION_ID_LEN];
    let _tcp_guard = registry.register_tcp_link(session_id, stats);

    let (active_up, _active_up_peer) = tokio::io::duplex(64);
    let (active_down, _active_down_peer) = tokio::io::duplex(64);
    let active = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Duplex,
                40,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:443")),
            tcp_half("active"),
            Some(Box::pin(active_up)),
            Some(Box::pin(active_down)),
            None,
        )
        .await
        .unwrap()
        .expect("flow should activate before drain");
    let active_cancel = active._flow_lease.cancellation_token();

    let (pending_up, _pending_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Open,
                    41,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:443")),
                tcp_half("pending"),
                Some(Box::pin(pending_up)),
                None,
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    registry.begin_drain().await;
    assert!(!registry.is_accepting());
    assert!(!active_cancel.is_cancelled());
    assert!(registry.tcp.lock().await.is_empty());

    let (late_down, mut late_peer) = tokio::io::duplex(64);
    let error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Attach,
                41,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("late"),
            None,
            Some(Box::pin(late_down)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::FlowLimit);
    assert_eq!(
        read_flow_result(&mut late_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::FlowLimit)
    );

    let (new_up, _new_up_peer) = tokio::io::duplex(64);
    let (new_down, mut new_peer) = tokio::io::duplex(64);
    let error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Duplex,
                42,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:443")),
            tcp_half("new"),
            Some(Box::pin(new_up)),
            Some(Box::pin(new_down)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::FlowLimit);
    assert_eq!(
        read_flow_result(&mut new_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::FlowLimit)
    );

    drop(active);
}

fn header(
    role: FlowRole,
    flow_id: u32,
    kind: FlowKind,
    uplink: Carrier,
    downlink: Carrier,
) -> FlowHeader {
    FlowHeader {
        role,
        flow_id,
        kind,
        uplink,
        downlink,
    }
}

fn target(value: &str) -> Target {
    value.parse().unwrap()
}

fn path(label: &str) -> LinkPath {
    LinkPath {
        peer: format!("{label}.client:1234"),
        local: "portal.test:2077".into(),
    }
}

fn tcp_half(label: &str) -> LinkHalf {
    LinkHalf::tcp(path(label))
}

fn quic_half(label: &str, generation: u64) -> LinkHalf {
    LinkHalf::quic(path(label), generation)
}

fn available_udp_permits(registry: &PairingRegistry, session_id: SessionId) -> usize {
    registry
        .links
        .lock()
        .expect("link registry poisoned")
        .get(&session_id)
        .expect("registered session")
        .udp_flow_budget
        .available_permits()
}

struct PendingWriter;

trait PairingResultExt<T> {
    fn unwrap_pairing_error(self) -> PairingError;
}

impl<T> PairingResultExt<T> for Result<T, PairingError> {
    fn unwrap_pairing_error(self) -> PairingError {
        match self {
            Ok(_) => panic!("pairing operation unexpectedly succeeded"),
            Err(error) => error,
        }
    }
}

impl AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn old_quic_guard_does_not_cancel_flow_on_replacement_generation() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [1; SESSION_ID_LEN];
    let _tcp_guard = registry.register_tcp_link(session_id, stats.clone());

    let first_replaced = tokio_util::sync::CancellationToken::new();
    let first = registry
        .register_quic_link(session_id, stats.clone(), first_replaced.clone())
        .await;
    let second_replaced = tokio_util::sync::CancellationToken::new();
    let second = registry
        .register_quic_link(session_id, stats.clone(), second_replaced.clone())
        .await;
    assert!(first_replaced.is_cancelled());
    assert!(!second_replaced.is_cancelled());

    let (downlink, mut downlink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Attach,
                    7,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::Quic,
                ),
                None,
                quic_half("new", second.quic_generation()),
                None,
                Some(Box::pin(downlink)),
                None,
            )
            .await
            .unwrap()
            .is_none()
    );
    let (uplink, _uplink_peer) = tokio::io::duplex(64);
    let mut paired = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Open,
                7,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::Quic,
            ),
            Some(target("target.test:443")),
            tcp_half("up"),
            Some(Box::pin(uplink)),
            None,
            None,
        )
        .await
        .unwrap()
        .expect("new generation should pair");
    let flow_cancel = paired._flow_lease.cancellation_token();

    drop(first);
    tokio::task::yield_now().await;
    assert!(!flow_cancel.is_cancelled());
    assert_eq!(stats.link_udp.load(Ordering::Relaxed), 1);

    paired.downlink.write_all(b"new").await.unwrap();
    let mut received = [0; 3];
    downlink_peer.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"new");
    drop(paired);
    drop(second);
    assert_eq!(stats.link_udp.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn quic_replacement_immediately_rejects_pending_split_flows() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [0x33; SESSION_ID_LEN];
    let _tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let first = registry
        .register_quic_link(
            session_id,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

    let (tcp_uplink, _tcp_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Open,
                    30,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::Quic,
                ),
                Some(target("target.test:443")),
                tcp_half("tcp-pending"),
                Some(Box::pin(tcp_uplink)),
                None,
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    let (uot_downlink, mut uot_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_udp(
                session_id,
                header(
                    FlowRole::Attach,
                    31,
                    FlowKind::Udp,
                    Carrier::Quic,
                    Carrier::TlsTcp,
                ),
                None,
                tcp_half("udp-pending"),
                UdpHalf::Downlink(UdpDown::TlsTcp {
                    writer: Box::pin(uot_downlink),
                    liveness: None,
                }),
            )
            .await
            .unwrap()
            .is_none()
    );

    let second = registry
        .register_quic_link(
            session_id,
            stats,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    assert!(registry.tcp.lock().await.is_empty());
    assert!(registry.udp.lock().await.is_empty());
    assert_eq!(
        read_flow_result(&mut uot_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );

    let (tcp_downlink, mut tcp_result) = tokio::io::duplex(64);
    let error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Attach,
                30,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::Quic,
            ),
            None,
            quic_half("replacement", second.quic_generation()),
            None,
            Some(Box::pin(tcp_downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::SessionReplaced);
    assert_eq!(
        read_flow_result(&mut tcp_result).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );

    drop(first);
    drop(second);
}

#[tokio::test]
async fn stale_open_after_map_lock_leaves_exact_rejection_for_tcp_attach() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [2; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let first = registry
        .register_quic_link(
            session_id,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    let old_generation = first.quic_generation();

    let map_guard = registry.tcp.lock().await;
    let (uplink, _uplink_peer) = tokio::io::duplex(64);
    let submit_registry = registry.clone();
    let submit = tokio::spawn(async move {
        submit_registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Open,
                    8,
                    FlowKind::Tcp,
                    Carrier::Quic,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:443")),
                quic_half("stale", old_generation),
                Some(Box::pin(uplink)),
                None,
                None,
            )
            .await
    });
    tokio::task::yield_now().await;

    let replace_registry = registry.clone();
    let replace_stats = stats.clone();
    let replacement = tokio::spawn(async move {
        replace_registry
            .register_quic_link(
                session_id,
                replace_stats,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.active_quic_generation(session_id) == Some(old_generation) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement generation should become visible");
    drop(map_guard);

    let error = tokio::time::timeout(Duration::from_secs(1), submit)
        .await
        .expect("stale submit should finish")
        .unwrap()
        .unwrap_pairing_error();
    assert_eq!(error.code(), FlowErrorCode::SessionReplaced);

    let (downlink, mut downlink_peer) = tokio::io::duplex(64);
    let attach_error = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Attach,
                8,
                FlowKind::Tcp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("downlink"),
            None,
            Some(Box::pin(downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(attach_error.code(), FlowErrorCode::SessionReplaced);
    let mut result = [0; 1];
    downlink_peer.read_exact(&mut result).await.unwrap();
    assert_eq!(
        result,
        encode_flow_result(FlowResult::Reject(FlowErrorCode::SessionReplaced))
    );

    let second = replacement.await.unwrap();
    drop(first);
    drop(second);
    drop(tcp_guard);
}

#[tokio::test]
async fn initially_stale_udp_open_leaves_exact_rejection_for_uot_attach() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());
    let session_id = [7; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let first = registry
        .register_quic_link(
            session_id,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    let old_generation = first.quic_generation();
    let second = registry
        .register_quic_link(
            session_id,
            stats,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

    let (_datagram_tx, datagram_rx) = mpsc::channel(1);
    let open_error = registry
        .submit_udp(
            session_id,
            header(
                FlowRole::Open,
                15,
                FlowKind::Udp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:53")),
            quic_half("stale-uplink", old_generation),
            UdpHalf::Uplink {
                uplink: UdpUp::Quic(QuicUdpReceiver::new_without_barrier(
                    datagram_rx,
                    Arc::new(AtomicBool::new(false)),
                    || {},
                )),
            },
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(open_error.code(), FlowErrorCode::SessionReplaced);

    let (downlink, mut peer) = tokio::io::duplex(64);
    let attach_error = registry
        .submit_udp(
            session_id,
            header(
                FlowRole::Attach,
                15,
                FlowKind::Udp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("uot-downlink"),
            UdpHalf::Downlink(UdpDown::TlsTcp {
                writer: Box::pin(downlink),
                liveness: None,
            }),
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(attach_error.code(), FlowErrorCode::SessionReplaced);
    assert_eq!(
        read_flow_result(&mut peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::SessionReplaced)
    );

    drop(first);
    drop(second);
    drop(tcp_guard);
}

#[tokio::test]
async fn late_attach_receives_original_open_pair_timeout() {
    let registry = registry(8, Duration::from_millis(10));
    let stats = Arc::new(Stats::default());

    let tcp_session = [8; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(tcp_session, stats.clone());
    let (tcp_uplink, _tcp_uplink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_tcp(
                tcp_session,
                header(
                    FlowRole::Open,
                    16,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:443")),
                tcp_half("tcp-open"),
                Some(Box::pin(tcp_uplink)),
                None,
                None,
            )
            .await
            .unwrap()
            .is_none()
    );
    let tcp_key = FlowKey {
        session_id: tcp_session,
        flow_id: 16,
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.terminal_rejection(tcp_key, false) != Some(FlowErrorCode::PairTimeout) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (tcp_downlink, mut tcp_peer) = tokio::io::duplex(64);
    let tcp_error = registry
        .submit_tcp(
            tcp_session,
            header(
                FlowRole::Attach,
                16,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("tcp-attach"),
            None,
            Some(Box::pin(tcp_downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(tcp_error.code(), FlowErrorCode::PairTimeout);
    assert_eq!(
        read_flow_result(&mut tcp_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::PairTimeout)
    );

    let udp_session = [9; SESSION_ID_LEN];
    let udp_guard = registry.register_tcp_link(udp_session, stats);
    let (udp_uplink, _udp_uplink_peer) = tokio::io::duplex(64);
    assert!(
        registry
            .submit_udp(
                udp_session,
                header(
                    FlowRole::Open,
                    17,
                    FlowKind::Udp,
                    Carrier::TlsTcp,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:53")),
                tcp_half("udp-open"),
                UdpHalf::Uplink {
                    uplink: UdpUp::TlsTcp(Box::pin(udp_uplink)),
                },
            )
            .await
            .unwrap()
            .is_none()
    );
    let udp_key = FlowKey {
        session_id: udp_session,
        flow_id: 17,
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while registry.terminal_rejection(udp_key, false) != Some(FlowErrorCode::PairTimeout) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (udp_downlink, mut udp_peer) = tokio::io::duplex(64);
    let udp_error = registry
        .submit_udp(
            udp_session,
            header(
                FlowRole::Attach,
                17,
                FlowKind::Udp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("udp-attach"),
            UdpHalf::Downlink(UdpDown::TlsTcp {
                writer: Box::pin(udp_downlink),
                liveness: None,
            }),
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(udp_error.code(), FlowErrorCode::PairTimeout);
    assert_eq!(
        read_flow_result(&mut udp_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::PairTimeout)
    );

    drop(tcp_guard);
    drop(udp_guard);
}

#[tokio::test]
async fn tombstones_deliver_exact_reject_on_selected_downlink() {
    let registry = registry(8, Duration::from_secs(30));
    let stats = Arc::new(Stats::default());

    let tcp_session = [3; SESSION_ID_LEN];
    let quic_guard = registry
        .register_quic_link(
            tcp_session,
            stats.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    registry
        .reject_flow_setup(tcp_session, 9, FlowErrorCode::DialFailed)
        .await;
    let (tcp_downlink, mut tcp_peer) = tokio::io::duplex(64);
    let tcp_error = registry
        .submit_tcp(
            tcp_session,
            header(
                FlowRole::Attach,
                9,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::Quic,
            ),
            None,
            quic_half("tcp-reject", quic_guard.quic_generation()),
            None,
            Some(Box::pin(tcp_downlink)),
            None,
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(tcp_error.code(), FlowErrorCode::DialFailed);
    let mut tcp_result = [0; 1];
    tcp_peer.read_exact(&mut tcp_result).await.unwrap();
    assert_eq!(
        tcp_result,
        encode_flow_result(FlowResult::Reject(FlowErrorCode::DialFailed))
    );

    let udp_session = [4; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(udp_session, stats);
    registry
        .reject_flow_setup(udp_session, 10, FlowErrorCode::InternalError)
        .await;
    let (uot_downlink, mut uot_peer) = tokio::io::duplex(64);
    let udp_error = registry
        .submit_udp(
            udp_session,
            header(
                FlowRole::Attach,
                10,
                FlowKind::Udp,
                Carrier::Quic,
                Carrier::TlsTcp,
            ),
            None,
            tcp_half("udp-reject"),
            UdpHalf::Downlink(UdpDown::TlsTcp {
                writer: Box::pin(uot_downlink),
                liveness: None,
            }),
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(udp_error.code(), FlowErrorCode::InternalError);
    assert_eq!(
        read_flow_result(&mut uot_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::InternalError)
    );

    drop(quic_guard);
    drop(tcp_guard);
}

#[tokio::test]
async fn cancel_all_cancels_active_flows_without_waiting_for_pending_writer() {
    let registry = registry(8, Duration::from_secs(60));
    let stats = Arc::new(Stats::default());
    let session_id = [5; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let quic_guard = registry
        .register_quic_link(
            session_id,
            stats,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

    assert!(
        registry
            .submit_tcp(
                session_id,
                header(
                    FlowRole::Attach,
                    11,
                    FlowKind::Tcp,
                    Carrier::TlsTcp,
                    Carrier::Quic,
                ),
                None,
                quic_half("blocked", quic_guard.quic_generation()),
                None,
                Some(Box::pin(PendingWriter)),
                None,
            )
            .await
            .unwrap()
            .is_none()
    );

    let (active_stream, _active_peer) = tokio::io::duplex(64);
    let (active_downlink, _downlink_peer) = tokio::io::duplex(64);
    let active = registry
        .submit_tcp(
            session_id,
            header(
                FlowRole::Duplex,
                12,
                FlowKind::Tcp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:443")),
            tcp_half("active"),
            Some(Box::pin(active_stream)),
            Some(Box::pin(active_downlink)),
            None,
        )
        .await
        .unwrap()
        .expect("duplex flow should activate");
    let active_cancel = active._flow_lease.cancellation_token();

    tokio::time::timeout(Duration::from_millis(500), registry.cancel_all())
        .await
        .expect("cancel_all must not await a blocked network writer");
    assert!(active_cancel.is_cancelled());
    assert!(registry.tcp.lock().await.is_empty());
    assert!(registry.udp.lock().await.is_empty());
    assert_eq!(
        registry
            .claims
            .lock()
            .expect("flow claim registry poisoned")
            .len(),
        1,
        "only the cancelled active lease remains until it is dropped"
    );
    drop(active);
    assert!(
        registry
            .claims
            .lock()
            .expect("flow claim registry poisoned")
            .is_empty()
    );

    drop(quic_guard);
    drop(tcp_guard);
}

#[tokio::test]
async fn udp_permit_is_shared_by_quic_and_uot_and_released_by_cancel() {
    let registry = registry(1, Duration::from_secs(60));
    let stats = Arc::new(Stats::default());
    let session_id = [6; SESSION_ID_LEN];
    let tcp_guard = registry.register_tcp_link(session_id, stats.clone());
    let quic_guard = registry
        .register_quic_link(
            session_id,
            stats,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

    let (_datagram_tx, datagram_rx) = mpsc::channel(1);
    assert!(
        registry
            .submit_udp(
                session_id,
                header(
                    FlowRole::Open,
                    13,
                    FlowKind::Udp,
                    Carrier::Quic,
                    Carrier::TlsTcp,
                ),
                Some(target("target.test:53")),
                quic_half("udp-up", quic_guard.quic_generation()),
                UdpHalf::Uplink {
                    uplink: UdpUp::Quic(QuicUdpReceiver::new_without_barrier(
                        datagram_rx,
                        Arc::new(AtomicBool::new(false)),
                        || {},
                    )),
                },
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(available_udp_permits(&registry, session_id), 0);

    let (rejected_uplink, _rejected_uplink_peer) = tokio::io::duplex(64);
    let (rejected_downlink, mut rejected_peer) = tokio::io::duplex(64);
    let rejected = registry
        .submit_udp(
            session_id,
            header(
                FlowRole::Duplex,
                14,
                FlowKind::Udp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:53")),
            tcp_half("uot-limited"),
            UdpHalf::Duplex {
                uplink: UdpUp::TlsTcp(Box::pin(rejected_uplink)),
                downlink: UdpDown::TlsTcp {
                    writer: Box::pin(rejected_downlink),
                    liveness: None,
                },
            },
        )
        .await
        .unwrap_pairing_error();
    assert_eq!(rejected.code(), FlowErrorCode::FlowLimit);
    assert_eq!(
        read_flow_result(&mut rejected_peer).await.unwrap(),
        FlowResult::Reject(FlowErrorCode::FlowLimit)
    );

    registry.cancel_udp(session_id, 13).await;
    assert_eq!(available_udp_permits(&registry, session_id), 1);

    let (uot_uplink, _uot_uplink_peer) = tokio::io::duplex(64);
    let (uot_downlink, _uot_downlink_peer) = tokio::io::duplex(64);
    let paired = registry
        .submit_udp(
            session_id,
            header(
                FlowRole::Duplex,
                14,
                FlowKind::Udp,
                Carrier::TlsTcp,
                Carrier::TlsTcp,
            ),
            Some(target("target.test:53")),
            tcp_half("uot-accepted"),
            UdpHalf::Duplex {
                uplink: UdpUp::TlsTcp(Box::pin(uot_uplink)),
                downlink: UdpDown::TlsTcp {
                    writer: Box::pin(uot_downlink),
                    liveness: None,
                },
            },
        )
        .await
        .unwrap()
        .expect("released permit should admit UoT flow");
    assert_eq!(available_udp_permits(&registry, session_id), 0);
    drop(paired);
    assert_eq!(available_udp_permits(&registry, session_id), 1);

    drop(quic_guard);
    drop(tcp_guard);
}
