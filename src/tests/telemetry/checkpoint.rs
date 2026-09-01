use super::*;

#[test]
fn checkpoint_keeps_the_external_pool_placeholder_and_field_order() {
    let stats = Stats::default();
    stats.tcp_active.store(2, Ordering::Relaxed);
    stats.udp_active.store(3, Ordering::Relaxed);
    stats.tcp_rx.store(4, Ordering::Relaxed);
    stats.tcp_tx.store(5, Ordering::Relaxed);
    stats.udp_rx.store(6, Ordering::Relaxed);
    stats.udp_tx.store(7, Ordering::Relaxed);

    assert_eq!(
        Checkpoint::capture(1, 9, &stats).to_string(),
        "CHECK_POINT|MODE=1|PING=9ms|POOL=0|TCPS=2|UDPS=3|TCPRX=4|TCPTX=5|UDPRX=6|UDPTX=7"
    );
}

#[test]
fn checkpoint_passes_through_mix_policy_modes() {
    let stats = Stats::default();
    assert!(
        Checkpoint::capture(8, 0, &stats)
            .to_string()
            .starts_with("CHECK_POINT|MODE=8|")
    );
}
