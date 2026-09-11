use super::*;

#[test]
fn exhausted_allocator_recovers_only_released_ids() {
    let allocator = FlowIdAllocator::new();
    let first = allocator.allocate_with_limit(3).unwrap();
    let second = allocator.allocate_with_limit(3).unwrap();
    let third = allocator.allocate_with_limit(3).unwrap();
    assert!(
        allocator
            .allocate_with_limit(3)
            .unwrap_err()
            .to_string()
            .contains("space exhausted")
    );
    let released = second.id();
    drop(second);
    let reused = allocator.allocate_with_limit(3).unwrap();
    assert_eq!(reused.id(), released);
    assert_ne!(reused.id(), first.id());
    assert_ne!(reused.id(), third.id());
    assert!(allocator.allocate_with_limit(3).is_err());
}

#[test]
fn allocator_never_reuses_an_active_id() {
    let allocator = FlowIdAllocator::new();
    let first = allocator.allocate().unwrap();
    let second = allocator.allocate().unwrap();
    assert_ne!(first.id(), second.id());
    let extra: Vec<_> = (0..4096).map(|_| allocator.allocate().unwrap()).collect();
    assert_eq!(extra.len(), 4096);
    let released = first.id();
    drop(first);
    let third = allocator.allocate().unwrap();
    assert_ne!(third.id(), second.id());
    assert!(released != 0);
}

#[test]
fn allocator_skips_zero_at_wrap() {
    let allocator = FlowIdAllocator::new();
    let first = allocator.allocate().unwrap();
    assert_eq!(first.id(), 1);
    allocator.next.store(MAX_FLOW_ID, Ordering::Relaxed);
    let max = allocator.allocate().unwrap();
    let wrapped = allocator.allocate().unwrap();
    assert_eq!(max.id(), MAX_FLOW_ID);
    assert_eq!(wrapped.id(), 2);
}
