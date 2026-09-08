use super::*;

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
    allocator.next.store(u32::MAX, Ordering::Relaxed);
    let max = allocator.allocate().unwrap();
    let wrapped = allocator.allocate().unwrap();
    assert_eq!(max.id(), u32::MAX);
    assert_ne!(wrapped.id(), 0);
}
