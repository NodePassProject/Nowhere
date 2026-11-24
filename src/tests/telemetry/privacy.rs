// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Endpoint/target validation and random instance identity regressions.

use super::*;

#[test]
fn instance_ids_are_random_lowercase_hex() {
    let first = random_id().unwrap();
    let second = random_id().unwrap();
    assert_eq!(first.len(), 32);
    assert!(
        first
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
    );
    assert_ne!(first, second);
}
