// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Case-insensitive filtering for TUI feed records.

use super::{AccessRecord, RuntimeRecord};

pub fn access_matches(record: &AccessRecord, lowercase_filter: &str) -> bool {
    lowercase_filter.is_empty()
        || record
            .protocol
            .to_ascii_lowercase()
            .contains(lowercase_filter)
        || record.route.to_ascii_lowercase().contains(lowercase_filter)
        || record
            .client
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(lowercase_filter))
        || record
            .target
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(lowercase_filter))
        || record
            .message
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(lowercase_filter))
}

pub fn runtime_matches(record: &RuntimeRecord, lowercase_filter: &str) -> bool {
    lowercase_filter.is_empty()
        || record.kind.to_ascii_lowercase().contains(lowercase_filter)
        || record
            .message
            .to_ascii_lowercase()
            .contains(lowercase_filter)
        || record
            .client
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(lowercase_filter))
}
