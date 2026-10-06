// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Outbound source policy configuration boundaries.

use super::*;
use crate::common::query_first;
use url::Url;

impl From<&str> for DialPolicy {
    fn from(value: &str) -> Self {
        Self::from_query(&HashMap::from([("dial".to_owned(), value.to_owned())]))
            .expect("valid legacy source in test")
    }
}

fn parse(query: &str) -> Result<DialPolicy> {
    let url = Url::parse(&format!("portal://key@localhost:2000?{query}"))?;
    DialPolicy::from_query(&query_first(&url, &["dial", "dial4", "dial6"])?)
}

#[test]
fn source_policy_configuration_matrix() {
    for (query, summary, v4, v6) in [
        ("", "dial=auto", None, None),
        ("dial=auto", "dial=auto", None, None),
        (
            "dial4=127.0.0.1",
            "dial4=127.0.0.1 dial6=auto",
            Some("127.0.0.1"),
            None,
        ),
        ("dial6=::1", "dial4=auto dial6=::1", None, Some("::1")),
        (
            "dial4=127.0.0.1&dial6=%3A%3A1",
            "dial4=127.0.0.1 dial6=::1",
            Some("127.0.0.1"),
            Some("::1"),
        ),
        ("dial4=auto&dial6=auto", "dial4=auto dial6=auto", None, None),
        (
            "dial4=0.0.0.0&dial6=::",
            "dial4=0.0.0.0 dial6=::",
            Some("0.0.0.0"),
            Some("::"),
        ),
    ] {
        let policy = parse(query).unwrap();
        assert_eq!(policy.to_string(), summary);
        assert_eq!(
            policy.local_ip("192.0.2.1".parse().unwrap()).unwrap(),
            v4.map(|ip| ip.parse().unwrap())
        );
        assert_eq!(
            policy.local_ip("2001:db8::1".parse().unwrap()).unwrap(),
            v6.map(|ip| ip.parse().unwrap())
        );
    }
}

#[test]
fn legacy_sources_restrict_the_family() {
    for (source, other) in [
        ("127.0.0.1", "::1"),
        ("::1", "127.0.0.1"),
        ("0.0.0.0", "::1"),
        ("::", "127.0.0.1"),
    ] {
        let policy = parse(&format!("dial={source}")).unwrap();
        assert_eq!(
            policy.local_ip(source.parse().unwrap()).unwrap(),
            Some(source.parse().unwrap())
        );
        assert!(!policy.accepts(other.parse().unwrap()));
        assert!(policy.local_ip(other.parse().unwrap()).is_err());
    }
    assert!(parse("dial=::ffff:192.0.2.1").is_ok());
}

#[test]
fn rejects_conflicts_and_invalid_source_values() {
    for query in [
        "dial=auto&dial4=auto",
        "dial4=auto&dial=auto",
        "dial=127.0.0.1&dial6=::1",
        "dial6=::1&dial=::1",
        "dial4=",
        "dial6",
        "dial4=::1",
        "dial6=127.0.0.1",
        "dial6=::ffff:192.0.2.1",
        "dial4=localhost",
        "dial6=localhost",
        "dial4=127.0.0.1:80",
        "dial6=[::1]",
        "dial6=[::1]:80",
        "dial6=fe80::1%25en0",
        "dial4=Auto",
        "dial6=AUTO",
        "dial4=%20auto",
        "dial6=::1%20",
        "dial6=%GG",
    ] {
        assert!(parse(query).is_err(), "accepted {query}");
    }
}

#[test]
fn first_duplicate_is_selected_even_when_later_values_are_invalid() {
    assert_eq!(
        parse("dial4=auto&dial4=%GG&dial6=::1&dial6=bad")
            .unwrap()
            .to_string(),
        "dial4=auto dial6=::1"
    );
    assert!(parse("dial4=bad&dial4=auto").is_err());
    assert!(parse("dial=auto&dial=auto&dial4=auto").is_err());
}
