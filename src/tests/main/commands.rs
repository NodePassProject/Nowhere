// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! CLI command dispatch and argument counts.

use super::super::start;

#[tokio::test]
async fn commands_reject_extra_arguments() {
    for command in ["help", "version", "status", "generate-key"] {
        let error = start(vec![
            "nowhere".to_owned(),
            command.to_owned(),
            "extra".to_owned(),
        ])
        .await
        .unwrap_err();
        assert!(error.to_string().starts_with("usage:"));
    }
}

#[tokio::test]
async fn fingerprint_requires_exactly_one_share_link() {
    for arguments in [
        vec!["nowhere", "fingerprint"],
        vec![
            "nowhere",
            "fingerprint",
            "nowhere://secret@localhost:2000#My%20Portal",
            "extra",
        ],
    ] {
        let error = start(arguments.into_iter().map(str::to_owned).collect())
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "usage: nowhere fingerprint <nowhere-url>"
        );
    }
}

#[tokio::test]
async fn probe_requires_exactly_a_url_and_target() {
    for arguments in [
        vec![
            "nowhere",
            "probe",
            "vector://0123456789abcdef0123456789abcdef@localhost:2000",
        ],
        vec![
            "nowhere",
            "probe",
            "vector://0123456789abcdef0123456789abcdef@localhost:2000",
            "example.com:443",
            "extra",
        ],
    ] {
        let error = start(arguments.into_iter().map(str::to_owned).collect())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "usage: nowhere probe <URL> <TARGET>");
    }
}

#[tokio::test]
async fn no_arguments_succeeds_without_a_terminal_and_unknown_commands_fail() {
    start(vec!["nowhere".to_owned()]).await.unwrap();
    let error = start(vec!["nowhere".to_owned(), "unknown-command".to_owned()])
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with("unknown command"));
}
