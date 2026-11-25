// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! CLI command dispatch and argument counts.

use super::super::start;

#[tokio::test]
async fn commands_report_usage_for_incorrect_argument_counts() {
    const SHARE: &str = "nowhere://0123456789abcdef0123456789abcdef@localhost:2000?morph=0";
    const VECTOR: &str = "vector://0123456789abcdef0123456789abcdef@localhost:2000";
    const FINGERPRINT_USAGE: &str = "usage: nowhere fingerprint <nowhere-url>";
    const PROBE_USAGE: &str = "usage: nowhere probe <URL> <TARGET>";
    let cases: &[(&[&str], &str)] = &[
        (&["help", "extra"], "usage: nowhere --help"),
        (&["version", "extra"], "usage: nowhere --version"),
        (&["status", "extra"], "usage: nowhere status"),
        (&["generate-key", "extra"], "usage: nowhere generate-key"),
        (&["fingerprint"], FINGERPRINT_USAGE),
        (&["fingerprint", SHARE, "extra"], FINGERPRINT_USAGE),
        (&["probe", VECTOR], PROBE_USAGE),
        (&["probe", VECTOR, "example.com:443", "extra"], PROBE_USAGE),
    ];
    for (args, usage) in cases {
        let arguments = std::iter::once("nowhere")
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect();
        let error = start(arguments).await.unwrap_err();
        assert_eq!(error.to_string(), *usage);
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
