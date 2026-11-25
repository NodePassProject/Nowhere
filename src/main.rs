// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Command-line entry point for Portal, Vector and Egress.

use std::{env, error, fmt};

use anyhow::{Context, Result, bail};
use nowhere::{
    Egress, Logger, Portal, Vector, generate_key, run_fingerprint, run_probe, run_status,
    validate_endpoint_url_input,
};
use url::Url;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
struct ProbeFailed;

impl fmt::Display for ProbeFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("probe failed")
    }
}

impl error::Error for ProbeFailed {}

const HELP_TEXT: &str = "\
Usage:
  nowhere                              Show help and exit
  nowhere <portal-url>                 Run a Portal relay
  nowhere <vector-url>                 Run a SOCKS ingress Vector
  nowhere <egress-url>                 Run a TLS or QUIC Egress
  nowhere generate-key                 Generate a random 128-bit key as hex
  nowhere fingerprint <nowhere-url>    Read the TLS certificate SHA-256 fingerprint
  nowhere probe <vector-url> <target>  Test one real TCP Flow
  nowhere status                       Read one local telemetry snapshot
  nowhere -h | --help                  Show this help message
  nowhere -v | --version               Show version information

URL forms:
  portal://<key>@<endpoint>[?<options>]
  vector://<key>@<endpoint>?in=[user:pass@]host:port[&<options>]
  egress://<key>@<endpoint>[?<options>]
  nowhere://<key>@<host>:<port>[?<options>][#<name>]

Service options:
  out=<exit>          Portal direct (default), egress, or SOCKS5 address.
  tls=1|2             Portal generated certificate or supplied PEM files.
  crt=<path>          Portal certificate chain when tls=2.
  key=<path>          Portal private key when tls=2.
  in=<listener>       Vector SOCKS5 listener; optional for probe.
  dial=<ip|auto>      Portal/Egress target source binding.
  dial4=<ipv4|auto>   IPv4 source; mutually exclusive with dial.
  dial6=<ipv6|auto>   IPv6 source; mutually exclusive with dial.
  sni=<name|none>     Client verified server name; default endpoint host.
  pin=<sha256|none>   Exact certificate pin; otherwise system CA verification.
  morph=0|1|2         Morph: off, Full, or Core; default 1, both peers must agree.
  cipher=chacha|aes   Morph algorithm; default chacha, both peers must agree.
  rate=<mbps>         Vector-to-target limit; default 0 disables it.
  etar=<mbps>         Target-to-Vector limit; default 0 disables it.

Endpoint syntax:
  host:port                   Portal TLS+QUIC; Vector TLS; Egress QUIC.
  host/tcp:port               One TLS carrier for any role.
  host/udp:port               One QUIC carrier for any role.
  host/tcp:port/udp:port      Two carriers for Portal only.
  tcp4, udp4 / tcp6, udp6     Restrict a carrier to IPv4 or IPv6.
  *                           Portal wildcard; others require a concrete host.

Constraints:
  Vector and Egress paths each declare one carrier.
  out=egress accepts TLS/QUIC and rejects dial, dial4 and dial6.
  Shared keys require exactly 32 lowercase hex text characters.
  Unknown parameters are ignored; first recognized duplicate wins.
  fingerprint requires morph=0|1|2; net defaults to tcp.
  probe sends no target payload. fingerprint queries TCP/TLS only.

Documentation:
  https://github.com/NodePassProject/Nowhere/tree/main/docs
";

#[tokio::main]
async fn main() {
    if let Err(err) = start(env::args().collect()).await {
        if should_print_start_error(&err) {
            Logger.error(format_args!("{err:#}"));
        }
        std::process::exit(1);
    }
}

fn should_print_start_error(error: &anyhow::Error) -> bool {
    !error.is::<ProbeFailed>()
}

async fn start(args: Vec<String>) -> Result<()> {
    if args.len() == 1 {
        print_help();
        return Ok(());
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => {
            require_args(&args, 2, "nowhere --help")?;
            print_help();
            return Ok(());
        }
        "version" | "--version" | "-v" => {
            require_args(&args, 2, "nowhere --version")?;
            println!(
                "nowhere-v{VERSION} {}/{}",
                env::consts::OS,
                env::consts::ARCH
            );
            return Ok(());
        }
        "generate-key" => {
            require_args(&args, 2, "nowhere generate-key")?;
            println!("{}", generate_key()?);
            return Ok(());
        }
        "fingerprint" => {
            require_args(&args, 3, "nowhere fingerprint <nowhere-url>")?;
            let url = parse_command_url(&args[2]).context("invalid nowhere share link")?;
            return run_fingerprint(url).await;
        }
        "probe" => {
            require_args(&args, 4, "nowhere probe <URL> <TARGET>")?;
            let url = parse_toolbox_url(&args[2])?;
            return match run_probe(url, &args[3]).await? {
                true => Ok(()),
                false => Err(ProbeFailed.into()),
            };
        }
        "status" => {
            require_args(&args, 2, "nowhere status")?;
            return run_status().await;
        }
        _ => {}
    }
    if !args[1].contains("://") {
        bail!("unknown command; run \"nowhere --help\" for usage");
    }
    if args.len() > 2 {
        bail!("expected exactly one configuration URL; run \"nowhere --help\" for usage");
    }

    let command_url = parse_command_url(&args[1]).context("invalid configuration url")?;
    let scheme = command_url.scheme().to_string();
    if !matches!(scheme.as_str(), "portal" | "vector" | "egress") {
        bail!(
            "invalid configuration url: scheme must be portal, vector or egress, found {scheme:?}"
        );
    }
    let logger = Logger;

    match scheme.as_str() {
        "portal" => {
            let portal = Portal::new(command_url, logger)?;
            portal.run().await
        }
        "vector" => {
            let vector = Vector::new(command_url, logger)?;
            vector.run().await
        }
        "egress" => Egress::new(command_url, logger)?.run().await,
        _ => unreachable!("scheme was validated above"),
    }
}

fn require_args(args: &[String], expected: usize, usage: &str) -> Result<()> {
    if args.len() != expected {
        bail!("usage: {usage}");
    }
    Ok(())
}

fn parse_toolbox_url(raw: &str) -> Result<Url> {
    parse_command_url(raw).context("invalid configuration url")
}

fn print_help() {
    println!(
        "NOWHERE\n───────\nv{VERSION} · {}/{}\n\n{}",
        env::consts::OS,
        env::consts::ARCH,
        format_help()
    );
}

fn format_help() -> String {
    HELP_TEXT
        .lines()
        .map(|line| {
            if !line.starts_with(' ')
                && let Some(title) = line.strip_suffix(':')
            {
                format!(
                    "{}\n{}",
                    title.to_ascii_uppercase(),
                    "─".repeat(title.len())
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_command_url(raw: &str) -> Result<Url> {
    validate_endpoint_url_input(raw, "endpoint")?;
    Ok(Url::parse(raw)?)
}

#[cfg(test)]
#[path = "tests/main/mod.rs"]
mod tests;
