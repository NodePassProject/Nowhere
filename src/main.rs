// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Command-line entry point for running a Nowhere Portal or Vector.

use std::env;
use std::io::IsTerminal;

use anyhow::{Context, Result, bail};
use nowhere::common::{LogLevel, Logger, query_first, validate_endpoint_url_input};
use nowhere::portal::Portal;
use nowhere::vector::Vector;
use url::{ParseError, Url};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const HELP_TEXT: &str = "\
Usage:
  nowhere
  nowhere tui
  nowhere <portal-or-vector-url>
  nowhere -h | --help
  nowhere -v | --version

Commands:
  tui              Open the read-only multi-instance TUI.
  <portal-url>     Run the Portal relay service.
  <vector-url>     Run the Vector native SOCKS5 client.
  -h, --help       Print this help message.
  -v, --version    Print version and target platform.

Portal URL:
  portal://<shared-key>@<listen-host>:<listen-port>[?<parameters>]
  portal://<shared-key>@<listen-host>/<carrier>:<port>[/<carrier>:<port>]

Vector URL:
  vector://<shared-key>@<portal-host>:<portal-port>?socks=<listen-endpoint>[&<parameters>]
  vector://<shared-key>@<portal-host>/<carrier>:<port>[/<carrier>:<port>]?socks=...

Examples:
  nowhere 'portal://secret@:2077'
  nowhere 'portal://secret@*/tcp4:2077?log=info'
  nowhere 'portal://secret@*/tcp:2077/udp:3088'
  nowhere 'portal://secret@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
  nowhere 'portal://secret@:2077?socks=user:pass@127.0.0.1:1080'
  nowhere 'portal://relay-key@:2077?next=upstream-key@origin.example:2077'
  nowhere 'portal://relay-key@:2077?next=upstream-key@origin.example:2077&up=tcp&down=tcp'
  nowhere 'portal://secret@:2077?rate=100&etar=200'
  nowhere 'vector://secret@relay.example:2077?sni=relay.example&socks=127.0.0.1:1080'
  nowhere 'vector://secret@127.0.0.1:2077?up=tcp&down=tcp&socks=:1080'

Required URL parts:
  shared-key       Non-empty URL username. Percent-encode reserved characters.
  endpoint-port    Portal listen port or remote Portal port.
  Password credentials are not supported.

Listen host:
  *                Bind IPv4 and IPv6 wildcard sockets as allowed by carrier.
  empty            Compact form only; equivalent to *.
  0.0.0.0          Bind IPv4 wildcard only.
  [::]             Bind IPv6 wildcard only.
  IP or hostname   Bind all matching resolved listen addresses.

Portal parameters:
  tls=1|2          TLS mode. 1 for RAM certificate; 2 for PEM files. Default: 1.
                   tls=0 is not supported.
  crt=<path>       PEM certificate chain for tls=2.
  key=<path>       PEM private key for tls=2.
  rate=<mbps>      Client-to-target traffic limit. 0 disables it.
  etar=<mbps>      Target-to-client traffic limit. 0 disables it.
  dial=<ip|auto>   Local source IP for outbound target connections. Default: auto.
  socks=<proxy>    SOCKS5 outbound proxy: host:port or user:pass@host:port.
                   Omit or use none to disable.
  next=<portal>    Native upstream Portal using the same endpoint grammar.
                   Example: shared-key@host/tcp:2077/udp6:3088. Omit or use
                   none to disable. Mutually exclusive with socks.
  up=tcp|udp|mix   Native upstream upload carrier. Mix chooses per flow.
                   Defaults to the only declared carrier, or UDP.
  down=tcp|udp|mix Native upstream download carrier. Mix chooses per flow.
                   Defaults to the only declared carrier, or UDP.
  mux=0|1          Use TLS Mux when the native route can select TCP. Default: 0.
  sni=<name|none>  Native upstream certificate DNS name. Default: none.
  pin=<sha256|none> Native upstream certificate fingerprint. Default: none.
                   These five options are ignored unless next is enabled.
  log=<level>      none, debug, info, warn, error, event. Default: info.

Vector parameters:
  up=tcp|udp|mix   Upload carrier. Defaults to the only declared carrier, or UDP.
  down=tcp|udp|mix Download carrier. Defaults to the only declared carrier, or UDP.
  mux=0|1          Use TLS Mux when either direction can select TCP. Default: 0.
  sni=<name|none>  Verify the certificate for a DNS name. Empty, omitted, or
                   none disables certificate validation. Default: none.
  pin=<sha256|none> Pin the server certificate SHA-256 fingerprint. Empty,
                    omitted, or none disables pinning. Default: none.
  rate=<mbps>      SOCKS client-to-target limit. 0 disables it.
  etar=<mbps>      Target-to-SOCKS client limit. 0 disables it.
  socks=<listener> Required SOCKS5 listener: [user:pass@]host:port.
                   An empty host, as in :1080, binds IPv4 and IPv6 wildcards.
  log=<level>      none, debug, info, warn, error, event. Default: info.

Query handling:
  Unknown parameters are ignored. If a parameter appears more than once, only
  its first value is used. Missing optional parameters use their defaults.
  The net parameter is ignored; carrier paths select listeners.

Carrier endpoint grammar:
  tcp, udp          Do not restrict the address family.
  tcp4, udp4        Use IPv4 only.
  tcp6, udp6        Use IPv6 only.
  host:port         Shorthand for TCP and UDP on the same port.

Transport capabilities:
  TLS/TCP          TCP relay and UDP-over-TCP (UoT).
  QUIC/UDP         TCP relay streams and DATAGRAM UDP flows.

SOCKS5 outbound:
  CONNECT proxies every TCP relay. UDP ASSOCIATE proxies every DATAGRAM/UoT flow.
  Target hostnames are resolved by the proxy. Proxy failure never falls back direct.
  Percent-encode reserved characters in SOCKS usernames and passwords.

SOCKS5 inbound:
  Vector supports CONNECT and UDP ASSOCIATE. BIND is not supported.
  Configured username/password authentication cannot downgrade to no-auth.
  SOCKS5 UDP fragmentation is not supported.

Environment:
  NOW_MAX_TCP_FLOWS         TCP flows per authenticated client session.
  NOW_MAX_UDP_FLOWS         UDP flows per authenticated client session.
  NOW_QUIC_UDP_QUEUE_BYTES  Maximum queued/reassembling UDP bytes per QUIC connection.
  NOW_QUIC_MEMORY_PROFILE   memory, balanced, or throughput. Default: throughput.
  NOW_MAX_PENDING_PAIRS     Maximum pending logical-flow IDs per session.
  NOW_FLOW_PAIR_TIMEOUT     Timeout for completing a split logical flow.
  NOW_FLOW_SETUP_TIMEOUT    Timeout for waiting for a logical flow to become ready.
  NOW_MIX_FALLBACK_TIMEOUT  Primary Mix route preparation budget. Default: 1s.
  NOW_TCP_DATA_BUF_SIZE     TCP relay buffer size.
  NOW_UDP_DATA_BUF_SIZE     UDP target receive buffer size.
  NOW_TCP_DIAL_TIMEOUT      TCP target dial timeout.
  NOW_UDP_DIAL_TIMEOUT      UDP target dial timeout.
  NOW_TCP_READ_TIMEOUT      TCP half-close grace timeout.
  NOW_UDP_IDLE_TIMEOUT      QUIC and DATAGRAM/UoT flow idle timeout.
  NOW_HANDSHAKE_TIMEOUT     Per-phase TLS, authentication, and request deadline.
  NOW_REPORT_INTERVAL       Local CHECK_POINT report interval.
  NOW_TELEMETRY_INTERVAL    Local TUI telemetry interval (250ms..60s; default 1s).
  NOW_SERVICE_COOLDOWN      Transport reconnect retry delay.
  NOW_SHUTDOWN_TIMEOUT      Graceful shutdown wait.
  NOW_RELOAD_INTERVAL       Minimum PEM certificate reload interval.
";

#[tokio::main]
async fn main() {
    if let Err(err) = start(env::args().collect()).await {
        eprintln!("{}", format_start_error(&err));
        std::process::exit(1);
    }
}

fn format_start_error(error: &anyhow::Error) -> String {
    format!("error: {error:#}")
}

async fn start(args: Vec<String>) -> Result<()> {
    if args.len() == 1 {
        return run_tui().await;
    }
    if args.len() > 2 {
        bail!("expected exactly one configuration URL; run 'nowhere --help' for usage");
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            return Ok(());
        }
        "version" | "--version" | "-v" => {
            println!(
                "nowhere-v{VERSION} {}/{}",
                env::consts::OS,
                env::consts::ARCH
            );
            return Ok(());
        }
        "tui" => return run_tui().await,
        _ => {}
    }

    let command_url = parse_command_url(&args[1]).with_context(|| "invalid configuration URL")?;
    let scheme = command_url.url.scheme().to_string();
    if !matches!(scheme.as_str(), "portal" | "vector") {
        bail!("invalid configuration URL: scheme must be portal or vector, found {scheme:?}");
    }
    // Startup only needs `log` here. Each role parses its own configuration,
    // including Portal's intentionally ignored upstream options when `next`
    // is disabled.
    let query = query_first(&command_url.url, &["log"])
        .with_context(|| "invalid configuration URL query")?;
    let logger = init_logger(query.get("log").map(String::as_str))?;

    match scheme.as_str() {
        "portal" => {
            let portal = Portal::new_with_listen_host(
                command_url.url,
                command_url.listen_host.as_deref(),
                logger,
            )?;
            portal.run().await
        }
        "vector" => {
            let vector = Vector::new(command_url.url, logger)?;
            vector.run().await
        }
        _ => unreachable!("scheme was validated above"),
    }
}

async fn run_tui() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("main::run_tui: an interactive terminal is required")
    }
    nowhere::tui::run().await
}

fn print_help() {
    println!(
        "nowhere-v{VERSION} {}/{}\n\n{HELP_TEXT}",
        env::consts::OS,
        env::consts::ARCH
    );
}

struct CommandUrl {
    url: Url,
    listen_host: Option<String>,
}

fn parse_command_url(raw: &str) -> Result<CommandUrl> {
    validate_endpoint_url_input(raw, "endpoint")?;
    match Url::parse(raw) {
        Ok(url) => Ok(CommandUrl {
            url,
            listen_host: None,
        }),
        Err(ParseError::EmptyHost) => {
            let normalized = normalize_empty_portal_host(raw)
                .ok_or(ParseError::EmptyHost)
                .and_then(|url| Url::parse(&url))?;
            Ok(CommandUrl {
                url: normalized,
                listen_host: Some(String::new()),
            })
        }
        Err(err) => Err(err.into()),
    }
}

fn normalize_empty_portal_host(raw: &str) -> Option<String> {
    let prefix = "portal://";
    let rest = raw.strip_prefix(prefix)?;
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_len);
    let host_port_start = authority.rfind('@').map_or(0, |idx| idx + 1);
    let host_port = &authority[host_port_start..];

    if !host_port.starts_with(':') || host_port.len() == 1 {
        return None;
    }

    let mut normalized = String::with_capacity(raw.len() + "localhost".len());
    normalized.push_str(prefix);
    normalized.push_str(&authority[..host_port_start]);
    normalized.push_str("localhost");
    normalized.push_str(host_port);
    normalized.push_str(suffix);
    Some(normalized)
}

fn init_logger(level: Option<&str>) -> Result<Logger> {
    let logger = Logger::new(LogLevel::Info, true);
    match level {
        None | Some("info") => {}
        Some("none") => logger.set_log_level(LogLevel::None),
        Some("debug") => {
            logger.set_log_level(LogLevel::Debug);
            logger.debug(format_args!("main::init_logger: log level set to DEBUG"));
        }
        Some("warn") => {
            logger.set_log_level(LogLevel::Warn);
            logger.warn(format_args!("main::init_logger: log level set to WARN"));
        }
        Some("error") => {
            logger.set_log_level(LogLevel::Error);
            logger.error(format_args!("main::init_logger: log level set to ERROR"));
        }
        Some("event") => {
            logger.set_log_level(LogLevel::Event);
            logger.event(format_args!("main::init_logger: log level set to EVENT"));
        }
        Some(value) => {
            bail!("log must be none, debug, info, warn, error, or event; found {value:?}")
        }
    }
    Ok(logger)
}

#[cfg(test)]
#[path = "tests/main.rs"]
mod tests;
