# Quick start

Connect applications to a trusted Portal through a local SOCKS5 ingress.

## Contents

- [Before you begin](#before-you-begin)
- [Build and create a key](#build-and-create-a-key)
- [Start Portal](#start-portal)
- [Establish trust](#establish-trust)
- [Connect applications](#connect-applications)
- [Verify the connection](#verify-the-connection)
- [Choose the exit](#choose-the-exit)

## Before you begin

Use a stable Rust toolchain and a reachable Portal host. The examples use TCP
port `2000` and UDP port `2001`; permit both through the Portal host's firewall.
Run each service in its own terminal or process supervisor.

Replace `KEY` with the same generated value on each peer. Replace
`relay.example` with the Portal host and `TRUSTED_SHA256` with its verified
certificate fingerprint. See [Platforms](platforms.md) for Windows and
container command lines.

## Build and create a key

Build from the repository root:

```sh
cargo build --release --locked
```

Generate a Shared Key of 32 lowercase hexadecimal characters:

```sh
./target/release/nowhere generate-key
```

## Start Portal

Listen for TLS on TCP `2000` and QUIC on UDP `2001`:

```sh
./target/release/nowhere "portal://KEY@*/tcp:2000/udp:2001"
```

Portal generates a new self-signed certificate on every start. Its startup log
includes the fingerprint needed for the next step. After a restart, verify the
new fingerprint and update pinned clients. For a persistent certificate, use
`tls=2` with supplied PEM files; see [certificate trust](security.md#certificate-trust).

## Establish trust

Read the presented certificate over TCP/TLS:

```sh
./target/release/nowhere fingerprint "nowhere://KEY@relay.example:2000?morph=1"
```

Compare the result with Portal's fingerprint obtained through a trusted channel,
such as its startup log on a host you control. Use the matching value for `pin`.
A CA-issued certificate with a matching hostname can be used instead; see
[certificate trust](security.md#certificate-trust).

## Connect applications

Run Vector with a local SOCKS5 listener:

```sh
./target/release/nowhere "vector://KEY@relay.example/tcp:2000?in=127.0.0.1:1080&pin=TRUSTED_SHA256"
```

Point applications at SOCKS5 `127.0.0.1:1080`. This listener has no SOCKS
credentials and is bound to loopback. The example selects dedicated TLS on TCP
`2000`; use `relay.example/udp:2001` to select QUIC. See
[SOCKS5 ingress](configuration.md#socks5-ingress) before exposing a listener.

## Verify the connection

Perform one TCP Flow setup through the QUIC path:

```sh
./target/release/nowhere probe "vector://KEY@relay.example/udp:2001?pin=TRUSTED_SHA256" "example.com:443"
```

Probe sends no target payload and does not require `in`. Read local instance identity and traffic statistics on either host:

```sh
./target/release/nowhere status
```

Both commands work without a terminal. Status reads one snapshot and exits.

## Choose the exit

Portal forwards directly by default. Use a SOCKS5 upstream through `out`, or
register a remote Egress with `out=egress`.

| Next step | Guide |
|---|---|
| Choose listeners, transports or a SOCKS5 upstream | [Configuration](configuration.md) |
| Place target access on another host | [Egress](egress.md) |
| Diagnose setup or observe a service | [Operations](operations.md) |
