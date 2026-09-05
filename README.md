<p align="center">
  <img src="assets/nowhere.png" width="540" alt="Nowhere">
</p>

<p align="center">
  <strong>Two-transport encrypted relay with independently split directions</strong>
</p>

<p align="center">
  A cross-platform encrypted relay that composes TLS/TCP and QUIC/UDP<br>
  independently for upload and download.
</p>

<p align="center">
  <a href="#live-operations">Live operations</a> &middot;
  <a href="#how-it-works">Architecture</a> &middot;
  <a href="#quick-start">Quick start</a> &middot;
  <a href="docs/README.md">Documentation</a> &middot;
  <a href="docs/protocol.md">Wire protocol</a>
</p>

Nowhere gives one service edge two encrypted carrier families. A local
**Vector** accepts SOCKS5 traffic; a remote **Portal** authenticates carriers,
opens targets, and relays data. Every logical flow chooses its uplink and
downlink independently instead of forcing both directions onto one transport.

| Core property | What it means |
| --- | --- |
| One service edge | TLS/TCP and QUIC/UDP share one host, credential, and lifecycle, with independent ports and address families |
| Split directions | Uplink and downlink independently select TLS/TCP or QUIC/UDP |
| Complete ingress | SOCKS5 CONNECT carries TCP; UDP ASSOCIATE carries UDP |
| Native chaining | A Portal can forward directly to another Portal without a loopback SOCKS5 conversion |
| Local observability | The same binary discovers running instances and renders live telemetry metrics |

## Live operations

<p align="center">
  <img src="assets/nowhere.gif" width="1280" alt="Nowhere TUI showing live traffic histories, connection and carrier metrics, privacy-aware access logs, runtime events, filtering, pause, and help">
</p>

The read-only TUI discovers Portal and Vector instances for the current user.
It presents traffic, carriers, process metrics, Access logs, and Runtime logs
without owning the service lifecycle. Start it from another terminal:

```bash
nowhere tui
```

## How it works

```text
 Application
  TCP / UDP
      |
    SOCKS5
      |
      v
+------------+  Uplink carrier   +--------------+  Native `next` uplink   +-------------+
|   Vector   |==================>| Entry Portal |========================>| Next Portal |
|            |<==================|              |<========================| (optional)  |
+------------+  Downlink carrier +--------------+  Native `next` downlink +-------------+
                                         |                                       |
                                 direct or SOCKS5                        direct or SOCKS5
                                         |                                       |
                                         v                                       v
                                  +------------+                          +------------+
                                  |   Target   |                          |   Target   |
                                  +------------+                          +------------+
```

Every service URL has one shared host and either a compact or explicit
endpoint. The compact form enables both carriers on one port. The explicit
form enables only the listed carriers and gives each one its own port and
address-family policy.

| Endpoint | Meaning |
|---|---|
| `@*:2000` | TLS/TCP and QUIC/UDP wildcard candidates, port 2000 |
| `@*/tcp:2006` | TLS/TCP only, IPv4 and IPv6 |
| `@*/udp:2017` | QUIC/UDP only, IPv4 and IPv6 |
| `@*/tcp4:2006/udp6:2017` | TLS/TCP on IPv4 and QUIC/UDP on IPv6 |

`*` is a Portal listen host. Vector and `next` use a concrete IP address or
hostname. The compact Portal form also accepts an empty host, so `@:2000` and
`@*:2000` have the same meaning. See
[Configuration](docs/configuration.md) for the complete grammar, validation
rules, DNS behavior, family availability, and canonical output.

### One flow, two transport decisions

Vector's `up` and `down` parameters accept `tcp`, `udp`, or `mix`:

| `up` ↓ / `down` → | `tcp` | `udp` | `mix` |
|---|---|---|---|
| `tcp` | TT | TQ | TT ↔ TQ |
| `udp` | QT | QQ | QT ↔ QQ |
| `mix` | TT ↔ QT | TQ ↔ QQ | TT ↔ QQ |

T means TLS/TCP and Q means QUIC/UDP, with uplink first. Each mixed cell makes
one stateless 50/50 choice per flow; `mix/mix` produces only TT or QQ. The
primary route has a `NOW_MIX_FALLBACK_TIMEOUT` budget (default `1s`), then the
other route is attempted once with a new flow ID. FlowHeader carries only the
resolved concrete pair, and no fallback occurs after its write begins. Portal
`next=` applies the same policy independently per hop.

## Engineered for a small data path

The data path uses compact binary frames, connection-bound authentication,
reusable buffers, bounded queues, and native QUIC streams and DATAGRAMs. TLS
flows use dedicated lanes or lazily opened Mux Shards. Detailed framing and
resource bounds live in [Protocol](docs/protocol.md) and
[Security](docs/security.md).

### Native Portal chaining

A relay Portal can terminate the incoming TLS/QUIC carrier and open the next
Nowhere flow directly with the same transport engine used by Vector:

```bash
nowhere \
  'portal://relay-key@:2000?next=origin-key@origin.example:2000&up=udp&down=udp'
```

`next` is lazy and mutually exclusive with outbound `socks`. Portal forwarding
uses the native flow protocol and is bounded to seven hops.

## Quick start

Building from source requires a supported target and a stable Rust toolchain.

### 1. Build

```bash
cargo build --release --locked
```

### 2. Start Portal

The compact endpoint accepts TLS/TCP and QUIC/UDP on port `2000`:

```bash
./target/release/nowhere 'portal://change-me@127.0.0.1:2000'
```

### 3. Start Vector

This Vector exposes SOCKS5 on `127.0.0.1:1080`:

```bash
./target/release/nowhere \
  'vector://change-me@127.0.0.1:2000?up=tcp&down=tcp&socks=127.0.0.1:1080'
```

Mux, split-carrier, certificate, and chaining examples are in the
[configuration guide](docs/configuration.md) and
[quick start](docs/quick-start.md).

### 4. Inspect

Open another terminal and run:

```bash
./target/release/nowhere tui
```

## Before public deployment

The local examples omit `sni`, which disables certificate verification. A
public Portal should use a CA-trusted certificate with strict verification:

```bash
nowhere 'portal://change-me@:2000?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
nowhere 'vector://change-me@relay.example:2000?sni=relay.example&socks=127.0.0.1:1080'
```

Certificate pinning is also available. Review the
[security model](docs/security.md) and [configuration](docs/configuration.md)
before exposing a Portal publicly.

## Operational boundaries

Portal, Vector, relay, TUI, and local discovery run on every supported
platform; process telemetry varies by operating system. See
[Platforms](docs/platforms.md) and [Operations](docs/operations.md).

## Documentation map

Start with the [documentation index](docs/README.md). It links the focused
guides for configuration, protocol, security, operations, platforms, and
integrations.

## Development

Run the project checks on a supported host:

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

On macOS with [Apple Container](https://github.com/apple/container), the
reusable Linux check environment remains available:

```bash
./scripts/check-linux.sh
```

CI runs the project on Linux, macOS, and Windows. Release packaging covers
Linux GNU/musl on x86-64 and AArch64, macOS on Apple Silicon, and Windows
x86-64 MSVC.

Protocol changes must update the normative wire document and protocol-vector
tests in the same change.

## License

Nowhere is licensed under the [GNU General Public License v3.0](LICENSE).
Distributions of original or modified binaries must comply with the GPLv3
source and notice requirements.

---

© 2026 NodePassProject. All rights reserved.
