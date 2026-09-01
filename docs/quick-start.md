# Quick Start

Use a release archive for a supported target or build with
`cargo build --release --locked`. The commands below work in Linux/macOS
shells and PowerShell. Windows Command Prompt users should replace single
quotes with double quotes and invoke `nowhere.exe`.

```text
+-------------+  SOCKS5  +--------+  encrypted carrier  +--------+  TCP/UDP  +--------+
| Application |<-------->| Vector |<===================>| Portal |<--------->| Target |
+-------------+          +--------+                     +--------+           +--------+
                              ^                              ^
                              | read-only telemetry          | read-only telemetry
                              +---------------+--------------+
                                              |
                                          +---+---+
                                          |  TUI  |
                                          +-------+
```

Portal and Vector are long-running processes. The TUI is an optional local
observer and does not start, stop, or reconfigure either process.

## 1. Start Portal

```text
nowhere 'portal://secret@:2077?log=info'
```

Portal listens for TLS/TCP and QUIC on the same numeric port when `net=mix`
(the default).

## 2. Start Vector

Dedicated TLS lanes in both directions:

```text
nowhere 'vector://secret@127.0.0.1:2077?up=tcp&down=tcp&socks=127.0.0.1:1080'
```

QUIC in both directions:

```text
nowhere 'vector://secret@127.0.0.1:2077?up=udp&down=udp&socks=127.0.0.1:1080'
```

The full route-policy matrix is:

| `up` ↓ / `down` → | `tcp` | `udp` | `mix` |
|---|---|---|---|
| `tcp` | TT | TQ | TT ↔ TQ |
| `udp` | QT | QQ | QT ↔ QQ |
| `mix` | TT ↔ QT | TQ ↔ QQ | TT ↔ QQ |

T means TLS/TCP and Q means QUIC/UDP, with uplink first. A `↔` cell chooses one
route per flow and can use the other once if primary preparation fails.

Stateless per-flow selection across full-duplex TLS and QUIC uses:

```text
nowhere 'vector://secret@127.0.0.1:2077?up=mix&down=mix&socks=127.0.0.1:1080'
```

`mix/mix` chooses `tcp/tcp` or `udp/udp` once per flow. A single mixed
direction can resolve to a split carrier pair. `net=mix` makes every matrix
cell reachable. The primary choice has a `NOW_MIX_FALLBACK_TIMEOUT` budget
(default `1s`).

TLS Mux is enabled on Vector. Portal recognizes the marked carrier
automatically:

```text
nowhere 'vector://secret@127.0.0.1:2077?up=tcp&down=tcp&mux=1&socks=127.0.0.1:1080'
```

Nowhere 2 negotiates `nw2` with another V2 peer and falls back to `now/1` when
connecting to a default V1 peer. There is no configurable ALPN parameter; Mux
selection is independent from protocol version.
`udp/udp&mux=1` is canonicalized to `mux=0` because no TLS lane can use it.

## 3. Use SOCKS5

```text
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

On Windows, use `curl.exe` to avoid PowerShell aliases:

```text
curl.exe --proxy socks5h://127.0.0.1:1080 https://example.com/
```

Vector supports SOCKS5 CONNECT and UDP ASSOCIATE. Configure credentials with
the `socks` URL value when required; see
[Configuration](configuration.md).

## 4. Open the TUI

Run `nowhere` without a URL. Local instances are discovered through a per-user
registry and loopback control socket on Linux, macOS, and Windows. Use page `1`
for Overview and page `2` for Logs.

See [Platforms](platforms.md) for release targets, native paths, process
control, and telemetry differences. Before exposing Portal publicly, configure
certificate verification as described in [Security](security.md).
