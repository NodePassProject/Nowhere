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
nowhere 'portal://secret@:2000?log=info'
```

The compact endpoint listens for TLS/TCP and QUIC on the same numeric port.
Use `portal://secret@*/tcp4:2006` for a TCP-only IPv4 listener, or
`portal://secret@*/tcp:2006/udp:2017` to use separate ports.

On a host with IPv4 and IPv6 available, choose a listener form from the service
edge you want to expose:

| Portal endpoint | TCP listeners | UDP listeners |
|---|---|---|
| `@:2000` | `0.0.0.0:2000`, `[::]:2000` | `0.0.0.0:2000`, `[::]:2000` |
| `@*:2000` | `0.0.0.0:2000`, `[::]:2000` | `0.0.0.0:2000`, `[::]:2000` |
| `@*/tcp:2006/udp:2017` | `0.0.0.0:2006`, `[::]:2006` | `0.0.0.0:2017`, `[::]:2017` |
| `@*/tcp4:2006` | `0.0.0.0:2006` | disabled |
| `@*/udp6:2017` | disabled | `[::]:2017` |

The IPv6 listeners are `V6ONLY`; the IPv4 and IPv6 rows represent separate
sockets. A hostname or IP literal replaces `*` when the Portal should bind
only selected interfaces. Hostnames are resolved once during startup.

For independent carrier ports, start Portal with:

```text
nowhere 'portal://secret@*/tcp:2006/udp:2017?log=info'
```

Portal prints one listening line for each bound TCP or UDP address. The TUI
shows the actual address lists after startup. A carrier must bind at least one
address; explicit families, concrete addresses, permission errors, and occupied
ports fail startup. Only an unrestricted `*` listener may continue when the
operating system does not support one address family.

## 2. Start Vector

Dedicated TLS lanes in both directions:

```text
nowhere 'vector://secret@127.0.0.1:2000?up=tcp&down=tcp&socks=127.0.0.1:1080'
```

QUIC in both directions:

```text
nowhere 'vector://secret@127.0.0.1:2000?up=udp&down=udp&socks=127.0.0.1:1080'
```

When Portal uses independent ports, Vector declares the same endpoint:

```text
nowhere 'vector://secret@127.0.0.1/tcp:2006/udp:2017?up=tcp&down=udp&socks=127.0.0.1:1080'
```

The carrier path describes what can be dialed. `up` and `down` choose from
those carriers for each logical direction. A single-carrier endpoint needs no
explicit direction policy:

```text
nowhere 'vector://secret@127.0.0.1/tcp4:2006?socks=127.0.0.1:1080'
nowhere 'vector://secret@[::1]/udp6:2017?socks=127.0.0.1:1080'
```

The first command defaults both directions to TCP; the second defaults both to
UDP. Vector rejects `up`, `down`, or `mix` when the endpoint does not declare
the required carrier. Vector resolves TCP and UDP independently and never
ignores a `4` or `6` suffix. Check the Portal log, local firewall, container
port publication, and the Vector endpoint together when one carrier is
unreachable.

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
nowhere 'vector://secret@127.0.0.1:2000?up=mix&down=mix&socks=127.0.0.1:1080'
```

`mix/mix` chooses `tcp/tcp` or `udp/udp` once per flow. A single mixed
direction can resolve to a split carrier pair. Declaring both carriers makes
every matrix cell reachable. The primary choice has a
`NOW_MIX_FALLBACK_TIMEOUT` budget (default `1s`).

TLS Mux is enabled on Vector. Portal recognizes the marked carrier
automatically:

```text
nowhere 'vector://secret@127.0.0.1:2000?up=tcp&down=tcp&mux=1&socks=127.0.0.1:1080'
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
