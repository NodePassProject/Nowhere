# Configuration

URLs and environment variables have the same meaning on Linux, macOS, and
Windows. Shell quoting and filesystem path syntax follow the host platform;
see [Platforms](platforms.md).

## Portal URL

```text
portal://shared-key@host:port?net=mix&tls=1&log=info
```

| Query | Values | Default |
|---|---|---|
| `net` | `mix`, `tcp`, `udp` | `mix` |
| `tls` | `1` generated certificate, `2` supplied certificate | `1` |
| `crt`, `key` | PEM paths, required with `tls=2` | — |
| `rate`, `etar` | Mbps, `0` disables limit | `0` |
| `dial` | `auto` or local IP | `auto` |
| `socks` | outbound SOCKS5 configuration | disabled |
| `next` | `shared-key@host:port` | disabled |
| `up`, `down` | native next-hop policy: `tcp`, `udp`, or `mix` | `udp` |
| `mux` | native next-hop TLS: `0` dedicated lanes, `1` Mux when TCP is possible | `0` |
| `sni` | native next-hop verified DNS name, or `none` | `none` |
| `pin` | native next-hop certificate SHA-256 pin, or `none` | `none` |
| `log` | `none`, `debug`, `info`, `warn`, `error`, `event` | `info` |

When `next` is enabled, `up`, `down`, `mux`, `sni`, and `pin` configure that
upstream hop. Protocol version is negotiated independently with the next
Portal. These upstream options are ignored when `next` is absent or `none`.
`socks` and `next` are mutually exclusive outbound paths.

## Vector URL

```text
vector://shared-key@host:port?up=tcp&down=tcp&socks=127.0.0.1:1080
```

| Query | Values | Default |
|---|---|---|
| `up`, `down` | `tcp`, `udp`, or `mix` | `udp` |
| `mux` | `0` dedicated TLS lanes, `1` TLS Mux | `0` |
| `sni` | verified DNS name, or `none` | `none` |
| `pin` | certificate SHA-256 pin, or `none` | `none` |
| `rate`, `etar` | Mbps, `0` disables limit | `0` |
| `socks` | required local listen address, optionally credentials | — |
| `log` | logging threshold | `info` |

## Option scope

```text
Portal URL
    |
    +-- listener: net, tls, crt, key
    +-- relay:    rate, etar, dial, log
    |
    +-- outbound path
          |
          +-- direct target access
          +-- socks  --> SOCKS5 proxy --> target
          +-- next   --> {up, down, mux, sni, pin} --> Portal

Vector URL
    |
    +-- Portal client: up, down, mux, sni, pin
    +-- SOCKS5 edge:   socks
    +-- relay:         rate, etar, log
```

`rate` limits client-to-target traffic and `etar` limits target-to-client
traffic. The direction names have the same meaning through a native Portal
chain.

`mix` is a per-flow client policy. A single mixed direction randomly selects
TLS/TCP or QUIC/UDP; a fixed direction always uses its configured carrier.
`mix/mix` uses one correlated choice and resolves only to `tcp/tcp` or
`udp/udp`. The resolved pair is fixed for the flow and is the only value
written to FlowHeader. Each native Portal hop resolves its policy
independently.

| `up` ↓ / `down` → | `tcp` | `udp` | `mix` |
|---|---|---|---|
| `tcp` | TT | TQ | TT ↔ TQ |
| `udp` | QT | QQ | QT ↔ QQ |
| `mix` | TT ↔ QT | TQ ↔ QQ | TT ↔ QQ |

T means TLS/TCP and Q means QUIC/UDP; uplink is written first. `↔` marks the
two routes eligible for the initial random choice and the single pre-commit
fallback.

The primary route must acquire all lanes within `NOW_MIX_FALLBACK_TIMEOUT`
(default `1s`). Failure or timeout discards its local resources and starts the
other allowed route once with a new flow ID. READY failures, target dial
failures, and established payload failures do not trigger fallback. The policy
has no health score or circuit breaker. `net=mix` is the recommended upstream;
a single-family listener may consume the budget on each affected flow or leave
no legal route for a fixed direction.

With `mux=1`, Shards open lazily according to active flow pressure. New flows
use the least-loaded shard; a shard carries 4 active flows before another
opens and closes after 30 seconds fully idle. With `mux=0`, every TLS-carried
Flow owns one on-demand lane that closes with the Flow. Mux applies when at
least one direction is `tcp` or `mix`. `udp/udp&mux=1` canonicalizes to
`mux=0`.

Portal and Vector offer fixed ALPNs in the order `nw2`, `now/1`. V2 peers select
`nw2`; a V2 peer talking to a default V1 peer selects `now/1`. The removed
`alpn` query is ignored under the normal unknown-parameter rule. Protocol
version and Mux are independent settings. Portal's `mux` option controls only
its `next` client. Inbound Portal connections accept a `0xff`-marked Mux carrier
or an unmarked dedicated lane on the same listener.

For `tls=2`, `crt` and `key` are native filesystem paths. Quote the complete
URL when a Windows path, space, `&`, or another shell-significant character is
present.

## URL parsing rules

- The shared key occupies the URL username. Password userinfo, URL paths, and
  fragments are invalid.
- Reserved bytes in shared keys, nested credentials, and query values use
  percent encoding.
- Recognized query keys use their first occurrence. Later duplicates and
  unknown keys are ignored.
- A Portal with an empty listen host binds wildcard addresses. Vector requires
  a Portal host and a `socks` listener.
- `socks=user:pass@host:port` enables RFC 1929 authentication. Omitting the
  credentials enables SOCKS5 no-auth.

## Environment

Durations use humantime syntax such as `250ms`, `15s`, `2m`, or `1h`.

| Variable | Default | Purpose |
|---|---:|---|
| `NOW_MAX_TCP_FLOWS` | `1024` | TCP flows per authenticated client session |
| `NOW_MAX_UDP_FLOWS` | `256` | UDP flows per authenticated client session |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4 MiB` | QUIC datagram and reassembly byte budget |
| `NOW_QUIC_MEMORY_PROFILE` | `throughput` | QUIC profile: `memory`, `balanced`, or `throughput` |
| `NOW_MAX_PENDING_PAIRS` | `1024` | Pending split-flow pairs per Portal session |
| `NOW_FLOW_PAIR_TIMEOUT` | `15s` | Portal split-flow pairing deadline |
| `NOW_FLOW_SETUP_TIMEOUT` | `20s` | Client wait for `SetupResult` |
| `NOW_MIX_FALLBACK_TIMEOUT` | `1s` | Primary Mix route preparation budget before fallback |
| `NOW_TCP_DATA_BUF_SIZE` | `32 KiB` | Per-direction TCP relay buffer size |
| `NOW_UDP_DATA_BUF_SIZE` | `64 KiB` | UDP target receive buffer size |
| `NOW_TCP_DIAL_TIMEOUT` | `15s` | Portal TCP target dial deadline |
| `NOW_UDP_DIAL_TIMEOUT` | `15s` | Portal UDP target setup deadline |
| `NOW_TCP_READ_TIMEOUT` | `30s` | Opposite-direction TCP half-close grace period |
| `NOW_UDP_IDLE_TIMEOUT` | `2m` | UDP flow and QUIC idle timeout |
| `NOW_HANDSHAKE_TIMEOUT` | `5s` | TLS, authentication, and request phase deadline |
| `NOW_REPORT_INTERVAL` | `5s` | Event checkpoint interval |
| `NOW_TELEMETRY_INTERVAL` | `1s` | TUI sample period; accepted range is `250ms..60s` |
| `NOW_SERVICE_COOLDOWN` | `3s` | Client transport reconnect delay |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Graceful shutdown deadline |
| `NOW_RELOAD_INTERVAL` | `1h` | Supplied-certificate reload interval |

Mux limits are library defaults with strict validation: 512 KiB per stream and
connection, 256 active streams per Mux, and 512 queued frame slots. Payload in
the queue is also charged against the 512 KiB connection window, so slot capacity
does not multiply the byte bound. The application uses a 4-flow shard density
and retires fully idle shards after 30 seconds. `NOW_MAX_TCP_FLOWS` is the hard
per-session logical TCP limit shared by TLS and QUIC. `NOW_MAX_UDP_FLOWS` is the
corresponding UDP limit shared by UoT and QUIC DATAGRAM. Excess flows fail
without waiting for capacity. QUIC internally admits the sum of both limits as
bidirectional streams; this derived capacity has no separate setting.

Portal and Vector use the same QUIC profile regardless of negotiated protocol
version or the client Mux setting.
The stream/connection/send windows are respectively 4/8/8 MiB for `memory`,
8/16/16 MiB for `balanced`, and 16/32/32 MiB for `throughput`. These are
flow-control ceilings, not eager allocations. Larger windows are useful only
when the required bandwidth-delay product justifies their in-flight memory.
