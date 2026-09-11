# Configuration

URLs and environment variables have the same meaning on Linux, macOS, and
Windows. Shell quoting and filesystem path syntax follow the host platform;
see [Platforms](platforms.md).

## Service endpoint grammar

Portal, Vector, and native Portal chaining share one endpoint model:

```text
portal://KEY@HOST:PORT[?QUERY]
portal://KEY@HOST/CARRIER:PORT[/CARRIER:PORT][?QUERY]

vector://KEY@HOST:PORT?QUERY
vector://KEY@HOST/CARRIER:PORT[/CARRIER:PORT]?QUERY

next=KEY@HOST:PORT
next=KEY@HOST/CARRIER:PORT[/CARRIER:PORT]
```

The outer URL remains a standard URL. `KEY` is URL userinfo, `HOST` is the URL
host, and each `CARRIER:PORT` is a path segment. RFC 3986 defines the standard
[authority](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2) and allows
the colon in a [path segment](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3),
so the explicit form does not replace or extend URL authority grammar.

| Form | Enabled carriers | Ports | Address-family policy |
|---|---|---|---|
| `HOST:PORT` | TCP and UDP | Shared | Unrestricted |
| `HOST/tcp:PORT` | TCP only | TCP port | Unrestricted |
| `HOST/udp:PORT` | UDP only | UDP port | Unrestricted |
| `HOST/tcp:PORT/udp:PORT` | TCP and UDP | Independent | Unrestricted |
| `HOST/tcp4:PORT/udp6:PORT` | TCP and UDP | Independent | TCP IPv4, UDP IPv6 |

Carrier names have the same meaning in every role:

| Carrier | Transport | Accepted address family |
|---|---|---|
| `tcp` | TLS over TCP | IPv4 and IPv6 |
| `tcp4` | TLS over TCP | IPv4 only |
| `tcp6` | TLS over TCP | IPv6 only |
| `udp` | QUIC over UDP | IPv4 and IPv6 |
| `udp4` | QUIC over UDP | IPv4 only |
| `udp6` | QUIC over UDP | IPv6 only |

`tcp` and `udp` mean that the endpoint does not restrict the address family.
They do not require both families to exist on the host. An IP literal narrows
an unrestricted carrier naturally; an explicit suffix that conflicts with the
literal is invalid.

Both carriers always share `HOST`. Use separate service URLs when TCP and UDP
must use different IP addresses or hostnames. The explicit path controls which
carriers exist, so an omitted carrier is disabled rather than assigned a
default port.

Canonical output lists TCP before UDP regardless of input order. It uses the
compact form when both carriers are unrestricted and use the same port;
otherwise it prints the explicit path. Effective configuration, logs, and the
TUI use this normalized endpoint and omit the shared key.

## Portal URL

```text
portal://shared-key@host:port?tls=1&log=info
portal://shared-key@*:2000?tls=1&log=info
portal://shared-key@*/tcp:2006/udp:2017?tls=1&log=info
portal://shared-key@host/tcp4:2006/udp6:2017?tls=1&log=info
portal://shared-key@*:2000?tls=1&morph=1&log=info
```

The compact `host:port` form enables TLS/TCP and QUIC/UDP on the same port.
The explicit path enables only the listed carriers. `tcp` and `udp` accept
either address family; suffix `4` or `6` to restrict that carrier. Each carrier
may appear at most once.

Both carriers share the host; their ports and address families are independent.
The wildcard `*` expands to separate IPv4 and IPv6 sockets, with IPv6 sockets
set to `V6ONLY`. Hostnames resolve at startup to all matching, deduplicated
addresses; listeners do not refresh DNS while running.

An unrestricted wildcard listener can omit an unavailable address family with
a warning. Each declared carrier must bind at least one address. Explicit
address families, concrete addresses, occupied ports, and permission failures
cause startup to fail and release the listeners already opened.

The Portal host controls binding:

| Host | Listener behavior |
|---|---|
| empty in compact form | Alias for `*` |
| `*` | Separate wildcard sockets for every permitted address family |
| IPv4 literal | Bind that IPv4 address |
| bracketed IPv6 literal | Bind that IPv6 address |
| hostname | Resolve once and bind every matching, deduplicated address |

IPv6 TCP and UDP listeners set `V6ONLY`, including wildcard listeners. A
dual-stack wildcard therefore consists of distinct `0.0.0.0` and `[::]`
sockets instead of relying on an operating-system dual-stack default.

| Query | Values | Default |
|---|---|---|
| `tls` | `1` generated certificate, `2` supplied certificate | `1` |
| `crt`, `key` | PEM paths, required with `tls=2` | — |
| `rate`, `etar` | Mbps, `0` disables limit | `0` |
| `dial` | `auto` or local IP | `auto` |
| `morph` | `0` bare TLS/QUIC wire, `1` keyed wire transform | `0` |
| `socks` | outbound SOCKS5 configuration | disabled |
| `next` | `shared-key@host:port` or explicit carrier endpoint | disabled |
| `up`, `down` | native next-hop policy: `tcp`, `udp`, or `mix` | only carrier, otherwise `tcp` |
| `mux` | native next-hop TLS: `0` dedicated lanes, `1` Mux when TCP is possible | `0` |
| `sni` | native next-hop verified DNS name, or `none` | `none` |
| `pin` | native next-hop certificate SHA-256 pin, or `none` | `none` |
| `log` | `none`, `debug`, `info`, `warn`, `error`, `event` | `info` |

When `next` is enabled, `up`, `down`, `mux`, `sni`, and `pin` configure that
upstream hop. Protocol version is negotiated independently with the next
Portal. These upstream options are ignored when `next` is absent or `none`.
`socks` and `next` are mutually exclusive outbound paths.

`morph=1` controls both the Portal listener and its native `next` client. The
listener derives Morph keys from the outer Portal key; the `next` client derives
them from the key inside `next`. The nested value never carries an inner query.

## Vector URL

```text
vector://shared-key@host:port?up=tcp&down=tcp&socks=127.0.0.1:1080
vector://shared-key@host/tcp:2006?socks=127.0.0.1:1080
vector://shared-key@host/udp6:2017?socks=127.0.0.1:1080
vector://shared-key@host/tcp:2006/udp:2017?up=tcp&down=udp&socks=127.0.0.1:1080
vector://shared-key@host:2000?morph=1&socks=127.0.0.1:1080
```

Vector uses the TCP carrier port only for TLS and the UDP carrier port only for
QUIC. Hostname results are filtered independently for each carrier. `tcp4` and
`udp4` never fall through to IPv6, and `tcp6` and `udp6` never fall through to
IPv4. If no resolved address matches the selected family, dialing fails with a
configuration-specific address error.

When an endpoint declares one carrier, omitted `up` and `down` both select that
carrier. When both carriers exist, each omitted direction selects TCP. An
explicit direction may select only a declared carrier, and `mix` requires both
TCP and UDP. These checks run before the SOCKS listener begins accepting
traffic. The transport default does not enable Mux; omitted `mux` remains `0`.

| Query | Values | Default |
|---|---|---|
| `up`, `down` | `tcp`, `udp`, or `mix` | only carrier, otherwise `tcp` |
| `mux` | `0` dedicated TLS lanes, `1` TLS Mux | `0` |
| `sni` | verified DNS name, or `none` | `none` |
| `pin` | certificate SHA-256 pin, or `none` | `none` |
| `rate`, `etar` | Mbps, `0` disables limit | `0` |
| `morph` | `0` bare TLS/QUIC wire, `1` keyed wire transform | `0` |
| `socks` | required local listen address, optionally credentials | — |
| `log` | logging threshold | `info` |

## Native next endpoint

The `next` value omits a scheme but otherwise uses the Vector endpoint grammar:

```text
portal://relay-key@*/tcp4:2006?next=origin-key@origin.example/udp6:2017
portal://relay-key@:2000?next=origin-key@origin.example/tcp:2006/udp:2017&up=tcp&down=udp
```

The local Portal listener and upstream endpoint are independent. The first
example accepts inbound TLS/TCP over IPv4 and opens the next hop with QUIC/UDP
over IPv6. A carrier or family chosen locally does not constrain the next hop.

`next` must contain exactly one encoded shared key, `@`, and one endpoint. Its
host must be concrete; `*` is invalid. It has no inner query or fragment.
`up`, `down`, `mux`, `sni`, `pin`, and `morph` remain query parameters of the outer
Portal URL. Reserved bytes in the nested key are percent-encoded once and are
decoded once when the upstream credentials are built.

The `dial` IP from the outer Portal URL also constrains native upstream
connections. The selected endpoint family and the local `dial` family must
both match a resolved upstream address. No connection crosses an explicit
family boundary to recover from a failure.

## Option scope

```text
Portal URL
    |
    +-- listener: endpoint path, tls, crt, key, morph
    +-- relay:    rate, etar, dial, log
    |
    +-- outbound path
          |
          +-- direct target access
          +-- socks  --> SOCKS5 proxy --> target
          +-- next   --> {up, down, mux, sni, pin, morph} --> Portal

Vector URL
    |
    +-- Portal client: up, down, mux, sni, pin, morph
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
has no health score or circuit breaker. Both carriers must be declared for
`mix`; a single-carrier endpoint rejects a policy that selects the absent
carrier.

With `mux=1`, one session shares a pool of at most eight full-duplex TLS carriers.
New flows reuse idle carriers; when all are busy and a slot is available,
they establish another carrier. Establishments may run in parallel and count
against the same eight slots. At capacity, flows choose the lowest credit/queue
occupancy, breaking ties by live streams plus pending reservations. Connecting
carriers also accept reservations to balance cold bursts. Existing streams do not migrate, and a full pool
continues accepting new streams until a carrier's 4,096-stream resource ceiling.
There is no stream-density target.
A carrier closes after 30 seconds
fully idle. With `mux=0`, every TLS-carried
Flow owns one on-demand lane that closes with the Flow. Mux applies when at
least one direction is `tcp` or `mix`. `udp/udp&mux=1` canonicalizes to
`mux=0`.

Portal and Vector use only the fixed ALPN `nw2`. A peer that does not offer
`nw2` cannot establish a carrier. The `alpn` query is ignored under the
normal unknown-parameter rule. Portal's `mux` option controls only
its `next` client. Inbound Portal connections accept a `0xff`-marked Mux carrier
or an unmarked dedicated lane on the same listener.

Morph is hop-local and has no negotiation or fallback. Both endpoints must
configure the same value. Compact `HOST:PORT` endpoints apply it to TCP and
UDP on the shared port; explicit paths apply it only to the carrier entries
present in the path. Values other than `0` and `1`, including an empty value,
are configuration errors. Duplicate `morph` keys follow the general rule that
the first recognized value wins.

For `tls=2`, `crt` and `key` are native filesystem paths. Quote the complete
URL when a Windows path, space, `&`, or another shell-significant character is
present.

## URL parsing rules

- The shared key occupies the URL username. Password userinfo and fragments are
  invalid.
- Endpoints use either `HOST:PORT` or
  `HOST/CARRIER:PORT[/CARRIER:PORT]`; the forms cannot be combined. Empty path
  segments, trailing slashes, unknown or duplicate carriers, and zero ports are
  invalid.
- Portal allows `*` as the wildcard listen host. The compact
  `portal://key@:port` form is equivalent to `*`; explicit
  carrier paths require a host. Vector and `next` reject `*`.
- IP literals must agree with an explicit `4` or `6` carrier suffix. Hostnames
  are filtered to the selected address family.
- Reserved bytes in shared keys, nested credentials, and query values use
  percent encoding.
- Recognized query keys use their first occurrence. Later duplicates and
  unknown keys are ignored.
- The `net` query is an unknown parameter and has no effect. `/tcp:PORT` and
  `/udp:PORT` select a single carrier; compact endpoints enable both carriers.
- `socks=user:pass@host:port` enables RFC 1929 authentication. Omitting the
  credentials enables SOCKS5 no-auth.

The following inputs fail validation before a Portal or Vector reaches its
running state:

| Invalid shape | Reason |
|---|---|
| `host:2000/tcp:2006` | Compact authority port and carrier path are mutually exclusive |
| `host/tcp:2006/` | Trailing slash creates an empty carrier segment |
| `host/tcp:2006/tcp6:2006` | TCP is declared more than once |
| `host/sctp:2000` | Carrier name is unknown |
| `192.0.2.1/tcp6:2006` | IPv4 literal conflicts with IPv6-only TCP |
| `host/tcp:0` | Carrier ports are limited to `1..=65535` |
| `*/tcp:2006` on Vector or `next` | Wildcard is limited to Portal listeners |

Errors identify the role and invalid endpoint component, exit with a nonzero
status, and do not print shared keys. Dot segments, including percent-encoded
forms, are rejected before a URL parser can normalize the path.

## Environment

Durations use humantime syntax such as `250ms`, `15s`, `2m`, or `1h`.

| Variable | Default | Purpose |
|---|---:|---|
| `NOW_TRANSPORT_MEMORY_PROFILE` | `throughput` | QUIC and TLS Mux profile: `memory`, `balanced`, or `throughput` |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4 MiB` | QUIC datagram and reassembly byte budget |
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

TLS Mux shares the transport profile's 4/8, 8/16, or 16/32 MiB stream/connection
receive windows with QUIC. A Mux carrier admits at most 4,096 active streams and
has 512 queued frame slots; queued payload remains charged against the connection
window. Each flow has at most one DATA frame queued or being written, so a bulk
writer cannot fill the shared queue. Receive queues are bounded by byte credit
without blocking unrelated flows on per-flow frame counts. The application
shares at most eight carriers across both directions and retires
fully idle shards after 30 seconds. The former TCP, UDP, SOCKS association, and
pending split-pair application quotas are absent. Independent resource admission
allows up to 1,024 accepted SOCKS clients and 1,024 active SOCKS UDP targets per
Vector. QUIC stream credit
grows with live and pending QUIC
flows, reserving setup headroom of at least 64 streams or 25% of that count.
This avoids the former application flow quotas and excessive eager stream allocation.
Byte budgets and setup, pairing, and idle deadlines apply; per-flow
Mux metadata and Vector SOCKS target tasks have the resource ceilings described
above. These do not impose an aggregate limit on Portal sessions or target sockets.

Portal and Vector use the same QUIC profile regardless of the client Mux setting.
The stream/connection/send windows are respectively 4/8/8 MiB for `memory`,
8/16/16 MiB for `balanced`, and 16/32/32 MiB for `throughput`. These are
flow-control ceilings, not eager allocations. Larger windows are useful only
when the required bandwidth-delay product justifies their in-flight memory.
