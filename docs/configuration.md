# Configuration Reference

Nowhere runs one command URL per process. Query order is accepted freely.
Unknown parameters are ignored, the first occurrence of a repeated parameter
wins, and missing optional parameters use their defaults. A malformed selected
value or structurally invalid required configuration still fails startup.

The URL username is the percent-decoded shared key (`1..255` bytes). URL
password components are forbidden. Literal `+` remains `+` rather than becoming
a space.

## Portal

```text
portal://<shared-key>@<listen-host>:<port>?net=...&tls=...&crt=...&key=...&alpn=...&rate=...&etar=...&dial=...&socks=...&log=...
```

An empty listen host binds separate IPv4 and IPv6 wildcard sockets. An IP binds
that family; a hostname resolves to its first address.

| Parameter | Default | Rules |
| --- | --- | --- |
| `net` | `mix` | `mix`, `tcp`, or `udp` |
| `tls` | `1` | `1` ephemeral in-memory certificate; `2` PEM files |
| `crt` | omitted | Required and nonempty only with `tls=2` |
| `key` | omitted | Required and nonempty only with `tls=2` |
| `alpn` | `now/1` | Nonempty decoded value, `1..255` bytes |
| `rate` | `0` | Client-to-target Mbps, nonnegative integer |
| `etar` | `0` | Target-to-client Mbps, nonnegative integer |
| `dial` | `auto` | `auto` or a local IP literal |
| `socks` | `none` | Portal outbound SOCKS5 endpoint or `none` |
| `log` | `info` | `none`, `debug`, `info`, `warn`, `error`, or `event` |

Portal startup output uses `net`, `tls`, `alpn`, `rate`, `etar`, `dial`,
`socks` in that order.

Rate conversion is `Mbps * 125000` bytes per second. Zero disables a direction.

Portal outbound SOCKS syntax is:

```text
socks=host:port
socks=user:password@host:port
socks=user:p%40ss@[2001:db8::10]:1080
```

Configured credentials offer only username/password authentication. Without
credentials only no-auth is offered. CONNECT covers TCP targets; every UDP flow
owns a UDP ASSOCIATE control connection. Failure never falls back to direct
dialing. `socks=` is invalid; use omission or `socks=none` to disable.

Examples:

```text
portal://secret@:2077
portal://secret@0.0.0.0:2077?net=tcp
portal://secret@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem
portal://secret@:2077?alpn=now%2Fprivate&rate=100&etar=200
```

## Vector

```text
vector://<shared-key>@<portal-host>:<port>?up=...&down=...&pool=...&sni=...&alpn=...&rate=...&etar=...&socks=...&log=...
```

Portal host and port are required. The canonical query order shown by help and
operator logs is `up`, `down`, `pool`, `sni`, `alpn`, `rate`, `etar`, `socks`.

| Parameter | Default | Rules |
| --- | --- | --- |
| `up` | `udp` | `tcp` or `udp` |
| `down` | `udp` | `tcp` or `udp` |
| `pool` | `5` for `tcp/tcp` | Nonnegative integer, clamped to 256; ignored otherwise |
| `sni` | `none` | DNS certificate name; empty, omitted, or `none` disables verification |
| `alpn` | `now/1` | Must match Portal |
| `rate` | `0` | Local SOCKS-client-to-target Mbps |
| `etar` | `0` | Local target-to-SOCKS-client Mbps |
| `socks` | required | `[user:password@]listen-host:port` |
| `log` | `info` | Same levels as Portal |

For `tcp/tcp`, pool defaults to 5, zero disables preconnection, and values over
256 are clamped to 256. Other carrier pairs ignore the supplied value and
always report the effective value as `pool=0`.

If `sni` contains a DNS name, Vector loads the system trust store and verifies
both the chain and configured name. If empty, omitted, or `none`, certificate
validation is deliberately disabled; a domain Portal host is still sent as
ClientHello SNI for virtual-host routing. Operator output always prints the
effective value, including `sni=none`.

The SOCKS value cannot be empty, but its listen host may be empty:

```text
vector://secret@127.0.0.1:2077?socks=127.0.0.1:1080
vector://secret@127.0.0.1:2077?up=tcp&down=tcp&pool=5&socks=:1080
vector://secret@relay.example:2077?sni=relay.example&socks=user:p%40ss@0.0.0.0:1080
```

An empty SOCKS host binds separate IPv4 and IPv6 wildcard listeners. Explicit
wildcards are allowed, so authentication or firewalling is the operator's
responsibility.

## Environment Limits

| Variable | Purpose |
| --- | --- |
| `NOW_QUIC_MAX_STREAMS` | Authenticated QUIC streams; also Vector local SOCKS flow cap |
| `NOW_QUIC_MAX_UDP_FLOWS` | UDP flows per session; also Vector global UDP target cap |
| `NOW_QUIC_UDP_QUEUE_BYTES` | QUIC UDP queue and reassembly byte budget |
| `NOW_TCP_IDLE_POOL_CONNS` | Portal authenticated idle TLS lane cap |
| `NOW_MAX_PENDING_PAIRS` | Pending split-flow cap per session |
| `NOW_FLOW_PAIR_TIMEOUT` | Split-flow pairing deadline |
| `NOW_TCP_DATA_BUF_SIZE` | TCP relay buffer size |
| `NOW_UDP_DATA_BUF_SIZE` | UDP receive buffer size |
| `NOW_TCP_DIAL_TIMEOUT` | TCP connect deadline |
| `NOW_UDP_DIAL_TIMEOUT` | UDP setup deadline |
| `NOW_TCP_READ_TIMEOUT` | Opposite-half TCP drain grace |
| `NOW_UDP_IDLE_TIMEOUT` | UDP flow and association target idle timeout |
| `NOW_HANDSHAKE_TIMEOUT` | Authentication and setup deadline |
| `NOW_REPORT_INTERVAL` | CHECK_POINT and LINK_STATUS interval |
| `NOW_SERVICE_COOLDOWN` | Transport reconnect retry delay (default 3 seconds) |
| `NOW_SHUTDOWN_TIMEOUT` | Graceful shutdown deadline |
| `NOW_RELOAD_INTERVAL` | PEM certificate reload interval |
