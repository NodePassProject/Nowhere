# Operations

## Health model

Portal and Vector expose lifecycle, logical flow counts, TLS/QUIC carrier
counts, and traffic totals through the local TUI on every supported platform.
Linux also reports process CPU and RSS. These process-resource fields are
unavailable on macOS and Windows; relay behavior is unchanged.

Run `nowhere` without a URL and select:

- `1` Overview;
- `2` Logs.

## Listener lifecycle

Portal validates the complete URL, resolves every declared carrier, and opens
its UDP and TCP listener sets before entering `READY`. Each successful bind is
logged with its actual transport and socket address:

```text
listening on TLS/TCP 0.0.0.0:2006
listening on TLS/TCP [::]:2006
listening on QUIC/UDP 0.0.0.0:2017
listening on QUIC/UDP [::]:2017
```

The effective configuration keeps the normalized logical endpoint, such as
`*/tcp:2006/udp:2017`. TUI instance summaries show the actual TCP and UDP
address lists after binding. Disabled carriers appear as `none`; shared keys
are absent from both views.

One hostname may resolve to several addresses. Portal deduplicates the startup
result and binds every address that matches the carrier family. These sockets
form one logical carrier listener set. DNS is not refreshed while the process
runs, and an unexpected exit from any active listener set stops the service.

Startup is all-or-nothing for declared carriers. A carrier must bind at least
one address. A port conflict, permission error, unavailable concrete address,
or explicit family failure stops startup and releases sockets already opened.
The only partial-family case is `*` with unrestricted `tcp` or `udp`: an
operating system without one address family logs a warning and continues with
the other family.

| Symptom | Check |
|---|---|
| TCP works but QUIC does not | UDP port publication, firewall, and the endpoint's UDP entry |
| QUIC works but TCP does not | TCP port publication, firewall, and the endpoint's TCP entry |
| IPv4 works but IPv6 does not | Carrier suffix, IPv6 route, and the separate `[::]` bind log |
| Startup reports no matching address | DNS results and the carrier's `4` or `6` suffix |
| Startup reports address in use | Each transport/port pair and any duplicate service instance |
| Vector rejects `up`, `down`, or `mix` | The remote endpoint must declare every selected carrier |
| Morph peers cannot handshake | Both ends need the same `morph` value and shared key |
| QUIC fails only with Morph | The UDP path must carry at least 1212-byte payloads and allow MTU probes |

## Capacity

Payload memory is controlled by the selected 4/8, 8/16, or 16/32 MiB
per-stream/per-Mux receive windows, bounded reusable relay-buffer caches, and
QUIC UDP queue/reassembly limits. Logical TCP, UDP, SOCKS, and pending-pair
counts have no fixed application cap; metadata and sockets grow with concurrency.
TLS
shards originated with `mux=1` by Vector or a Portal `next` client adapt their
pool to concurrent flow demand, stop at eight carriers per session
across both directions, use lowest-occupancy placement, and
close after 30 seconds fully idle. Frame queue slots do not bypass byte credit. Windows are granted as
permits and payload is admitted incrementally.

QUIC stream credit grows with live and pending QUIC flows plus setup headroom.
Pairing and setup deadlines reclaim incomplete requests.

QUIC uses the shared `throughput` memory profile by default. Select `balanced`
or `memory` when connection density matters more than a single flow's
bandwidth-delay product.

Morph adds 12 bytes once per TCP connection and 12 bytes to every UDP
datagram. It preserves TCP payload length and keeps GSO/GRO batching when the
platform provides it. UDP socket buffers reserve space for the outer nonce;
Quinn measures decoded QUIC datagram sizes and performs path MTU discovery with
12 bytes reserved for the outer nonce. Morph reuses initialized transport
buffers and applies ChaCha20 while copying between caller and wire buffers. UDP
nonce batches come from a user-space CSPRNG seeded from the operating system and
reseeded before stream exhaustion.

### TLS Shard placement

An originating client shares one full-duplex TLS carrier pool across directions.
Mux and application sessions impose no fixed logical-flow count limit.

```text
new flow --> idle carrier? --> reuse
                 |
                 +--> free slot? --> establish TLS (up to eight in parallel)
                          |
                          +--> lowest credit/queue occupancy --> multiplex
                               (connecting slots accept reservations too)
```

Connections are created on demand. At most eight pool slots cover establishment
and carrier lifetime. Each slot shares one initializer and counts pending flows
alongside live streams. A cancelled initializer can be retried in the same slot.
No polling task or setup-latency threshold is used.
After load falls, an empty carrier remains available during its idle period:

```text
+--------+  last stream closes  +------+  30s with no stream  +--------+
| ACTIVE |--------------------->| IDLE |--------------------->| CLOSED |
+---+----+                      +--+---+                      +--------+
    ^                              |
    +-------- new stream ----------+
```

Portal applies the same idle lifecycle to an inbound authenticated Mux
carrier. Portal does not choose the peer's Shard count.

## Failure behavior

When a physical carrier closes, its logical flows close. SSH, download, and
WebSocket clients reconnect according to their application policy after
Wi-Fi/5G changes, NAT rebuilds, or TCP resets.

Failure domains are carrier-local: one dedicated TLS lane owns one logical
lane; one Mux Shard owns its assigned streams; one QUIC connection owns all of
its reliable streams and DATAGRAM routes. Closing one Shard does not close a
sibling Shard from the same authenticated session.

For a policy containing `mix`, the primary route must acquire every lane within
`NOW_MIX_FALLBACK_TIMEOUT` (default `1s`). Failure or timeout closes its local
resources and attempts the other allowed route with a new flow ID. The runtime
carrier event records both routes and the first error. Selection has no
cross-flow health state or carrier race, and READY or payload failures do not
trigger fallback. The fallback route uses normal transport deadlines.

Vector CHECK_POINT reports the configured policy rather than an individual
flow decision: `0..8` map to `tcp/tcp`, `tcp/udp`, `udp/tcp`, `udp/udp`,
`mix/tcp`, `mix/udp`, `tcp/mix`, `udp/mix`, and `mix/mix`.

## Shutdown

Ctrl+C starts graceful shutdown on Linux, macOS, and Windows. Unix process
managers may use SIGINT or SIGTERM. Shutdown stops accepting new work, rejects
incomplete pairings, lets established relay tasks drain until
`NOW_SHUTDOWN_TIMEOUT`, and then closes remaining carriers. Local telemetry
registry files are removed when their server exits; stale entries are also
discarded during discovery.

Run Portal and Vector under the platform's normal service manager. The manager
should preserve the URL and environment configuration, forward a graceful
termination event, restart only after the process exits, and allow the
configured shutdown deadline.

## Deployment checks

Functional validation belongs on every deployment platform:

- Portal reports every expected TCP and UDP address before reaching `READY`;
- compact endpoints accept both carriers on one port, while explicit endpoints
  expose only their declared carrier/port/family combinations;
- wildcard IPv6 listeners are `V6ONLY` and coexist with IPv4 listeners on the
  same numeric port;
- hostname listeners bind every deduplicated startup address, and a failed
  startup releases listeners opened earlier;
- Vector accepts SOCKS5 CONNECT and UDP ASSOCIATE;
- every configured uplink/downlink carrier combination reaches a target;
- every Mix policy resolves only to its documented concrete pairs and cleans
  up a failed pre-commit attempt;
- negotiated protocol version, credentials, certificate verification, and
  native chains match at both ends;
- flow limits fail promptly instead of waiting for capacity;
- idle Mux Shards and UDP flows retire at their documented deadlines;
- graceful shutdown reaches `STOPPED` within the configured deadline;
- the local TUI discovers the process without exposing credentials or payload.
