# Operations

## Health model

Portal and Vector expose lifecycle, logical flow counts, TLS/QUIC carrier
counts, and traffic totals through the local TUI on every supported platform.
Linux also reports process CPU and RSS. These process-resource fields are
unavailable on macOS and Windows; relay behavior is unchanged.

Run `nowhere` without a URL and select:

- `1` Overview;
- `2` Logs.

## Capacity

The important memory bounds are the 1,024 concurrent TCP flows and 256 UDP flows
per authenticated client session, the 512 KiB per-stream and per-Mux receive
windows, 256 streams per Mux, bounded reusable relay-buffer caches, and QUIC UDP
queue/reassembly limits. UoT and QUIC DATAGRAM share the UDP flow limit. TLS
shards originated with `mux=1` by Vector or a Portal `next` client target 4
active flows, use least-loaded placement, and close after 30 seconds fully
idle. Frame queue slots do not bypass byte credit. Windows are granted as
permits and payload is admitted incrementally.

At a session flow limit, TCP setup returns a failure immediately. A SOCKS5 UDP
packet whose logical route cannot be admitted receives no UDP response; the
association remains available for existing routes.

QUIC uses the shared `throughput` memory profile by default. Select `balanced`
or `memory` when connection density matters more than a single flow's
bandwidth-delay product.

### TLS Shard placement

An originating client keeps separate uplink and downlink Shard sets. Only a
direction that selects TLS/TCP uses a set; a symmetric `tcp/tcp` flow uses one
duplex stream from the uplink set.

```text
                         +-------------------------+
new TLS-carried Flow --->| live Shard below 4?     |
                         +------------+------------+
                                      |
                        +-------------+---------------+
                        | yes                         | no
                        v                             v
              +------------------+          +------------------+
              | choose the       |          | open one TLS     |
              | least-loaded one |          | Mux Shard        |
              +---------+--------+          +---------+--------+
                        |                             |
                        +--------------+--------------+
                                       |
                                       v
                              open logical stream
```

While load grows from zero, a direction uses `ceil(active flows / 4)` Shards.
After load falls, an empty Shard remains available during its idle period:

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

Failure domains remain carrier-local: one dedicated TLS lane owns one logical
lane; one Mux Shard owns its assigned streams; one QUIC connection owns all of
its reliable streams and DATAGRAM routes. Closing one Shard does not close a
sibling Shard from the same authenticated session.

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

- Portal reaches `READY` on every configured listener;
- Vector accepts SOCKS5 CONNECT and UDP ASSOCIATE;
- every configured uplink/downlink carrier combination reaches a target;
- negotiated protocol version, credentials, certificate verification, and
  native chains match at both ends;
- flow limits fail promptly instead of waiting for capacity;
- idle Mux Shards and UDP flows retire at their documented deadlines;
- graceful shutdown reaches `STOPPED` within the configured deadline;
- the local TUI discovers the process without exposing credentials or payload.
