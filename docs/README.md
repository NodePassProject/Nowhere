# Documentation

The documentation has one source of truth for each concern:

| Need | Document |
|---|---|
| Run a local Portal and Vector | [Quick start](quick-start.md) |
| Choose and operate a supported platform | [Platforms](platforms.md) |
| Understand URL and environment options | [Configuration](configuration.md) |
| Implement or inspect the wire format | [Protocol](protocol.md) |
| Deploy and observe the processes | [Operations](operations.md) |
| Review authentication and memory bounds | [Security](security.md) |
| Understand version negotiation and peer interoperability | [Interoperability](compatibility.md) |
| Implement another client or integration | [Integrations](integrations.md) |

`configuration.md` is authoritative for command URLs and runtime settings.
`protocol.md` is normative for bytes exchanged between peers. Portal and
Vector share one internal bounded TLS Mux engine.

Portal and Vector have the same transport behavior on Linux, macOS, and
Windows. Platform-specific packaging, process control, filesystem paths, and
telemetry availability are documented separately instead of being mixed into
the protocol.

## System map

```text
+-------------+  SOCKS5  +--------+  TLS/TCP or QUIC/UDP  +--------------+
| Application |<-------->| Vector |<=====================>| Entry Portal |
+-------------+          +--------+                       +------+-------+
                                                                 |
                                                         +-------+-------+
                                                         | outbound path |
                                                         +-------+-------+
                                                                 |
                                      +--------------------------+---------------------------+
                                      |                                                      |
                                      v                                                      v
                              +---------------+                                       +-------------+
                              | direct/SOCKS5 |                                       | Native next |
                              +-------+-------+                                       +------+------+
                                      |                                                      |
                                      v                                                      v
                               +-------------+                                        +-------------+
                               |   Target    |                                        | Next Portal |
                               +-------------+                                        +------+------+
                                                                                             |
                                                                                             v
                                                                                      +-------------+
                                                                                      |   Target    |
                                                                                      +-------------+
```

Each Portal chooses exactly one outbound path for a flow: direct target
access, an outbound SOCKS5 proxy, or a native `next` Portal. The carrier choice
on one hop does not constrain the carrier choice on another hop.

## Endpoint summary

Portal listeners, Vector remote endpoints, and Portal `next` endpoints use the
same carrier grammar:

```text
HOST:PORT
HOST/CARRIER:PORT[/CARRIER:PORT]
```

The compact form declares TLS/TCP and QUIC/UDP on one port. The explicit form
declares only its listed carriers. `tcp` and `udp` accept IPv4 and IPv6;
`tcp4`, `udp4`, `tcp6`, and `udp6` restrict the address family. Both carriers
share `HOST`, while their ports and address families remain independent.

| Role | Host rule | Endpoint result |
|---|---|---|
| Portal | `*`, IP literal, hostname, or compact empty host | Opens every declared listener |
| Vector | IP literal or hostname | Dials only the declared remote carriers |
| Portal `next` | IP literal or hostname | Uses the same client engine as Vector |

`portal://key@:2000` is the compact alias for
`portal://key@*:2000`. Vector and `next` reject `*`. A Portal resolves listener
hostnames once at startup and binds every matching address; clients resolve and
filter each carrier by its declared family. Configuration errors stop startup
before service traffic is accepted. The full syntax and error rules are in
[Configuration](configuration.md).

## Protocol summary

| Client Mux setting | TLS/TCP | QUIC/UDP | Failure scope |
|---|---|---|---|
| `mux=0` | Dedicated lane per flow | Native streams/datagrams | One flow per carrier |
| `mux=1` | Shared bounded Mux | Native streams/datagrams | Assigned flows close with the carrier |

V2 peers negotiate the fixed `nw2` ALPN and fall back to the default V1 value
`now/1` for compatibility. The client-side route-policy matrix is:

| `up` ↓ / `down` → | `tcp` | `udp` | `mix` |
|---|---|---|---|
| `tcp` | TT | TQ | TT ↔ TQ |
| `udp` | QT | QQ | QT ↔ QQ |
| `mix` | TT ↔ QT | TQ ↔ QQ | TT ↔ QQ |

T means TLS/TCP and Q means QUIC/UDP, with uplink first. All four concrete
routes use the same FlowHeader, Target, pairing, and relay semantics. `mix` is
a local Vector or Portal-`next` policy; FlowHeader contains only the resolved
concrete route. Portal accepts dedicated and `0xff`-marked Mux connections on
the same TLS listener.
