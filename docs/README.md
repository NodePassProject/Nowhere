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

`protocol.md` is normative. Portal and Vector share one internal bounded TLS
Mux engine.

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

## Protocol summary

| Client Mux setting | TLS/TCP | QUIC/UDP | Failure scope |
|---|---|---|---|
| `mux=0` | Dedicated lane per flow | Native streams/datagrams | One flow per carrier |
| `mux=1` | Shared bounded Mux | Native streams/datagrams | Assigned flows close with the carrier |

V2 peers negotiate the fixed `nw2` ALPN and fall back to the default V1 value
`now/1` for compatibility. All four uplink/downlink carrier combinations use
the same FlowHeader, Target, pairing, and relay semantics in this release.
Portal accepts dedicated and `0xff`-marked Mux connections on the same TLS
listener. The client Mux setting is available on Vector and on Portal when
`next` is enabled.
