# Integrations

Nowhere exposes integration contracts through command URLs, the local SOCKS5
listener, and the documented wire protocol. Its Rust modules are internal and
do not provide a separately versioned SDK surface.

```text
                         local interface                 wire interface

+-------------+  SOCKS5  +--------+  Nowhere protocol   +--------+  TCP/UDP  +--------+
| Application |<-------->| Vector |<===================>| Portal |<--------->| Target |
+-------------+          +--------+                     +--------+           +--------+
                                                            ^
                                                            |
                     +------------------+===================+
                     | Alternate client |
                     +------------------+
                                                            ^
                                                            |
                     +------------------+===================+
                     | Portal `next`    |
                     +------------------+
```

An integration chooses one boundary. Applications normally use SOCKS5;
alternate clients implement the wire protocol; Portal chains use the native
client engine.

## Alternate clients

Implementers should follow [Protocol](protocol.md). QUIC uses native reliable
streams and DATAGRAM frames, never TLS Mux framing. V2 clients offer `nw2` and
the compatible V1 value `now/1`; the negotiated value selects the version for
that carrier. A Mux TLS connection places the `0xff` marker after
authentication; a dedicated lane places its FlowHeader there instead. Portal
accepts both forms on the same TLS listener and selects the decoder from that
first byte.

An alternate client provides:

- one random 16-byte session ID shared by its physical carriers;
- an AuthFrame bound to each carrier's TLS exporter and transport type;
- nonzero Flow IDs unique among active flows in that session;
- matching OPEN and ATTACH metadata for split-carrier flows;
- bounded retry and reconnection behavior after carrier failure.

The `mix` URL policy is client-side only and resolves once to TT, TQ, QT, or QQ.
The primary pair has a one-second preparation budget by default. Failure or
timeout selects the other allowed pair once with a new flow ID. A client never
replays a request after any FlowHeader or Target bytes may have been accepted.

## Chained Portal

`next=shared-key@host:port` creates the same transport-only client engine used
by Vector, including `up/down=mix` and pre-commit fallback. `mux=0|1` selects
dedicated or Mux TLS when TCP can be selected and defaults to `0`; it has no
effect without `next` and canonicalizes to `0` for `udp/udp`. Authentication,
flow setup, bounds, and failure semantics are identical at every hop.
