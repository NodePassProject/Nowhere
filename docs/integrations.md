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

## Command URL endpoints

Launchers and configuration generators produce one of two standard URL shapes:

```text
SCHEME://KEY@HOST:PORT
SCHEME://KEY@HOST/CARRIER:PORT[/CARRIER:PORT]
```

The compact form declares TCP and UDP on one unrestricted port. The explicit
form declares only the listed carrier entries. `tcp`, `tcp4`, and `tcp6` map to
TLS/TCP; `udp`, `udp4`, and `udp6` map to QUIC/UDP. The numeric suffix limits
DNS and literal addresses to IPv4 or IPv6.

Configuration integrations should preserve these invariants:

- encode the shared key as URL username data and never as password userinfo;
- keep one shared host for both carriers;
- use either an authority port or carrier path, never both;
- emit each transport at most once and order canonical output as TCP then UDP;
- emit the compact form when unrestricted TCP and UDP share a port;
- reserve `*` and compact empty hosts for Portal listeners;
- keep `next` policy in the outer Portal query rather than adding an inner
  query to the nested endpoint.

Portal accepts `portal://key@:2000` as the compact wildcard alias. Explicit
Portal listeners use `portal://key@*/tcp:2006/udp:2017`. Vector and native
`next` endpoints require an IP literal or hostname. Implementations that show
or log effective configuration omit credentials and retain the normalized
carrier path.

An invalid URL is a startup error. Integrations should display the process
error without retrying a different carrier or rewriting an explicit address
family, because doing so would change the user's declared service edge.

## Alternate clients

Implementers should follow [Protocol](protocol.md). QUIC uses native reliable
streams and DATAGRAM frames, never TLS Mux framing. Clients must offer `nw2`,
and the negotiated ALPN must be exactly `nw2`. A Mux TLS connection places
the `0xff` marker after
authentication; a dedicated lane places its FlowHeader there instead. Portal
accepts both forms on the same TLS listener and selects the decoder from that
first byte.

An alternate client provides:

- one random 16-byte session ID shared by its physical carriers;
- an AuthFrame bound to each carrier's TLS exporter and transport type;
- nonzero Flow IDs unique among active flows in that session;
- matching OPEN and ATTACH metadata for split-carrier flows;
- bounded retry and reconnection behavior after carrier failure.

The command URL is not transmitted. It selects the remote socket used for each
physical carrier; the negotiated ALPN, AuthFrame transport byte, and FlowHeader
then identify wire behavior. TCP and UDP may arrive at different Portal ports
and still belong to one session because the authenticated `session_id`, rather
than the socket address, defines the pairing scope.

The `mix` URL policy is client-side only and resolves once to TT, TQ, QT, or QQ.
The primary pair has a one-second preparation budget by default. Failure or
timeout selects the other allowed pair once with a new flow ID. A client never
replays a request after any FlowHeader or Target bytes may have been accepted.

## Chained Portal

`next=shared-key@host:port` or an explicit endpoint such as
`next=shared-key@host/tcp:2006/udp:2017` creates the same client engine used
by Vector, including `up/down=mix` and pre-commit fallback. `mux=0|1` selects
dedicated or Mux TLS when TCP can be selected and defaults to `0`; it has no
effect without `next` and canonicalizes to `0` for `udp/udp`. Authentication,
flow setup, bounds, and failure semantics are identical at every hop.

The nested value contains no scheme, query, or fragment. Percent-encoded key
bytes are decoded exactly once. `up`, `down`, `mux`, `sni`, and `pin` stay on
the outer Portal URL, while the outer `dial` address also constrains the local
family used for upstream TCP and UDP sockets.
