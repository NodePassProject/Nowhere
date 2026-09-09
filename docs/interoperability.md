# Interoperability

## Peer contract

Every TLS/TCP and QUIC/UDP carrier uses TLS 1.3 and the ALPN `nw2`. The client
offers `nw2`, and the server accepts a carrier only when TLS selects it. The
authentication derivation, flow headers, setup results, and Mux frames follow
the [Nowhere wire protocol](protocol.md).

Portal and Vector use the same wire contract. Alternate clients and native
Portal chains follow it as peers rather than relying on a separately versioned
SDK.

## Endpoint contract

Portal listeners, Vector remotes, and Portal `next` endpoints share two forms:

```text
HOST:PORT
HOST/CARRIER:PORT[/CARRIER:PORT]
```

The compact form declares TLS/TCP and QUIC/UDP on one numeric port. The explicit
form declares only the listed carriers and may select separate ports or address
families. An empty Portal host, as in `portal://key@:2000`, selects the wildcard
listener. Vector and `next` endpoints require a dialable host.

Endpoint syntax selects local sockets and is not transmitted on the wire. The
complete grammar and validation rules are in [Configuration](configuration.md).

## Morph contract

Peers use `morph=1` on both ends of a hop or `morph=0` on both ends. Morph has
no in-band marker or negotiation. TCP has one client-generated 12-byte nonce
and direction-specific keys; UDP has one 12-byte nonce per datagram and one
shared UDP key. The exact HKDF labels, counter origin, byte limits, and wire
layout are normative in [Protocol](protocol.md).

Implementations must preserve TCP stream offsets across partial I/O and treat
each GSO/GRO segment as a separate UDP datagram. QUIC sees the decoded packet
length; the physical UDP path sees 12 additional bytes. Interoperability tests
should use fixed derivation and ChaCha20 vectors before attempting a live TLS
or QUIC handshake.

## TLS lane contract

| Mux setting | TLS behavior | Failure scope |
|---|---|---|
| `mux=0` | One authenticated connection per logical flow | One flow |
| `mux=1` | Logical streams share TLS carriers | Every stream on the failed carrier |

After the 32-byte AuthFrame, `0xff` selects Mux framing; every other valid first
byte starts a dedicated FlowHeader. Portal accepts both lane forms on the same
TLS listener.

The Mux pool is full duplex and shared by both logical directions. It opens
carriers lazily, reuses idle carriers, selects the least occupied carrier at
capacity, and contains at most eight connecting or established carriers per
session. A fully idle carrier closes after 30 seconds. Logical stream counts
have no fixed application limit.

## Route contract

Uplink and downlink independently use TLS/TCP or QUIC/UDP. Every concrete route
uses the same FlowHeader, Target, pairing, setup-result, and relay semantics.
`mix` is a local client policy that resolves to a concrete route before the
FlowHeader is sent.

| `up` / `down` | `tcp` | `udp` | `mix` |
|---|---|---|---|
| `tcp` | TT | TQ | TT or TQ |
| `udp` | QT | QQ | QT or QQ |
| `mix` | TT or QT | TQ or QQ | TT or QQ |

T denotes TLS/TCP and Q denotes QUIC/UDP, with uplink first.
