# Interoperability

## Version negotiation

Nowhere 2 uses ALPN as its data-plane version selector. Portal and Vector offer
the fixed protocols `nw2` and `now/1`, in that order. A negotiated `nw2` carrier
is V2; a negotiated `now/1` carrier is compatible V1. The `alpn` URL parameter
is ignored as an unknown parameter.

| Client | Portal | Negotiated version |
|---|---|---|
| V2 | V2 | `nw2` / V2 |
| V2 | default V1 | `now/1` / V1 |
| default V1 | V2 | `now/1` / V1 |

V1 installations using a custom ALPN cannot interoperate with V2. A V1 client
that had already customized its ALPN to `nw2` is classified as V2; this rare
collision has no compatibility exception.

## Endpoint configuration

The compact `portal://key@host:port`, `vector://key@host:port`, and
`next=key@host:port` forms declare TCP and UDP on the same port. The empty
Portal host in `portal://key@:port` is an alias for the wildcard host `*`.

Carrier paths select the enabled carriers. The `net` query follows the
unknown-parameter rule and has no effect on carrier selection:

```text
portal://key@*/tcp:2006
portal://key@*/udp:2017
```

Use `/tcp4:PORT`, `/tcp6:PORT`, `/udp4:PORT`, and `/udp6:PORT` when the address
family must also be fixed. URL compatibility is separate from wire
compatibility: default V1 and V2 peers communicate using the version negotiation
described above. Compatible compact address syntax does not imply identical
query semantics across versions.

The endpoint path is local process configuration and never appears on the wire.
It determines which TCP or UDP socket carries the TLS/QUIC connection before
ALPN and AuthFrame processing begin.

| Configuration | V2 behavior | V1 interoperability consequence |
|---|---|---|
| `HOST:PORT` | Both carriers use one unrestricted port | A default V1 client can reach both carriers |
| `HOST/tcp:2006` | Only TLS/TCP exists | A peer must select TCP and use port 2006 |
| `HOST/udp:2017` | Only QUIC/UDP exists | A peer must select UDP and use port 2017 |
| `HOST/tcp:2006/udp:2017` | Carriers use independent ports | A client must understand or otherwise know both ports |
| `HOST/tcp4:2006/udp6:2017` | Carrier DNS/address results are family-filtered | Peer reachability must satisfy the same families |

A V1 client URL has one authority port and cannot describe separate TCP and UDP
ports. A V2 Portal intended to serve unmodified V1 clients therefore uses the
compact form on that compatibility edge. A V2 Vector may use an explicit
endpoint with a V1 Portal when each declared address and port matches a listener
that the V1 Portal actually exposes.

`net` has no meaning to the V2 endpoint parser. For example,
`portal://key@*:2000?net=tcp` still declares both carriers because the compact
endpoint declares both. A TCP-only V2 service uses
`portal://key@*/tcp:2006`. This query difference does not change ALPN or the
compatible V1 wire encoding.

## TLS lane contract

Vector `mux=0` opens one authenticated TLS connection per Flow. Vector `mux=1`
opens marked Mux connections and assigns logical streams to dynamic Shards.

Portal accepts both forms on one listener. After the 32-byte authentication
frame:

- `0xff` identifies a Mux connection;
- every other byte is the first byte of a dedicated FlowHeader.

The marker cannot collide with a valid FlowHeader. Dedicated and marked Mux
connections use the same listener without separate inbound configuration.
An authenticated dedicated connection has 40 seconds to provide its first
FlowHeader byte.

```text
                         first byte after AuthFrame
                                      |
                    +-----------------+-----------------+
                    |                                   |
                  0xff                              any other byte
                    |                                   |
                    v                                   v
          +--------------------+              +--------------------+
          | Mux frame decoder  |              | FlowHeader decoder |
          | shared TLS carrier |              | dedicated TLS lane |
          +--------------------+              +--------------------+
```

Portal dispatches every authenticated TLS connection by its framing:

| Bytes after AuthFrame | Selected form | Result |
|---|---|---|
| Valid FlowHeader | Dedicated TLS | accepted |
| `0xff`, then valid Mux frames | Marked Mux TLS | accepted |
| Unmarked Mux bytes | Invalid FlowHeader | rejected |

The `0xff` byte is the Mux mode marker. It is always present on a Mux carrier
and never appears on a dedicated lane.

## Runtime contract

Mux Shards open lazily using TLS setup latency and carrier pressure, up to a
4-Shard directional pool. They select the least-loaded live Shard and close
after 30 seconds fully idle.
Dedicated lanes and Mux streams use the
same authentication, FlowHeader, Target, setup result, pairing and limits.
QUIC behavior is independent from the client Mux setting.

Peers must also use matching credentials and reachable carrier families. A
Portal with `next=` negotiates the upstream version independently and applies
the same `tcp|udp|mix` policy as Vector for that hop. Mix resolves locally
before transmission, and the peer receives a standard TT, TQ, QT, or QQ
FlowHeader. Portal compatibility is independent of whether the client policy
is fixed or mixed.
The upstream Mux selection defaults to `0`, is ignored without an enabled
`next`, and canonicalizes to `0` for a fixed `udp/udp` route.

Each hop has its own endpoint constraints. A V2 Portal may accept an inbound V1
TLS client on a compact listener and use an IPv6-only QUIC endpoint for its V2
`next` hop. The incoming ALPN, local listener family, upstream ALPN, and upstream
address family are evaluated independently.

Interoperability tests exercise both peer roles: one endpoint as Portal and the
other as client. The complete 3×3 `up`/`down` policy matrix covers all four
concrete routes and all five policies containing `mix`, together with both
negotiated versions, dedicated TLS, and marked Mux.
