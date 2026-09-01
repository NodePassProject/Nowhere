# Interoperability

## Version negotiation

Nowhere 2 uses ALPN as its data-plane version selector. Portal and Vector offer
the fixed protocols `nw2` and `now/1`, in that order. A negotiated `nw2` carrier
is V2; a negotiated `now/1` carrier is compatible V1. The `alpn` URL parameter
has been removed and is ignored as an unknown parameter.

| Client | Portal | Negotiated version |
|---|---|---|
| V2 | V2 | `nw2` / V2 |
| V2 | default V1 | `now/1` / V1 |
| default V1 | V2 | `now/1` / V1 |

V1 installations using a custom ALPN cannot interoperate with V2. A V1 client
that had already customized its ALPN to `nw2` is classified as V2; this rare
collision has no compatibility exception.

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

Mux Shards open lazily at 4 active flows, select the least-loaded live Shard,
and close after 30 seconds fully idle. Dedicated lanes and Mux streams use the
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

Interoperability tests exercise both peer roles: one endpoint as Portal and the
other as client. The complete 3×3 `up`/`down` policy matrix covers all four
concrete routes and all five policies containing `mix`, together with both
negotiated versions, dedicated TLS, and marked Mux.
