# Interoperability

## Nowhere 2 wire boundary

Nowhere 2 supports one data-plane protocol. TLS/TCP and QUIC clients must offer
the ALPN `nw2`, and the negotiated ALPN must be exactly `nw2`. A peer that
offers only `now/1`, a custom ALPN, or no ALPN cannot establish a Nowhere 2
carrier.

Nowhere 1 wire compatibility is intentionally absent. This includes the
authentication key derivation and TLS Mux framing. Portal and Vector must be
upgraded together.

The `alpn` URL parameter remains an ignored unknown parameter. It cannot change
the fixed wire protocol.

## Endpoint configuration

The compact `portal://key@host:port`, `vector://key@host:port`, and
`next=key@host:port` forms declare TCP and UDP on the same port. The empty
Portal host in `portal://key@:port` is an alias for the wildcard host `*`.

Explicit carrier paths select listeners and dial targets:

```text
portal://key@*/tcp:2006
portal://key@*/udp:2017
portal://key@*/tcp4:2006/udp6:2017
```

The `net` query follows the unknown-parameter rule and has no effect. Endpoint
syntax is local configuration and is not transmitted on the wire.

## TLS lane contract

Vector `mux=0` opens one authenticated TLS connection per flow. Vector `mux=1`
opens marked Mux carriers and assigns logical streams to adaptive shards.
Portal accepts both forms on one TLS listener. After the 32-byte AuthFrame,
`0xff` selects Mux framing; every other valid first byte begins a dedicated
FlowHeader.

Mux carriers open lazily, choose the least-loaded live shard, and use at most
four physical TLS carriers per logical direction. A symmetric TCP/TCP flow uses
one full-duplex logical stream. A carrier closes after it has remained fully
idle for 30 seconds.

Dedicated lanes, Mux streams, and QUIC streams use the same FlowHeader, Target,
setup result, pairing, and resource limits.
