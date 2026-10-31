# Interoperability

Validate independent Nowhere Protocol implementations against Nowhere's Rust
runtime. The [Core specification entry](protocol.md) identifies the Wire
baseline. The [Prelude Extension](prelude.md) defines Morph TCP bootstrap
authentication and the per-socket UDP Prelude; the [Egress Extension](egress.md)
defines remote-exit behavior.
This guide describes integration and validation, not a second Wire specification.

## Contents

- [Transport and authentication](#transport-and-authentication)
- [Flow direction and framing](#flow-direction-and-framing)
- [UDP delivery and lifetime](#udp-delivery-and-lifetime)
- [Morph](#morph)
- [Reference vectors and observation](#reference-vectors-and-observation)

## Transport and authentication

Follow [Core transport and authentication](protocol.md).
When connecting to Nowhere, use its [Shared Key provisioning](configuration.md)
and [certificate trust](security.md#certificate-trust) interfaces. Configuration URL
parsing is independent of the authenticated Wire frames.

Test fresh and resumed connections, invalid credentials and replayed tags. A
failed connection must not dial a target or claim Egress registration ownership.
The authentication fixtures include Egress tags for both TLS and QUIC.

## Flow direction and framing

Exercise both TLS and QUIC with TCP and UDP payloads. Include authentication-only
Stream 0, a pipelined first request, partial reads, reserved-bit decoding, TCP
half-close, rejection before READY and failure isolation after READY.

A standard Vector uses the same Core protocol when Portal selects Egress as its
exit. It does not implement registration or reverse Stream initiation. Egress
peers separately test the [registration barrier](egress.md#registration),
role-direction rejection and [registration ownership](egress.md#registration-ownership-and-lifetime).

## UDP delivery and lifetime

Validate empty packets, Stream-derived ID boundaries, fragmented payloads,
out-of-order delivery, duplicate/conflicting fragments and unknown or not-yet-ready
routes. Missing QUIC DATAGRAM capability must not trigger a hidden carrier fallback.

Exercise control-stream FIN, reset and STOP_SENDING without relying on a CLOSE
DATAGRAM. Reassembly and queue pressure must not prevent unrelated Flows from
making progress. For Egress, validate both bridge legs and disconnect cleanup;
reconnection must not recover a previous Flow.

## Morph

Use the [Core Morph contract](protocol.md). Test both enabled and disabled
configurations, TCP partial reads/writes and continuous cipher offsets, UDP
segmentation boundaries and nonce overhead. The receive path must accept the
64-byte prelude independently of the sender's generation policy. Nowhere's
[prelude policies](configuration.md#tcp-morph-prelude) do not require a matching
policy on the peer.

Morph TCP senders must encode the [Prelude Extension](prelude.md). Portal
requires a valid Tag and Counter independently of the generation policy.
Invalid Tags are rejected before ClientHello parsing. Replay precheck precedes
silent ClientHello acceptance; successful acceptance precedes atomic replay
commit and TLS responses. There is no unauthenticated Prelude fallback.

| Sender | This Portal's Morph TCP ingress |
|---|---|
| Without authenticated Prelude | Rejected silently |
| With valid authenticated Prelude | Accepted subject to TLS, AuthFrame and replay checks |

Test all three policies, invalid Tags, unauthenticated input, invalid and
replayed Counters, and the commit boundary after ClientHello acceptance. Verify
that zero linger remains enabled through TLS and AuthFrame validation and is
restored only after complete authorized Vector or Egress authentication within
the deadline. Check normal authenticated close and half-close behavior and
standard TLS (`morph=0`) coverage.

### Morph UDP Prelude compatibility

Morph-enabled Vector and Egress QUIC clients send one independent 12-byte
[UDP Prelude](prelude.md#morph-udp-prelude) per socket. Portal silently discards
Morph UDP datagrams of 12 bytes or less and does not require a Prelude before
QUIC packets. Receivers need no matching generation policy, authentication
decoder or replay state for the Prelude. Normal Morph UDP datagrams contain a
12-byte Nonce followed by the masked QUIC packet. Interoperable receivers must
silently discard these short datagrams without sending a response.

## Reference vectors and observation

The [wire fixtures](../src/tests/protocol/vectors.json),
[Morph fixtures](../src/tests/transport/morph.rs) and
[Prelude fixtures](../src/tests/transport/morph/prelude.rs) cover Core and
extension encoding. Fixed byte agreement complements live
transport and lifecycle tests; it does not replace them. See [Testing](testing.md).

Third-party observers use the separate [Telemetry JSON contract](telemetry.md).
Local IPC, discovery, process identity and statistics are implementation
interfaces, not requirements for a forwarding protocol peer.
