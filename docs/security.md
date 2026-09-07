# Security and Resource Bounds

## Authentication

The shared key is never sent on the wire. A derived HMAC key authenticates a
frame bound to the TLS exporter, carrier type, and random session ID. Replaying
the frame on another connection fails.

```text
shared key ---------> key derivation --------+
TLS exporter --------------------------------+
transport byte ------------------------------+--> HMAC --> AuthFrame tag
session_id ----------------------------------+
```

The exporter binds the tag to one TLS or QUIC connection. The transport byte
prevents a valid TLS/TCP AuthFrame from being reused as QUIC authentication,
and `session_id` gives all authenticated carriers from one client a shared
pairing scope.

TLS is version 1.3. Deployments may use a certificate pin, normal system-root
verification with SNI, or the explicitly configured unverified certificate
mode used by generated local certificates.

## Endpoint exposure

The service endpoint is also the network exposure policy. A compact Portal
endpoint exposes TLS/TCP and QUIC/UDP on the same port. An explicit path exposes
only its declared carriers, ports, and address families:

```text
portal://key@*/tcp4:2006
portal://key@192.0.2.10/tcp:2006/udp:2017
portal://key@[2001:db8::10]/udp6:2017
```

`*` and the compact empty host bind wildcard interfaces. Use a concrete local
address when the service should be limited to one interface, and enforce the
same transport, port, and family policy in host and perimeter firewalls. Every
IPv6 listener is `V6ONLY`, so IPv4 exposure is always represented by a separate
socket and firewall decision.

A hostname listener binds all matching addresses resolved at startup. The
result is not refreshed dynamically, which prevents a later DNS answer from
silently expanding a running process, but operators must review the complete
startup address list after each restart. Vector and native `next` honor
explicit family suffixes and never retry through the other family.

Effective URLs, startup summaries, TUI descriptors, and configuration errors
omit the shared key. The original command URL still contains the credential;
protect shell history, process arguments, service-manager configuration, and
deployment logs accordingly. Reserved key bytes must be percent-encoded, and
nested `next` credentials are decoded exactly once.

## Admission

Portal bounds pre-authentication work and applies per-source admission before
expanding QUIC stream windows. Flow pairing, logical IDs, UDP routes, datagram
queues, and fragment reassembly are separately bounded.

## Mux memory safety

Mux payload stays within the active carrier's bounded outbound queue. A sender
needs both stream and connection credit before a data frame enters that queue.
A receiver charges both windows before delivery and returns credit only after
application consumption. Closing the carrier releases queued payload.

The fixed maximum frame payload is 65,535 bytes and the runtime emits at most
32 KiB per STREAM frame. Malformed kinds, flags, IDs, lengths, window overflow,
and DATA for unknown streams close the carrier. Late terminal and credit frames
for a terminal stream are idempotent.

The transport memory profile bounds Mux stream/connection windows at 4/8,
8/16, or 16/32 MiB, and each Mux allows 256 active streams. With client `mux=1`,
Vector or Portal `next` adapts a shard's target density to TLS setup latency and
live connection pressure, caps each direction at 4 shards, distributes new flows to the
least-loaded shard, and closes a fully idle shard after 30 seconds. One
authenticated inbound Mux carrier is subject to the same fully idle timeout.
One authenticated client session admits at most 1,024 concurrent logical TCP
flows and 256 logical UDP flows across all of its carriers. UoT and QUIC
DATAGRAM flows share the UDP limit.
Per-stream and connection credit plus bounded channel admission limit how much
one stream can occupy. The finite frame queue has 512 slots, but
payload admission is capped by the selected connection window; empty
SYN/FIN/WINDOW frames cannot turn those slots into
retained application payload. These are credit ceilings rather than eagerly
allocated payload buffers.

```text
authenticated client session
    |
    +-- TCP budget: 1,024 active flows
    |     |
    |     +-- dedicated TLS lane
    |     +-- Mux stream --> adaptive TLS Shard
    |     +-- QUIC reliable stream
    |
    +-- UDP budget: 256 active flows
          |
          +-- UoT stream --> dedicated TLS lane or Mux Shard
          +-- QUIC control stream + DATAGRAM route
```

The TCP and UDP budgets are per authenticated session rather than process-wide.
Multiple sessions using the same shared key receive independent flow budgets.
All Shards from one session share its TCP or UDP admission budget. The shared
key is a credential, not a stable user identity, so Portal does not aggregate
these limits across every client that knows the same key. Operators control
aggregate exposure through key distribution, host resource limits, and
network-level admission policy.

Relay scratch buffers use bounded reuse caches: each process retains at most 64
TCP buffers and 32 UDP buffers. A short-lived concurrency spike therefore
cannot leave an unbounded allocator cache behind.

## Local telemetry

The TUI control plane binds only IPv4 loopback and publishes a descriptor in
the platform's per-user temporary directory. The client validates the registry
identity against the server hello. No shared keys or payload bytes enter
telemetry. Unix registry files receive owner-only permissions; every platform
also validates the per-user descriptor and server identity before displaying
an instance.

## Threat boundary

Nowhere protects traffic on its carrier links. Target-side security, local
SOCKS access control, endpoint compromise, denial of service within configured
limits, and application reconnection policy remain operational
responsibilities.
