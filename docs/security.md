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

## Morph boundary

With `morph=1`, HKDF-SHA256 derives separate TCP client-to-server,
TCP server-to-client, and UDP keys from the endpoint shared key. ChaCha20 XOR
then masks the TLS stream or each QUIC datagram below the secure transport.
The nonce is public: TCP carries one 12-byte client nonce per connection and
UDP carries one 12-byte nonce per datagram.

An observer without the shared key cannot directly recover the bare TLS/QUIC
wire image or feed captured bytes directly to a generic TLS/QUIC parser. Morph
does not authenticate bytes, detect modification, reject replay, hide lengths
or timing, imitate HTTPS, or provide session security. TLS/QUIC and AuthFrame
remain mandatory. Random nonces can collide, UDP maintains no replay state,
and TCP does not remember previously used client nonces. Shared keys therefore
need adequate entropy; HKDF does not make a guessable key expensive to search.

Morph has no negotiation or downgrade path. A missing setting or wrong key
appears as a TLS/QUIC handshake failure or timeout rather than a distinct
authenticated Morph error.

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
32 KiB per DATA frame. Malformed kinds, codes, IDs, lengths, window overflow,
and DATA for unknown streams close the carrier. Late terminal and credit frames
for a terminal stream are idempotent.

The transport memory profile bounds Mux stream/connection windows at 4/8,
8/16, or 16/32 MiB. Each Mux carrier admits at most 4,096 active streams. With client `mux=1`,
Vector or Portal `next` shares at most eight TLS carriers across both directions,
reuses idle carriers before creating more, distributes flows by occupancy at capacity,
and closes a fully idle carrier after 30 seconds. Stream and pending lifecycle
metadata remain proportional to admitted streams; separate OPEN admission bounds
metadata that carries no DATA credit. One
authenticated inbound Mux carrier is subject to the same fully idle timeout.
The former authenticated-session logical-flow quotas are absent. Independent
resource admission caps Mux streams, accepted SOCKS clients, and active SOCKS UDP
targets; byte windows do not bound those resources.
Per-stream and connection credit plus OPEN admission limit how much
one stream can occupy. The finite frame queue has 512 slots, but
payload admission is capped by the selected connection window; empty
OPEN/FIN/RESET/WINDOW frames cannot turn those slots into
retained application payload. These are credit ceilings rather than eagerly
allocated payload buffers.

TCP, UoT, and QUIC flows all follow the same policy: byte budgets, lifecycle
timeouts, and resource admission apply without restoring legacy application quotas. QUIC expands
stream credit with actual demand instead of preallocating a huge stream ceiling.
Operators control aggregate exposure through key distribution, host resource
limits, and network-level admission policy.

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
