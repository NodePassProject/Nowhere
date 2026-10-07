# Security and Resource Bounds

## Authentication

Portal enforces a 32–64-character lowercase hexadecimal shared key on both
its listener and enabled native `next` hop. Use `nowhere generate-key`, which
encodes 16 operating-system random bytes and provides 128 bits of random
entropy. A matching format alone does not prove entropy or generator provenance.
All peers on each hop use the same key text. The complete text bytes are the
authentication and Morph derivation input, without hex decoding.
See [Configuration](configuration.md#shared-keys).

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

TLS is version 1.3. Vector, `probe`, and native Portal `next` verify the peer
certificate against system CA roots by default, using the endpoint host as the
verified DNS name or IP address. `sni=` overrides that name. Omitting `sni`,
using `sni=none`, or leaving it empty still requires certificate verification.
Missing, empty, or `none` pins also retain system-root verification. Unavailable
or invalid system roots fail client initialization; clients never fall back to
accepting an untrusted certificate.

An explicit `pin=<sha256>` instead requires the exact leaf-certificate SHA-256
fingerprint and a valid TLS handshake signature. Pinning takes precedence over
CA and server-name validation, allowing a generated self-signed Portal
certificate to be used securely. Obtain the expected fingerprint through a
trusted channel, such as the Portal host's certificate log. A generated
certificate changes when Portal restarts, so its configured pin must be updated.

`nowhere fingerprint <nowhere-url>` accepts a `nowhere://` share link and reads
a certificate without CA or pin validation for inspection. This command sends
no Nowhere authentication or Flow data and does not establish the certificate's
trusted identity. It cannot disable verification for Vector, `probe`, or native
`next`.

An active man-in-the-middle can present its own certificate, causing the
command to report the attacker's fingerprint. Copying that result directly
into `pin=` would trust the attacker. Compare the returned fingerprint with an
expected value obtained independently through a trusted channel, such as the
Portal host's startup log accessed through an authenticated administration
session. The remote inspection result alone is not a trusted source for a pin.

## Morph boundary

With `morph=1`, HKDF-SHA256 derives separate client-to-server and
server-to-client keys for both TCP and UDP from the endpoint shared key.
ChaCha20 XOR then masks the TLS stream or each QUIC datagram below the secure
transport. The nonce is public: TCP carries one 12-byte client nonce per
connection and UDP carries one 12-byte nonce per datagram. A TCP connection
begins with a 64-byte opaque prelude; its contents are selected by the client.

An observer without the shared key cannot directly recover the bare TLS/QUIC
wire image or feed captured bytes directly to a generic TLS/QUIC parser. Morph
does not authenticate bytes, detect modification, reject replay, hide lengths
or timing, imitate HTTPS, or provide session security. TLS/QUIC and AuthFrame
remain mandatory. Random nonces can collide, UDP maintains no replay state,
and TCP does not remember previously used client nonces. Shared keys therefore
need adequate entropy; HKDF does not make a guessable key expensive to search.
The default `full8` policy fills the prelude with unrestricted random bytes.
Explicit `low7` clears each byte's high bit. The TCP prelude is only
first-flight byte shaping. It provides no
authentication, integrity, replay defense, camouflage guarantee, or censorship
resistance.

Morph has no negotiation or downgrade path. A missing setting or wrong key
appears as a TLS/QUIC handshake failure or timeout rather than a distinct
authenticated Morph error.

## Endpoint exposure

The service endpoint is also the network exposure policy. A compact Portal
endpoint exposes TLS/TCP and QUIC/UDP on the same port. An explicit path exposes
only its declared carriers, ports, and address families:

```text
portal://<generated-key>@*/tcp4:2006
portal://<generated-key>@192.0.2.10/tcp:2006/udp:2017
portal://<generated-key>@[2001:db8::10]/udp6:2017
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
and DATA for genuinely unknown streams close the carrier. DATA already in flight
after a local close remains subject to both receive windows, is discarded, and
returns only connection credit. Late terminal and credit frames for a terminal
stream are idempotent.

The transport memory profile bounds Mux stream/connection windows at 4/8,
8/16, or 16/32 MiB. Each Mux carrier retains at most 4,096 active and closed
flow states. With client `mux=1`,
Vector or Portal `next` shares at most eight TLS carriers across both directions,
reuses idle carriers before creating more, distributes flows by occupancy at capacity,
and closes a fully idle carrier after 30 seconds. Stream and pending lifecycle
metadata remain proportional to admitted streams. Active streams, pending
incoming deliveries, and terminal deliveries each have a separate 4,096-entry
ceiling, so OPEN/RESET churn cannot grow either delivery queue without bound.
Queue overflow closes the carrier without blocking its reader. One
authenticated inbound Mux carrier is subject to the same fully idle timeout.
Resource admission caps Mux streams, accepted SOCKS clients, active SOCKS UDP
targets, and Portal flow claims. Each authenticated Portal session admits 4,096
active or pending claims, with 65,536 across the pairing registry; byte windows
do not bound those resources.
Per-stream and connection credit plus OPEN admission limit how much
one stream can occupy. The finite frame queue has 512 slots, but
payload admission is capped by the selected connection window; empty
OPEN/FIN/RESET/WINDOW frames cannot turn those slots into
retained application payload. These are credit ceilings rather than eagerly
allocated payload buffers.

TCP, UoT, and QUIC flows are governed by byte budgets, lifecycle timeouts, and
resource admission. QUIC expands stream credit with actual demand and clamps
it to the session claim budget.
Operators control aggregate exposure through key distribution, host resource
limits, and network-level admission policy.

Relay scratch buffers use bounded reuse caches: each process retains at most 64
TCP buffers and 32 UDP buffers. A short-lived concurrency spike therefore
cannot leave an unbounded allocator cache behind.

## Local telemetry

Telemetry uses protected Unix domain sockets or local-only Windows named pipes,
with access restricted to the same operating-system user. It has no network
listener and never falls back to TCP. The client validates discovery, endpoint
and peer identity; a self-reported hello is not independent authentication.

No shared keys, business payloads, raw endpoints or configuration summaries enter
telemetry output. Client, target and peer identities are instance-local keyed
pseudonyms; correlation, timing and traffic size remain observable. Events expose
fixed codes rather than arbitrary error strings. The TUI cannot reveal raw
addresses. Independent stdout/stderr business logs retain their own policy.

Same-user compromise and administrator access are outside this isolation boundary.
Authorized collectors control what they store or forward after receipt. Queues,
connections, frames and commands are bounded. Telemetry initializes only if
permissions and identity can be established; otherwise forwarding continues
without it. Container subscription is supported within the same container and
user, not through shared cross-namespace directories. See the
[telemetry contract](telemetry.md) for exact fields, limits and discovery rules.

## Threat boundary

Nowhere protects traffic on its carrier links. Target-side security, local
SOCKS access control, endpoint compromise, denial of service within configured
limits, and application reconnection policy remain operational
responsibilities.
