# Security

Understand trust, authentication, transport admission and the limits of local
and network isolation. Wire contracts follow the
[Core specification](protocol.md), [Prelude Extension](prelude.md) and
[Egress Extension](egress.md).

## Contents

- [Certificate trust](#certificate-trust)
- [Connection authentication](#connection-authentication)
- [Morph transport protection](#morph-transport-protection)
- [Observable boundaries](#observable-boundaries)
- [Admission and Flow resources](#admission-and-flow-resources)
- [Flow lifetime and exit ownership](#flow-lifetime-and-exit-ownership)
- [Local IPC](#local-ipc)
- [Metadata and diagnostics](#metadata-and-diagnostics)

## Certificate trust

Vector and Egress require system CA trust with hostname validation, or an exact
certificate SHA-256 pin. TLS 1.3 and ALPN `nw3` are mandatory. 0-RTT is disabled,
including on resumed connections.

| Trust mode | Verification |
|---|---|
| System CA | The certificate chain is trusted and the server name matches |
| Exact pin | The presented certificate matches the configured SHA-256 fingerprint |
| Fingerprint inspection | Reads the presented certificate for separate trust verification |

A pin is 64 lowercase hexadecimal characters. A missing, empty or `none` pin
uses normal certificate verification. Explicit fingerprint inspection does
not establish trust; compare its result through a trusted channel before use.
See [Operations](operations.md#diagnose-target-setup) for inspection commands.

## Connection authentication

AuthFrame is a 16-byte HMAC tag over the transport byte and normal TLS exporter.
Tags are compared in constant time and bind authentication to the connection,
transport and role, including on resumed TLS connections. The
[Core specification](protocol.md) defines Vector authentication; the
[Egress Extension](egress.md#authentication) defines the additional role key.

### Shared Key authority

Portal, Vector, Egress, Probe and fingerprint inspection require exactly 32
lowercase hexadecimal text characters. Shared Key is percent-decoded once and
used as text bytes.
`nowhere generate-key` encodes 16 cryptographically random bytes as text,
providing 128 bits of entropy. The accepted format alone does not guarantee
entropy; key derivation does not increase it.

One credential derives both Vector and Egress role keys. Sharing it shares its
authority; role derivation does not provide independent credential permissions.

## Morph transport protection

Morph masks the transport wire image. TLS/QUIC supplies authenticated encryption
and integrity. TCP bootstrap authentication and UDP version filtering apply at
different ingress stages; neither replaces AuthFrame authentication.

### Cipher and Nonce limits

Each TCP cipher direction is limited to `2^38 - 64` bytes to prevent cipher
block-counter wrap within a connection. The 96-bit TCP Nonce is randomly
generated, so uniqueness across connections sharing a key is probabilistic.
A repeated Nonce reuses the outer Morph keystream; Prelude counters do not
prevent that collision.

### TCP bootstrap and replay

Portal requires a valid 14-byte Prelude Tag and Counter before ClientHello
parsing. All configured [Prelude policies](configuration.md#tcp-morph-prelude)
use the same authentication and replay checks.

Replay precheck precedes silent ClientHello parsing. After rustls Acceptor
accepts ClientHello, Portal checks the deadline and atomically rechecks and
commits replay state before any TLS response. Incomplete or malformed
ClientHello does not reserve a Counter. Later TLS or AuthFrame failures do not
undo a commit.

Each Identity has a 1024-bit replay window while it remains in the
16,384-entry FIFO registry. Eviction or Portal restart removes its history.
Shared Key holders can churn the registry or advance replay windows; random
64-bit Identity collisions can cause unwanted window sharing.

### TCP ClientHello admission

Portal reads ClientHello through rustls Acceptor without sending parser alerts.
Before acceptance, incomplete or rejected input, including a peer's write-side
FIN, is held silently until the authentication deadline. The absolute deadline
starts when TCP accept completes and covers Prelude, Nonce, ClientHello, TLS
and AuthFrame together. `NOW_HANDSHAKE_TIMEOUT` controls it; its unset default is
derived once from the Shared Key in the range 3–30s. See
[timeout semantics](configuration.md#timeout-semantics).
Shutdown may end the connection earlier. Resets and unrecoverable I/O failures
detected while reading may also end it before input is rejected.

When authentication processing is full, Morph TCP connections wait silently
without reading input, creating TLS state or holding a processing or business
connection permit. Released processing permits wake waiting connections to
retry admission within their original deadline. Waiting does not guarantee
ordering or eventual admission under sustained contention.

Silent rejection during authentication immediately stops reading and retains
the socket and processing permit until the original deadline. Further input,
FIN or RST does not shorten or extend that wait. Portal sends no filler data
and introduces no random delays.

The silent stage ends after ClientHello acceptance, successful replay commit
and the deadline check. Configuration-dependent ClientHello checks, TLS
completion and AuthFrame validation follow; TLS processing can send alerts
at this point. Standard TLS (`morph=0`) and QUIC do not use this stage.

### TCP socket closure

For Morph TCP, Portal enables `SO_LINGER=0` when TCP accept completes and
retains it through TLS, ALPN and AuthFrame verification.

| Authentication state | Socket close policy |
|---|---|
| Prelude, replay or ClientHello checks incomplete or rejected | Zero linger; abortive close |
| TLS, ALPN or AuthFrame incomplete or rejected | Zero linger; abortive close |
| Complete authorized Vector or Egress AuthFrame within the deadline | Restore normal linger; normal close and half-close |

Portal checks the original deadline before and after restoring normal linger.
Expiry retains zero linger; failure, timeout or cancellation before successful
authentication does not restore normal linger. Socket-option failures terminate
the connection without forwarding.

On Linux, zero linger requests RST even with unread data. Packet-level FIN/RST
behavior on other operating systems depends on the kernel. Resource rejection
before connection authentication begins and socket-option failures are outside
this close policy's guarantees.

### UDP version handling

After unmasking, Portal checks the first QUIC packet in each UDP datagram before
handing it to Quinn. A long header with an incomplete or unsupported Version,
including Version 0, is silently discarded. Supported versions follow Quinn's
default endpoint version list. Short headers pass to Quinn without version
filtering.

Each UDP GRO segment is checked independently. This filter applies only to
Portal's Morph UDP ingress; native QUIC retains its normal Version Negotiation
behavior. The filter adds no replay state or authentication exchange.

Portal requires Retry for QUIC connections whose remote address has not been
validated. Version filtering does not change address validation, TLS,
AuthFrame or business Flow admission.

### Morph UDP Prelude

The [UDP Prelude](prelude.md#morph-udp-prelude) contains 12 policy-generated
random bytes. It provides neither identity authentication nor replay protection
and is separate from every encrypted datagram's Morph Nonce. Portal silently
discards it without a response or authentication state. QUIC uses TLS 1.3 and
AuthFrame for connection protection and authentication.

## Observable boundaries

Transport admission limits early responses. Its protection depends on the
input and the stage it reaches:

| Input or stage | Observable behavior |
|---|---|
| Rejected Morph TCP bootstrap or ClientHello | No parser response before the original deadline; socket closure remains observable |
| Accepted Morph TCP ClientHello with committed replay state | TLS responses and later alerts are possible before AuthFrame succeeds |
| Unsupported-version Morph UDP long header | Silently discarded before Quinn; no Version Negotiation response |
| Captured valid QUIC Initial | Can trigger Retry and address validation |
| Standard TLS or native QUIC | Uses the transport's normal response behavior |

RST, deadlines, business connection limits and operating-system resource
exhaustion remain observable. These protections do not eliminate all
active-probing or traffic-analysis fingerprints. Morph UDP version filtering
does not authenticate datagrams or provide replay protection. TLS and AuthFrame
must succeed before target access.

The Prelude Tag authenticates bootstrap metadata, not the encrypted TLS stream.
An observer who knows a captured ClientHello field's position and value can
modify its Morph ciphertext without the Shared Key. Modified input may pass
Acceptor and trigger later alerts; a captured bootstrap can race its first use
with a modified ClientHello and consume its Counter.

A captured bootstrap also permits offline verification of candidate Shared Keys
through its Tag. Prelude masking has no forward secrecy: disclosure of the
Shared Key permits decoding captured Identity and Counter metadata.

## Admission and Flow resources

Authentication precedes target work and Egress registration. Portal applies
these limits before accepting a role:

| Resource | Pre-authentication limit |
|---|---|
| Authentication processing | 256 total; 32 per IPv4 source or IPv6 /64, shared by TCP and QUIC |
| QUIC Stream credit | One client bidirectional Stream; no unidirectional Streams |
| QUIC connection receive window | 64 KiB |
| Handshake and authentication | `NOW_HANDSHAKE_TIMEOUT`, Shared Key-derived default `3s`–`30s` |

Morph TCP connections waiting for authentication processing are bounded by the
operating system's file descriptor limit, not a separate application quota.
They retain a socket and task until admission, the original deadline or shutdown.
Accepted connections also require a shared connection permit (1024 total), held
through their business lifetime; parked connections do not hold this permit.
Temporary TCP accept resource failures use a 10 ms exponential backoff capped
at 250 ms, reset after a successful accept. Existing tasks continue to run and
expire during backoff. Extreme load can exhaust file descriptors, memory or CPU,
degrade service and require operational intervention. QUIC requires Retry for
unvalidated addresses and ignores arrivals when admission is full.

After authentication, receive windows are raised to the selected QUIC profile.
Business resources remain bounded by target Flow permits, Stream credit,
UDP queues, reassembly reservations and transport receive buffers. See
[Configuration](configuration.md#runtime-environment) for runtime settings.

UDP DATAGRAM bypasses Stream flow control. Unknown, pre-READY and unauthenticated
IDs are discarded. Reassembly permits 64 partial packets per connection with a
ten-second TTL. Queued datagrams and fragments share the per-connection
`NOW_QUIC_UDP_QUEUE_BYTES` budget (default 4 MiB), separate from QUIC's DATAGRAM
receive and send buffers (4 MiB each). Reservations remain held until delivery
or cleanup. Full Flow queues use nonblocking dispatch so one slow Flow cannot
stall the connection.

## Flow lifetime and exit ownership

Stream direction and the 30-bit derived UDP ID range are checked before use,
without truncation. ID exhaustion stops admission and triggers a bounded drain
and close or reconnect. FIN, RESET, STOP_SENDING, idle timeout and connection loss
reclaim UDP routes independently of CLOSE DATAGRAM delivery.

Egress registers only when Portal has `out=egress`. Queue claims and cleanup
are tied to the actual connection. Egress waits for ACCEPTED before target work.
Offline Flows wait within the setup deadline, without local fallback. Vector
connection acquisition, request writing and READY reading share one Flow setup
deadline; timeout drops pending streams and UDP routes. A temporary first-Flow
QUIC connection is closed, while a reused connection retains its other Flows.
QUIC Egress registration bounds Stream acquisition, AuthFrame sending and the
complete ACCEPTED reply with one handshake deadline. See
[Egress ownership](egress.md#registration-ownership-and-lifetime).

DNS and target sockets belong to the selected exit. Explicit source binding
errors fail the dial and do not retry with an automatic source.

## Local IPC

Local observation is restricted to the service's operating-system user.

| Boundary | Protection |
|---|---|
| Unix registry and sockets | Permissions and symlink/object checks |
| Windows registry and named pipes | ACLs and peer checks |
| Collector discovery | Registry/Hello consistency, process liveness and platform peer identity |
| Linux and Windows discovery | Additional process-incarnation checks |

Discovery and cleanup stay inside the documented IPC namespace. Administrators
and compromised processes running as the same user are outside this isolation
boundary.

A 64 KiB server frame ceiling, 16-client limit and bounded writes constrain
resource use. A five-second write deadline disconnects blocked consumers. See
[Telemetry](telemetry.md) for limits and identity requirements.

## Metadata and diagnostics

Startup output omits Shared Key and SOCKS credentials. Private key contents are
never logged. IPC metadata exposes validated service endpoints to authorized
collectors; it includes no configuration summary, client address or transport
peer identity.

IPC carries instance identity and six statistics. It contains no Flow events,
error messages or logs.

Service errors preserve their original cause chains and can contain addresses
or paths. Error construction excludes passwords, Shared Keys and complete
credential URLs. See [Telemetry privacy](telemetry.md#privacy-and-trust).
