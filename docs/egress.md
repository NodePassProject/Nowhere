# Egress Extension

Egress is a Nowhere-specific extension to [Nowhere Protocol (NW3)](protocol.md),
not part of NW3 Core. A Portal with `out=egress` shares one logical output among
all Egress connections authenticated with its Shared Key. Vector uses the Core
protocol and does not know about Egress registration.

## Contents

- [Roles and connections](#roles-and-connections)
- [Configure the peers](#configure-the-peers)
- [Authentication](#authentication)
- [Registration](#registration)
- [Business flows](#business-flows)
- [UDP identity and bridging](#udp-identity-and-bridging)
- [Registration ownership and lifetime](#registration-ownership-and-lifetime)
- [TLS Hydra](#tls-hydra)
- [Morph](#morph)
- [Observe registration](#observe-registration)
- [Validation](#validation)

## Roles and connections

Arrows show connection establishment; traffic is bidirectional:

```text
               TLS / QUIC                   TLS / QUIC
+----------+                 +----------+                 +----------+
|  Vector  |---------------->|  Portal  |<----------------|  Egress  |
+----------+                 +----------+                 +----------+
                                                               |
                                                               | TCP / UDP
                                                               v
                                                          +----------+
                                                          |  Target  |
                                                          +----------+
```

Each Egress is a transport client and Portal is the server. Multiple Egress
instances may independently connect over TLS or QUIC. Portal initiates each
business Flow; Egress resolves and dials the target. There is no discovery,
coordination or instance identifier between Egress processes.

## Configure the peers

Use the same Shared Key on Portal, Vector and Egress. Portal needs a listener for
each Egress carrier in use:

```sh
nowhere "portal://KEY@*/tcp:2000/udp:2001?out=egress"
nowhere "egress://KEY@relay.example/tcp:2000?pin=TRUSTED_SHA256"
nowhere "egress://KEY@relay.example/udp:2001?pin=TRUSTED_SHA256"
```

Each Egress URL selects one carrier. `HOST:PORT` selects QUIC by default.
Portal's `out=egress` conflicts with explicit `dial`, `dial4` and `dial6`;
Egress applies those options only to targets. Certificate trust, address family,
Morph and other options are described in [Configuration](configuration.md).

## Authentication

Both carriers use TLS 1.3, ALPN `nw3`, certificate verification, disabled
0-RTT and the same Shared Key and Egress role-key derivation:

```text
salt       = SHA256("nowhere/nw3/auth-root")
root       = HMAC-SHA256(salt, shared_key)
egress_key = HMAC-SHA256(root, "egress-authentication" || 0x01)
exporter   = TLS-Exporter("EXPORTER-Nowhere-nw3-Auth", empty_context, 32)
transport  = 0x01 for TLS/TCP; 0x02 for QUIC
AuthFrame  = HMAC-SHA256(egress_key, transport || exporter)[0..16]
```

Portal compares the connection-bound tags against the Vector and Egress role
keys in constant time. Tags cannot be replayed on another connection or carrier.
The same Shared Key derives both authorities; role separation does not provide
independent credentials. Registration is permitted only for `out=egress`.

## Registration

RegistrationResult is one byte: `00` ACCEPTED or `01` BUSY. Invalid
authentication or disallowed Egress policy closes the connection without an
application result. Egress waits for ACCEPTED before processing Flow requests.

For TLS, authentication, registration and the sole Flow share the connection:

```text
Egress → Portal: AuthFrame
Egress ← Portal: ACCEPTED or BUSY
Egress ← Portal: FlowStart + Target
Egress → Portal: SetupResult
Egress ↔ Portal: Payload after READY
```

For QUIC, registration uses client bidirectional Stream 0 and the reply is
followed by FIN. The AuthFrame is followed by FIN, with no Flow bytes on that
Stream. Portal then initiates each business bidirectional Stream, starting with
Stream 1. Client-initiated Egress business Streams are role-direction violations.
Unauthenticated DATAGRAMs and DATAGRAMs received while awaiting registration are
discarded.

Portal caps the aggregate number of pending TLS registrations with
`NOW_PORTAL_TLS_IDLE_MAX` (default 128, range 1–1023). Connections
being accepted count toward that cap. Full capacity returns BUSY. All accepted
connections also hold a shared connection permit until they close;
claiming a TLS connection releases only its pending-registration allowance.

## Business flows

Portal keeps one FIFO of registered connections across all Egress instances and
both carriers. Claiming a QUIC connection immediately puts it back at the tail;
it can carry multiple simultaneous Flows. Claiming a TLS connection permanently
removes it; that connection carries exactly one Flow. Closed and expired entries
are discarded. FIFO does not promise fairness, carrier priority, weight or a
particular traffic split.

For example, starting with four registered connections (head on the left):

```text
   +----------+   +----------+   +----------+   +----------+
   | QUIC A   |-->| TLS B    |-->| QUIC C   |-->| TLS D    |
   +----------+   +----------+   +----------+   +----------+

Claim QUIC A: it returns to the tail and can carry a Flow.

   +----------+   +----------+   +----------+   +----------+
   | TLS B    |-->| QUIC C   |-->| TLS D    |-->| QUIC A   |
   +----------+   +----------+   +----------+   +----------+

Claim TLS B: it leaves the FIFO and carries one Flow.

   +----------+   +----------+   +----------+
   | QUIC C   |-->| TLS D    |-->| QUIC A   |
   +----------+   +----------+   +----------+
```

These labels identify connections in the example, not protocol instance IDs.

When no connection is available, Flow setup waits for registration within the
`NOW_FLOW_SETUP_TIMEOUT` operation budget. Selection, claim, request writing and
result reading share that budget. Once a connection has been selected,
any setup or forwarding failure ends that Flow: Portal does not retry another
Egress, change carrier, fall back locally or migrate active traffic.

For either carrier, `FlowStart + Target`, `SetupResult`, TCP half-close and UDP
semantics follow Core. TLS carries UDP using Core stream framing; QUIC uses
business Streams and DATAGRAMs. There is no mux or additional control protocol. Invalid requests and resource/dial failures affect the selected Flow.

## UDP identity and bridging

A QUIC Egress business Stream is server-initiated. Its connection-local UDP
Flow ID follows the Core formula `(quic_stream_id >> 2) + 1`, with the range
`1..=2^30-1`; the last usable server-initiated raw ID is `4294967289`.
The authentication Stream creates no UDP route. Exhaustion stops admission,
drains within the configured shutdown deadline, closes and reconnects.

Each bridge leg independently handles UDP framing, routing, reassembly and MTU;
IDs do not identify a Flow across connections. FIN, reset, STOP_SENDING, idle
expiry and connection loss reclaim the Flow without relying on CLOSE DATAGRAM.

## Registration ownership and lifetime

A registration owns its connection and cancellation state. TLS standby is
claimed at most once; QUIC registration cleanup removes only the actual
connection's queue entry. Each Flow owns its selected handles and cannot be
recovered by a later registration. Portal shutdown cancels waiters and closes
owned resources. QUIC uses keepalive and idle timeouts.

After a claim, the connection's carrier determines its ownership:

```text
                 +---------------------------+
                 |  Portal FIFO: QUIC + TLS  |
                 +-------------+-------------+
                               | claim
                +--------------+--------------+
                |                             |
                v                             v
        +---------------+             +---------------+
        | QUIC carrier  |             |  TLS standby  |
        +-------+-------+             +-------+-------+
                |                             |
         +------+--------+                    v
         |               |            +---------------+
         v               v            |   one Flow    |
  +-------------+ +-------------+     +-------+-------+
  |  FIFO tail  | | open Stream |             |
  +-------------+ +-------------+             v
                                      +---------------+
                                      |    closed     |
                                      +---------------+
```

Portal and Egress independently expire idle TLS standby connections after
120 seconds. On Portal, the timer ends when the connection is claimed; on
Egress, it ends when a FlowStart is received. An active Flow is not subject to
this standby TTL. A claim racing expiration may fail directly.

Egress enables kernel TCP keepalive on its TLS connections to Portal before
the handshake, with a 15-second idle time and a 15-second probe interval.
The probe count uses the system default. Keepalive remains enabled through
standby and active Flows; it does not extend the standby TTL.

## TLS Hydra

Each TLS Egress has one supervisor and starts with one standby seed. Its budget
counts connections being established, registering and waiting for a Flow; active
Flows do not count. `NOW_EGRESS_TLS_POOL_MAX` sets the per-process maximum,
default 128 and minimum 1.

On receiving FlowStart the connection leaves the standby budget, and the
supervisor starts up to two replacements without exceeding the maximum.
Failures, disconnects and expiry do not cause growth. If the budget reaches
zero, the supervisor restores one seed; failed seed attempts use
`NOW_SERVICE_COOLDOWN` (default `3s`). Unused surplus naturally expires, so the
pool returns to the seed without a separate maintenance protocol.

## Morph

TLS Egress uses the same authenticated TCP Prelude, replay protection and
continuous TCP Morph transform as TLS Vector connections. QUIC Egress uses the
UDP Morph transform; directional keys follow transport roles even
though Portal initiates business Streams. Peers must agree on Shared Key and
Morph enablement out of band.

## Observe registration

Registration ownership is internal. IPC reports TCP/UDP traffic and active
business Flows; standby connections are not active Flows. Diagnostic stderr
reports connection, registration and target failures. `nowhere probe` checks
real target setup through the configured output. See [Operations](operations.md)
and [Telemetry](telemetry.md).

## Validation

The [authentication fixtures](../src/tests/protocol/vectors.json) include role
keys and tags for both carriers. Tests cover mixed carriers, multiple instances,
FIFO and QUIC rotation, TLS single-claim ownership, capacity, TTL, Hydra growth
and decay, failure cleanup, Morph and TCP/UDP forwarding. See [Testing](testing.md).
