# Nowhere Wire Protocol

This document specifies the wire format implemented by Nowhere. All integers
are unsigned and use network byte order. Byte offsets start at zero. Reserved
bits MUST be zero, and decoders reject unknown values unless this document says
otherwise.

## Contents

1. [Carrier model](#1-carrier-model)
2. [Connection authentication](#2-connection-authentication)
3. [TLS mode dispatch and Mux frames](#3-tls-mode-dispatch-and-mux-frames)
4. [FlowHeader](#4-flowheader)
5. [Target](#5-target)
6. [SetupResult](#6-setupresult)
7. [TCP payload](#7-tcp-payload)
8. [UDP over stream](#8-udp-over-stream-uot)
9. [UDP over QUIC DATAGRAM](#9-udp-over-quic-datagram)
10. [Portal forwarding budget](#10-portal-forwarding-budget)
11. [Runtime limits and failure scope](#11-runtime-limits-and-failure-scope)

## 1. Carrier model

TLS/TCP and QUIC use TLS 1.3 with the sole ALPN `nw2`. A client offers `nw2`,
and the server requires the handshake to select exactly `nw2` before Nowhere
authentication.

### Command endpoint mapping

The command URL chooses the socket for each physical carrier before this wire
protocol begins. Its endpoint forms map as follows:

| Command endpoint entry | Physical carrier | Wire transport byte |
|---|---|---:|
| compact `HOST:PORT` TCP side | TLS 1.3 over TCP on `PORT` | `0x01` |
| compact `HOST:PORT` UDP side | QUIC over UDP on `PORT` | `0x02` |
| `HOST/tcp:PORT`, `HOST/tcp4:PORT`, or `HOST/tcp6:PORT` | TLS 1.3 over TCP on its own port/family | `0x01` |
| `HOST/udp:PORT`, `HOST/udp4:PORT`, or `HOST/udp6:PORT` | QUIC over UDP on its own port/family | `0x02` |

TCP and UDP may use different ports and address families while sharing one
command endpoint host. Port numbers, hostnames, wildcard selection, and
address-family suffixes are not serialized in AuthFrame or FlowHeader. They
only select the local listener or remote socket on which a carrier is
established.

Disabling a carrier by omitting it from an explicit endpoint does not create a
new wire mode. It prevents the local process from listening or dialing that
physical transport. Client `up`, `down`, and `mix` policy must select from the
declared carriers before a FlowHeader is encoded.

Separate TCP and UDP socket addresses do not separate sessions. The same
authenticated `session_id` joins all physical carriers created by one client,
so split OPEN and ATTACH lanes can pair across carrier ports and IP families.
Address family is never negotiated on the wire; reachability and family
filtering complete before TLS or QUIC authentication.

### Morph socket layer

When the command endpoint has `morph=1`, a keyed transform sits below TLS/TCP
or QUIC/UDP. It changes the socket wire image and is removed before bytes reach
rustls or Quinn. There is no magic, version, negotiation, fallback, padding,
framing protocol, TLS parser, or QUIC parser.

The decoded shared-key bytes are the HKDF input:

```text
morph_root = HKDF-Extract-SHA256(
    salt = ASCII("nowhere/morph"),
    IKM  = shared_key
)

tcp_c2s_key = HKDF-Expand-SHA256(morph_root, ASCII("tcp c2s"), 32)
tcp_s2c_key = HKDF-Expand-SHA256(morph_root, ASCII("tcp s2c"), 32)
udp_key     = HKDF-Expand-SHA256(morph_root, ASCII("udp"), 32)
```

Labels contain exactly the shown ASCII bytes and no trailing NUL. The cipher
is IETF ChaCha20 with a 256-bit key, 96-bit nonce, and internal block counter
starting at zero.

For TCP, the active connector generates one nonce and sends it before TLS:

```text
client -> server: nonce[12] || ChaCha20-XOR(TLS bytes, tcp_c2s_key, nonce)
server -> client:              ChaCha20-XOR(TLS bytes, tcp_s2c_key, nonce)
```

The server sends no Morph prefix. Each direction has an independent stream
offset. TLS bytes retain their length and the connection adds exactly 12 bytes.
A direction stops before counter exhaustion, after at most `2^38 - 64`
transformed bytes, and never wraps or rekeys.

For UDP, every socket datagram is independent in either direction:

```text
wire datagram = nonce[12] || ChaCha20-XOR(QUIC datagram, udp_key, nonce)
```

TCP nonces come directly from the operating system CSPRNG. Each UDP socket
seeds a user-space ChaCha20 CSPRNG from the operating system and reseeds it
before its stream is exhausted. Receivers drop wire datagrams of 12 bytes or
fewer. Morph adds 12 bytes to every QUIC datagram, including Retry, stateless
reset, handshake, application, and MTU-probe packets. QUIC's 1200-byte minimum
therefore requires a path capable of carrying a 1212-byte UDP payload. With
Morph enabled, Quinn's default 1452-byte path-MTU discovery upper bound is
reduced to 1440 bytes, keeping the transformed UDP payload at 1452 bytes.

The command URL controls Morph for every carrier declared by that endpoint.
For Portal chaining, the outer `morph` value controls both adjacent hops while
each hop derives keys from its own shared key. Morph adds no authentication,
integrity, replay defense, traffic-analysis resistance, or session security;
the TLS/QUIC and AuthFrame layers retain those responsibilities.

One client session has one random 16-byte `session_id`. Every physical carrier
is authenticated with that ID, so Portal can pair logical lanes belonging to
the same client session.

```text
session_id
    |
    +-- dedicated TLS connection --> one logical lane
    +-- Mux TLS connection --------> multiple logical streams
    +-- QUIC connection -----------> reliable streams + UDP DATAGRAM routes
                                      |
                                      +-- each flow uses a nonzero flow_id
```

`session_id` is the cross-carrier pairing scope. `flow_id` identifies one
logical TCP or UDP flow inside that scope.

### Dedicated TLS lane

Each TLS connection carries one logical lane:

```text
Client -> Portal

+------------+--------------+----------+-------------------+
| AuthFrame  | FlowHeader   | Target?  | flow payload ...  |
| 32 bytes   | 5 bytes      | variable | after READY       |
+------------+--------------+----------+-------------------+

Portal -> Client

+-------------+-------------------+
| SetupResult | flow payload ...  |
| 1 byte      | only after READY  |
+-------------+-------------------+
```

`Target` is present only for `DUPLEX` and `OPEN`. A split flow uses an `OPEN`
lane for uplink and an `ATTACH` lane for downlink.

### Mux TLS carrier

A Mux TLS connection carries an authentication frame, the fixed Mux marker,
and a sequence of Mux frames on the client-to-Portal half:

```text
Client -> Portal

+------------+------------+-------------+-------------+-----+
| AuthFrame  | Mux marker | MuxFrame    | MuxFrame    | ... |
| 32 bytes   | 0xff       | 7 + N bytes | 7 + N bytes |     |
+------------+------------+-------------+-------------+-----+

Reconstructed logical stream

+--------------+----------+-------------------+
| FlowHeader   | Target?  | flow payload ...  |
| 5 bytes      | variable | after READY       |
+--------------+----------+-------------------+
```

The Mux `flow_id` and the `flow_id` inside the logical stream's FlowHeader MUST
match. After the marker, both directions use Mux frames; Portal does not echo
the marker. Mux frames never wrap QUIC.

### QUIC carrier

A QUIC connection authenticates on its first bidirectional stream. That stream
may contain only the AuthFrame or continue directly with the first logical
flow. Every later logical flow uses another bidirectional stream without a
second AuthFrame.

```text
First client-initiated bidirectional stream

+------------+--------------+----------+-------------------+
| AuthFrame  | FlowHeader?  | Target?  | flow payload ...  |
| 32 bytes   | 5 bytes      | variable | after READY       |
+------------+--------------+----------+-------------------+

Later client-initiated bidirectional stream

+--------------+----------+-------------------+
| FlowHeader   | Target?  | flow payload ...  |
| 5 bytes      | variable | after READY       |
+--------------+----------+-------------------+
```

TCP payload uses the reliable stream. UDP payload uses QUIC DATAGRAM after its
reliable control stream has received `READY`.

Client `mux=0` originates dedicated TLS lanes. Client `mux=1` originates Mux
TLS carriers. This client setting is available on Vector and on Portal when
`next` is enabled; it defaults to `0` and applies only when the configured
policy can select TLS/TCP. A fixed `udp/udp&mux=1` URL is canonicalized to
`mux=0`. Portal accepts both TLS forms on the same listener and selects the
decoder from the first byte after AuthFrame.

## 2. Connection authentication

Every physical TLS connection and every QUIC connection begins with one
AuthFrame on its first byte stream.

```text
AuthFrame - 32 bytes

 offset  0                                      16              32
         +---------------------------------------+---------------+
         | session_id                            | tag           |
         | 16 bytes                              | 16 bytes      |
         +---------------------------------------+---------------+
```

The shared key is 1–255 decoded bytes and is never transmitted. Authentication
uses these fixed derivations:

```text
salt      = SHA256("nowhere/nw2/auth-root")
auth_root = HMAC-SHA256(salt, shared_key)
auth_key  = HMAC-SHA256(auth_root, "authentication" || 0x01)

transport = 0x01 for TLS/TCP
          = 0x02 for QUIC

tag       = first 16 bytes of
            HMAC-SHA256(auth_key,
                        transport || exporter[32] || session_id[16])
```

The 32-byte exporter uses label `EXPORTER-Nowhere-Auth` and empty context.
Authentication is bound to the current TLS connection; replaying a captured
AuthFrame on another connection fails.

Portal applies authentication and bootstrap deadlines before accepting flow
state. Authentication has no response frame of its own.

## 3. TLS mode dispatch and Mux frames

Portal reads one byte immediately after a TLS AuthFrame:

```text
                    +----------------------+
next byte == 0xff ->| Mux frame decoder    |
                    +----------------------+

                    +----------------------+
next byte != 0xff ->| FlowHeader byte 0    |
                    +----------------------+
```

`0xff` cannot be a valid FlowHeader byte because its role bits are `0b11`,
which is reserved. The marker belongs to the TLS carrier and is not part of a
Mux frame.

### MuxHeader

Every Mux frame starts with a 7-byte header. A DATA frame carries
exactly `value` payload bytes; control frames carry no payload.

```text
MuxHeader - 7 bytes

 offset  0        1               3                       7
         +--------+---------------+-----------------------+
         | kind   | value         | flow_id               |
         | u8     | u16           | u32                   |
         +--------+---------------+-----------------------+
```

| `kind` | Name | `value` | `flow_id` |
|---:|---|---|---|
| `0x01` | OPEN | opener receive-window extension in 1 KiB units | nonzero |
| `0x02` | DATA | payload length, 1..65535 | nonzero |
| `0x03` | WINDOW | returned credit in 1 KiB units | `0` for connection, nonzero for stream |
| `0x04` | FIN | always `0` | nonzero |
| `0x05` | RESET | always `0` | nonzero |

OPEN carries no payload and extends
the opener's 4 MiB initial stream receive window. The runtime emits DATA
payloads of at most 32 KiB.

FIN and RESET carry no payload. FIN half-closes a logical stream; RESET
immediately removes it. Other frame kinds are invalid. Every nonzero `flow_id`
must be at most `0x3fffffff`; the upper two bits of its u32 field must be zero.

WINDOW carries no payload and requires nonzero credit in 1 KiB
units. A
WINDOW with `flow_id=0` replenishes connection credit; a nonzero ID replenishes
that logical stream. Credit that would exceed the configured window closes the
carrier. A late stream-local WINDOW for an already closed stream is ignored.

DATA for an unknown flow is a carrier error. Late or duplicate FIN/RESET processing
is idempotent. Closing the physical Mux carrier fails every logical stream on
that carrier.

Mux uses an initial 4 MiB stream window and 8 MiB connection window. Each side
sends one WINDOW to extend its connection window. OPEN advertises the opener's
stream extension; the receiver returns its stream extension with WINDOW.
The selected transport profile sets final windows to 4/8, 8/16, or 16/32 MiB.
Each carrier admits at most 4,096 active streams as an implementation resource
ceiling, independent of application flow policy. Each carrier has 512 queued
outbound frame slots and 4,096 queued terminal-delivery slots; each stream may
have one DATA frame queued or being written.
Payload must obtain
both stream and connection credit before it enters the outbound queue.

```text
application write
        |
        v
+----------------+    +-------------------+    +----------------+    +----------+
| stream credit  |--->| connection credit |--->| bounded queue  |--->| MuxFrame |
+----------------+    +-------------------+    +----------------+    +----------+
        ^                       ^
        | WINDOW(flow_id)       | WINDOW(flow_id=0)
        +-----------------------+
```

Both credit checks precede queue admission. A stream therefore cannot reserve
payload beyond either advertised receive window.

Client-side TLS Mux carriers share one session pool, with at most eight established
or connecting carriers combined. Each TLS carrier is full duplex. New flows
reuse idle carriers first. If all are busy and capacity remains, the new flow
establishes another carrier; independent establishments run concurrently. At
capacity, new flows use the carrier with the lowest maximum occupancy of send
credit, receive credit, and outbound frame slots; stream count plus pending
reservations breaks ties. Connecting slots also accept reservations, so a cold
burst does not pile onto the first completed handshake. Each slot shares one
initializer; cancellation allows a waiter to retry it. Failed expansion can
fall back to an established carrier. There is no stream-density target, latency
threshold, background polling, or migration
of established streams. This favors parallel throughput over minimizing the
number of carriers for many idle logical streams.

Receive queues use byte-credit admission rather than blocking the carrier reader
on a per-flow frame count. Every DATA frame consumes at least one KiB of credit,
bounding queued payload and DATA metadata across the carrier. Separate OPEN
admission caps active streams, pending incoming deliveries, and pending terminal
deliveries separately at 4,096 per carrier. A full incoming or terminal queue
closes the carrier immediately without blocking its reader; OPEN/RESET churn
cannot bypass these queue limits. Authentication remains
separate from Mux placement. A fully idle carrier closes after 30
seconds. Portal applies the same timeout to an authenticated Mux carrier with
no active streams. Sharding is runtime placement and does not add wire fields.

## 4. FlowHeader

Every logical lane begins with a 5-byte FlowHeader.

```text
FlowHeader - 5 bytes

 offset  0                        1                       5
         +------------------------+-----------------------+
         | flags                  | flow_id               |
         | u8                     | u32                   |
         +------------------------+-----------------------+

flags byte

 bit     7       5   4      3      2      1       0
         +---------+------+------+------+-----------+
         | hops    | down | up   | kind | role      |
         | 3 bits  | 1 bit| 1 bit| 1 bit| 2 bits    |
         +---------+------+------+------+-----------+
```

Field values:

| Field | Bits | Value |
|---|---:|---|
| `role` | 1..0 | `0=DUPLEX`, `1=OPEN`, `2=ATTACH`, `3=invalid` |
| `kind` | 2 | `0=TCP`, `1=UDP` |
| `up` | 3 | `0=TLS/TCP`, `1=QUIC` |
| `down` | 4 | `0=TLS/TCP`, `1=QUIC` |
| `hops` | 7..5 | remaining Portal forwarding budget, `0..7` |

`flow_id` is in `1..=0x3fffffff` and is scoped to `session_id`. Its u32 field's
upper two bits must be zero. The same logical flow uses the same ID on OPEN
and ATTACH, in MuxHeader, and in QUIC UDP DATAGRAM frames.

Role semantics:

| Role | Target follows | Current lane | Payload direction |
|---|---|---|---|
| DUPLEX | yes | MUST match both `up` and `down`; both carriers MUST be equal | both |
| OPEN | yes | MUST match `up` | client to Portal |
| ATTACH | no | MUST match `down` | Portal to client |

When `up` and `down` select the same carrier, one DUPLEX lane is used. When
they differ, Portal pairs OPEN and ATTACH by `(session_id, flow_id)`. Their
kind, carrier selection, and hop metadata must agree.

FlowHeader has no `mix` carrier value. Vector and a Portal `next` client resolve
the command-URL policy locally before opening a logical flow.

| `up` ↓ / `down` → | `tcp` | `udp` | `mix` |
|---|---|---|---|
| `tcp` | TT | TQ | TT ↔ TQ |
| `udp` | QT | QQ | QT ↔ QQ |
| `mix` | TT ↔ QT | TQ ↔ QQ | TT ↔ QQ |

T means TLS/TCP and Q means QUIC/UDP, with uplink first. `mix/mix` therefore
resolves only to TT or QQ. The primary pair must acquire all physical lanes
within `NOW_MIX_FALLBACK_TIMEOUT` (default `1s`). Failure or timeout discards
the attempt and starts the other allowed pair with a new flow ID. Starting the
FlowHeader or Target write commits the flow and disables fallback.

```text
Same carrier

Client                                            Portal
  |---- DUPLEX + Target on selected carrier ------->|
  |<=============== payload both ways =============>|

Split carriers

Client                                            Portal
  |---- OPEN + Target on uplink carrier ----------->|
  |---- ATTACH on downlink carrier ---------------->| pair by
  |                                                 | (session_id, flow_id)
  |================ uplink payload ================>|
  |<=============== downlink payload ===============|
```

Both split lanes are client-initiated. OPEN identifies the payload uplink;
ATTACH identifies the payload downlink.

## 5. Target

Target uses SOCKS5 address encoding and follows DUPLEX or OPEN.

```text
IPv4 target - 7 bytes

+--------+-------------------------------+---------------+
| ATYP   | IPv4 address                  | port          |
| 0x01   | 4 bytes                       | u16           |
+--------+-------------------------------+---------------+

Domain target - 4 + N bytes

+--------+--------+-----------------------+---------------+
| ATYP   | length | ASCII/IDNA hostname   | port          |
| 0x03   | u8=N   | N bytes               | u16           |
+--------+--------+-----------------------+---------------+

IPv6 target - 19 bytes

+--------+-----------------------------------------------+---------------+
| ATYP   | IPv6 address                                  | port          |
| 0x04   | 16 bytes                                      | u16           |
+--------+-----------------------------------------------+---------------+
```

Port zero is invalid. A domain is 1–253 ASCII bytes. Each DNS label is 1–63
bytes, contains only ASCII letters, digits, or `-`, and does not begin or end
with `-`. The wire contains no trailing NUL.

## 6. SetupResult

Portal returns exactly one setup byte on the logical downlink before payload
relay starts.

```text
SetupResult - 1 byte

+--------+
| result |
| u8     |
+--------+
```

| Value | Name | Meaning |
|---:|---|---|
| `0x00` | READY | flow is established |
| `0x01` | INVALID_REQUEST | malformed or carrier-inconsistent setup |
| `0x02` | METADATA_CONFLICT | OPEN and ATTACH metadata conflict |
| `0x03` | PAIR_TIMEOUT | the matching split lane did not arrive |
| `0x04` | FLOW_LIMIT | admission or forwarding limit reached |
| `0x05` | DIAL_FAILED | target or upstream connection failed |
| `0x06` | SESSION_REPLACED | a newer authenticated carrier replaced this session state |
| `0x07` | INTERNAL_ERROR | local processing failure |

Unknown result values are invalid. DUPLEX receives the result on its own lane.
A split flow receives it on ATTACH, the selected downlink. An OPEN-side
rejection is retained long enough to return the same result when ATTACH arrives.
The client MUST NOT send application payload before READY.

## 7. TCP payload

After READY, a TCP flow is an unframed full-duplex byte stream. Dedicated TLS,
Mux STREAM, and QUIC reliable streams carry identical application bytes. EOF
and half-close map to the active stream's shutdown semantics.

## 8. UDP over stream (UoT)

TLS-carried UDP uses a sequence of length-prefixed packets inside a dedicated
lane or Mux logical stream.

```text
UoT packet - 2 + N bytes

+---------------+-----------------------+
| payload_len   | UDP payload           |
| u16=N         | N bytes               |
+---------------+-----------------------+
```

`N` is `0..65535`; a zero-length UDP packet is valid. Clean stream EOF before
the next two-byte header ends the UoT flow. EOF inside the header or payload is
a truncated frame. UoT has no packet type or flow ID because those belong to
the enclosing logical stream.

## 9. UDP over QUIC DATAGRAM

A QUIC-carried UDP flow uses a reliable bidirectional control stream for
FlowHeader, Target, and SetupResult. After READY, UDP packets use QUIC DATAGRAM.
Every DATAGRAM contains exactly one DATA, FRAGMENT, or CLOSE frame.

### Common DATA/CLOSE header

```text
QUIC UDP DATA or CLOSE - 4 + N bytes

 offset  0                                               4
         +------------------------------------------------+
         | type:2 | flow_id:30                             |
         | u32, network byte order                        |
         +------------------------------------------------+
         | payload ...                                    |  DATA only
         +------------------------------------------------+
```

| `type` | Name | Payload |
|---:|---|---|
| `0b00` | DATA | remaining DATAGRAM bytes; zero length is valid |
| `0b01` | FRAGMENT | uses the 12-byte header below |
| `0b10` | CLOSE | none; total DATAGRAM length MUST be 4 |
| `0b11` | invalid | — |

The common word is `(type << 30) | flow_id`, with type in bits 31..30 and
`flow_id` in bits 29..0. `flow_id` is in `1..=0x3fffffff`. DATA has no
payload-length field because the QUIC DATAGRAM boundary supplies the length.
CLOSE immediately removes the UDP route.

### Fragment header

Packets that exceed the current QUIC maximum DATAGRAM size are divided into
2–255 fragments.

```text
QUIC UDP FRAGMENT - 12 + N bytes

 offset  0                    4            8          9         10           12
         +--------------------+------------+----------+---------+------------+
         | type:2|flow_id:30   | packet_id  | frag_ix  | count   | total_len  |
         | u32                | u32        | u8       | u8      | u16        |
         +--------------------+------------+----------+---------+------------+
         | fragment payload, N > 0                                          |
         +------------------------------------------------------------------+
```

`packet_id` is nonzero and identifies one packet within the active reassembly
window of a flow. `frag_ix` is zero-based and smaller than `frag_count`.
`frag_count` is `2..255`. `total_len` is the nonzero original packet length and
is at most 65535. All fragments for a packet must carry consistent metadata.

Reassembly is bounded to 64 active packet slots per authenticated QUIC
connection, a shared byte budget, and a 10-second fragment TTL. Conflicting
duplicates or metadata drop the packet. Unknown flows, pre-authentication
DATAGRAMs, and payload received before READY are discarded rather than queued.

## 10. Portal forwarding budget

Vector-originated FlowHeaders use `hops=0`. A Portal forwarding to `next`
computes the outgoing value as follows:

```text
incoming hops = 0  -> outgoing hops = 7
incoming hops = 1  -> reject with FLOW_LIMIT
incoming hops = N  -> outgoing hops = N - 1, for N in 2..7
```

The budget is carried identically by TCP and UDP and must match across OPEN and
ATTACH.

## 11. Runtime limits and failure scope

The former application-level TCP, UDP, and pending-pair quotas are absent.
Independent implementation safeguards admit at most 4,096 active streams per
Mux carrier, 1,024 accepted SOCKS clients per Vector, and 1,024 active SOCKS UDP
targets per Vector. Portal admits at most 4,096 active or pending claims per
authenticated session and 65,536 claims across its pairing registry.
Active flow IDs are unique within `1..=0x3fffffff`. Allocation wraps to 1,
skips IDs held by live leases, and fails when the space is exhausted. Released
IDs may be reused; this does not provide generation isolation for delayed
messages. Byte flow control, queue budgets, and pairing/setup timeouts apply.

QUIC bidirectional-stream credit grows with live and pending QUIC flows, with
setup headroom of max(64, live / 4), and is clamped to the 4,096-claim session
budget. A QUIC TCP flow owns one reliable stream;
a QUIC UDP flow owns one reliable control stream plus its DATAGRAM route.
This is sliding transport credit, not a fixed application concurrency ceiling.

Failure scope follows the physical carrier:

- a dedicated TLS failure closes its single logical lane;
- a Mux TLS failure closes every stream assigned to that Shard;
- a QUIC connection failure closes its streams and UDP DATAGRAM routes;
- closing one logical Mux stream does not close sibling streams;
- queued payload and target sockets are released with their owning flow or
  carrier.

Implementations bound unauthenticated work, active flow IDs, pending OPEN and
ATTACH pairs, Mux windows and queues, QUIC streams, UDP routes, DATAGRAM bytes,
and fragment reassembly. Invalid reserved bits, zero IDs where forbidden,
unknown result values, excess credit, inconsistent metadata, and truncated
fixed frames are protocol errors.
