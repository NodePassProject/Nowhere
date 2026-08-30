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

TLS/TCP and QUIC use TLS 1.3 and negotiate a data-plane version through ALPN.
Nowhere 2 offers `nw2` first and the default V1 value `now/1` second. A selected
`nw2` carrier is V2; every accepted non-`nw2` carrier is V1, which in this
implementation means exactly `now/1`.

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
| 32 bytes   | 0xff       | 8 + N bytes | 8 + N bytes |     |
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
`next` is enabled; it defaults to `0`. Portal accepts both TLS forms on the
same listener and selects the decoder from the first byte after AuthFrame.

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
salt      = SHA256("nowhere/now/1/auth-root")
auth_root = HMAC-SHA256(salt, shared_key)
auth_key  = HMAC-SHA256(auth_root, "authentication" || 0x01)

transport = 0x01 for TLS/TCP
          = 0x02 for QUIC

tag       = first 16 bytes of
            HMAC-SHA256(auth_key,
                        transport || exporter[32] || session_id[16])
```

The 32-byte exporter uses label `EXPORTER-Nowhere-Auth` and empty context. The
fixed derivation labels are shared by the compatible V1 and V2 paths in this
release; the negotiated version does not change authentication bytes.
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

Every Mux frame starts with an 8-byte header. STREAM and DATAGRAM frames carry
exactly `value` payload bytes; WINDOW carries no payload.

```text
MuxHeader - 8 bytes

 offset  0        1        2               4                       8
         +--------+--------+---------------+-----------------------+
         | kind   | flags  | value         | flow_id               |
         | u8     | u8     | u16           | u32                   |
         +--------+--------+---------------+-----------------------+
```

| `kind` | Name | `value` | `flow_id` |
|---:|---|---|---|
| `0x01` | STREAM | payload length | nonzero |
| `0x02` | WINDOW | returned byte credit | `0` for connection, nonzero for stream |
| `0x03` | DATAGRAM | payload length | nonzero |

The runtime implements STREAM and WINDOW. DATAGRAM headers are recognized by
the codec but are not registered as a runtime plane; receiving one closes the
Mux carrier as unsupported.

For STREAM, the low three flag bits are:

```text
flags byte

 bit     7                   3   2     1     0
         +---------------------+-----+-----+-----+
         | reserved            | RST | FIN | SYN |
         +---------------------+-----+-----+-----+
```

- `SYN=0x01` creates the logical stream before optional payload is delivered.
- `FIN=0x02` half-closes the sender after optional payload is delivered.
- `RST=0x04` resets the stream. It MUST be the only flag and `value` MUST be 0.
- All other flag bits MUST be zero.

WINDOW uses `flags=0`, carries no payload, and requires nonzero credit. A
WINDOW with `flow_id=0` replenishes connection credit; a nonzero ID replenishes
that logical stream. Credit that would exceed the configured window closes the
carrier. A late stream-local WINDOW for an already closed stream is ignored.

STREAM data for an unknown flow is a carrier error. Late FIN or RST processing
is idempotent. Closing the physical Mux carrier fails every logical stream on
that carrier.

The runtime emits at most 32 KiB of data per STREAM frame. Default Mux bounds
are 512 KiB per-stream receive credit, 512 KiB connection-wide receive credit,
256 active streams, and 512 queued outbound frame slots. Payload must obtain
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

Client-side Shards open lazily in separate uplink and downlink sets. A new flow
uses the least-loaded live Shard for its TLS direction; a new Shard opens when
all live Shards in that set have 4 active flows. A symmetric `tcp/tcp` flow
uses one duplex stream from the uplink set. A fully idle Shard closes after 30
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

`flow_id` is nonzero and is scoped to `session_id`. The same logical flow uses
the same ID on OPEN and ATTACH, in MuxHeader, and in QUIC UDP DATAGRAM frames.

Role semantics:

| Role | Target follows | Current lane | Payload direction |
|---|---|---|---|
| DUPLEX | yes | MUST match both `up` and `down`; both carriers MUST be equal | both |
| OPEN | yes | MUST match `up` | client to Portal |
| ATTACH | no | MUST match `down` | Portal to client |

When `up` and `down` select the same carrier, one DUPLEX lane is used. When
they differ, Portal pairs OPEN and ATTACH by `(session_id, flow_id)`. Their
kind, carrier selection, and hop metadata must agree.

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
| `0x04` | FLOW_LIMIT | admission, session flow, or forwarding limit reached |
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
QUIC UDP DATA or CLOSE - 5 + N bytes

 offset  0                        1                       5
         +------------------------+-----------------------+
         | flags                  | flow_id               |
         | u8                     | u32                   |
         +------------------------+-----------------------+
         | payload ...                                    |  DATA only
         +------------------------------------------------+

flags byte

 bit     7                           2   1       0
         +-----------------------------+-----------+
         | reserved, MUST be zero      | type      |
         | 6 bits                      | 2 bits    |
         +-----------------------------+-----------+
```

| `type` | Name | Payload |
|---:|---|---|
| `0b00` | DATA | remaining DATAGRAM bytes; zero length is valid |
| `0b01` | FRAGMENT | uses the 13-byte header below |
| `0b10` | CLOSE | none; total DATAGRAM length MUST be 5 |
| `0b11` | invalid | — |

`flow_id` is nonzero. DATA has no payload-length field because the QUIC
DATAGRAM boundary supplies the length. CLOSE immediately removes the UDP route.

### Fragment header

Packets that exceed the current QUIC maximum DATAGRAM size are divided into
2–255 fragments.

```text
QUIC UDP FRAGMENT - 13 + N bytes

 offset  0      1            5            9          10        11           13
         +------+------------+------------+----------+---------+------------+
         | 0x01 | flow_id    | packet_id  | frag_ix  | count   | total_len  |
         | u8   | u32        | u32        | u8       | u8      | u16        |
         +------+------------+------------+----------+---------+------------+
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

One authenticated client session admits 1,024 concurrent logical TCP flows and
256 concurrent logical UDP flows by default. Pending flows count toward the
same limits. A full-duplex flow counts once regardless of its carrier
combination. Admission at the limit returns FLOW_LIMIT without waiting.

The QUIC bidirectional-stream ceiling is derived from both flow limits: 1,280
by default. A QUIC TCP flow owns one reliable stream. A QUIC UDP flow owns one
reliable control stream plus its DATAGRAM route.

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
