# Nowhere 1.5 Wire Protocol

This document defines the normative Nowhere 1.5 wire format.

All multibyte integers use network byte order. A receiver MUST reject nonzero
reserved bits, invalid enum values, zero flow IDs, truncated fields, and lengths
outside the bounds below.

## 1. Transport Bundle

A logical bundle has a random client-generated `session_id[16]`. It may contain
one current QUIC connection and any number of authenticated TLS/TCP lanes. A
logical flow has a nonzero `flow_id_u32` unique among active and pending flows
within that session.

TLS 1.3 is mandatory. TLS/TCP and QUIC advertise exactly one configured ALPN;
the default is `now/1`. ALPN changes transport negotiation only.

Application data is never accepted as TLS 0-RTT or half-RTT server data.

## 2. Connection-Bound Authentication

The URL username, after strict percent decoding, is the shared key. Password
userinfo is forbidden. Implementations derive the read-only key once:

```text
salt      = SHA-256(ASCII("nowhere/now/1/auth-root"))
auth_root = HKDF-Extract-SHA256(salt, shared_key_bytes)
auth_key  = HKDF-Expand-SHA256(auth_root, ASCII("authentication"), 32)
```

After each physical TLS or QUIC handshake, both peers derive:

```text
exporter = TLS-Exporter(
  label   = ASCII("EXPORTER-Nowhere-Auth"),
  context = present empty byte string,
  length  = 32
)
```

The explicit empty context is used for both rustls TLS and Quinn QUIC APIs.

Transport domain bytes are `0x01` for TLS/TCP and `0x02` for QUIC. The tag is:

```text
tag = HMAC-SHA256(auth_key, transport || exporter || session_id)[0..16]
```

The authentication frame is exactly:

```text
session_id[16] || tag[16]
```

The receiver compares the tag in constant time. Authentication failure is
reported only locally and closes after the Portal's common deadline.
No target may be dialed before authentication succeeds. A captured frame cannot
authenticate another physical connection because its exporter differs.

## 3. Flow Header

Every flow begins with five bytes:

```text
flags_u8 || flow_id_u32
```

`flags` is packed as follows:

| Bits | Meaning |
| --- | --- |
| 0..1 | role: 0 DUPLEX, 1 OPEN, 2 ATTACH, 3 invalid |
| 2 | kind: 0 TCP, 1 UDP |
| 3 | uplink: 0 TLS/TCP, 1 QUIC/UDP |
| 4 | downlink: 0 TLS/TCP, 1 QUIC/UDP |
| 5..7 | reserved, MUST be zero |

`DUPLEX` requires equal carriers and the current physical carrier must match.
It carries a Target and immediately describes both halves. `OPEN` requires
different carriers, must arrive on its declared direction, carries a Target,
and creates a pending pair. `ATTACH` requires different carriers, carries no
Target, and must exactly match the pending role metadata.

Flow IDs are allocated monotonically, skipping zero. An ID cannot be reused
while active or pending. At wrap, the client searches from one for a free ID.

## 4. Target

Target encoding deliberately reuses SOCKS5 ATYP values:

```text
IPv4   = 0x01 || ipv4[4]  || port_u16
Domain = 0x03 || len_u8   || ascii_domain[len] || port_u16
IPv6   = 0x04 || ipv6[16] || port_u16
```

IPv4 is 7 bytes and IPv6 is 19 bytes. Domain length is `1..253`; the bytes are
an ASCII/IDNA wire hostname without brackets or a port. Port zero, empty names,
non-ASCII names, unknown ATYP, and truncated input are invalid.

OPEN and DUPLEX carry one Target immediately after the Flow Header. ATTACH does
not carry one.

## 5. Setup Result

The selected downlink receives exactly one result byte before application data:

| Value | Name |
| --- | --- |
| 0 | READY |
| 1 | INVALID_REQUEST |
| 2 | METADATA_CONFLICT |
| 3 | PAIR_TIMEOUT |
| 4 | FLOW_LIMIT |
| 5 | DIAL_FAILED |
| 6 | SESSION_REPLACED |
| 7 | INTERNAL_ERROR |

Unknown values are protocol errors. A non-asymmetric uplink receives no
separate result; the chosen downlink result is authoritative for the complete
logical flow.

## 6. TLS/TCP Lanes

A cold lane is:

```text
TLS handshake -> auth[32] -> flow_header[5] -> optional Target -> payload
```

The client may submit auth, flow metadata, Target, and initial TCP payload in
one application write. The Portal reads the declared fields and preserves any
already-buffered payload.

A warm lane performs the handshake and auth immediately, then waits idle. When
acquired it sends flow metadata and data. Each lane carries one flow half and is
never returned to the pool after relay completion.

## 7. QUIC Streams

Before authentication the Portal permits one client-initiated bidirectional
stream and bounded receive credit. The first stream contains:

```text
auth[32] || optional first flow
```

After the exact auth bytes validate, the Portal raises authenticated stream and
receive limits. If more bytes remain, that same stream is handled as the first
flow. An auth-only client finishes the stream. Subsequent bidirectional streams
start directly with a Flow Header.

QUIC Retry is required. Authentication before 1-RTT completion is forbidden.

## 8. QUIC DATAGRAM

The first byte uses bits 0..1 for type and bits 2..7 as zero reserved bits:

- `0`: DATA
- `1`: FRAGMENT
- `2`: CLOSE
- `3`: invalid

An unfragmented packet, including a zero-length UDP packet, is:

```text
flags || flow_id_u32 || payload
```

The header overhead is 5 bytes. It MUST be used whenever the complete packet
fits the connection's current maximum DATAGRAM size.

A fragmented packet is:

```text
flags || flow_id_u32 || packet_id_u32 || fragment_index_u8
      || fragment_count_u8 || total_len_u16 || fragment_payload
```

The header overhead is 13 bytes. `fragment_count` is `2..255`, index is less
than count, and total length is `1..65535`. All fragments for a packet agree on
ID, count, and total length. Conflicting duplicates discard the complete
reassembly slot; identical duplicates are ignored. MTU shrink retry uses a new
packet ID. Packet IDs increment and skip zero.

Close is exactly:

```text
flags || flow_id_u32
```

It immediately releases flow, target socket, association, queues, and waiters.

Authentication-pending DATAGRAMs and DATA for a flow that has not reached READY
are discarded. They are never retained or replayed.

## 9. UDP over TLS/TCP

After READY, every UoT packet is:

```text
payload_len_u16 || payload
```

Zero length represents a valid empty UDP datagram. Each frame is one complete
datagram. Clean EOF closes that half; an incomplete length or payload is a
protocol error. There are no data/control type bytes in this phase.

## 10. Session Replacement and Limits

A newly authenticated QUIC connection with an existing session ID replaces the
old QUIC carrier. The old carrier stops accepting flows, pending pairs receive
SESSION_REPLACED, and existing flows are cancelled rather than migrated. New
connections do not inherit reassembly or packet-ID state.

Implementations retain explicit limits for authenticated streams, UDP flows,
pending pairs, idle TLS lanes, queue bytes and packets, reassembly slots and
lifetime, authentication deadlines, and idle flows. A decoder validates lengths
before allocating from network-controlled values.

The Rust implementation keeps Quinn-owned DATA and FRAGMENT payloads as
`Bytes` slices. A fragmented packet is copied only once, when its out-of-order
pieces are joined into the contiguous UDP payload required by the socket API.
Partial reassembly and completed queue entries share one byte budget, with the
same reservation moving between those states. Send-side fragments are produced
one at a time, so an MTU retry does not preallocate frames that will never be
sent.

## 11. Compatibility

Nowhere 1.5 completely replaces the earlier wire format while retaining the
default `now/1` ALPN. Mixed releases may complete TLS/QUIC negotiation but fail
during application authentication. Portal and clients must be upgraded
together; there is no legacy detection or downgrade.
