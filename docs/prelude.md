# Prelude Extension

The Prelude Extension supplements [Nowhere Protocol (NW3)](protocol.md) below
TLS and QUIC. Morph TCP uses an authenticated 64-byte Prelude. Morph UDP clients
send one independent 12-byte Prelude datagram per socket. The extension requires
no additional negotiation, ALPN, round trip or artificial delay.

## Contents

- [Morph TCP Prelude](#morph-tcp-prelude)
- [Morph UDP Prelude](#morph-udp-prelude)
- [Compatibility](#compatibility)

## Morph TCP Prelude

Authenticated Prelude carries Shared Key authentication data in the 64-byte
Morph TCP Prelude. It is mandatory for Morph TCP ingress. Portal
verifies the Tag and Counter before parsing ClientHello and commits replay
state before sending a TLS response.

Vector and Egress use the same client implementation. The extension uses the
Core TCP envelope, Nonce and directional cipher keys. TLS 1.3, certificate
verification, exporter-bound AuthFrame and Flow processing apply.

### Base generation policies

`NOW_MORPH_TCP_PRELUDE` accepts `fade` (default), `full8` and `low7`:

- `fade`: independently sample uniform A in `[8,12]` and B in `[16,32]`.
  Bytes `[0,A)` are uniform printable ASCII (`0x20–0x7E`), `[A,B)` are uniform
  low7 (`0x00–0x7F`), and `[B,64)` are uniform full8 (`0x00–0xFF`).
- `full8`: generate all eight bits randomly throughout the 64-byte base Prelude.
- `low7`: clear each random byte's highest bit throughout the base Prelude.

All modes use a secure random source. Fade uses rejection sampling for its
boundaries and printable ASCII. These distributions describe the base Prelude
before authentication encoding; the encoded tail preserves highest bits and
carries masked payload in its low seven bits.

### Wire layout

The TCP envelope starts with a 64-byte Prelude and a 12-byte random Nonce:

```text
Offset  0                          64             76
        +--------------------------+--------------+------------------------+
        |      Prelude (64B)       | Nonce (12B)  | ChaCha20-XOR(TLS) ...  |
        +--------------------------+--------------+------------------------+

Offset  0                          32                         64
        +--------------------------+--------------------------+
        |      Prefix P (32B)      |    Encoded tail (32B)    |
        +--------------------------+--------------------------+
          Base policy bytes          H bit + 7 payload bits per byte

Bit       7   6   5   4   3   2   1   0
        +---+---------------------------+
Tail    | H |    Masked payload bits    |
        +---+---------------------------+
        Repeated for all 32 tail bytes.
```

The client first generates all 64 bytes using the configured
[Prelude policy](configuration.md#tcp-morph-prelude): `fade`, `full8` or `low7`.
It preserves the first 32 bytes and every highest bit, replacing only the tail's
low seven bits. The tail carries `32 x 7 = 224` bits, exactly 28 bytes:

```text
Offset  0                8              14                           28
        +----------------+--------------+----------------------------+
        | Identity (8B)  | Counter (6B) |         Tag (14B)          |
        +----------------+--------------+----------------------------+
```

Identity and Counter are unsigned big-endian integers. Payload bits are encoded
most significant bit first, in byte order. No visible marker or version field
is reserved. Nonce consists of twelve independent CSPRNG bytes; none of its bits
are reused for authentication metadata. Portal uses one decoder for all policies.

### Authentication

The authentication input uses these byte strings:

| Symbol | Size | Meaning |
|---|---|---|
| `P` | 32 bytes | `Prelude[0..32]` |
| `N` | 12 bytes | Morph Nonce |
| `H` | 4 bytes | Highest bits of `Prelude[32..64]`, packed MSB-first |
| `I` | 8 bytes | Encoded Identity |
| `C` | 6 bytes | Encoded Counter |

Derive two separate keys from the Morph root:

```text
root     = HMAC-SHA256(key="nowhere/nw3/morph", data=SharedKey)
auth_key = HMAC-SHA256(key=root, data="tcp prelude auth" || 0x01)
mask_key = HMAC-SHA256(key=root, data="tcp prelude mask" || 0x01)

Tag      = HMAC-SHA256(key=auth_key, data=N || P || H || I || C)[0..14]
Mask     = HMAC-SHA256(key=mask_key, data=N || P || H)[0..28]
Payload  = (I || C || Tag) XOR Mask
```

SharedKey is the validated ASCII byte string, without hexadecimal decoding.
Labels are exact ASCII bytes without terminators or version suffixes.
The root, auth key and mask key are 32 bytes. Auth and mask keys are independent
of the four directional TCP/UDP keys.

Split Payload into 32 consecutive seven-bit groups, MSB-first, and write each
group to a tail byte's low seven bits. Preserve that byte's highest bit.
Portal reverses this encoding, reconstructs Mask, recovers Identity, Counter and
Tag, and compares all fourteen Tag bytes in constant time. A matching Tag marks
an authenticated input before Counter validity is checked.

### Identity and Counter

Each Vector or Egress instance lazily generates one random 64-bit Identity on
its first Morph TCP connection. All TCP Flows and TLS client clones share that
Identity and one atomic Counter. QUIC and disabled Morph do not allocate counter
values.

Counter starts at one and is allocated immediately before Prelude encoding and
transmission. Each allocation is unique, including concurrent attempts. Failed
connections and cancelled tasks consume any value already allocated. Values
range from `1` through `2^48-1`; exhaustion rejects further allocations without
wrapping. Identity and Counter are not persisted. A new client instance creates
fresh state.

### Replay window

All TCP listeners of one Portal instance share a fixed registry:

| State | Bound | Update rule |
|---|---|---|
| Identity FIFO | 16,384 entries | Append on first successful registration |
| Highest Counter | One per Identity | Advance when a higher Counter commits |
| Replay bitmap | 1024 bits per Identity | Mark accepted Counter offsets |

Bit zero represents Highest Counter. Increasing the highest value shifts old
marks toward larger offsets; a jump of 1024 or more clears the previous window.
An unused Counter up to 1023 below Highest is accepted. Zero, duplicate values
and values below the window are rejected.

```text
Counter     Highest    Highest - 1    ...     Highest - 1023
Offset         0            1         ...          1023
         +-----------+-------------+-------+------------------+
Bitmap   |     1     |    0 / 1    |  ...  |      0 / 1       |
         +-----------+-------------+-------+------------------+
           Newer values advance the window; older values fall out.
```

Updating an existing Identity does not refresh FIFO order. At capacity, a new
Identity replaces the oldest registration. An evicted Identity can register
again. Established Flows do not reference registry entries and survive eviction.
There is no TTL, timer, persistence or additional Nonce cache. Registry storage
is preallocated; registration, window updates and eviction allocate no per-Flow
memory. A new Portal instance starts with an empty registry.

### Silent admission

Portal applies the accept-time handshake deadline, admission limits and socket
close policy. Rejected input stops further reads until that deadline. Prelude
verification precedes ClientHello parsing; successful parsing precedes replay
commit:

```text
   Vector / Egress                                      Portal
         |                                                 |
         |---------------- TCP connection ---------------->|
         |-------------- Prelude + Nonce ----------------->|
         |                                     Verify Tag  |
         |                              Replay precheck    |
         |-------------- Masked ClientHello -------------->|
         |                              Silent Acceptor    |
         |                          Replay recheck/commit  |
         |                                 Deadline check  |
         |<-------------- TLS 1.3 response ----------------|
         |------------------- AuthFrame ------------------>|
         |                           Verify role AuthFrame |
         |                          Linger/deadline check  |
         |<========= Authenticated TLS connection ========>|
         |                                                 |
```

Prelude alone never reserves a Counter. Incomplete or malformed ClientHello
leaves replay state untouched. After rustls Acceptor accepts ClientHello, Portal
checks the deadline and atomically rechecks and commits replay state before any
TLS response. Concurrent copies can commit only once while their Identity
remains registered. A mutex protects registry operations and is released before
network IO or TLS work. Poisoned state rejects authenticated inputs.

Invalid Tags, invalid Counters and replay rejection stay on the silent rejection
path without TLS responses. Later socket, TLS, ALPN or AuthFrame failures do not
undo a commit. Configuration-dependent TLS checks after the silent boundary
can send alerts.

Portal enables zero linger before reading the bootstrap and retains it through
Prelude validation, TLS, ALPN and AuthFrame verification. A complete, valid
Vector or Egress AuthFrame for an available role permits restoration of normal
linger. The absolute deadline is checked before and after restoration; expiry
retains zero linger.
Timeouts, cancellation and failures before this point retain abortive close.
Authenticated Flows use normal close and half-close behavior. Packet-level
FIN/RST behavior depends on the operating system.

### Acceptance policy and limits

Portal applies these rules to every complete Morph TCP bootstrap:

| Tag and Counter | Result |
|---|---|
| Nonmatching Tag | Reject silently before ClientHello parsing |
| Matching Tag, valid unused Counter | Precheck, parse ClientHello, then atomically recheck and commit |
| Matching Tag, zero, duplicate or out-of-window Counter | Reject silently before TLS responses |

Portal requires Prelude authentication and has no unauthenticated fallback.
See [Interoperability](interoperability.md#morph) for peer requirements.
Receivers that ignore Prelude contents can consume an authenticated sender's
envelope; no negotiated policy or additional configuration is needed.

The Tag does not bind the complete ClientHello: a captured bootstrap can race
its first use with a modified hello and consume its Counter. FIFO eviction and Portal restart discard history.
Shared Key holders can churn the FIFO or advance windows; random 64-bit
Identity collisions can cause unwanted window sharing.

Captured bootstrap data permits offline checks of guessed Shared Keys. Masking
hides Identity and Counter from observers without the key, but provides no
forward secrecy for this metadata after Shared Key disclosure.

The 112-bit Tag authenticates bootstrap metadata. TLS supplies integrity for
the connection. See [Security](security.md#morph-transport-protection) and
[Interoperability](interoperability.md) for the full protection boundary and
peer requirements.

## Morph UDP Prelude

### Generation policies

`NOW_MORPH_UDP_PRELUDE` selects the local generation policy for Morph-enabled
QUIC clients, including Vector and Egress. The default is `fade`.

| Policy | Independent 12-byte datagram |
|---|---|
| `fade` | 2 uniform printable ASCII bytes (`0x20–0x7E`), 8 uniform low7 bytes (`0x00–0x7F`), 2 uniform full8 bytes (`0x00–0xFF`) |
| `full8` | 12 uniform full8 bytes (`0x00–0xFF`) |
| `low7` | 12 uniform low7 bytes (`0x00–0x7F`) |

All bytes originate from a secure random source. Printable ASCII uses rejection
sampling to avoid modulo bias. UDP Fade has fixed boundaries at offsets 2 and 10.

```text
UDP Prelude datagram (12B, fade)
Offset  0       2                               10      12
        +-------+-------------------------------+-------+
        | ASCII |             low7              | full8 |
        |  2B   |              8B               |  2B   |
        +-------+-------------------------------+-------+

Subsequent Morph UDP datagram (separate packet)
Offset  0                   12
        +-------------------+--------------------------------+
        |    Nonce (12B)    |    ChaCha20-XOR(QUIC packet)   |
        +-------------------+--------------------------------+
```

### Transmission and reception

Each new Morph client UDP socket sends the Prelude through that same socket to
the destination of its first QUIC transmission. The Prelude is an independent,
unmasked datagram without a Morph Nonce or GSO segmentation. It must be
successfully submitted to the underlying socket before the first QUIC datagram
is submitted. The client sends the QUIC datagram without waiting for a Prelude
response or introducing a delay. UDP does not guarantee network delivery or
arrival order.

```text
Vector / Egress (one UDP socket)                    Portal
       |                                              |
       |------------- Prelude (12B) ----------------->|
       |                               Silent discard |
       |------------- Nonce + QUIC Initial ---------->|
       |<============ Normal QUIC exchange ==========>|
       |                                              |
       |       Further Flows using this socket        |
       |       send no additional Prelude             |
```

The diagram shows submission order; Prelude delivery is not acknowledged.

The nonblocking writable path retries an unsubmitted Prelude using the same
bytes after `WouldBlock`. Successful submission consumes that socket's pending
Prelude, even if the subsequent QUIC send must be retried. Other Prelude send
errors propagate through the QUIC error path.

The Prelude is sent once per socket, not once per Flow or QUIC transmission.
Each socket generates its own Prelude; reusing a socket does not send another.
Portal and other server-role sockets do not send it. Disabled Morph bypasses
the extension entirely.

Portal's Morph UDP receiver silently discards datagrams of 12 bytes or less,
including this Prelude. It sends no response, performs no Prelude
authentication and allocates no Prelude admission or replay state. Normal
Morph datagrams use `Nonce (12B) || ChaCha20-XOR(QUIC packet)`.

### Security boundary

The UDP Prelude carries no Identity, Counter, Tag, authentication or replay
protection. It is not a normal Morph UDP Nonce, is not consumed by the Nonce
generator and does not alter the encryption or format of subsequent datagrams.
TLS 1.3, QUIC and AuthFrame provide connection security. MTU, Keep-Alive,
timeouts and handshake behavior follow the QUIC transport configuration.

## Compatibility

Portal requires authenticated TCP Preludes. UDP ingress does not require a
Prelude: Portal accepts Morph-protected QUIC packets without a preceding UDP
Prelude, subject to QUIC and AuthFrame checks. Interoperable Morph UDP receivers
silently discard datagrams of 12 bytes or less without sending a response.

Prelude policies are local choices and need not match the peer. They are not
negotiated or specified in URLs. See
[Configuration](configuration.md#udp-morph-prelude) and
[Interoperability](interoperability.md#morph).
