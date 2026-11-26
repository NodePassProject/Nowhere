# Grade Extension

The Grade Extension defines Full Morph and Core Morph for
[Nowhere Protocol (NW3)](protocol.md). The grade selects which bytes are
masked below TLS and QUIC. The [Cipher Extension](cipher.md) defines the
keystream, and the
[Prelude Extension](prelude.md) defines the bootstrap and Nonce envelopes.

## Contents

- [Configuration](#configuration)
- [Directional keys](#directional-keys)
- [TCP masking](#tcp-masking)
- [QUIC masking](#quic-masking)
- [Compatibility](#compatibility)

## Configuration

Vector, Portal, Egress and [share links](configuration.md#share-links) use
`morph=1` (default) to enable Morph and `morph=0` to pass transport bytes
through.

| `grade` | Masking with Morph enabled |
| --- | --- |
| `full` (default) | All TLS stream or QUIC Datagram bytes |
| `core` | TLS Record headers and selected TLS and QUIC bytes |

Both grades support ChaCha20-IETF (`cipher=chacha`, the default) and
AES-128-CTR (`cipher=aes`). Grade and Cipher are validated independently
of the enable switch and apply only when Morph is enabled.

## Directional keys

Full and Core share the [Morph key derivation](cipher.md#keystream) and
directional labels.

| Direction | Label |
| --- | --- |
| TCP client to server | `tcp c2s` |
| TCP server to client | `tcp s2c` |
| UDP client to server | `udp c2s` |
| UDP server to client | `udp s2c` |

Directions follow the transport roles. Vector and Egress use client keys for
sending to Portal, including when Portal initiates a business Stream.

TCP Prelude authentication and masking derive their keys independently of the
grade. Both grades use the same UDP Nonce generator.

## TCP masking

Full masks the entire TLS stream. Core masks every 5-byte TLS Record Header.
For Core, inspect the clear Header when sending and the recovered Header when
receiving. Core passes the Payload through if all three fields match:

- Outer content type is 23.
- Legacy record version is `0x0303`.
- The unsigned big-endian Payload length is at most 18432 bytes.

Core masks the entire declared Payload for other Headers. The next Header
starts after the declared Payload, including when the length is zero. TLS
validates its own Records and enforces its own length limit.

Each direction counts its absolute offset from its first TLS byte. Skipped
bytes advance the offset and count towards the
[Cipher limit](security.md#cipher-and-nonce-limits). The Cipher generates
keystream for the selected ranges. A partial write advances only by the
accepted prefix.

## QUIC masking

Each logical QUIC Datagram has an outer 12-byte Morph Nonce. Masking offsets
start at the first byte after the Nonce. The independent UDP Prelude has its
own handling.

Full masks every Datagram byte. Core applies these rules to the Datagram
as a whole:

| First byte and length | Masked ranges |
| --- | --- |
| High bit set, any length | Entire Datagram |
| High bit clear, length at most 41 bytes | Entire Datagram |
| High bit clear, length over 41 bytes | `[0, 25)` and `[length - 16, length)` |

The sender classifies the clear first byte. For Datagrams over 41 bytes, the
receiver recovers the first 25 bytes and uses the recovered first byte to
select the rest of the mask. Each selected byte is masked once at its absolute
Datagram offset. The first byte of a coalesced Datagram governs its complete
mask. Retry, Version Negotiation and Stateless Reset use the same rules.
Each GSO or GRO segment has its own Nonce and offsets.

## Compatibility

Peers select the same Morph enable setting and, when enabled, the same
Grade and Cipher. The envelope carries no Grade or Cipher identifier.
Configuration is out of band, with no negotiation or fallback. Portal requires
the authenticated TCP Prelude for either grade. See
[Interoperability](interoperability.md#morph).
