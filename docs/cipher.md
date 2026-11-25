# Cipher Extension

Morph masks the transport bytes below TLS or QUIC with ChaCha20-IETF or
AES-128-CTR. TLS and QUIC provide authentication and integrity. Enabled
peers select the same Cipher through local configuration. The wire format
carries no Cipher identifier and peers do not negotiate a Cipher.

ChaCha20-IETF (`cipher=chacha`) is the default. Select `cipher=aes` on both
peers to use AES-128-CTR. Both ciphers use the byte ranges specified by the
[Grade Extension](grade.md).

## Keystream

HMAC arguments below are `(key, data)`.

```text
root      = HMAC-SHA256("nowhere/nw3/morph", SharedKey)
direction = HMAC-SHA256(root, label || 0x01)
```

Both ciphers use the same [directional labels](grade.md#directional-keys).
The [Prelude Auth and Mask keys](prelude.md#morph-tcp-prelude) use separate
labels. The UDP Nonce generator uses ChaCha20 for both ciphers.

### AES-128-CTR

- **TCP.** Send the 64-byte authenticated Prelude and 12-byte
  client nonce. For each direction, use the first 16 bytes of
  `HMAC-SHA256(direction, nonce)` as the AES key and 16 zero bytes as the
  initial counter. Increment the full 128-bit counter in big-endian order.
  At byte offset `p`, use block `p / 16` and skip `p % 16` bytes. Each
  direction permits `2^48` bytes
  (256 TiB). After exhaustion, a nonempty operation fails.
- **UDP.** For each direction, use the first 16 bytes of its direction key.
  Each datagram has its own 12-byte nonce followed by the masked
  QUIC packet. The initial counter is `nonce || 00000000`; increment the
  full counter in big-endian order. Each logical segment of a batch gets
  its own counter and nonce. The 12-byte UDP Prelude remains separate.

The AES libraries select their available backend. A software AES backend
and a hardware AES backend produce the same bytes.
