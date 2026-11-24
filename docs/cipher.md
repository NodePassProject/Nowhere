# Cipher Extension

Morph masks the wire image below TLS or QUIC with ChaCha20-IETF or
AES-128-CTR. TLS and QUIC provide authentication and integrity. Enabled
peers select the same Cipher through local configuration. The wire format
carries no Cipher identifier and peers do not negotiate a Cipher.

Morph is enabled by default and uses ChaCha20-IETF (`cipher=chacha`).
Select `cipher=aes` on both peers to use AES-128-CTR. Set `morph=0` on both
peers to disable Morph. See [Configuration](configuration.md) for service and
share URLs.

## Keystream

HMAC arguments below are `(key, data)`.

```text
root      = HMAC-SHA256("nowhere/nw3/morph", SharedKey)
direction = HMAC-SHA256(root, label || 0x01)
```

Both Ciphers use the `tcp c2s`, `tcp s2c`, `udp c2s`, and `udp s2c` labels.
The [Prelude Auth and Mask keys](prelude.md#morph-tcp-prelude) use separate
labels. The UDP Nonce generator uses ChaCha20 for both Ciphers.

### AES-128-CTR

- **TCP.** Send the 64-byte authenticated Prelude and 12-byte
  client nonce. For each direction, use the first 16 bytes of
  `HMAC-SHA256(direction, nonce)` as the AES key and 16 zero bytes as the
  initial counter. XOR the TLS byte stream with AES-128-CTR. Increment the
  full 128-bit counter in big-endian order. At byte offset `p`, use block
  `p / 16` and skip `p % 16` bytes. Each direction permits `2^48` bytes
  (256 TiB). After exhaustion, a nonempty operation fails.
- **UDP.** For each direction, use the first 16 bytes of its direction key.
  Each datagram has its own 12-byte nonce followed by the masked
  QUIC packet. The initial counter is `nonce || 00000000`; increment the
  full counter in big-endian order. Each logical segment of a batch gets
  its own counter and nonce. The 12-byte UDP Prelude remains separate.

The AES libraries select their available backend. A software AES backend
and a hardware AES backend produce the same bytes.
