# Nowhere Protocol

Nowhere is a Rust implementation of **Nowhere Protocol**. The Wire
version is **NW3**, with ALPN `nw3`.

The independent [Core specification](https://github.com/NodePassProject/Nowhere-Protocol/blob/main/PROTOCOL.md)
defines Vector/Portal connections, authentication, Flow framing, UDP and Morph.
The extensions below add Nowhere-specific behavior to that baseline. In
particular, Core permits receivers to ignore the TCP Morph Prelude, while this
Portal requires the authenticated Prelude Extension. A Core-only Morph TCP
sender is therefore not sufficient for this Portal.

| Nowhere documentation | Purpose |
| --- | --- |
| [Configuration](configuration.md) | Service URLs, runtime defaults and Morph prelude policy |
| [Prelude Extension](prelude.md) | Morph TCP authentication and replay protection; Morph UDP Prelude |
| [Egress Extension](egress.md) | Optional remote exits: deployment, authentication, registration and Wire rules |
| [Security](security.md) | Certificate trust and implementation resource protection |
| [Interoperability](interoperability.md) | Compatible peer requirements and validation cases |
| [Testing](testing.md) | Implementation regression coverage and checks |

The independent specification uses CC BY 4.0.
Nowhere's Rust implementation and tests use GPL-3.0-only.
