# Integrations

## Direct Process Management

Nowhere is one binary with two URL commands. A service manager should store the
complete URL outside the repository and restart only after configuration
validation succeeds.

Portal example:

```text
portal://change-me@:2077?net=mix&tls=2&crt=/etc/nowhere/fullchain.pem&key=/etc/nowhere/privkey.pem&alpn=now%2F1
```

Vector example:

```text
vector://change-me@relay.example:2077?up=tcp&down=tcp&pool=5&sni=relay.example&alpn=now%2F1&rate=0&etar=0&socks=127.0.0.1:1080&log=event
```

Do not expose URLs through world-readable unit files or process dashboards: the
username is the shared key.

## OpenCtrl

[OpenCtrl](https://github.com/NodePassProject/OpenCtrl) may supervise Portal
processes and consume stdout EVENT records. The managed URL must use the 1.5
parameter set and omit removed legacy fields. OpenCtrl lifecycle, persistence,
REST, and SSE are management-layer concerns; they do not change the wire
protocol.

Before migrating an existing record:

1. Remove the legacy protocol-shape parameter.
2. Confirm the intended ALPN on both sides.
3. Upgrade the Portal binary and compatible clients together.
4. Verify CHECK_POINT and a real TCP and UDP flow.

## Vector SOCKS5

Vector provides the standard integration point for applications and gateways:

- CONNECT maps to one Nowhere TCP logical flow.
- UDP ASSOCIATE maps each target address to an idle-timed UDP logical flow.
- RFC1929 is enabled by putting percent-encoded credentials in `socks`.
- BIND and SOCKS5 UDP fragmentation are unsupported.

Prefer a loopback listener. Wildcard listeners require authentication and
network policy.

## Anywhere Compatibility

The current [Anywhere](https://github.com/NodePassProject/Anywhere) source tree
mirrors the previous codec. It is intentionally not modified by the Rust-only
1.5 work and cannot connect to a 1.5 Portal. Keep it paired with its matching
older Portal until a coordinated Apple-client update is available.

The retained `now/1` ALPN does not signal wire compatibility. Mixed versions
fail during application authentication.

## Third-Party Clients

Implement the normative codec directly. Required conformance includes
TLS exporter authentication, exact flags and reserved-bit checks, binary SOCKS5
ATYP targets, one-byte setup results, 5/13-byte QUIC DATAGRAM headers, and
length-only UoT. Portal and clients must target the same protocol release.
