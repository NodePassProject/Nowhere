# Security Notes

## Transport and Identity

Nowhere requires TLS 1.3 for TLS/TCP and QUIC. Plaintext operation, 0-RTT
application data, and half-RTT server data are disabled.

The shared key authenticates each physical connection through a TLS exporter.
It is never sent on the wire. The 16-byte authentication tag binds transport,
connection secrets, and logical session ID, so a captured authentication frame
cannot be replayed on another TLS or QUIC connection.

Use a high-entropy shared key and treat command lines, management records, and
debug logs containing it as secrets. Authentication is authorization to dial
arbitrary targets; Nowhere does not implement accounts or target allowlists.

## Certificate Policy

Portal `tls=1` creates a new self-signed certificate at each start. It is useful
for local testing but has no stable identity.

Portal `tls=2` loads a PEM chain and key and can reload them. Public deployments
should use a CA-trusted certificate.

Vector has an explicit trust boundary:

- Supplying `sni=<name>` loads system roots and requires valid chain and name.
- Empty, omitted, or `sni=none` disables certificate verification; operator
  output records the effective value as `sni=none`.

Exporter-bound shared-key authentication does not replace server certificate
verification: without it, an active intermediary that knows or obtains the
shared key can impersonate a Portal. Prefer `sni` outside controlled networks.

## Authentication Failure

No target is dialed before auth succeeds. Failure paths wait for a common
authentication deadline and return no detailed network error. QUIC closes
with a generic access-denied application error; diagnostic details remain in
local logs.

## Resource Boundaries

Before QUIC authentication, Portal requires Retry, admits only bounded global
and source-prefix connection counts, exposes one bidi stream, and grants small
receive credit. Pre-authentication DATAGRAMs are discarded rather than queued.

After auth, explicit caps cover streams, UDP flows, pending pairs, TLS idle
lanes, queue bytes, reassembly slots and lifetime, target length, setup time,
and idle flows. Decoders check length and enum bounds before allocating.

Vector applies global local SOCKS flow limits, pins UDP ASSOCIATE traffic to the
control peer, rejects SOCKS UDP fragments, and closes all target flows when the
association control connection ends.

## SOCKS Exposure

`socks=:1080`, `0.0.0.0`, and `[::]` expose Vector to other hosts. Configure
RFC1929 credentials and firewall rules before using wildcard listeners.
Credentials are redacted from effective URLs and access logs.

Portal outbound SOCKS errors never fall back direct, preventing route-policy
bypass. Domain targets stay unresolved until the configured outbound proxy
when proxying is enabled.

## Deployment Checklist

- Use `tls=2` and Vector `sni` for public or long-lived deployments.
- Restrict certificate/key file permissions.
- Use independent high-entropy shared and SOCKS keys.
- Enable only required Portal listener transports.
- Monitor CHECK_POINT, LINK_STATUS, authentication failures, and restarts.
- Coordinate Portal and Vector upgrades; mixed wire versions are unsupported.
- Treat debug access paths as sensitive operational metadata.
