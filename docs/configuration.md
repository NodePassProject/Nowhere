# Configuration

Configure listeners, transport selection and a fixed exit with service URLs.

## Contents

- [Role URLs](#role-urls)
- [Endpoints](#endpoints)
- [Share links](#share-links)
- [Portal URL](#portal-url)
- [Vector URL](#vector-url)
- [Egress URL](#egress-url)
- [Parsing configuration](#parsing-configuration)
- [Parameter overview](#parameter-overview)
- [Runtime environment](#runtime-environment)

## Role URLs

| Role | URL | Purpose |
|---|---|---|
| Portal | `portal://KEY@ENDPOINT` | TLS/QUIC listeners and one fixed exit |
| Vector | `vector://KEY@ENDPOINT?in=HOST:PORT` | Local SOCKS5 ingress and one connection carrier to Portal |
| Egress | `egress://KEY@ENDPOINT` | TLS or QUIC registration and target access |

`KEY` is percent-decoded once and used as text bytes. All three roles require
exactly 32 lowercase hexadecimal characters. Generate a key with
`nowhere generate-key` and use the same value on the peers. Service URLs do not
accept a password component or display-name fragment.

`ENDPOINT` selects the host, port and transport. Query parameters follow `?`
and are separated by `&`.

## Endpoints

All roles use the same endpoint grammar, with different carrier limits:

| ENDPOINT form | Portal | Vector | Egress |
|---|---|---|---|
| `HOST:PORT` | TLS and QUIC on the same port | TLS | QUIC |
| `HOST/tcp:PORT` | TLS listener | TLS connection | TLS connection |
| `HOST/udp:PORT` | QUIC listener | QUIC connection | QUIC connection |
| `HOST/tcp:PORT/udp:PORT` | Separate TLS and QUIC listener ports | Unsupported | Unsupported |

Portal paths declare one or two carriers. Vector paths declare exactly one
carrier; Egress paths also declare exactly one carrier. Both TLS and QUIC carry
TCP and UDP business Flows.

Each carrier may specify an address family:

| Carrier | Transport | Address family |
|---|---|---|
| `tcp` | TLS | IPv4 or IPv6 |
| `tcp4` | TLS | IPv4 only |
| `tcp6` | TLS | IPv6 only |
| `udp` | QUIC | IPv4 or IPv6 |
| `udp4` | QUIC | IPv4 only |
| `udp6` | QUIC | IPv6 only |

Use a DNS name, IPv4 address or bracketed IPv6 address for `HOST`. Portal also
accepts `*` for wildcard listeners. Vector and Egress require a concrete host.
A concrete IP must match the carrier's address family.
Ports are decimal integers in `1..=65535`.

Do not combine an authority port with a carrier path. Paths do not accept empty
segments, dot segments or a trailing slash. Portal's two carriers may appear in
either order, but TCP and UDP may each be declared only once, including their
family-specific forms.

Examples:

```text
portal://KEY@*:2000
portal://KEY@*/tcp4:2000/udp6:2001
vector://KEY@relay.example/tcp:2000?in=127.0.0.1:1080
vector://KEY@relay.example/udp:2001?in=127.0.0.1:1080
egress://KEY@[2001:db8::1]/udp6:2001
```

Unrestricted wildcard Portal listeners may omit an unavailable family with a
diagnostic on stderr. Explicit families and concrete binds fail on errors. See
[network exposure](platforms.md#network-exposure) for socket and firewall rules.

## Share links

Share links use a compact host and port:

```text
nowhere://KEY@HOST:PORT
nowhere://KEY@HOST:PORT?net=udp&morph=1#NAME
```

Share links do not accept carrier paths. Use a concrete DNS name, IPv4 address
or bracketed IPv6 address. A display name as `#NAME` is recommended.
Percent-encode spaces and reserved characters in names.

Optional parameters:

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `net` | `tcp` or `udp` | `tcp` | Client carrier: TLS or QUIC |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |

For certificate inspection with `fingerprint`, see
[Operations](operations.md#diagnose-target-setup).

## Portal URL

```text
portal://KEY@ENDPOINT[?out=EXIT]
```

Portal listens on `ENDPOINT` and uses one fixed `out` for all Flows.

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `out` | `direct`, `egress` or `[USER:PASS@]HOST:PORT` | `direct` | Direct target access, registered Egress or a SOCKS5 upstream |
| `tls` | `1` or `2` | `1` | Generated certificate (`1`) or supplied PEM files (`2`) for TLS and QUIC |
| `crt` | Certificate-chain PEM path | Absent | Required exactly when `tls=2` |
| `key` | Private-key PEM path | Absent | Required exactly when `tls=2` |
| `dial` | IP literal or `auto` | `auto` | Outbound source binding; an IP restricts connections to its address family |
| `dial4` | IPv4 literal or `auto` | `auto` | IPv4 outbound source binding |
| `dial6` | IPv6 literal or `auto` | `auto` | IPv6 outbound source binding; IPv4-mapped addresses are invalid |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |
| `rate` | `0..=2147483647` Mbps | `0` | Vector-to-Target upload limit; `0` disables it |
| `etar` | `0..=2147483647` Mbps | `0` | Target-to-Vector download limit; `0` disables it |

`out=egress` accepts Egress on any enabled TLS or QUIC listener and conflicts
with explicit `dial`, `dial4` or `dial6`, including `auto`. See [Egress](egress.md) for registration and offline
behavior.

### Target source selection

`dial` is mutually exclusive with `dial4` and `dial6`. In the family-specific
form, an omitted family uses `auto`. Explicit source binding errors fail the
dial; they do not trigger an unbound retry. Portal applies these settings to
its own outbound work, including connections to a SOCKS5 upstream.

### SOCKS credentials

Portal's SOCKS5 `out` and Vector's `in` split credentials at raw delimiters
before decoding each component once. Percent-encode reserved credential
characters. For example:

```text
out=a%3Ab:p%40ss@127.0.0.1:1080
```

The decoded username is `a:b` and the password is `p@ss`. Both components must
contain between 1 and 255 UTF-8 bytes.

## Vector URL

```text
vector://KEY@ENDPOINT?in=[USER:PASS@]HOST:PORT
```

Vector connects to Portal over the carrier selected by `ENDPOINT`.

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `in` | `[USER:PASS@]HOST:PORT` | Required for a service; optional for probe | Local SOCKS5 listener, with optional authentication |
| `sni` | ASCII DNS name, empty or `none` | Endpoint host | Verified server name; empty or `none` uses the host |
| `pin` | 64 lowercase hexadecimal characters, empty or `none` | System CA and hostname verification | Exact certificate SHA-256; empty or `none` uses normal verification |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |
| `rate` | `0..=2147483647` Mbps | `0` | Vector-to-Target upload limit; `0` disables it |
| `etar` | `0..=2147483647` Mbps | `0` | Target-to-Vector download limit; `0` disables it |

Obtain a fingerprint with `nowhere fingerprint` and compare it through a trusted
channel before setting `pin`. See [certificate trust](security.md#certificate-trust).
Upload and download follow the Vector-to-Target business direction, regardless
of which transport peer establishes the connection.

## Egress URL

```text
egress://KEY@ENDPOINT
```

Egress connects to Portal over its selected TLS or QUIC carrier and provides
target access. The `HOST:PORT` shorthand continues to select QUIC.

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `sni` | ASCII DNS name, empty or `none` | Endpoint host | Verified server name; empty or `none` uses the host |
| `pin` | 64 lowercase hexadecimal characters, empty or `none` | System CA and hostname verification | Exact certificate SHA-256; empty or `none` uses normal verification |
| `dial` | IP literal or `auto` | `auto` | Target source binding; an IP restricts target connections to its address family |
| `dial4` | IPv4 literal or `auto` | `auto` | IPv4 target source binding |
| `dial6` | IPv6 literal or `auto` | `auto` | IPv6 target source binding; IPv4-mapped addresses are invalid |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |
| `rate` | `0..=2147483647` Mbps | `0` | Vector-to-Target upload limit; `0` disables it |
| `etar` | `0..=2147483647` Mbps | `0` | Target-to-Vector download limit; `0` disables it |

Egress's `dial`, `dial4` and `dial6` follow the same mutual-exclusion and
explicit-bind rules as Portal. They bind outbound target sockets and filter
resolved target addresses. DNS lookup uses the host resolver; these options
do not select the DNS query's source address. Egress-to-Portal connections
use automatic source selection.

## Parsing configuration

Unknown parameters and their values are ignored. For recognized parameters,
the first duplicate wins; an invalid first value is an error.

| Query | Result |
|---|---|
| `morph=1&morph=0` | Morph is enabled |
| `morph=invalid&morph=1` | Configuration error |

Startup logs show role URLs with explicit defaults. Shared Key, SOCKS
credentials, `crt`, `key` and unknown options are omitted. Portal with
`out=egress` also omits source-binding parameters. These redacted URLs are
diagnostic views, not complete launch configurations.

## Parameter overview

A dash means that the role does not recognize the parameter.

| Parameter | Accepted value | Default | Portal | Vector | Egress |
|---|---|---|:---:|:---:|:---:|
| `in` | `[USER:PASS@]HOST:PORT` | Required for Vector service | — | Yes | — |
| `out` | `direct`, `egress`, `[USER:PASS@]HOST:PORT` | `direct` | Yes | — | — |
| `tls` | `1`, `2` | `1` | Yes | — | — |
| `crt` | Certificate-chain PEM path | Absent | Yes | — | — |
| `key` | Private-key PEM path | Absent | Yes | — | — |
| `sni` | ASCII DNS name, empty, `none` | Endpoint host | — | Yes | Yes |
| `pin` | 64 lowercase hex characters, empty, `none` | System CA and hostname verification | — | Yes | Yes |
| `dial` | IP literal, `auto` | `auto` | Yes | — | Yes |
| `dial4` | IPv4 literal, `auto` | `auto` | Yes | — | Yes |
| `dial6` | IPv6 literal, `auto` | `auto` | Yes | — | Yes |
| `morph` | `0`, `1` | `1` | Yes | Yes | Yes |
| `rate` | `0..=2147483647` Mbps | `0` | Yes | Yes | Yes |
| `etar` | `0..=2147483647` Mbps | `0` | Yes | Yes | Yes |

## Runtime environment

Set environment variables before starting the service. Byte sizes use integer
values; duration settings use values such as `5s` or `250ms`. Vector, Portal and
Egress validate all duration settings listed below at startup, including settings
not used by the selected role or carrier. Values must be positive, valid Unicode,
and fit the duration parser and timer implementation; UDP idle must also fit
QUIC's idle-timeout limit. Invalid values fail startup with the variable name.
Only unset variables use defaults.

`NOW_QUIC_UDP_QUEUE_BYTES` is also validated once at startup by all three roles,
including TLS-only configurations. It accepts positive integer byte counts up to
the smaller of `Semaphore::MAX_PERMITS` and `u32::MAX`. The saved value bounds each
QUIC connection's UDP queue and reassembly reservations, and Vector's separate
local UDP queue budget. Invalid values fail startup with the variable name.

| Variable | Default | Purpose |
|---|---|---|
| `NOW_TCP_DATA_BUF_SIZE` | `32768` | TCP copy buffer bytes |
| `NOW_TCP_DIAL_TIMEOUT`, `NOW_UDP_DIAL_TIMEOUT` | `15s` | Target dial limits |
| `NOW_HANDSHAKE_TIMEOUT` | Shared Key-derived `3s`–`30s` | Transport/authentication limit |
| `NOW_FLOW_SETUP_TIMEOUT` | `20s` | Complete Flow setup operation deadline |
| `NOW_TCP_READ_TIMEOUT` | `30s` | TCP half-close completion limit |
| `NOW_UDP_IDLE_TIMEOUT` | `120s` | UDP Flow/QUIC idle limit |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4194304` | Connection-wide queue/reassembly reservation |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Bounded drain |
| `NOW_RELOAD_INTERVAL` | `1h` | Supplied certificate reload |
| `NOW_SERVICE_COOLDOWN` | `3s` | Egress reconnect and failed-seed backoff |
| `NOW_EGRESS_TLS_POOL_MAX` | `128` | Maximum TLS Egress pending connections per process |
| `NOW_PORTAL_TLS_IDLE_MAX` | `128` | Portal-wide TLS Egress pending capacity |
| `NOW_TRANSPORT_MEMORY_PROFILE` | `throughput` | QUIC window profile |
| `NOW_MORPH_TCP_PRELUDE` | `fade` | [Morph prelude mode](#tcp-morph-prelude): `fade`, `full8` or `low7` |

### Timeout semantics

When `NOW_HANDSHAKE_TIMEOUT` is unset, each instance derives its default once
from the URL-decoded, validated Shared Key bytes:

```text
digest = HMAC-SHA256(key = SharedKey, data = "nowhere/handshake-timeout")
value = BE64(digest[0..8])
timeout = (3000 + 100 * (value % 271)) ms
```

The key is used as ASCII bytes, without hexadecimal decoding. The label is the
exact ASCII string shown, with no suffix or NUL. The 271 possible values span
3.0–30.0 seconds in 100ms steps. For example, Shared Key
`0123456789abcdef0123456789abcdef` produces `9100ms`. The same key produces the
same default in Portal, Vector, Egress, Probe and certificate fingerprint queries,
regardless of TLS/QUIC or Morph. Instances with different keys are independent.

An explicit value takes precedence, must meet the duration validation above, and
may be outside the derived range. Services save the effective value at startup
and include it in their starting INFO log. Connections, reconnects and Flows reuse
that value. Vector's SOCKS5 handshake and TLS UDP tunnel close also use the
instance value. Flow setup has a separate 20s default deadline, which can expire
before a longer handshake budget.

- **Operation Deadline:** one budget for an operation, without restarting it at
  each stage. Vector TCP and UDP setup share `NOW_FLOW_SETUP_TIMEOUT` from the
  start of setup through READY, including DNS, connection acquisition, initial
  TLS/QUIC handshakes, reuse/lock and Stream-credit waits, AuthFrame and request
  writes, and result reads. Handshake stage limits also apply within that budget.
  Portal-to-Egress setup keeps one budget for selection, claim, request and
  result. Probe uses the same Vector setup operation; cleanup has its own budget.
  QUIC Egress registration uses one `NOW_HANDSHAKE_TIMEOUT` after transport
  connection, covering `open_bi`, AuthFrame write/finish and the complete reply.
  `NOW_TCP_READ_TIMEOUT` is a completion deadline for the remaining TCP direction
  after the other direction finishes normally (Half-Close). Traffic does not
  restart it; it is not a timeout on every TCP read.
- **Idle Timeout:** `NOW_UDP_IDLE_TIMEOUT` controls UDP Flow activity and QUIC
  transport idle timeouts. It does not cap the total lifetime of an active
  Flow. Fully open TCP Flows have no read-idle timeout.
- **Fixed TTL:** unused TLS Egress standby connections expire after a fixed
  `120s`, independently at Portal and Egress. Activity does not renew this TTL;
  claimed connections leave standby and follow normal Flow lifetime rules.
  UDP fragment reassembly expires after `10s`.

Setup deadlines end at READY; they do not limit established Flow lifetimes.

### QUIC window profiles

| Profile | Stream receive | Connection receive | Send window |
|---|---:|---:|---:|
| `memory` | 4 MiB | 8 MiB | 8 MiB |
| `balanced` | 8 MiB | 16 MiB | 16 MiB |
| `throughput` | 16 MiB | 32 MiB | 32 MiB |

Portal uses a 64 KiB connection receive window before authentication and raises
it after success. Transport windows are separate from UDP application budgets
and do not represent total process memory.

### TCP Morph prelude

Morph TCP emits an [Authenticated Prelude](prelude.md). After
generating the base prelude, it replaces the last 32 bytes' low seven bits with
masked authentication data; the first 32 bytes and all highest bits retain the
selected policy.

`NOW_MORPH_TCP_PRELUDE` selects the base Prelude generation policy. The receiver
consumes the 64-byte prelude independently of that policy; this setting is not
negotiated and need not match the peer's generation policy.

- `fade` (default): independently sample uniform A in `[8,12]` and B in `[16,32]`.
  Bytes `[0,A)` are uniform printable ASCII (`0x20–0x7E`), `[A,B)` are uniform
  low7 (`0x00–0x7F`), and `[B,64)` are uniform full8 (`0x00–0xFF`).
- `full8`: generate all eight bits randomly throughout the base prelude.
- `low7`: clear each random byte's high bit.

All modes use a secure random source. Fade uses rejection sampling for its
boundaries and printable ASCII to avoid modulo bias. The distributions above
describe the base Prelude before authentication encoding. The encoded tail
preserves highest bits and carries masked payload in its low seven bits.
The [Core Morph contract](protocol.md) defines the envelope and directional
cipher; the [Prelude Extension](prelude.md) defines authentication encoding
and acceptance.
