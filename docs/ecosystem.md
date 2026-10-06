# Ecosystem and share links

Nowhere has a small set of focused tools around the Portal and Vector runtime.
Use only the layer you need: connect from an Apple device, deploy one Linux
server, supervise local processes through an API, or operate a Portal fleet
from a web dashboard.

| Project | Role | Get started |
| --- | --- | --- |
| [Anywhere](https://github.com/NodePassProject/Anywhere) | Native Nowhere client for iOS, iPadOS, and tvOS | [App Store](https://apps.apple.com/us/app/id6758235178) · [Import guide](https://github.com/NodePassProject/Anywhere#deep-links) |
| **Vector** | Built-in SOCKS5 edge for desktop and server workflows | [Quick start](quick-start.md) · [Configuration](configuration.md#vector-url) |
| [nowhere-sh](https://github.com/NodePassProject/nowhere-sh) | Interactive Linux VPS deployment and management script | [Quick start](https://github.com/NodePassProject/nowhere-sh#quick-start)  · [Commands](https://github.com/NodePassProject/nowhere-sh#commands) |
| [OpenCtrl](https://github.com/NodePassProject/OpenCtrl) | Advanced control plane for Portal and Vector processes | [Run](https://github.com/NodePassProject/OpenCtrl#run) · [API reference](https://github.com/NodePassProject/OpenCtrl/blob/main/docs/master.md) |
| [NowhereDash](https://github.com/NodePassProject/NowhereDash) | Web dashboard for Portal fleets managed through OpenCtrl | [Quick start](https://github.com/NodePassProject/NowhereDash#quick-start) · [Product tour](https://github.com/NodePassProject/NowhereDash#product-tour) |

## How the pieces fit

```text
Connect

  +----------+                          +--------+
  | Anywhere |--- Nowhere protocol ---->| Portal |
  +----------+                          +--------+
  +----------+                              ^
  |  Vector  |--- Nowhere protocol ---------+
  +----------+

Deploy

  +------------+                        +--------+
  | nowhere-sh |--- installs/operates ->| Portal |
  +------------+                        +--------+

Manage

  +-------------+    REST + SSE    +----------+    supervises     +-------------------------+
  | NowhereDash |----------------->| OpenCtrl |------------------>| Portal / Vector process |
  +-------------+                  +----------+                   +-------------------------+
```

**Anywhere** connects directly to Portal and imports `nowhere://` links.
**Vector** ships in the `nowhere` binary and exposes a local SOCKS5 endpoint.

**nowhere-sh** installs and manages one systemd Portal on a Linux VPS. Its
interactive workflow covers release selection and upgrades, carrier and Portal
configuration, service lifecycle, logs, the built-in TUI, and generated
Anywhere or Vector links. It operates the Portal directly without adding a
control-plane service.

**OpenCtrl** runs beside the Nowhere processes it supervises. It stores Portal
or Vector definitions and exposes lifecycle, logs, and telemetry over a
versioned REST API and Server-Sent Events. The controller and its child
processes must share a host or container, operating-system user, and telemetry
namespace.

**NowhereDash** sits above OpenCtrl. It provides a web interface for multiple
OpenCtrl endpoints, operates Portal instances, displays live telemetry, and
publishes protected subscriptions with QR codes and mobile import links. Its
management model is intentionally Portal-only.

## Share links

### Link format

Nowhere uses separate URL schemes for client sharing and service configuration:

| Scheme | Purpose | Used by |
| --- | --- | --- |
| `nowhere://` | Share a Portal connection and display name | Anywhere, CLI `fingerprint` |
| `vector://` | Connect to Portal and expose a local SOCKS5 listener | `nowhere` CLI |
| `portal://` | Configure a server listener and optional forwarding | `nowhere` CLI |

### Anywhere share links

The following format describes Anywhere's current import/export support:

```text
nowhere://KEY@HOST:PORT[?QUERY][#NAME]
nowhere://KEY@HOST/tcp:TCP_PORT[/udp:UDP_PORT][?QUERY][#NAME]
nowhere://KEY@HOST/udp:UDP_PORT[?QUERY][#NAME]
```

`KEY` is the shared Portal key, percent-encoded as URL userinfo; it is not
Base64. Encode reserved characters such as `@`, `:`, `/`, `?`, `#`, and `%`.
The decoded key must contain 1–255 UTF-8 bytes. Use a concrete hostname or IP
address and ports from `1` to `65535`; bracket IPv6 literals, as in
`[2001:db8::1]:2000`. The optional `NAME` is a percent-encoded display name.

The compact `HOST:PORT` form enables both carriers on one port. The explicit
form enables only the listed carriers, each at most once, and has no port
on `HOST`. Both carriers share the same host.

| Query | Values | Default / behavior |
| --- | --- | --- |
| `up` | `tcp`, `udp` | Upload carrier; TCP if available, otherwise UDP |
| `down` | `tcp`, `udp` | Download carrier; TCP if available, otherwise UDP |
| `mux` | `0`, `1` | `0`; `1` enables TLS multiplexing when either direction uses TCP |
| `morph` | `0`, `1` | `0`; must match the Portal's Morph setting |
| `sni` | Server name | Endpoint host when omitted, empty, or `none` |

Each direction must select a carrier declared by the endpoint. Percent-encode
reserved characters in query values. Morph Prelude selection is a local client
setting and is not included in share links.

#### Anywhere compatibility

- **No `mix` policy:** `up` and `down` accept only `tcp` or `udp`.
- **No address-family suffixes:** carrier paths accept only `tcp` and `udp`,
  not `tcp4`, `tcp6`, `udp4`, or `udp6`. IPv6 literals such as
  `[2001:db8::1]:2000` are supported; the restriction concerns explicit
  address-family selection through carrier suffixes.
- **No certificate `pin` parameter:** Anywhere's share-link parser does not
  import the CLI's certificate pin setting.

#### Examples

**TLS over TCP with multiplexing**

```text
nowhere://change-me@relay.example:2000?up=tcp&down=tcp&mux=1#My%20Portal
```

**QUIC over UDP with Morph** — the Portal must also set `morph=1`.

```text
nowhere://change-me@relay.example:2000?up=udp&down=udp&morph=1#QUIC%20Portal
```

**Separate ports and split directions** — upload over TLS, download over QUIC.

```text
nowhere://change-me@relay.example/tcp:2006/udp:2017?up=tcp&down=udp&sni=relay.example#Split%20Portal
```

Paste a link into Anywhere, or use its deep link to open the import screen:

```text
anywhere://add-proxy?link=nowhere://change-me@relay.example:2000?up=tcp&down=tcp&mux=1#My%20Portal
```

The `add-proxy` wrapper takes everything after `?link=` verbatim; do not
percent-encode the entire inner URL again.

### CLI configuration URLs

Service configuration uses `portal://` and `vector://` in the CLI. Vector
additionally requires `socks=` for its local listener; these service URLs do
not accept display-name fragments.
The `fingerprint` subcommand instead accepts `nowhere://` share links, including
their display-name fragments, and reads the certificate over TCP. It uses only
the endpoint, shared key, `morph`, and `sni`; Flow route options are ignored.
Vector uses the endpoint host as its verified server name by default and
requires system CA trust unless an exact certificate pin is configured. `sni`
can override the server name. See [Security](security.md) for Vector's
verification policy.

Use [Configuration](configuration.md) for the full CLI grammar, listener
options, chaining, and environment variables.
