# Ecosystem

Connect, deploy and operate with tools built around Nowhere's public interfaces.

## Contents

- [Projects](#projects)
- [Connections and management](#connections-and-management)
- [Share links](#share-links)
- [Service configuration](#service-configuration)

## Projects

Use the layer that fits your workflow. Each project's documentation describes
the protocol and interfaces it supports.

| Project | Purpose | Get started |
|---|---|---|
| [Anywhere](https://github.com/NodePassProject/Anywhere) | Native connections on iOS, iPadOS and tvOS | [App Store](https://apps.apple.com/us/app/id6758235178) · [Import guide](https://github.com/NodePassProject/Anywhere#deep-links) |
| **Vector** | Built-in SOCKS5 ingress for desktop and server applications | [Quick start](quick-start.md) · [Configuration](configuration.md#vector-url) |
| [nowhere-sh](https://github.com/NodePassProject/nowhere-sh) | Linux VPS deployment and service management | [Quick start](https://github.com/NodePassProject/nowhere-sh#quick-start) · [Commands](https://github.com/NodePassProject/nowhere-sh#commands) |
| [OpenCtrl](https://github.com/NodePassProject/OpenCtrl) | Local process supervision through REST and SSE | [Run](https://github.com/NodePassProject/OpenCtrl#run) · [API reference](https://github.com/NodePassProject/OpenCtrl/blob/main/docs/master.md) |
| [NowhereDash](https://github.com/NodePassProject/NowhereDash) | Portal fleet operations through OpenCtrl | [Quick start](https://github.com/NodePassProject/NowhereDash#quick-start) · [Product tour](https://github.com/NodePassProject/NowhereDash#product-tour) |

## Connections and management

Client traffic, deployment and process management use separate interfaces:

```text
Connect

+----------+                 +----------+                 +----------+
| Anywhere |-- wire protocol>|  Portal  |<-- wire protocol|  Vector  |
+----------+                 +----------+                 +----------+

Deploy

+------------+     installs and operates      +-----------------+
| nowhere-sh |------------------------------->| Portal / Egress |
+------------+                                +-----------------+

Manage

+-------------+       REST + SSE       +----------+
| NowhereDash |----------------------->| OpenCtrl |
+-------------+                        +-----+----+
                                            |
                                            | supervises
                                            v
                              +---------------------------+
                              |  Portal / Vector / Egress |
                              +---------------------------+
```

### Connect

The Anywhere clients connect to Portal and import `nowhere://` links. Vector ships
in the `nowhere` binary and exposes a local SOCKS5 endpoint. Client peers
implement [Nowhere Protocol (NW3)](protocol.md) independently of the Rust runtime.
Check the client's own documentation and validate the versions used in a
deployment. Nowhere also provides an [Egress Extension](egress.md); ordinary
client peers do not need that extension when Portal uses a remote exit.

### Deploy

nowhere-sh installs and manages one systemd service on a Linux VPS, running
Portal or Egress. Its interactive workflow covers release selection, upgrades,
transport and service configuration, lifecycle, logs and generated Anywhere or
Vector links for Portal deployments.

### Manage

OpenCtrl runs beside the Portal, Vector or Egress processes it supervises. It stores
process definitions and exposes lifecycle, logs and telemetry through a
versioned REST API and Server-Sent Events. The controller and its children
share a host or container, operating-system user and telemetry namespace.

NowhereDash connects to multiple OpenCtrl endpoints. It operates Portal
instances, displays live telemetry and publishes protected subscriptions with
QR codes and mobile import links. Its management model is Portal-only.

## Share links

Use [share links](configuration.md#share-links) to distribute Portal connections.
Client import guides describe any additional fields.

## Service configuration

The CLI runs `portal://`, `vector://` and `egress://` URLs:

```text
portal://KEY@HOST/tcp:2000/udp:2001?out=egress
vector://KEY@HOST/tcp:2000?in=127.0.0.1:1080
egress://KEY@HOST/udp:2001
```

Use a key from `nowhere generate-key`. Vector requires `in` for its local
listener and selects one carrier through its endpoint path. Egress uses TLS or
QUIC and registers only with a Portal configured for `out=egress`. These lines
illustrate URL forms; with Portal's default generated certificate, Vector and
Egress also need a verified `pin`. See [certificate trust](security.md#certificate-trust).

[Configuration](configuration.md) defines the complete CLI grammar, defaults,
listener options and environment variables. [Integrations](integrations.md)
describes service supervision and third-party Telemetry subscribers.
