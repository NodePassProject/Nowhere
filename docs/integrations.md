# Integrations

Launch Nowhere services and observe them through public process and IPC interfaces.

## Contents

- [Service processes](#service-processes)
- [Local observation](#local-observation)
- [Subscriber workflow](#subscriber-workflow)
- [Deployment boundaries](#deployment-boundaries)

## Service processes

Each Portal, Vector or Egress runs as a service process with local statistics.
Configure it with a [role URL](configuration.md), supervise its lifetime and
allow the bounded shutdown to complete.

| Role | Integration point |
|---|---|
| Portal | Declared listeners and one fixed `out` |
| Vector | SOCKS5 ingress through `in`; one carrier selected by `ENDPOINT` |
| Egress | Outbound TLS or QUIC registration; target dialing when selected by Portal |

`nowhere probe` performs a one-shot setup check without an ingress listener.
`nowhere status` reads a local snapshot and exits. See [Platforms](platforms.md#process-control)
for process signals and [Operations](operations.md) for diagnostics.

## Local observation

Each service maintains six logical statistics independent of consumers and
publishes them over protected local IPC. stdout carries startup, TLS fingerprint
and graceful shutdown records. stderr carries diagnostic errors.

OpenCtrl supervises Portal, Vector and Egress. It consumes statistics through IPC
and forwards both child output streams as original SSE log text. Its three states
come from process startup and exit: `running`, `stopped`, `error`. IPC interruption
and Egress reconnection do not change process state.

## Subscriber workflow

1. Discover an instance in the local per-user registry.
2. Validate permissions, namespace, endpoint and process/peer identity.
3. Connect and validate Hello; send no command.
4. Read the immediate Snapshot and subsequent one-second snapshots.
5. On a five-second read timeout or disconnect, reconnect; keep cumulative totals
   for the same instance without adding repeated samples. Clear stale active
   counts; a different instance ID starts a separate counter lifetime.

The [discovery record](telemetry.md#validate-discovery),
[JSON messages](telemetry.md#messages) and [JSON Schema](telemetry.md#json-schema)
define the local interface.
See [Testing](testing.md) for native IPC regression coverage.

## Deployment boundaries

The service and collector share an operating-system user and the platform's
system temporary directory. In containers, they also share the same container
and namespaces. Telemetry uses Unix sockets or local Windows named pipes;
it does not publish an HTTP or network service.

Use the [ecosystem guide](ecosystem.md) for client, deployment and controller
projects. Their own documentation defines the interfaces they support.
