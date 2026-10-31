# Operations

Inspect service state, diagnose setup and manage the lifetime of running instances.

## Contents

- [Read local status](#read-local-status)
- [Diagnose target setup](#diagnose-target-setup)
- [Check deployment settings](#check-deployment-settings)
- [Monitor Egress](#monitor-egress)
- [Understand failure boundaries](#understand-failure-boundaries)
- [Manage capacity and shutdown](#manage-capacity-and-shutdown)

## Read local status

Read one snapshot from the local service processes:

```sh
nowhere status
```

Status discovers protected IPC endpoints, queries at most eight instances at a
time with a two-second deadline per instance, and exits without requiring a
terminal. Results are sorted by role, PID and instance ID. Successful snapshots
remain visible when another instance fails; partial failures are reported and
the command exits unsuccessfully. When no instances are discovered, it reports
`IDLE` and exits successfully.

| Display | Meaning |
|---|---|
| Role, PID, instance ID and endpoint | Process identity |
| TCP/UDP upload and download | Per-process cumulative logical payload |
| TCP/UDP Flows | Active business Flow owners |

Counters continue without clients. [JSON IPC](telemetry.md) carries statistics;
stdout carries startup, TLS fingerprint and graceful shutdown logs, while stderr
carries raw errors. Collectors must not add different processes' totals as unique
end-to-end bytes.

## Diagnose target setup

Perform one real TCP Flow setup using Vector's configured transport:

```sh
nowhere probe "vector://KEY@relay.example:2000?pin=TRUSTED_SHA256" "example.com:443"
```

Probe and fingerprint inspection require the same 32 lowercase hexadecimal
Shared Key characters as services, checked after URL decoding and before
connecting.

`in` is optional for probe. READY verifies the selected Portal output; probe
sends no target payload and does not verify an application protocol at the
target. Output failures return the fixed SetupResult described in the
[wire specification](protocol.md).

Read a presented certificate over TCP/TLS:

```sh
nowhere fingerprint "nowhere://KEY@relay.example:2000?morph=1"
```

`fingerprint` requires `morph=0|1` matching Portal; `#NAME` and an `sni` DNS
name are optional. Inspection uses TCP/TLS even with `net=udp`, so the shared
host and port must expose TLS. Compare the result through a trusted channel
before configuring a pin. See [Security](security.md#certificate-trust).

The default self-signed certificate changes on every Portal restart. Update
pinned clients after independently verifying the new fingerprint. Supplied
certificates can be reloaded as described in [certificate trust](security.md#certificate-trust).

Running `nowhere` without arguments displays help and exits normally.

## Check deployment settings

Expose the declared Portal carrier ports and the intended SOCKS ingress.
Confirm certificate trust, Morph agreement, the endpoint carrier, `in` and `out`.
Startup output shows the effective role URL with explicit defaults and redacted
credentials.

See [Configuration](configuration.md#parsing-configuration) for
parsing and redaction rules, and [Platforms](platforms.md#network-exposure) for
firewall and container exposure.

## Monitor Egress

Portal's `out` is fixed for its lifetime. `out=egress` accepts registrations
on enabled TLS and QUIC listeners and cannot specify `dial`, `dial4` or `dial6`.
New Flows wait within their setup timeout while Egress is offline. Multiple
instances can register; TLS registrations receive BUSY when the Portal-wide
pending limit is full.

Registration ownership remains internal to forwarding. An idle registered
Egress has no business Flow. Diagnostic stderr reports registration, reconnection
and target failures. Use `nowhere probe` to test a real target setup; process
`running` means the process is alive, not that every target is reachable.
See [Egress](egress.md).

## Understand failure boundaries

| Failure | Effect |
|---|---|
| Ordinary setup or forwarding failure | Ends the affected Flow |
| Authentication or business Stream direction violation | Closes the connection |
| Egress connection loss | Ends every dependent bridge |
| UDP control FIN, RESET, STOP_SENDING, idle timeout or connection loss | Reclaims that Flow's routes and resources |

TLS is dedicated per Flow. QUIC carries business Streams in one initiation
direction. Reconnection starts new Flows. UDP control Streams remain open
through their lifetime; losing a CLOSE DATAGRAM does not keep a route alive.

## Manage capacity and shutdown

Admission and business resources are bounded. UDP budgets cover queued and
reassembly bytes; full Flow queues drop datagrams without blocking the
connection dispatcher. Flows using the same QUIC Egress connection share its
congestion and transport budgets.
Observe per-process and per-Flow behavior when choosing concurrency or rate
settings. Use [Testing](testing.md#performance-measurements) for measurements.

Shutdown stops admission, cancels service work and drains within
`NOW_SHUTDOWN_TIMEOUT` (default `5s`). Tasks and owned resources are reclaimed;
active counters decrement with their owners. Pending handshakes, authentication
and Egress registration waits are cancelled without waiting for their timeouts.
A timed-out drain aborts remaining tasks. QUIC UDP ID exhaustion also stops new
Flows and closes or reconnects
after bounded drain, without an additional protocol frame.

See [process control](platforms.md#process-control) for native shutdown signals.
