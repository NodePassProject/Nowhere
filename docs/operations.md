# Operations Guide

## Startup Output

Portal and Vector log a credential-free effective URL. Shared keys and SOCKS
passwords are never included. Vector prints `sni=none` when certificate
verification is disabled.

Both commands validate selected values before opening listeners. Unknown
parameters and later duplicates are ignored; missing optional parameters use
their defaults.

## Logs

Levels are `none`, `debug`, `info`, `warn`, `error`, and `event`.

EVENT emits periodic machine-readable records:

```text
CHECK_POINT|MODE=0|PING=0ms|POOL=5|TCPS=0|UDPS=0|TCPRX=0|TCPTX=0|UDPRX=0|UDPTX=0
```

Portal MODE values remain `0=mix`, `1=tcp`, `2=udp`. Vector MODE values encode
direction pairs: `0=tcp/tcp`, `1=tcp/udp`, `2=udp/tcp`, `3=udp/udp`.

DEBUG additionally emits:

```text
LINK_STATUS|TCP=0|UDP=0|PAIRS=0|UPTCP=0|UPUDP=0|DOWNTCP=0|DOWNUDP=0
```

Access logs use matching `starting` and `complete` messages and show upload and
download carriers plus client, relay, and target endpoints. They never include
authentication secrets.

## Pools and Reconnection

Vector `tcp/tcp` pool connections complete TLS and exporter authentication
before entering the idle set. Acquired lanes are single-use. Closed, expired,
or consumed slots are replenished in the background.

Vector remains running while Portal is unavailable. Current affected flows
fail; later requests trigger bounded-backoff reconnect, while the SOCKS listener
continues accepting requests. QUIC reconnect retains the logical session ID so
Portal can replace the stale carrier deterministically.

## Limits and Rate Control

`rate` is client-to-target and `etar` is target-to-client. Portal and Vector
enforce their configured limits independently; the effective path is bounded by
the tighter side.

Tune environment limits only after measuring CPU, memory, queue pressure, and
target behavior. Increasing QUIC streams or UDP flows also increases worst-case
state. Queue overload and invalid early DATAGRAMs are dropped rather than
allowed to grow without bound.

## Certificates

Portal `tls=2` checks PEM files at startup and reloads them no more often than
`NOW_RELOAD_INTERVAL`. Reload failure leaves the last valid certificate active
and writes an error.

Vector reads system roots for verified `sni` connections. Root-store or name
errors fail the carrier rather than falling back to unverified TLS.

## Graceful Shutdown

On Ctrl-C, listeners and reconnect loops stop, QUIC endpoints send close,
pending pairs receive cancellation, and active tasks drain for
`NOW_SHUTDOWN_TIMEOUT`. At deadline, remaining tasks are aborted and all rate
and pool state is released.

## Upgrade Rule

Nowhere has no mixed-version mode. Upgrade Portal and all 1.5-compatible clients
as one coordinated operation. The current Anywhere release must remain on an
older Portal until its codec is updated.
