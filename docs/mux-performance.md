# TLS Mux performance baseline

The local benchmark runs a real Vector, Toxiproxy-delayed TCP/TLS carrier,
Portal, and TCP target. It synchronizes the application transfers, reports
payload throughput, and samples peak RSS for both Nowhere processes every
100 ms.

```sh
cargo build --release --locked
scripts/bench-mux-local.sh 100 1 64 1
```

Arguments are RTT in milliseconds, concurrent flows, MiB per flow, `mux=0|1`,
and an optional binary path. Run samples serially so their fixed local ports do
not overlap. Apple Container's default kernel does not provide the netem qdisc,
so the local runner uses bidirectional Toxiproxy latency on the real carrier.

## 2026-09-07 development baseline

Host: Apple silicon macOS development host, Apple Container Toxiproxy 2.12.0,
`throughput` profile, fixed delay without artificial bandwidth or loss. These
numbers compare implementations on this host; they are not production capacity
claims.

| Implementation | RTT | Flows | Payload | Throughput | Portal peak RSS | Vector peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| Previous 512 KiB Mux | 100 ms | 1 | 64 MiB | 37.86 Mbps | 9.77 MiB | 8.95 MiB |
| Profile-window Mux | 100 ms | 1 | 64 MiB | 959.71 Mbps | 17.56 MiB | 10.52 MiB |
| Previous 512 KiB Mux | 300 ms | 1 | 32 MiB | 13.08 Mbps | 9.86 MiB | 9.16 MiB |
| Profile-window Mux | 300 ms | 1 | 32 MiB | 288.04 Mbps | 19.38 MiB | 10.27 MiB |
| One Mux Shard | 100 ms | 16 | 128 MiB | 1.81 Gbps | 26.83 MiB | 10.38 MiB |
| Four Mux Shards | 100 ms | 16 | 128 MiB | 4.38 Gbps | 71.66 MiB | 11.86 MiB |
| One Mux Shard | 300 ms | 16 | 128 MiB | 670.71 Mbps | 26.72 MiB | 10.19 MiB |
| Four Mux Shards | 300 ms | 16 | 128 MiB | 1.69 Gbps | 61.61 MiB | 11.88 MiB |

The larger profile removes the dominant high-RTT collapse. Four Shards improve
aggregate 16-flow throughput by about 2.5 times at both measured RTTs, while
raising peak RSS substantially. The runtime therefore adapts target density to
TLS setup latency and live carrier pressure, and caps the directional pool at
four. A single flow remains on one Shard.

At 300 ms, a 16 MiB stream window has a theoretical ceiling near 447 Mbps. The
measured 288.04 Mbps is about 64% of that ceiling, leaving room to improve credit
return timing, writer batching, allocation reuse, and TLS scheduling before
increasing the profile budgets.

## 2026-09-08 adaptive pass

This pass retains the minimal 8-byte STREAM/WINDOW wire format and the 1/8-window
credit-return threshold. A 1/16 threshold did not improve throughput and would
send more control frames. Generic TCP relay reads now transfer a pooled buffer
lease into `Bytes`, so the allocation returns to the existing transport pool
when the last payload owner drops. Mux-to-relay reads continue to hand off their
owned frame payload directly.

| RTT | Flows | Payload | TLS carriers | Throughput | Portal peak RSS | Vector peak RSS |
|---:|---:|---:|---:|---:|---:|---:|
| 10 ms | 16 | 48 MiB | 1 | 6.77 Gbps | 26.77 MiB | 10.84 MiB |
| 100 ms | 1 | 64 MiB | 1 | 937.75 Mbps | 20.08 MiB | 10.47 MiB |
| 300 ms | 1 | 32 MiB | 1 | 283.82 Mbps | 20.36 MiB | 12.56 MiB |
| 100 ms | 16 | 128 MiB | 4 | 4.74 Gbps | 57.48 MiB | 12.78 MiB |
| 300 ms | 16 | 128 MiB | 4 | 1.66 Gbps | 75.64 MiB | 26.30 MiB |

The adaptive policy keeps 16 simultaneous low-RTT flows on one carrier, while
100 and 300 ms samples expand to four. The high-RTT aggregate results match or
slightly exceed the fixed-four baseline within normal local-run variation, so
the four-carrier cap remains useful under high BDP without imposing four TLS
connections on low-latency workloads. Single-flow throughput is unchanged.

Multi-DATA vectored batching was tested and rejected. Tokio-rustls can complete
a vectored write after consuming only part of a header/payload pair; extending
that state machine across several frames caused boundary corruption under
concurrency. The retained writer issues one frame at a time but already sends
its 8-byte header and owned payload through one vectored-write path without
coalescing them into a copy buffer. Reader and writer loops now also observe a
closed flag before waiting, and the reader yields after each 32 DATA frames so
WINDOW production cannot be starved by a continuously ready TLS carrier.

The Apple Container Toxiproxy path became unreliable for sustained 10 ms bursts
above 48 MiB in this run, while 48 MiB crossed the 32 MiB connection window and
completed. The 100 and 300 ms sustained samples were run from fresh proxy
containers; the benchmark now records carrier topology alongside throughput and
RSS so future comparisons can distinguish pool-size changes from data-path
changes.
