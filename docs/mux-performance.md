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
raising peak RSS substantially. The runtime therefore opens Shards lazily at
four active flows and caps the directional pool at four. A single flow remains
on one Shard.

At 300 ms, a 16 MiB stream window has a theoretical ceiling near 447 Mbps. The
measured 288.04 Mbps is about 64% of that ceiling, leaving room to improve credit
return timing, writer batching, allocation reuse, and TLS scheduling before
increasing the profile budgets.
