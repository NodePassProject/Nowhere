# TLS Mux performance baseline

The auxiliary macOS benchmark runs Vector, Toxiproxy, Portal, and a TCP target.
Toxiproxy terminates and re-originates TCP, so its latency results are useful
for quick development comparisons but are not packet-level TCP network
emulation.

```sh
cargo build --release --locked
tests/bench-mux-local.sh 100 1 64 1
```

Hard throughput and RSS comparisons use `tests/bench-mux-netem.sh` on a Linux
host with network namespaces and the `netem` qdisc. The harness delays only the
physical carrier veth and samples RSS every 10 ms.

```sh
sudo tests/bench-mux-matrix.py \
  --baseline /path/to/baseline/nowhere \
  --current target/release/nowhere \
  --output mux-matrix.json
```

The fixed matrix is RTT 0/30/100/200/300 ms by 1/4/16 flows, with three serial
samples per cell and median comparison. One-flow payloads are 64 MiB except
32 MiB at 300 ms; four flows total 64 MiB and sixteen flows total 128 MiB.
Throughput may not regress by more than 3%. Per-process peak RSS may not rise by
more than the larger of 5% or 2 MiB. The runner also records non-gating 0.1%
loss observations at 100 ms/1 flow and 300 ms/16 flows.

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

In these historical proxy samples, the larger profile removes the dominant high-RTT collapse. Four Shards improve
aggregate 16-flow throughput by about 2.5 times at both measured RTTs, while
raising peak RSS substantially. That implementation adapted target density to
TLS setup latency and live carrier pressure, and caps the directional pool at
four. A single flow remains on one Shard.

At 300 ms, a 16 MiB stream window has a theoretical ceiling near 447 Mbps. The
measured 288.04 Mbps is about 64% of that ceiling, leaving room to improve credit
return timing, writer batching, allocation reuse, and TLS scheduling before
increasing the profile budgets.

## 2026-09-08 adaptive pass

These historical results used the former 8-byte STREAM/WINDOW development
format and the 1/8-window credit-return threshold. A 1/16 threshold did not
improve throughput and would
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

That historical adaptive policy kept 16 simultaneous low-RTT flows on one carrier, while
100 and 300 ms samples expand to four. The high-RTT aggregate results match or
slightly exceed the fixed-four baseline within normal local-run variation, so
these observations motivated the former four-carrier cap. They do not validate
the current eight-carrier pool or prove an optimal pool size.

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

## Current Nowhere 2 frame boundary

The current Mux header remains 8 bytes but uses separate OPEN, DATA, WINDOW,
and CLOSE kinds. It is wire-incompatible with every earlier development Mux
format. Historical results above remain useful as performance baselines; they
do not demonstrate current wire interoperability.

## 2026-09-08 nw2 frame smoke comparison

The macOS Toxiproxy runner compared the saved `cc64358` binary with the
OPEN/DATA/WINDOW/CLOSE implementation. Each cell is the median of three serial
runs using the throughput profile.

| Implementation | RTT | Flows | Payload | Throughput | Portal peak RSS | Vector peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| `cc64358` | 100 ms | 1 | 64 MiB | 900.17 Mbps | 21.53 MiB | 9.78 MiB |
| nw2 frames | 100 ms | 1 | 64 MiB | 918.02 Mbps | 22.16 MiB | 9.98 MiB |
| `cc64358` | 300 ms | 16 | 128 MiB | 1.690 Gbps | 69.77 MiB | 13.11 MiB |
| nw2 frames | 300 ms | 16 | 128 MiB | 1.689 Gbps | 69.20 MiB | 12.61 MiB |

Both smoke cells satisfy the 3% throughput and RSS thresholds. These results
exercise the real binaries and carrier topology, but Toxiproxy's TCP
termination means the Linux netem matrix remains the gating measurement.

## 2026-09-08 eight-carrier pool and stream admission

The current implementation shares at most eight connecting/established TLS
slots per session across directions. Idle carriers are reused before creating
more. At capacity, placement uses credit/queue occupancy, then live plus pending
streams. Connecting slots accept reservations and share one initializer, so a
cold burst is balanced before handshakes finish. There is no fixed Mux stream
count limit, setup-latency density rule, or scheduling timer. Application session
admission limits remain separate.

Each stream may have one queued/in-progress DATA frame. Receive queues rely on
byte credit rather than a per-stream packet count, removing the slow-small-packet
reader stall. No wire fields were added. The 30-second fully idle timeout remains.

The saved pre-change release is `cc5623a` (`/tmp/nowhere-mux-before-pool8`). Both
implementations used `NOW_TRANSPORT_MEMORY_PROFILE=throughput`. No builds or tests
ran concurrently with the samples below.

| Measurement | Implementation | TLS carriers | Throughput | Portal peak RSS | Vector peak RSS |
|---|---|---:|---:|---:|---:|
| Toxiproxy 300 ms, 16 flows, 128 MiB; median of 3 | Before | 4 | 1.668 Gbps | 75.56 MiB | 18.33 MiB |
| Toxiproxy 300 ms, 16 flows, 128 MiB; median of 3 | Current | 8 | 2.833 Gbps | 12.73 MiB | 10.66 MiB |
| Direct loopback, 16 flows, 24 GiB; one sample | Before | 1 | 13.086 Gbps | 26.61 MiB | 10.45 MiB |
| Direct loopback, 16 flows, 24 GiB; one sample | Current | 8 | 11.224 Gbps | 13.23 MiB | 12.78 MiB |

The final delayed samples were 2833.47, 2836.52, and 2766.98 Mbps; baseline samples
were 1667.70, 1668.21, and 1662.83 Mbps. The delayed median improves 69.9%, while
the loopback point regresses 14.2%. Loopback transfers took 15.755 and 18.367
seconds respectively. The fixed eight-slot policy therefore favors delayed
parallel transfers, not universal throughput improvement. This is not a completed
no-regression acceptance; the Linux netem matrix is still outstanding.

```sh
tests/bench-mux-local.sh 300 16 8 1 target/release/nowhere
python3 tests/mux-bench-local.py --direct --rtt-ms 0 \
  --flows 16 --mib-per-flow 1536 --binary target/release/nowhere
```

Rejected experiments:

- Pressure-only background expansion left the initial 16-flow burst on one
  carrier and reached only 671.63 Mbps at the same proxy delay.
- Expanding without reservations for connecting carriers produced a 1094.90 Mbps
  outlier among otherwise roughly 2.9 Gbps samples. Connecting-slot reservations
  remove that first-completed-carrier placement bias.
- Allowing four queued DATA frames per flow gave only 11.368 Gbps in the loopback
  point, with Portal/Vector RSS increasing to 14.89/15.38 MiB. The one-frame bound
  was retained.

A longer 300 ms proxy attempt (16 x 256 MiB) failed on the saved baseline with
early EOF and timeouts, so no sustained delayed comparison was obtained. This
does not establish whether the baseline or proxy path caused the failure. Short
proxy samples cannot substitute for packet-level loss/RTT testing.
