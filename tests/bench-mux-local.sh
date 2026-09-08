#!/bin/sh
# Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
# SPDX-License-Identifier: GPL-3.0-only

set -eu

rtt_ms=${1:-100}
flows=${2:-1}
mib_per_flow=${3:-64}
mux=${4:-1}
binary=${5:-target/release/nowhere}
container_name=nowhere-toxiproxy

# A timed-out high-rate sample can leave Toxiproxy links draining long after
# both Nowhere processes exit. Use a fresh proxy process so the next sample is
# independent instead of blocking while the old proxy is reconfigured.
container delete -f "$container_name" >/dev/null 2>&1 || true
while container list | awk 'NR > 1 { print $1 }' | grep -Fqx "$container_name"; do
    sleep 0.1
done
container run --rm -d --name "$container_name" \
    ghcr.io/shopify/toxiproxy:2.12.0 >/dev/null

proxy_ip=$(container list | awk -v name="$container_name" '
    NR == 1 {
        for (column = 1; column <= NF; column++) {
            if ($column == "IP") ip_column = column
        }
        next
    }
    $1 == name && ip_column != 0 {
        value = $ip_column
        sub("/24", "", value)
        print value
    }
')
if [ -z "$proxy_ip" ]; then
    echo "failed to discover Toxiproxy address" >&2
    exit 1
fi

if container exec "$container_name" /toxiproxy-cli list | grep -q '^nowhere'; then
    container exec "$container_name" /toxiproxy-cli delete nowhere >/dev/null
fi
container exec "$container_name" /toxiproxy-cli create \
    -l 0.0.0.0:2001 -u 192.168.64.1:2000 nowhere >/dev/null

one_way_ms=$((rtt_ms / 2))
container exec "$container_name" /toxiproxy-cli toxic add \
    -n latency_upstream -t latency -a "latency=$one_way_ms" -u nowhere >/dev/null
container exec "$container_name" /toxiproxy-cli toxic add \
    -n latency_downstream -t latency -a "latency=$one_way_ms" -d nowhere >/dev/null

python3 tests/mux-bench-local.py \
    --binary "$binary" \
    --rtt-ms "$rtt_ms" \
    --flows "$flows" \
    --mib-per-flow "$mib_per_flow" \
    --mux "$mux" \
    --proxy-host "$proxy_ip" \
    --external-proxy
