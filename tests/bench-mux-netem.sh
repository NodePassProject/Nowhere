#!/bin/sh
# Packet-level RTT/loss and RSS benchmark for a Linux host with iproute2.
set -eu

rtt_ms=${1:-100}
flows=${2:-1}
mib_per_flow=${3:-64}
mux=${4:-1}
binary=${5:-target/release/nowhere}
loss=${6:-0}

[ "$(uname -s)" = Linux ] || { echo "Linux is required" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "root is required for network namespaces" >&2; exit 2; }
command -v ip >/dev/null
command -v tc >/dev/null

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(realpath "$binary")
worker="$root/tests/mux-bench-worker.py"
suffix=$$
portal_ns=nwp-$suffix
vector_ns=nwv-$suffix
portal_pid=
vector_pid=
target_pid=

cleanup() {
    [ -z "$vector_pid" ] || kill "$vector_pid" 2>/dev/null || true
    [ -z "$portal_pid" ] || kill "$portal_pid" 2>/dev/null || true
    [ -z "$target_pid" ] || kill "$target_pid" 2>/dev/null || true
    ip netns delete "$vector_ns" 2>/dev/null || true
    ip netns delete "$portal_ns" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip netns add "$portal_ns"
ip netns add "$vector_ns"
ip link add nwpv-$suffix type veth peer name nwvp-$suffix
ip link set nwpv-$suffix netns "$portal_ns"
ip link set nwvp-$suffix netns "$vector_ns"
ip -n "$portal_ns" addr add 10.203.0.1/30 dev nwpv-$suffix
ip -n "$vector_ns" addr add 10.203.0.2/30 dev nwvp-$suffix
ip -n "$portal_ns" link set lo up
ip -n "$vector_ns" link set lo up
ip -n "$portal_ns" link set nwpv-$suffix up
ip -n "$vector_ns" link set nwvp-$suffix up

one_way=$(awk -v rtt="$rtt_ms" 'BEGIN { printf "%.3f", rtt / 2 }')
ip netns exec "$portal_ns" tc qdisc add dev nwpv-$suffix root netem delay "${one_way}ms" loss "${loss}%"
ip netns exec "$vector_ns" tc qdisc add dev nwvp-$suffix root netem delay "${one_way}ms" loss "${loss}%"

ip netns exec "$portal_ns" python3 "$worker" target --port 19000 &
target_pid=$!
ip netns exec "$portal_ns" env NOW_TRANSPORT_MEMORY_PROFILE=throughput "$binary" 'portal://secret@10.203.0.1/tcp:2000?log=none' &
portal_pid=$!
ip netns exec "$portal_ns" python3 "$worker" wait --port 2000 --host 10.203.0.1

ip netns exec "$vector_ns" env NOW_TRANSPORT_MEMORY_PROFILE=throughput "$binary" "vector://secret@10.203.0.1/tcp:2000?mux=$mux&socks=127.0.0.1:1080&log=none" &
vector_pid=$!
ip netns exec "$vector_ns" python3 "$worker" wait --port 1080

bytes=$((mib_per_flow * 1024 * 1024))
result=$(ip netns exec "$vector_ns" python3 "$worker" client --flows "$flows" --bytes "$bytes" --socks-port 1080 --target-port 19000 --portal-pid "$portal_pid" --vector-pid "$vector_pid")
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d.update(rtt_ms=float(sys.argv[2]), loss_percent=float(sys.argv[3]), mux=int(sys.argv[4])); print(json.dumps(d, sort_keys=True))' "$result" "$rtt_ms" "$loss" "$mux"
