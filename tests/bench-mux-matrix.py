#!/usr/bin/env python3
"""Run the fixed RTT/flow matrix and enforce throughput/RSS regression limits."""

import argparse
import json
import statistics
import subprocess
from pathlib import Path


RTTS = (0, 30, 100, 200, 300)
FLOWS = (1, 4, 16)


def mib_per_flow(rtt, flows):
    if flows == 1:
        return 32 if rtt == 300 else 64
    if flows == 4:
        return 16
    return 8


def sample(script, binary, rtt, flows, loss=0):
    output = subprocess.check_output(
        [
            str(script),
            str(rtt),
            str(flows),
            str(mib_per_flow(rtt, flows)),
            "1",
            str(binary),
            str(loss),
        ],
        text=True,
    )
    return json.loads(output)


def median_sample(samples):
    keys = ("mbps", "portal_peak_rss_mib", "vector_peak_rss_mib")
    result = {key: statistics.median(item[key] for item in samples) for key in keys}
    result["samples"] = samples
    return result


def run_matrix(script, binary, repeats):
    return {
        f"{rtt}ms/{flows}": median_sample(
            [sample(script, binary, rtt, flows) for _ in range(repeats)]
        )
        for rtt in RTTS
        for flows in FLOWS
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output")
    parser.add_argument("--skip-loss-observation", action="store_true")
    args = parser.parse_args()
    if args.repeats < 3:
        parser.error("--repeats must be at least 3")
    script = Path(__file__).with_name("bench-mux-netem.sh").resolve()
    baseline = run_matrix(script, Path(args.baseline).resolve(), args.repeats)
    current = run_matrix(script, Path(args.current).resolve(), args.repeats)
    failures = []
    for cell, before in baseline.items():
        after = current[cell]
        if after["mbps"] < before["mbps"] * 0.97:
            failures.append(
                f"{cell}: throughput {after['mbps']:.2f} < 97% of {before['mbps']:.2f}"
            )
        for process in ("portal", "vector"):
            key = f"{process}_peak_rss_mib"
            limit = before[key] + max(before[key] * 0.05, 2.0)
            if after[key] > limit:
                failures.append(
                    f"{cell}: {process} RSS {after[key]:.2f} MiB > {limit:.2f} MiB"
                )
    loss = {}
    if not args.skip_loss_observation:
        for rtt, flows in ((100, 1), (300, 16)):
            cell = f"{rtt}ms/{flows}"
            loss[cell] = median_sample(
                [sample(script, Path(args.current).resolve(), rtt, flows, 0.1)
                 for _ in range(args.repeats)]
            )
    report = {
        "baseline": baseline,
        "current": current,
        "loss_0_1_percent_observation": loss,
        "failures": failures,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
