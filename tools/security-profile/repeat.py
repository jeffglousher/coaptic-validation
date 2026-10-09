"""Repeat validated socket-free work probes; preserve every sample and failure."""

import argparse
import hashlib
import json
import math
import random
import platform
import statistics
import subprocess
from pathlib import Path

PHASES = {
    "plain_response_encode",
    "request_protect",
    "request_open",
    "response_protect",
    "response_open",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--operations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20261007)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.runs <= 100 or not 1 <= args.operations <= 60000:
        parser.error("runs must be 1..100; operations must be 1..60000")
    binaries = {"baseline": args.baseline.resolve()}
    if args.candidate:
        binaries["candidate"] = args.candidate.resolve()
    rng = random.Random(args.seed)
    cells = []
    for repetition in range(args.runs):
        cases = [64, 1024]
        rng.shuffle(cases)
        for size in cases:
            variants = list(binaries)
            if repetition % 2:
                variants.reverse()
            for variant in variants:
                cell = {"repetition": repetition, "body_bytes": size, "variant": variant}
                try:
                    result = subprocess.run(
                        [str(binaries[variant]), str(size), str(args.operations)],
                        capture_output=True, text=True, timeout=30, check=True,
                    )
                    rows = [json.loads(line) for line in result.stdout.splitlines()]
                    if len(rows) != len(PHASES) or {row["phase"] for row in rows} != PHASES:
                        raise ValueError("incomplete or duplicate phases")
                    for row in rows:
                        samples = row["latencies_ns"]
                        if (
                            row["schema"] != "coaptic-security-work/1"
                            or row["body_bytes"] != size
                            or row["operations"] != args.operations
                            or len(samples) != args.operations
                            or any(type(value) is not int or value < 0 for value in samples)
                        ):
                            raise ValueError("invalid sample metadata")
                    cell["rows"] = rows
                except (subprocess.SubprocessError, ValueError, KeyError, OSError) as error:
                    cell["error"] = str(error)
                    cell["stderr"] = str(getattr(error, "stderr", ""))[-4096:]
                cells.append(cell)
    summary = []
    for variant in binaries:
        for size in (64, 1024):
            matching = [cell for cell in cells if cell["variant"] == variant and cell["body_bytes"] == size]
            for phase in sorted(PHASES):
                runs = [
                    next(row["latencies_ns"] for row in cell["rows"] if row["phase"] == phase)
                    for cell in matching if "rows" in cell
                ]
                samples = sorted(value for run in runs for value in run)
                if not samples:
                    continue
                summary.append({
                    "variant": variant, "body_bytes": size, "phase": phase,
                    "valid_runs": len(runs), "expected_runs": args.runs,
                    "comparison_eligible": all(
                        sum("rows" in cell and cell["body_bytes"] == size and cell["variant"] == name for cell in cells) == args.runs
                        for name in binaries
                    ),
                    "mean_ns": statistics.mean(statistics.mean(run) for run in runs),
                    "p99_ns": samples[math.ceil(len(samples) * .99) - 1],
                    "min_ns": samples[0], "max_ns": samples[-1],
                    "run_means_ns": [statistics.mean(run) for run in runs],
                })
    report = {
        "schema": "coaptic-security-work-repetitions/1",
        "scope": "socket-free phases; not CPU utilization or end-to-end throughput",
        "seed": args.seed, "runs": args.runs, "operations": args.operations,
        "binaries": {key: str(value) for key, value in binaries.items()},
        "binary_sha256": {key: hashlib.sha256(value.read_bytes()).hexdigest() for key, value in binaries.items()},
        "platform": platform.platform(),
        "cells": cells, "summary": summary,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, separators=(",", ":")), encoding="utf-8")
    print(json.dumps({"summary": summary, "failures": sum("error" in cell for cell in cells)}))
    return int(any("error" in cell for cell in cells))


if __name__ == "__main__":
    raise SystemExit(main())
