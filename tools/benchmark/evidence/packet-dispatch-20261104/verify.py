"""Verify retained bytes and independently recompute the final paired comparison.

Uses only Python's standard library. Does not build, execute probes, or resample.
"""
from pathlib import Path
import hashlib
import json
import math
import statistics
import zipfile
import sys
VARIANT = sys.argv[1] if len(sys.argv) > 1 else "integrated"
assert VARIANT in ("staging", "integrated")

ROOT = Path(__file__).resolve().parent


def interval(ratios):
    logs = [math.log(value) for value in ratios]
    mean = statistics.mean(logs)
    return {
        "ratio": math.exp(mean),
        "upper95": math.exp(mean + 2.3533634348 * statistics.stdev(logs) / 2),
    }


def close(actual, expected):
    for key in ("ratio", "upper95"):
        assert math.isclose(actual[key], expected[key], rel_tol=1e-12)


with zipfile.ZipFile(ROOT / "observations.zip") as archive:
    hashes = json.loads((ROOT / "observation-sha256.json").read_text())
    assert set(archive.namelist()) == set(hashes)
    for name, digest in hashes.items():
        assert hashlib.sha256(archive.read(name)).hexdigest() == digest, name

    def read(name):
        return json.loads(archive.read(VARIANT + "/" + name))

    method = read("METHOD.json")
    result = read("measurement.json")
    assert method == json.loads((ROOT / (VARIANT + "-METHOD.json")).read_text())
    assert result == json.loads((ROOT / (VARIANT + "-measurement.json")).read_text())
    cells = method["cells"]
    assert len(cells) == 28 and len({tuple(c) for c in cells}) == 28
    assert len(result["rows"]) == 112
    rows = []
    for cell in cells:
        kind, profile, security, mode, size = cell
        label = "-".join(map(str, cell))
        qualifier = [read(f"qualify-{arm}-{label}.json") for arm in "AB"]
        for key in ("server_capacities", "client_capacities", "memory", "routes",
                    "calls", "deferred", "security_requests", "associations",
                    "app_inline_bytes"):
            if key in qualifier[0]:
                assert qualifier[0][key] == qualifier[1][key], (cell, key)
        count = 8192 if size in (32, 1024) else 1024
        for pair in range(4):
            means = {}
            for arm in "AB":
                sample = read(f"measure-{pair}-{label}-{arm}.json")
                assert sample["operations"] == count
                assert sample["security"] == security
                assert sample["payload_bytes"] == size
                if kind == "retained":
                    assert sample["mode"] == mode and sample["storage"] == profile
                    assert sample["verified"] == count + 128
                    assert sample["requests_per_operation"] == 2
                    assert sample["data_packets_per_operation"] == 11
                    values = sample["cycles"]
                elif profile == "small-device":
                    assert sample["black_box"] and sample["dedup"] == 4
                    values = sample["latencies_cycles"]
                else:
                    assert sample["black_box"] and sample["verified"] == count + 128
                    assert sample["server_poll_counts"] == [(size + 1023) // 1024] * count
                    values = sample["server_poll_cpu_cycles_sum"]
                assert len(values) == count and all(type(v) is int and v > 0 for v in values)
                means[arm] = statistics.mean(values)
            row = {"pair": pair, "cell": cell, "means": means,
                   "ratio": means["B"] / means["A"]}
            original = next(r for r in result["rows"] if r["pair"] == pair and r["cell"] == cell)
            assert row == original
            rows.append(row)
    failed = []
    for cell in cells:
        value = interval([r["ratio"] for r in rows if r["cell"] == cell])
        close(value, next(r for r in result["summary"] if r["cell"] == cell))
        if value["ratio"] > 1.02:
            failed.append(cell)
    groups = {}
    for kind in ("ordinary", "retained", "all"):
        for mode in ("sync", "async", "all"):
            paired = []
            for pair in range(4):
                chosen = [r["ratio"] for r in rows if r["pair"] == pair
                          and (kind == "all" or r["cell"][0] == kind)
                          and (mode == "all" or r["cell"][3] == mode)]
                paired.append(math.exp(statistics.mean(map(math.log, chosen))))
            key = kind + "-" + mode
            groups[key] = interval(paired)
            close(groups[key], result["groups"][key])
    accepted = not failed and all(groups[k + "-" + m]["upper95"] < 1
                                 for k in ("ordinary", "all") for m in ("sync", "async"))
    assert accepted == result["runtime_accepted"]
    assert failed == [r["cell"] for r in result["failed_point_guards"]]
    assert accepted == (VARIANT == "integrated")

for name, digest in json.loads((ROOT / "fixture-sha256.json").read_text()).items():
    assert hashlib.sha256((ROOT.parent / "dispatch-scratch-20261104/fixture" / name).read_bytes()).hexdigest() == digest
print(json.dumps({"verified_observation_files": len(hashes), "cells": len(cells),
                  "timing_processes": len(rows) * 2, "runtime_accepted": accepted,
                  "groups": groups}, indent=2))
