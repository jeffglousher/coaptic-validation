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
VARIANT = "integrated"

ROOT = Path(__file__).resolve().parent


def interval(ratios):
    logs = [math.log(value) for value in ratios]
    mean = statistics.mean(logs)
    return {
        "ratio": math.exp(mean),
        "upper95": math.exp(mean + 1.7530503557 * statistics.stdev(logs) / 4),
    }


def close(actual, expected):
    for key in ("ratio", "upper95"):
        assert math.isclose(actual[key], expected[key], rel_tol=1e-12)


sources = json.loads((ROOT / "source-verification.json").read_text(encoding="utf-8"))
for name, digest in sources["patch_sha256"].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name

with zipfile.ZipFile(ROOT / "observations.zip") as archive:
    hashes = json.loads((ROOT / "observation-sha256.json").read_text())
    assert set(archive.namelist()) == set(hashes)
    for name, digest in hashes.items():
        assert hashlib.sha256(archive.read(name)).hexdigest() == digest, name

    def read(name):
        return json.loads(archive.read(VARIANT + "/" + name))

    method = read("METHOD.json")
    result = read("measurement.json")
    assert method == json.loads((ROOT / "METHOD.json").read_text())
    assert result == json.loads((ROOT / "measurement.json").read_text())
    cells = method["cells"]
    assert len(cells) == 28 and len({tuple(c) for c in cells}) == 28
    assert len(result["rows"]) == 448
    rows = []
    for cell in cells:
        kind, profile, security, mode, size = cell
        label = "-".join(map(str, cell))
        qualifier = [read(f"qualify-{arm}-{label}.json") for arm in "AB"]
        for key in ("server_capacities", "client_capacities", "routes",
                    "calls", "deferred", "security_requests", "associations",
                    "rx_slots", "rx_datagram_bytes", "tx_slots", "tx_datagram_bytes",
                    "dedup", "observe", "rx_body_slots", "tx_body_slots", "blockwise"):
            if key in qualifier[0]:
                assert qualifier[0][key] == qualifier[1][key], (cell, key)
        a, b = qualifier
        if kind == "ordinary":
            expected = dict(a["memory"])
            if profile == "small-device":
                expected["app_including_transport_inline_bytes"] -= 64
            else:
                field = ("server_app_including_transport_inline_bytes" if profile == "service-fixed"
                         else "server_pool_requested_heap_bytes")
                expected[field] -= 1024
                expected["client_pool_requested_heap_bytes"] -= 128
            assert b["memory"] == expected, (cell, "memory")
        else:
            assert b["app_inline_bytes"] == a["app_inline_bytes"] - (256 if profile == "fixed" else 0)
        count = 8192 if size in (32, 1024) else 1024
        for pair in range(16):
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
        if value["upper95"] > 1.02:
            failed.append(cell)
    groups = {}
    for kind in ("ordinary", "retained", "all"):
        for mode in ("sync", "async", "all"):
            paired = []
            for pair in range(16):
                chosen = [r["ratio"] for r in rows if r["pair"] == pair
                          and (kind == "all" or r["cell"][0] == kind)
                          and (mode == "all" or r["cell"][3] == mode)]
                paired.append(math.exp(statistics.mean(map(math.log, chosen))))
            key = kind + "-" + mode
            groups[key] = interval(paired)
            close(groups[key], result["groups"][key])
    accepted = not failed and all(groups[k + "-" + m]["upper95"] <= 1.02
                                 for k in ("ordinary", "all") for m in ("sync", "async"))
    assert accepted == result["runtime_accepted"]
    assert failed == [r["cell"] for r in result["failed_point_guards"]]
    assert not accepted, "Every retained candidate failed its frozen runtime gates"

for name, digest in json.loads((ROOT / "fixture-sha256.json").read_text()).items():
    assert hashlib.sha256((ROOT.parent / "dispatch-scratch-20261104/fixture" / name).read_bytes()).hexdigest() == digest

# Reuse the pinned baseline diagnostic; never infer peak stack from a future.
memory = json.loads((ROOT / "memory-comparison.json").read_text())
with zipfile.ZipFile(ROOT / memory["baseline_layout_archive"]) as archive:
    baseline_layout = archive.read(memory["baseline_layout_member"])
with zipfile.ZipFile(ROOT / "observations.zip") as archive:
    candidate_layout = archive.read("integrated/owner-layout.txt")
    assert json.loads(archive.read("integrated/owners.json")) == json.loads((ROOT / "owners.json").read_text())
    for owner, profile, size, field in (
        ("SmallDevice App", "small-device", 32, "app_including_transport_inline_bytes"),
        ("Service fixed App", "service-fixed", 1024, "server_app_including_transport_inline_bytes"),
        ("Service allocated App", "service-allocated", 1024, "server_app_including_transport_inline_bytes"),
        ("Service allocated pool heap", "service-allocated", 1024, "server_pool_requested_heap_bytes"),
    ):
        row = next(row for row in memory["rows"] if row["owner"] == owner)
        for arm, side in (("A", "baseline"), ("B", "candidate")):
            qualifier = json.loads(archive.read(
                f"integrated/qualify-{arm}-ordinary-{profile}-unprotected-sync-{size}.json"))
            assert row[side] == qualifier["memory"][field], (owner, side)
assert hashlib.sha256(baseline_layout).hexdigest() == memory["baseline_layout_sha256"]
assert hashlib.sha256(candidate_layout).hexdigest() == memory["candidate_layout_sha256"]
for record in memory["layout_records"]:
    baseline = "baseline-future-layout.txt" in record["file"]
    data = baseline_layout if baseline else candidate_layout
    assert record["record"] in data.decode("utf-8")
    row = next(row for row in memory["rows"] if row["owner"] == record["owner"])
    assert f": {row['baseline' if baseline else 'candidate']} bytes, alignment:" in record["record"]
assert all(row["candidate"] <= row["baseline"] for row in memory["rows"])
assert memory["baseline_layout_complete"] is False
assert memory["candidate_layout_complete"] is True
print(json.dumps({"verified_observation_files": len(hashes), "cells": len(cells),
                  "timing_processes": len(rows) * 2, "runtime_accepted": accepted,
                  "groups": groups}, indent=2))
