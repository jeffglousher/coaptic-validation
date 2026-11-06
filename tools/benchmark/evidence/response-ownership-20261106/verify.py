"""Verify preserved failures with the standard library; never execute probes."""
from pathlib import Path
import hashlib
import json
import math
import re
import statistics
import zipfile
from prepare import adapt_fixture, fixture_inputs

ROOT = Path(__file__).resolve().parent
BASELINE = "fd7d18a72f795779e352443ebdeef9533be7fb27"
PINS = {
    "borrowed-handler": "04c1c8377cdd2896de91310c81714eb10865eaba",
    "unified-reply": "3a1e6004444beadd984d7f6e9c5c7573ce077ddb",
    "response-metadata": "6ad0bfd2eb7347cf6d2399ccf5cba47a0df9024f",
}
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
digest = lambda data: hashlib.sha256(data).hexdigest()


def interval(values):
    logs = list(map(math.log, values))
    mean = statistics.mean(logs)
    return {"ratio": math.exp(mean),
            "upper95": math.exp(mean + 1.67 * statistics.stdev(logs) / 8)}


def close(actual, expected):
    assert all(math.isclose(actual[k], expected[k], rel_tol=1e-12)
               for k in ("ratio", "upper95"))


def ledger(a, b):
    for key in ("server_capacities", "client_capacities", "routes", "calls",
                "deferred", "security_requests", "associations", "rx_slots",
                "rx_datagram_bytes", "tx_slots", "tx_datagram_bytes", "dedup",
                "observe", "rx_body_slots", "tx_body_slots", "blockwise"):
        if key in a:
            assert a[key] == b[key], key
    if "memory" in a:
        # These candidates do not change the recorded resident owners.
        assert a["memory"] == b["memory"]
    if "app_inline_bytes" in a:
        assert a["app_inline_bytes"] == b["app_inline_bytes"]


def dispatch_frames(text):
    rows = {}
    for block in re.split(r"(?=^\d+ \| S_LPROC32)", text, flags=re.M):
        if "dispatch_rx_io_async::async_fn$0" not in block:
            continue
        header = block.splitlines()[0]
        profile = ("SmallDevice" if "profiles::Constrained" in header else
                   "Service" if "profiles::Service" in header else "Default")
        storage = "allocated" if "async_fn$0<coaptic::storage::alloc_memory::AllocMemory" in header else "fixed"
        code = int(re.search(r"code size = (\d+)", block)[1])
        frame = int(re.search(r"size = (\d+), padding size", block)[1])
        rows[profile, storage] = (frame, code)
    assert len(rows) == 4
    return rows


archives = read(ROOT / "archives.json")
total = 0
for variant, pin in PINS.items():
    path = ROOT / (variant + ".zip")
    assert digest(path.read_bytes()) == archives[variant]["archive_sha256"]
    with zipfile.ZipFile(path) as z:
        hashes = read(ROOT / (variant + "-sha256.json"))
        assert len(z.namelist()) == len(set(z.namelist())) == len(hashes)
        assert set(z.namelist()) == set(hashes)
        assert len(hashes) == archives[variant]["members"]
        assert sum(i.file_size for i in z.infolist()) == archives[variant]["uncompressed_bytes"]
        for name, value in hashes.items():
            assert digest(z.read(name)) == value, (variant, name)
            assert Path(name).name not in {"OWNER.json", "start-notice.json", "rejection-notice.json", "timing-resource-status.json"}
        total += len(hashes)
        for name in ("candidate.patch", "source-verification.json", "METHOD-BEFORE.json", "result.json"):
            assert z.read(name) == (ROOT / (variant + "-" + name)).read_bytes()
        source = json.loads(z.read("source-verification.json"))
        assert source["source"] == pin and source["baseline"] == BASELINE
        assert digest(z.read("candidate.patch")) == source["patch_sha256"]
        before = json.loads(z.read("METHOD-BEFORE.json"))
        assert before["candidate"] == pin and before["baseline"] == BASELINE
        if variant != "borrowed-handler":
            assert not any(n.startswith(("measure-", "qualify-")) for n in z.namelist())
            assert "measurement.json" not in z.namelist()
            decision = json.loads(z.read("result.json"))
            assert decision["candidate"] == pin and decision["no_runtime_cohort"]
            preflight = json.loads(z.read("dispatch-preflight.json"))
            assert not preflight["nongrowth"]
            frames = dispatch_frames(z.read("dispatch-symbols.txt").decode())
            assert any(r["frame_bytes"] > r["baseline_frame_bytes"] for r in preflight["rows"])
            for row in preflight["rows"]:
                assert frames[row["profile"], row["storage"]] == (row["frame_bytes"], row["code_bytes"])

with zipfile.ZipFile(ROOT / "borrowed-handler.zip") as z:
    get = lambda name: json.loads(z.read(name))
    method, result = get("METHOD.json"), get("measurement.json")
    assert method["baseline"] == BASELINE and method["candidate"] == PINS["borrowed-handler"]
    cells = [["ordinary", p, s, m, n] for p in ("small-device", "service-fixed", "service-allocated")
             for s in ("unprotected", "oscore") for m in ("sync", "async")
             for n in ([32] if p == "small-device" else [1024, 16384])]
    cells += [["retained", p, s, m, 11264] for p in ("fixed", "allocated")
              for s in ("unprotected", "oscore") for m in ("sync", "async")]
    assert method["cells"] == cells and method["process_pairs"] == 64
    assert method["orders"] == ["AB", "BA", "BA", "AB"] * 16
    assert result["status"] == "complete" and len(result["rows"]) == 1792
    rows, expected_labels = [], []
    for cell in cells:
        label = "-".join(map(str, cell))
        ledger(get("qualify-A-" + label + ".json"), get("qualify-B-" + label + ".json"))
        expected_labels += ["qualify-" + arm + "-" + label for arm in "AB"]
    for pair, order in enumerate(method["orders"]):
        for cell in cells:
            kind, profile, security, mode, size = cell
            label = "-".join(map(str, cell))
            count = 8192 if size in (32, 1024) else 1024
            samples, means = {}, {}
            for arm in order:
                name = f"measure-{pair}-{label}-{arm}"
                expected_labels.append(name)
                sample = get(name + ".json")
                assert sample["operations"] == count and sample["warmup"] == 128
                assert sample["security"] == security and sample["payload_bytes"] == size
                assert sample["verified"] == count + 128
                if kind == "retained":
                    assert sample["mode"] == mode and sample["storage"] == profile
                    assert sample["requests_per_operation"] == 2 and sample["data_packets_per_operation"] == 11
                    values = sample["cycles"]
                elif profile == "small-device":
                    assert sample["black_box"] and sample["dedup"] == 4
                    values = sample["latencies_cycles"]
                else:
                    assert sample["black_box"] and sample["expiry_probe"] == "steady"
                    assert sample["server_poll_counts"] == [(size + 1023) // 1024] * count
                    values = sample["server_poll_cpu_cycles_sum"]
                assert len(values) == count and all(type(x) is int and x > 0 for x in values)
                means[arm], samples[arm] = statistics.mean(values), sample
            ledger(samples["A"], samples["B"])
            rows.append({"pair": pair, "cell": cell, "means": means, "ratio": means["B"] / means["A"]})
    assert rows == result["rows"]
    failures = []
    for cell in cells:
        value = interval([row["ratio"] for row in rows if row["cell"] == cell])
        close(value, next(row for row in result["summary"] if row["cell"] == cell))
        if value["upper95"] > 1.02:
            failures.append(cell)
    groups = {}
    for kind in ("ordinary", "retained", "all"):
        for mode in ("sync", "async", "all"):
            paired = [math.exp(statistics.mean(math.log(row["ratio"]) for row in rows
                      if row["pair"] == pair and (kind == "all" or row["cell"][0] == kind)
                      and (mode == "all" or row["cell"][3] == mode))) for pair in range(64)]
            groups[kind + "-" + mode] = interval(paired)
            close(groups[kind + "-" + mode], result["groups"][kind + "-" + mode])
    accepted = not failures and all(groups[k + "-" + m]["upper95"] <= 1.02
                                   for k in ("ordinary", "all") for m in ("sync", "async"))
    assert accepted == result["runtime_accepted"] == False
    assert failures == [row["cell"] for row in result["failed_point_guards"]]
    assert len(failures) == 17
    events = [json.loads(line) for line in z.read("process-exits.jsonl").decode().splitlines()]
    assert [event["label"] for event in events] == expected_labels
    assert len(events) == len(set(expected_labels)) == 3640
    for event in events:
        assert event["exit_code"] == 0
        assert event["stdout_bytes"] == len(z.read(event["label"] + ".json"))
    baseline_frames = dispatch_frames(z.read("A-dispatch-symbols.txt").decode())
    for kind, name in (("ordinary", "dispatch-probe.exe"), ("retained", "retained-probe.exe")):
        assert digest(z.read("B/" + name)) == method["binaries"]["B-" + kind]
        with zipfile.ZipFile(ROOT.parent / "phase-sharing-static-20261106/observations.zip") as baseline:
            assert digest(baseline.read("candidate/B/" + name)) == method["binaries"]["A-" + kind]

for variant in ("unified-reply", "response-metadata"):
    with zipfile.ZipFile(ROOT / (variant + ".zip")) as z:
        for row in json.loads(z.read("dispatch-preflight.json"))["rows"]:
            assert baseline_frames[row["profile"], row["storage"]] == (row["baseline_frame_bytes"], row["baseline_code_bytes"])

# Reconstruct fixture edits without writing files or invoking Git/native code.
original_fixture = fixture_inputs()
adapted_fixture = adapt_fixture(original_fixture)
with zipfile.ZipFile(ROOT / "borrowed-handler.zip") as z:
    for name in ("probe/retained.rs", "tools/benchmark/native/servers/src/bin/bench-core.rs"):
        assert z.read("fixture-original/" + name) == original_fixture[name]
    assert z.read("fixture-bound-adaptation.patch") == (ROOT / "fixture-bound-adaptation.patch").read_bytes()


def layouts(data):
    return {match[1]: int(match[2]) for match in re.finditer(
        r"^print-type-size type: `(.*)`: (\d+) bytes, alignment:", data.decode(), re.M)}


def future_sizes(records):
    prefix = "{async fn body of coaptic::app::async_server::<impl coaptic::App<"
    selected = {}
    for name, size in records.items():
        if not name.startswith(prefix) or "::progress_async<" not in name:
            continue
        if "profiles::Constrained, CoreIo, 4, false" in name:
            selected["SmallDevice"] = size
        elif "profiles::Service, ServiceIo, 32, true" in name:
            selected["Service allocated" if "::AllocMemory," in name else "Service fixed"] = size
    assert len(selected) == 3
    return selected


with zipfile.ZipFile(ROOT.parent / "phase-sharing-static-20261106/observations.zip") as z:
    baseline_layout = layouts(z.read("candidate/owner-layout.txt"))
with zipfile.ZipFile(ROOT.parent / "phase-sharing-static-20261106/layout32.zip") as z:
    baseline_layout32 = layouts(z.read("candidate-layout.txt"))
baseline_futures = future_sizes(baseline_layout)
assert baseline_futures == {"SmallDevice": 15952, "Service fixed": 15496, "Service allocated": 15496}
layout_summary = {}
for variant in PINS:
    with zipfile.ZipFile(ROOT / (variant + ".zip")) as z:
        current = layouts(z.read("owner-layout-2.txt"))
        futures = future_sizes(current)
        assert all(futures[key] < value for key, value in baseline_futures.items())
        common_apps = {name for name in current if name.startswith("coaptic::App<") and name in baseline_layout}
        assert len(common_apps) == 6
        assert all(current[name] == baseline_layout[name] for name in common_apps)
        target_b = layouts(z.read("layout32/candidate-layout.txt"))
        assert all(target_b[name] == size for name, size in baseline_layout32.items())
        layout_summary[variant] = {key: baseline_futures[key] - value for key, value in futures.items()}
        if variant == "response-metadata":
            assert all(delta == 120 for delta in layout_summary[variant].values())
            raw_log = z.read("lib-tests.log")
            text = raw_log.decode("utf-16" if raw_log.startswith(b"\xff\xfe") else "utf-8")
            assert "test result: ok. 1219 passed; 0 failed" in text

print(json.dumps({"archive_members": total, "cells": 28, "pairs_per_cell": 64,
                  "timing_outputs": 3584, "borrowed_runtime_accepted": accepted,
                  "failed_cells": len(failures), "groups": groups,
                  "future_reductions_bytes": layout_summary,
                  "untimed_rejections": ["unified-reply", "response-metadata"]}, indent=2))
