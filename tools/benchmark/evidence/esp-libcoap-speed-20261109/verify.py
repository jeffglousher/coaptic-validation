"""Recompute the completed evidence without benchmarks, binaries, network, or hardware."""
from pathlib import Path, PurePosixPath
from collections import Counter, defaultdict
import gzip
import hashlib
import json
import math
import statistics as st
import sys

ROOT = Path(__file__).resolve().parent
BUDGET = 64 * 1024 * 1024

def close(a, b):
    return math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-9)

def q(values, p):
    values = sorted(values)
    at = (len(values) - 1) * p
    lo, hi = math.floor(at), math.ceil(at)
    return values[lo] + (values[hi] - values[lo]) * (at - lo)

def interval(ratios):
    assert len(ratios) == 64
    logs = [math.log(x) for x in ratios]
    center = st.mean(logs)
    return {"ratio": math.exp(center), "upper95": math.exp(center + 1.67 * st.stdev(logs) / 8)}

def expected_cells():
    out = [["ordinary", p, s, m, n] for p in ["small-device", "service-fixed", "service-allocated"] for s in ["unprotected", "oscore"] for m in ["sync", "async"] for n in ([32] if p == "small-device" else [1024, 16384])]
    return out + [["retained", p, s, m, 11264] for p in ["fixed", "allocated"] for s in ["unprotected", "oscore"] for m in ["sync", "async"]]

def verify_cpu(value):
    method = value["method"]
    cells = expected_cells()
    assert method["cells"] == cells and method["orders"] == ["AB", "BA", "BA", "AB"] * 16 and method["process_pairs"] == 64 and method["cpu"] == 0
    records = value["records"]
    assert len(records) == 3640
    expected = []
    for cell in cells:
        for arm in ["A", "B"]:
            expected.append(("qualify-" + arm + "-" + "-".join(map(str, cell)), cell, arm, None, 8))
    for pair, order in enumerate(method["orders"]):
        for cell in cells:
            for arm in order:
                expected.append(("measure-" + str(pair) + "-" + "-".join(map(str, cell)) + "-" + arm, cell, arm, pair, 8192 if cell[-1] in [32, 1024] else 1024))
    qualified, pairs = {}, defaultdict(dict)
    total = 0
    for row, (label, cell, arm, pair, count) in zip(records, expected):
        assert (row["label"], row["cell"], row["arm"], row["pair"]) == (label, cell, arm, pair)
        assert row["exit_code"] == 0 and row["timeout"] is False
        assert row["cycles_count"] == row["scalars"]["operations"] == count
        assert type(row["cycles_sum"]) is int and 0 < row["cycles_min"] <= row["cycles_max"]
        assert row["cycles_min"] * count <= row["cycles_sum"] <= row["cycles_max"] * count
        assert len(row["raw_report_sha256"]) == 64 and all(c in "0123456789abcdef" for c in row["raw_report_sha256"])
        if cell[0] == "retained":
            assert row["counter_field"] == "cycles" and row["scalars"]["verified"] == count + 128
            assert row["scalars"]["requests_per_operation"] == 2 and row["scalars"]["data_packets_per_operation"] == 11
        elif cell[1] == "small-device":
            assert row["counter_field"] == "latencies_cycles" and row["scalars"]["black_box"] is True and row["scalars"]["dedup"] == 4
            assert 0 < row["scalars"]["populated_routes"] <= row["scalars"]["routes"]
        else:
            assert row["counter_field"] == "server_poll_cpu_cycles_sum" and row["scalars"]["verified"] == count + 128 and row["scalars"]["black_box"] is True
            assert row["capacities"]["server_capacities"]["dedup"] == 64
            sends = row["capacities"]["sends"]
            assert sends["combined"] == sends["client"] + sends["server"]
            assert sends["per_port_limit"] == 30000 and sends["combined_limit"] == 60000
            assert 0 < max(sends["client"], sends["server"]) <= sends["per_port_limit"] and sends["combined"] <= sends["combined_limit"]
        if pair is None:
            qualified[tuple(cell), arm] = row
        else:
            total += count
            pairs[tuple(cell), pair][arm] = row["cycles_sum"] / count
    for cell in cells:
        a, b = [qualified[tuple(cell), arm] for arm in ["A", "B"]]
        for name in ["server_capacities", "client_capacities", "memory"]:
            assert a["capacities"].get(name) == b["capacities"].get(name)
        for name in ["routes", "populated_routes", "calls", "deferred", "security_requests", "associations", "rx_slots", "rx_datagram_bytes", "tx_slots", "tx_datagram_bytes", "dedup", "observe", "rx_body_slots", "tx_body_slots", "blockwise"]:
            assert a["scalars"].get(name) == b["scalars"].get(name)
    ratios = {(cell, pair): means["B"] / means["A"] for (cell, pair), means in pairs.items()}
    summary = [{"cell": cell, **interval([ratios[tuple(cell), pair] for pair in range(64)])} for cell in cells]
    groups = {}
    for kind in ["ordinary", "retained", "all"]:
        for mode in ["sync", "async", "all"]:
            samples = [math.exp(st.mean(math.log(ratios[tuple(cell), pair]) for cell in cells if (kind == "all" or cell[0] == kind) and (mode == "all" or cell[3] == mode))) for pair in range(64)]
            groups[kind + "-" + mode] = interval(samples)
    reference = value["expected"]
    for actual, wanted in zip(summary, reference["summary"]):
        assert actual["cell"] == wanted["cell"] and all(close(actual[k], wanted[k]) for k in ["ratio", "upper95"])
    for name, actual in groups.items():
        assert all(close(actual[k], reference["groups"][name][k]) for k in ["ratio", "upper95"])
    failed = [z for z in summary if z["upper95"] > 1.02]
    accepted = not failed and all(groups[kind + "-" + mode]["upper95"] <= 1.02 for kind in ["ordinary", "all"] for mode in ["sync", "async"])
    assert [z["cell"] for z in failed] == [z["cell"] for z in reference["failed_cell_guards"]]
    assert accepted == reference["runtime_accepted"] is False
    assert total == reference["measured_operations"] == 14680064 and reference["measured_processes"] == 3584 and reference["qualification_processes"] == 56
    return {"name": value["name"], "candidate": value["candidate"], "operations": total, "sync": groups["all-sync"], "async": groups["all-async"], "failed_bounds": len(failed), "runtime_accepted": False}

def verify_host(value):
    method = value["method"]
    expected = {(r, p, c["bytes"], c["concurrency"]) for r in range(3) for p in method["peers"] for c in method["cases"]}
    assert len(expected) == 252 and len(method["peers"]) == 7
    seen, groups = set(), defaultdict(list)
    total = 0
    for row in value["rows"]:
        c, sample = row["case"], row["sample"]
        key = row["round"], row["peer"], c["bytes"], c["concurrency"]
        assert key in expected and key not in seen
        seen.add(key)
        assert row["exit_code"] == 0 and sample["failed"] == sample["warmup_failed"] == 0
        assert sample["completed"] == c["operations"] == len(sample["latencies_ns"])
        assert all(type(z) is int and z > 0 for z in sample["latencies_ns"]) and sample["elapsed_ns"] > 0
        assert sample["security"] == "unprotected" and sample["mode"] == c["mode"] and sample["concurrency"] == c["concurrency"]
        total += sample["completed"]
        groups[row["peer"], c["bytes"], c["concurrency"]].append(row)
    assert seen == expected and total == 564480
    summary = {}
    reference = {(z["peer"], z["bytes"], z["concurrency"]): z for z in value["expected"]["summary"]}
    for key, rows in groups.items():
        assert len(rows) == 3
        rates = [r["sample"]["completed"] * 1e9 / r["sample"]["elapsed_ns"] for r in rows]
        samples = [t / 1000 for r in rows for t in r["sample"]["latencies_ns"]]
        actual = {"goodput_ops_s": st.median(rates), "latency_p50_us": st.median(samples), "latency_p95_us": q(samples, .95), "latency_p99_us": q(samples, .99), "latency_max_us": max(samples), "post_load_private_bytes": st.median(r["loaded_memory"]["private"] for r in rows), "post_load_rss_bytes": st.median(r["loaded_memory"]["rss"] for r in rows), "idle_one_core_percent": st.median(r["idle_one_core_percent"] for r in rows)}
        assert all(close(v, reference[key][k]) for k, v in actual.items())
        summary[key] = actual
    ratios = {p: st.geometric_mean(v["goodput_ops_s"] / summary["libcoap", b, c]["goodput_ops_s"] for (name, b, c), v in summary.items() if name == p) for p in method["peers"]}
    for z in value["expected"]["ratios_vs_libcoap"]:
        assert close(ratios[z["peer"]], z["geometric_goodput_ratio_vs_libcoap"])
    return {"operations": total, "cells": len(expected), "geometric_goodput_ratio_vs_libcoap": ratios}

def verify_wifi(value):
    method = value["method"]
    names, controls = method["names"], method["C_names"]
    n = len(names)
    assert n in [6, 8] and method["order"] == [list(range(n)), list(reversed(range(n)))]
    assert len(value["boots"]) == 2 * n and value["normal_restored_verified"] is True
    groups, total, stability = defaultdict(list), 0, True
    for index, boot in enumerate(value["boots"]):
        rn, slot = index // n + 1, index % n
        name = names[method["order"][rn - 1][slot]]
        assert boot["name"] == name and boot["round"] == rn and boot["slot"] == slot + 1 and boot["passed"]
        cfg = boot["configuration"]
        assert cfg["sdk"]["ESP32S3_INSTRUCTION_CACHE_SIZE"] == (16384 if name == "pipeline-OsFat-cache16-async-iram-server" else 32768)
        assert cfg["sdk"]["ESP_DEFAULT_CPU_FREQ_MHZ"] == 240 and cfg["task_priority"] == 1
        assert boot["stack_reserved_bytes"] == cfg["task_stack_reserved_bytes"] == (16384 if name in controls else 196608 if boot["mode"] == "async" else 98304)
        assert 0 <= boot["stack_observed_used_bytes"] <= boot["stack_reserved_bytes"]
        quality = boot["quality"]
        stability &= quality["unexpected_disconnects"] == quality["connect_refusals"] == 0 and quality["application_dropped"] in [None, 0] and quality["wait_errors"] in [None, 0]
        order = ["sync", "async", "async", "sync"] if rn == 1 else ["async", "sync", "sync", "async"]
        assert len(boot["clients"]) == 4
        for ordinal, (client, mode) in enumerate(zip(boot["clients"], order), 1):
            assert client["passed"] and client["mode"] == mode and client["ordinal"] == ordinal and len(client["operations"]) == 24
            expected_ops = [(i, p, b) for i in range(8) for p, b in [("identity", 32), ("test", 7), ("large", 2000)]]
            for op, expected in zip(client["operations"], expected_ops):
                assert op["passed"] and (op["iteration"], op["path"], op["bytes"]) == expected
                assert type(op["elapsed_ns"]) is int and 0 < op["elapsed_ns"] < 5000000000
                assert sum(op[k] for k in ["prepare_ns", "poll_ns", "checkpoint_ns", "take_ns", "verify_ns", "sleep_ns"]) <= op["elapsed_ns"]
                ids = op["request_send_ids"]
                repeated = sum(v - 1 for v in Counter(ids).values())
                stability &= repeated == 0
                groups[name, mode, op["path"]].append((rn, op["elapsed_ns"] / 1e6))
                total += 1
    assert total == value["expected"]["operations"] == n * 192
    assert stability == value["expected"]["stability_passed"] is True
    lookup = {}
    for key, rows in groups.items():
        assert len(rows) == 32
        values = [v for _, v in rows]
        lookup[key] = {"median": st.median(values), "p95": q(values, .95), "p99": q(values, .99), "boot": [st.median(v for b, v in rows if b == rn) for rn in [1, 2]]}
    for z in value["expected"]["summary"]:
        actual = lookup[z["name"], z["client"], z["path"]]
        assert all(close(actual[k], z[k + "_ms"]) for k in ["median", "p95", "p99"])
        assert all(close(x, y) for x, y in zip(actual["boot"], z["boot_medians_ms"]))
    cells = [(c, p) for c in ["sync", "async"] for p in ["identity", "test", "large"]]
    for z in value["expected"]["comparisons"]:
        ratios = [lookup[z["left"], c, p]["median"] / lookup[z["right"], c, p]["median"] for c, p in cells]
        assert close(st.geometric_mean(ratios), z["geometric_median_ratio"])
        boots = [st.geometric_mean(lookup[z["left"], c, p]["boot"][i] / lookup[z["right"], c, p]["boot"][i] for c, p in cells) for i in [0, 1]]
        assert all(close(x, y) for x, y in zip(boots, z["boot_geometric_median_ratios"]))
    decisions = []
    for name in method["candidate_names"]:
        ratios = [lookup[name, c, p]["median"] / min(lookup[cn, c, p]["median"] for cn in controls) for c, p in cells]
        pairboots = [st.geometric_mean(lookup[name, c, p]["boot"][i] / lookup[cn, c, p]["boot"][i] for c, p in cells) for cn in controls for i in [0, 1]]
        ratio = st.geometric_mean(ratios)
        promising = stability and all(z < 1 for z in ratios) and ratio <= .97 and all(z < 1 for z in pairboots)
        wanted = next(z for z in value["expected"]["screen_decisions"] if z["name"] == name)
        assert close(ratio, wanted["strict_best_C_geometric_median_ratio"]) and promising == wanted["promising"] is False
        decisions.append({"name": name, "strict_best_C_ratio": ratio, "promising": promising})
    return {"name": value["name"], "operations": total, "boots": 2 * n, "stability_reported": stability, "decisions": decisions}

def verify_sources(inputs, fixture, cpu):
    assert inputs["schema"] == "coaptic-host-input-hashes/1" and len(inputs["cohorts"]) == 8
    expected = {v["name"]: v for v in cpu}
    assert {row["name"] for row in inputs["cohorts"]} == set(expected)
    last = None
    for row in inputs["cohorts"]:
        assert row["name"] in expected and row["baseline"] == "a85c51e689607051e36e450567fe051f8f85dc2b"
        assert row["candidate"] == expected[row["name"]]["candidate"] and row["passed"] is True and row["device_action"] is False
        for arm in ["baseline", "candidate"]:
            values = row["inputs_" + arm]
            assert len(values) == 181
            for name, sha in values.items():
                path = PurePosixPath(name)
                assert not path.is_absolute() and ".." not in path.parts and ":" not in name and "\\" not in name
                assert path.suffix in [".rs", ".toml", ".lock"] and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)
        assert row["flags"]["baseline"] == row["flags"]["candidate"] == {"RUSTFLAGS": "-Cforce-frame-pointers=yes", "release_debug": 1, "opt-level": 3, "lto": "thin", "codegen-units": 1}
        if row["name"] == "request-context":
            last = row
    assert last and fixture["schema"] == "coaptic-fixture-source-snapshot/1"
    assert fixture["core"] == last["candidate"] and fixture["suite"] == last["companion"]
    assert len(fixture["files"]) == 41 and len(fixture["omitted"]) == 1
    for name, value in {**fixture["files"], **fixture["omitted"]}.items():
        assert last["inputs_candidate"][name] == value["sha256"]
        if name in fixture["files"]:
            assert hashlib.sha256(value["text"].encode("utf-8")).hexdigest() == value["sha256"]
    return {"cohort_input_maps": 8, "files_per_arm": 181, "fixture_exact_files": 41, "fixture_omitted_files": 1}


def verify_provenance(value, data):
    assert value["schema"] == "coaptic-method-provenance/1"
    assert {row["name"] for row in value["cpu"]} == {v["name"] for k, v in data.items() if k.startswith("cpu/")}
    assert len(value["cpu"]) == 8 and len(value["wifi"]) == 2
    for row in value["cpu"]:
        original = data["cpu/" + row["name"] + ".json.gz"]
        assert row["source_method_sha256"] == original["source_digests"]["method"]
        preflight = row["method"]["compiler_future_preflight"]
        assert preflight["baseline"] == original["baseline"] and preflight["candidate"] == original["candidate"]
    for row in value["wifi"]:
        assert row["source_method_sha256"] == data["wifi/" + row["name"] + ".json.gz"]["source_digests"]["method"]
    assert value["host"]["source_method_sha256"] == data["host.json.gz"]["source_digests"]["RUNTIME-METHOD.json"]
    assert value["host"]["method"]["limits"] == {"phase_seconds": 480, "driver_seconds": 30, "private_bytes": 268435456}
    return {"cpu_methods": 8, "wifi_methods": 2, "host_method": 1}


def main(root=ROOT):
    root = Path(root).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8-sig"))
    assert manifest["adopted"] is False and manifest["goal_complete"] is False
    data = {}
    for name, expected in manifest["files"].items():
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts and name.endswith(".gz")
        local = root / name
        assert not local.is_symlink() and local.resolve().is_relative_to(root)
        raw = local.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected["sha256"]
        with gzip.open(local, "rb") as stream:
            unpacked = stream.read(BUDGET + 1)
        assert len(unpacked) == expected["uncompressed_bytes"] <= BUDGET and hashlib.sha256(unpacked).hexdigest() == expected["uncompressed_sha256"]
        if name.endswith(".json.gz"):
            data[name] = json.loads(unpacked)
    cpu = [verify_cpu(data[name]) for name in sorted(data) if name.startswith("cpu/")]
    assert len(cpu) == 8 and sum(v["operations"] for v in cpu) == 117440512
    sources = verify_sources(data["sources/host-inputs.json.gz"], data["sources/request-context-fixture.json.gz"], [data[name] for name in sorted(data) if name.startswith("cpu/")])
    provenance = verify_provenance(data["sources/method-provenance.json.gz"], data)
    host = verify_host(data["host.json.gz"])
    wifi = [verify_wifi(data[name]) for name in sorted(data) if name.startswith("wifi/")]
    assert sorted(v["operations"] for v in wifi) == [1152, 1536]
    out = {"verified": True, "cpu": cpu, "sources": sources, "provenance": provenance, "host": host, "wifi": wifi, "adopted": False, "goal_complete": False, "scope": "Portable sufficient-statistic and latency regrade only. Hardware/source execution and excluded private witnesses remain producer attestations."}
    print(json.dumps(out, indent=2))
    return out

if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT)
