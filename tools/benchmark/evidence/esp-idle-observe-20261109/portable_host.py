"""Pure original host regrade functions; no files, tested processes or network at import."""
from collections import defaultdict
from types import SimpleNamespace
import json, math, random, statistics as st
H="de9230aa22dab0c67604ea4b040a1c1daa59a41e"
A85="a85c51e689607051e36e450567fe051f8f85dc2b"
PEERS=["H-Mio","H-async","a85-Mio","a85-async","libcoap"]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def schedule(peers, cases, seed):
    rng = random.Random(seed)
    rows = []
    for round_no in range(3):
        for case_no in range(len(cases)):
            order = list(peers)
            rng.shuffle(order)
            for peer in order:
                rows.append({"sequence": len(rows), "round": round_no, "case": case_no, "peer": peer})
    return rows

def validate_method(method):
    cases = [dict(bytes=b, concurrency=c, operations=4096 if b <= 1024 else 512 if b == 16384 else 256, warmup=2, timeout_ms=2000, mode="con", protocol="coap", security="unprotected") for b in [64, 1024, 16384, 65536] for c in [1, 16, 64]]
    require(method["candidate"] == H and method["baseline"] == A85, "source pins differ")
    require(method["cases"] == cases and method["rounds"] == 3 and method["seed"] == 20261107, "case/round profile differs")
    require([p["id"] for p in method["peers"]] == PEERS, "peer profile differs")
    require(method["schedule"] == schedule(PEERS, cases, method["seed"]), "schedule/order differs")
    require(len(method["schedule"]) == 180 and sum(cases[r["case"]]["operations"] for r in method["schedule"]) == 403200, "operation accounting differs")
    require(method["limits"] == {"phase_seconds": 480, "driver_seconds": 30, "private_bytes": 268435456}, "original limits differ")
    require(method["acceptance"] == {"aggregate_goodput_ratio_minimum": 1.03, "every_round_geometric_goodput_ratio_strict_minimum": 1.0, "complete_cells": 180, "verified_operations": 403200, "all_capacity_and_failure_gates": True}, "prospective gate differs")
    for peer in method["peers"]:
        require(peer["driver"][1:] == ["{host}", "{port}", "{bytes}", "{concurrency}", "{operations}", "{warmup}", "{timeout_ms}", "{mode}"], "driver arguments differ")
        if peer["id"] != "libcoap":
            mode = "coaptic-mio" if peer["id"].endswith("Mio") else "coaptic-async"
            require(peer["server"][1:] == [mode, "{host}", "{port}", "{bytes}", "1472"], "Rust backend/capacity arguments differ")
        else:
            require(peer["server"][1:] == ["{host}", "{port}", "{bytes}"], "C arguments differ")
    return method

runner=SimpleNamespace(validate_method=validate_method,PEERS=PEERS,require=require)

def integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"invalid {name}")
    return value

def validate_sample(value, case):
    if not isinstance(value, dict) or value.get("schema") != "coaptic-load/1":
        raise ValueError("load driver schema")
    attempted = integer(value.get("attempted"), "attempted", 1, 200_000)
    completed = integer(value.get("completed"), "completed", 0, attempted)
    failed = integer(value.get("failed"), "failed", 0, attempted)
    if attempted != case["operations"] or completed + failed != attempted:
        raise ValueError("attempt accounting mismatch")
    elapsed = integer(value.get("elapsed_ns"), "elapsed_ns", 1, 86_400_000_000_000)
    values = value.get("latencies_ns")
    if not isinstance(values, list) or len(values) != completed:
        raise ValueError("latency/completion mismatch")
    for item in values:
        integer(item, "latency", 1, elapsed)
    integer(value.get("verified_bytes"), "verified_bytes", 0, 200_000 * 1024 * 1024)
    if value["verified_bytes"] != completed * case["bytes"]:
        raise ValueError("complete representation bytes mismatch")
    if value.get("concurrency") != case["concurrency"] or value.get("warmup") != case["warmup"]:
        raise ValueError("driver profile mismatch")
    integer(value.get("concurrency"), "concurrency", 1, 128)
    integer(value.get("warmup"), "warmup", 0, 10_000)
    integer(value.get("warmup_failed"), "warmup_failed", 0, case["warmup"] * case["concurrency"])
    integer(value.get("driver_failures", 0), "driver_failures", 0, failed)
    if value.get("mode") != case["mode"] or value.get("protocol") != case["protocol"] or value.get("security") != case["security"]:
        raise ValueError("driver protocol/mode mismatch")
    return value

def quantile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (position - low)

campaign=SimpleNamespace(validate_sample=validate_sample,quantile=quantile)

def capacities(peer, result, case):
    lines = result.get("server_stdout", "").splitlines()
    if peer == "libcoap":
        return {"passed": not lines, "witness": "pinned C binary/static GET-CON-Block2 fixture; no App pool-ledger or whole-capability parity claim"}
    try:
        ledger = json.loads(lines[0]) if len(lines) == 1 else {}
    except (ValueError, TypeError):
        ledger = {}
    if peer.endswith("Mio"):
        expected = {"schema": "coaptic-native-mio-resources/1", "server_kind": "coaptic-mio", "resource_profile": "host-control", "storage": "allocated", "routes": 1, "populated_routes": 1, "calls": 4, "deferred": 0, "associations": 1, "security_requests": 4, "blockwise": True, "rx_slots": 4, "tx_slots": 4, "rx_datagram_bytes": 1472, "tx_datagram_bytes": 1472, "dedup": 8, "observe": 4, "rx_body_slots": 1, "tx_body_slots": 2, "rx_body_bytes": max(1024, case["bytes"]), "tx_body_bytes": max(1024, case["bytes"]), "representation_bytes": case["bytes"], "security": "unprotected", "udp_scratch_bytes": 2049, "event_capacity": 8, "worker_threads": 0, "pending_kernel_operations": 0}
        passed = all(ledger.get(k) == v for k, v in expected.items())
        witness = "complete Mio startup capacity ledger plus source/binary pin"
    else:
        expected = {"schema": "coaptic-native-server-resources/2", "server_kind": "coaptic-async", "udp_scratch_bytes": 2049}
        passed = all(ledger.get(k) == v for k, v in expected.items()) and all(type(ledger.get(k)) is int and ledger[k] > 0 for k in ["adapter_inline_bytes", "app_including_adapter_bytes", "loop_future_borrowing_app_bytes"])
        witness = "actual async startup ledger plus unchanged source-bound HostControl capacity setup; async ledger itself omits pool capacities"
    return {"passed": passed, "witness": witness, "ledger": ledger}

def validate_record(value, method):
    step = value["step"]
    case = method["cases"][step["case"]]
    result = value["result"]
    sample = campaign.validate_sample(result["sample"], case)
    complete = sample["completed"] == case["operations"] and sample["failed"] == sample["warmup_failed"] == sample.get("driver_failures", 0) == 0 and result.get("exit_code") == 0
    cap = capacities(step["peer"], result, case)
    snapshots = [result.get("idle", {}).get("memory", {}), result.get("loaded", {}).get("before", {}).get("memory", {}), result.get("loaded", {}).get("after", {}).get("memory", {})]
    memory = all(type(row.get("private")) is int and 0 < row["private"] <= method["limits"]["private_bytes"] for row in snapshots)
    peak = result.get("loaded", {}).get("sampled_peak_memory", {}).get("private")
    memory = memory and (peak is None or type(peak) is int and 0 < peak <= method["limits"]["private_bytes"])
    gates = {"complete_body_and_failures": complete, "capacity_witness": cap["passed"], "observed_private_memory_limit": memory, "server_stderr_empty": result.get("server_stderr") == "", "full_capture_retained": value.get("capture_complete") is True}
    return {"eligible": all(gates.values()), "gates": gates, "capacity": cap}

def quantile(values, probability):
    return campaign.quantile(sorted(values), probability)

def median_value(rows, path):
    values = []
    for row in rows:
        value = row["result"]
        try:
            for part in path:
                value = value[part]
        except (KeyError, TypeError):
            continue
        if type(value) in [float, int] and math.isfinite(value):
            values.append(value)
    return st.median(values) if values else None

def analyze_records(method, records, complete):
    runner.validate_method(method)
    runner.require(len(records) <= 180, "extra observations")
    for row, expected in zip(records, method["schedule"]):
        runner.require(row["step"] == expected, "missing/duplicate/reordered observation")
    if complete:
        runner.require(len(records) == 180, "complete campaign missing cells")
    groups = defaultdict(list)
    eligibility = []
    total = failed = warmup_failed = 0
    for row in records:
        check = validate_record(row, method)
        step = row["step"]
        eligibility.append({"step": step, **check})
        groups[step["peer"], step["case"]].append(row)
        sample = row["result"]["sample"]
        total += sample["completed"]
        failed += sample["failed"]
        warmup_failed += sample["warmup_failed"]
    summaries = []
    lookup = {}
    for case_no, case in enumerate(method["cases"]):
        for peer in runner.PEERS:
            rows = groups[peer, case_no]
            samples = [r["result"]["sample"] for r in rows]
            vectors = [n / 1000 for v in samples for n in v["latencies_ns"]]
            goodput = [v["completed"] * 1e9 / v["elapsed_ns"] for v in samples]
            metrics = {"peer": peer, "bytes": case["bytes"], "concurrency": case["concurrency"], "case": case_no, "rounds": len(rows), "completed": sum(v["completed"] for v in samples), "failed": sum(v["failed"] for v in samples), "warmup_failed": sum(v["warmup_failed"] for v in samples), "driver_failures": sum(v.get("driver_failures", 0) for v in samples), "endpoint_rotations": sum(v.get("endpoint_rotations", 0) for v in samples), "goodput_ops_s": st.median(goodput) if goodput else None, "round_goodput_ops_s": {str(r["step"]["round"]): r["result"]["sample"]["completed"] * 1e9 / r["result"]["sample"]["elapsed_ns"] for r in rows}, "latency_p50_us": st.median(vectors) if vectors else None, "latency_p95_us": quantile(vectors, .95) if vectors else None, "latency_p99_us": quantile(vectors, .99) if vectors else None, "latency_max_us": max(vectors) if vectors else None, "latency_samples": len(vectors), "post_load_private_bytes": median_value(rows, ["loaded", "after", "memory", "private"]), "post_load_rss_bytes": median_value(rows, ["loaded", "after", "memory", "rss"]), "sampled_peak_private_bytes_median": median_value(rows, ["loaded", "sampled_peak_memory", "private"]), "sampled_memory_counts": [r["result"].get("loaded", {}).get("sample_count") for r in rows], "idle_one_core_percent": median_value(rows, ["idle", "one_core_percent"]), "loaded_process_cpu_window_us_per_op": median_value(rows, ["loaded", "server_cpu_window_us_per_verified_op"]), "startup_first_verified_response_ms": median_value(rows, ["startup_first_verified_response_ms"]), "forced_stop_pipe_settlement_ms": median_value(rows, ["forced_stop_and_pipe_settlement_ms"])}
            summaries.append(metrics)
            lookup[peer, case_no] = metrics
    pairs = [(p, "libcoap") for p in runner.PEERS if p != "libcoap"] + [("H-Mio", "a85-Mio"), ("H-async", "a85-async")]
    comparisons = []
    for left, right in pairs:
        cells = []
        for i, case in enumerate(method["cases"]):
            a, b = lookup[left, i], lookup[right, i]
            available = a["rounds"] == b["rounds"] == 3 and a["goodput_ops_s"] and b["goodput_ops_s"]
            cells.append({"bytes": case["bytes"], "concurrency": case["concurrency"], "goodput_ratio": a["goodput_ops_s"] / b["goodput_ops_s"] if available else None, "latency_p50_ratio": a["latency_p50_us"] / b["latency_p50_us"] if available and a["latency_p50_us"] and b["latency_p50_us"] else None, "round_ratios": [a["round_goodput_ops_s"][str(r)] / b["round_goodput_ops_s"][str(r)] for r in range(3)] if available else None})
        ready = all(c["goodput_ratio"] is not None for c in cells)
        comparisons.append({"left": left, "right": right, "cells": cells, "geometric_goodput_ratio": st.geometric_mean(c["goodput_ratio"] for c in cells) if ready else None, "round_geometric_goodput_ratios": [st.geometric_mean(c["round_ratios"][r] for c in cells) for r in range(3)] if ready else None})
    all_eligible = complete and len(records) == 180 and total == 403200 and all(r["eligible"] for r in eligibility)
    decisions = []
    for peer in ["H-Mio", "H-async"]:
        comp = next(c for c in comparisons if c["left"] == peer and c["right"] == "libcoap")
        ratio, rounds = comp["geometric_goodput_ratio"], comp["round_geometric_goodput_ratios"]
        accepted = all_eligible and ratio is not None and ratio >= 1.03 and all(r > 1 for r in rounds)
        decisions.append({"peer": peer, "geometric_goodput_ratio_vs_C": ratio, "round_geometric_goodput_ratios_vs_C": rounds, "all_completion_capacity_failure_gates": all_eligible, "host_gate_passed": accepted})
    return {"schema": "coaptic-idle-observe-host-analysis/1", "source": {"candidate": method["candidate"], "baseline": method["baseline"], "libcoap_binary_sha256": method["binary_sha256"]["libcoap"]}, "status": "COMPLETE" if complete else "INCOMPLETE", "observations": len(records), "expected_observations": 180, "completed": total, "failed": failed, "warmup_failed": warmup_failed, "all_complete_capacity_failure_gates": all_eligible, "summary": summaries, "comparisons": comparisons, "decisions": decisions, "cell_eligibility": eligibility, "scope": "Fresh five-peer Windows loopback complete unprotected CON workload. Aggregate is geometric mean of 12 median-of-three goodput cell ratios. Each round uses its own 12 matched case ratios. Descriptive pooled tails and process/resource samples; no isolated CPU, per-cell preservation CI, whole-capability parity, peak-RAM or ESP32/Wi-Fi claim. Failures are retained and invalidate acceptance; no successful-round filtering."}
