"""Portable exact-H evidence allowlists and pure statistical regrade helpers."""
from pathlib import Path, PurePosixPath
from collections import Counter, defaultdict
import gzip
import hashlib
import io
import json
import math
import re
import statistics as st

BASE = "a85c51e689607051e36e450567fe051f8f85dc2b"
H = "de9230aa22dab0c67604ea4b040a1c1daa59a41e"
RUNTIME = "32f8fcac22fc16b1957c35f4f145df6be3a72532"
BUDGET = 8 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    return sha(Path(path).read_bytes())


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def picked(value, keys):
    return {k: value[k] for k in keys if k in value}


def numeric(value):
    return {k: v for k, v in value.items() if type(v) in [int, float, bool] or v is None if not re.search(r"(?:^|_)(?:run|session|pid|mac|ip|address|credential|token|id)(?:_|$)", k, re.I)}


def private(raw):
    patterns = [r"(?<![a-z])[a-z]:[\\/]", r"/Users/|/home/", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", r"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", r"noise_psk|private-checkpoints|t3-thread://"]
    text = raw.decode("utf-8")
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def relative(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and ":" not in name and "\\" not in name and str(path) == name, "unsafe export path")
    return name


def unpack(packed, expected):
    require(sha(packed) == expected["sha256"], "compressed digest differs")
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        raw = stream.read(MAX_EXPANDED + 1)
    require(len(raw) == expected["raw_bytes"] <= MAX_EXPANDED and sha(raw) == expected["raw_sha256"], "raw digest/size differs")
    return raw


def snapshot(value):
    return {**picked(value, ["user_seconds", "system_seconds", "threads"]), "memory": picked(value.get("memory", {}), ["rss", "vms", "private"])}


def host_result(value):
    sample = picked(value["sample"], ["schema", "protocol", "security", "mode", "concurrency", "warmup", "attempted", "completed", "failed", "warmup_failed", "driver_failures", "endpoint_rotations", "verified_bytes", "elapsed_ns", "latencies_ns", "clock", "measurement"])
    loaded = value.get("loaded", {})
    result = picked(value, ["exit_code", "startup_first_verified_response_ms", "startup_probe_attempts", "forced_stop_and_pipe_settlement_ms", "graceful_shutdown_ms", "shutdown_note"])
    result["sample"] = sample
    result["idle"] = {**numeric(value.get("idle", {})), "memory": picked(value.get("idle", {}).get("memory", {}), ["rss", "vms", "private"])}
    result["loaded"] = {**numeric(loaded), **picked(loaded, ["cpu_resolution_note"]), "before": snapshot(loaded.get("before", {})), "after": snapshot(loaded.get("after", {})), "sampled_peak_memory": picked(loaded.get("sampled_peak_memory", {}), ["rss", "private"])}
    lines = value.get("server_stdout", "").splitlines()
    ledger = {}
    if len(lines) == 1:
        try:
            raw_ledger = json.loads(lines[0])
            ledger = {**numeric(raw_ledger), **picked(raw_ledger, ["schema", "server_kind", "resource_profile", "storage", "security", "nesting", "limits"])}
        except (ValueError, TypeError):
            pass
    result["server_stdout"] = json.dumps(ledger) + "\n" if ledger else "" if not lines else "<non-ledger producer output withheld; original digest retained>"
    result["server_stderr"] = "" if value.get("server_stderr", "") == "" else "<nonempty producer stderr withheld; original digest retained>"
    result["server_stdout_sha256"] = sha(value.get("server_stdout", "").encode())
    result["server_stderr_sha256"] = sha(value.get("server_stderr", "").encode())
    rows = value.get("resource_samples", [])
    first = rows[0]["at"] if rows else 0
    result["resource_samples"] = [{"offset_seconds": row["at"] - first, "snapshot": snapshot(row["snapshot"])} for row in rows]
    return result


def operation(value):
    result = picked(value, ["passed", "iteration", "path", "bytes", "elapsed_ns", "prepare_ns", "poll_ns", "checkpoint_ns", "take_ns", "verify_ns", "sleep_ns"])
    result["request_send_ids"] = [e[4] for e in value.get("events", []) if e[0] == 2 and e[3] > 4]
    require(all(type(n) is int for n in result["request_send_ids"]), "protocol MID type differs")
    return result


def clients(rows):
    output = []
    for row in rows:
        p = Path(row.get("report_path", ""))
        available = p.is_file()
        report = [json.loads(z) for z in p.read_text(encoding="utf-8-sig").splitlines() if z.strip()] if available else []
        original = digest(p) if available else row.get("source_report_sha256")
        if available and row.get("source_report_sha256"):
            require(original == row["source_report_sha256"], "original client report digest differs")
        output.append({**picked(row, ["mode", "ordinal", "passed", "operations"]), "report_available": available, "original_report_sha256": original, "operations": [operation(z) for z in report if z.get("case") == "complete_operation"], "final": picked(report[-1], ["case", "passed", "completed", "io_mode", "security"]) if report else None})
    return output


def host_decision(eligible, ratio, rounds):
    return bool(eligible and ratio is not None and ratio >= 1.03 and len(rounds) == 3 and all(r > 1 for r in rounds))


def wifi_decision(name, controls, lookup, eligible):
    cells = [(c, p) for c in ["sync", "async"] for p in ["identity", "test", "large"]]
    strict = []
    for client, path in cells:
        a = lookup[name, client, path]
        cs = [lookup[c, client, path] for c in controls]
        best = min(cs, key=lambda z: z["median_ms"])
        strict.append({"client": client, "path": path, "best_C": best["name"], "median_ratio": a["median_ms"] / best["median_ms"], "boot_best_C_ratios": [a["boot_medians_ms"][i] / min(z["boot_medians_ms"][i] for z in cs) for i in [0, 1]]})
    geom = st.geometric_mean(z["median_ratio"] for z in strict)
    boots = {c: [st.geometric_mean(lookup[name, client, path]["boot_medians_ms"][i] / lookup[c, client, path]["boot_medians_ms"][i] for client, path in cells) for i in [0, 1]] for c in controls}
    allcells = all(z["median_ratio"] < 1 for z in strict)
    bootpass = all(v < 1 for values in boots.values() for v in values)
    return {"name": name, "promising": bool(eligible and allcells and geom <= .97 and bootpass), "strict_best_C_geometric_median_ratio": geom, "all_six_cell_medians_below_best_C": allcells, "boot_best_C_geometric_ratios": [st.geometric_mean(z["boot_best_C_ratios"][i] for z in strict) for i in [0, 1]], "boot_pairwise_C_geometric_ratios": boots, "all_boot_pairwise_geomeans_below_one": bootpass, "cells": strict}


def q(values, p):
    values = sorted(values)
    at = (len(values) - 1) * p
    a, b = math.floor(at), math.ceil(at)
    return values[a] + (values[b] - values[a]) * (at - a)


def native_policy(boot, method):
    cfg = boot["configuration"]
    sdk = cfg.get("sdk", {})
    expected = {"ESP_DEFAULT_CPU_FREQ_MHZ": 240, "ESP32S3_INSTRUCTION_CACHE_SIZE": 32768, "ESP32S3_ICACHE_ASSOCIATED_WAYS": 8, "ESP32S3_INSTRUCTION_CACHE_LINE_SIZE": 32}
    valid = all(type(sdk.get(k)) is int and sdk[k] == v for k, v in expected.items())
    mode = boot["mode"]
    stack = 16384 if mode == "C" else 196608 if mode == "async" else 98304
    valid &= type(cfg.get("task_stack_reserved_bytes")) is int and cfg["task_stack_reserved_bytes"] == stack
    valid &= type(cfg.get("task_priority")) is int and cfg["task_priority"] == 1
    valid &= type(cfg.get("task_core")) is int and cfg["task_core"] in ([-1, 1] if mode == "C" else [-1])
    settle = boot.get("settle_seconds")
    valid &= type(settle) in [int, float] and math.isfinite(settle) and settle >= method["post_ota_settle_s"]
    return bool(valid)


def wifi_grade(value):
    method = value["method"]
    names, controls = method["names"], method["C_names"]
    require(method["core"] == H and method["runtime"] == RUNTIME and method["post_ota_settle_s"] == 30 and method["clients_per_boot"] == 4, "frozen device source/settling profile differs")
    require(len(names) == 6 and method["order"] == [list(range(6)), list(reversed(range(6)))], "WiFi grid differs")
    groups = defaultdict(list)
    stable = resources = True
    operations = 0
    complete = value["status"]["collection_complete"] and value["status"]["passed"] and len(value["boots"]) == 12
    for index, boot in enumerate(value["boots"]):
        rn, slot = index // 6 + 1, index % 6
        require(boot["name"] == names[method["order"][rn - 1][slot]] and boot["round"] == rn, "WiFi order differs")
        resources &= native_policy(boot, method)
        quality = boot["quality"]
        stable &= quality.get("unexpected_disconnects") == quality.get("connect_refusals") == 0 and quality.get("application_dropped") in [None, 0] and quality.get("wait_errors") in [None, 0]
        expected_stack = 16384 if boot["mode"] == "C" else 196608 if boot["mode"] == "async" else 98304
        resources &= 0 <= boot["stack_observed_used_bytes"] <= boot["stack_reserved_bytes"] == expected_stack and boot["instruction_cache_bytes"] == 32768
        cfg = boot["configuration"]
        if boot["name"] in method["candidate_names"]:
            resources &= cfg.get("core") == H and cfg.get("runtime") == RUNTIME and cfg.get("startup_diagnostic_only") is False and cfg.get("task_stack_reserved_bytes") == expected_stack and cfg.get("task_priority") == 1
            resources &= 0 <= boot["physical_net_static_ram_added_bytes"] <= (9984 if boot["mode"] == "async" else 61440)
            resources &= 0 <= boot["linked_iram_added_bytes"] <= (12288 if boot["mode"] == "async" else 65536)
        if boot["mode"] != "C":
            running = [h for h in boot["heap"] if h.get("phase") == "running" and h.get("caps") == "all_8bit"]
            resources &= bool(running) and all(8192 <= h["free_bytes"] <= h["total_bytes"] and h["largest_free_block_bytes"] >= 8192 and h["region_min_free_sum_bytes"] >= 12288 for h in running)
        expected_modes = ["sync", "async", "async", "sync"] if rn == 1 else ["async", "sync", "sync", "async"]
        complete &= len(boot["clients"]) == 4
        for ordinal, client in enumerate(boot["clients"]):
            complete &= client["mode"] == expected_modes[ordinal] and client["passed"] and client["report_available"] and len(client["operations"]) == 24
            for op, expected in zip(client["operations"], [(i, p, n) for i in range(8) for p, n in [("identity", 32), ("test", 7), ("large", 2000)]]):
                complete &= op.get("passed") is True and (op.get("iteration"), op.get("path"), op.get("bytes")) == expected
                elapsed = op.get("elapsed_ns")
                complete &= type(elapsed) is int and 0 < elapsed < 5000000000
                if type(elapsed) is not int or elapsed <= 0:
                    continue
                stages = [op.get(k) for k in ["prepare_ns", "poll_ns", "checkpoint_ns", "take_ns", "verify_ns", "sleep_ns"]]
                complete &= all(type(v) is int and v >= 0 for v in stages) and sum(v for v in stages if type(v) is int) <= elapsed
                repeats = sum(v - 1 for v in Counter(op["request_send_ids"]).values())
                stable &= repeats == 0
                groups[boot["name"], client["mode"], op["path"]].append((rn, elapsed / 1e6, repeats))
                operations += 1
    complete &= operations == 1152 and all(len(rows) == 32 for rows in groups.values()) and len(groups) == 36
    if not complete:
        return {"verified_complete": False, "operations": operations, "stability_passed": bool(stable), "resources_passed": bool(resources), "screen_decisions": []}
    summary = []
    for (name, client, path), rows in sorted(groups.items()):
        values = [v for _, v, _ in rows]
        summary.append({"name": name, "client": client, "path": path, "n": len(rows), "median_ms": st.median(values), "p95_ms": q(values, .95), "p99_ms": q(values, .99), "max_ms": max(values), "boot_medians_ms": [st.median(v for b, v, _ in rows if b == rn) for rn in [1, 2]], "repeated_request_send_attempts": sum(r for _, _, r in rows)})
    lookup = {(z["name"], z["client"], z["path"]): z for z in summary}
    decisions = [wifi_decision(name, controls, lookup, stable and resources) for name in method["candidate_names"]]
    cells = [(c, p) for c in ["sync", "async"] for p in ["identity", "test", "large"]]
    comparisons = []
    for left, right, meaning in method["control_pairs"] + [[a, b, "Rust / Ccontrol"] for a in names if a not in controls for b in controls]:
        rows = []
        for client, path in cells:
            a, b = lookup[left, client, path], lookup[right, client, path]
            rows.append({"client": client, "path": path, "median_ratio": a["median_ms"] / b["median_ms"], "p95_ratio": a["p95_ms"] / b["p95_ms"], "p99_ratio": a["p99_ms"] / b["p99_ms"], "boot_median_ratios": [v / w for v, w in zip(a["boot_medians_ms"], b["boot_medians_ms"]) ]})
        comparisons.append({"left": left, "right": right, "meaning": meaning, "geometric_median_ratio": st.geometric_mean(z["median_ratio"] for z in rows), "worst_median_ratio": max(z["median_ratio"] for z in rows), "boot_geometric_median_ratios": [st.geometric_mean(z["boot_median_ratios"][i] for z in rows) for i in [0, 1]], "cells": rows})
    return {"verified_complete": True, "operations": operations, "stability_passed": bool(stable), "resources_passed": bool(resources), "summary": summary, "comparisons": comparisons, "screen_decisions": decisions}


def wifi_memory(value):
    rows = []
    for name in value["method"]["names"]:
        boots = [b for b in value["boots"] if b["name"] == name]
        require(len(boots) == 2, "memory cohort lacks two boot observations")
        rows.append({"name": name, "task_stack_reserved_bytes": boots[0]["stack_reserved_bytes"], "max_observed_lifetime_stack_bytes": max(b["stack_observed_used_bytes"] for b in boots), "per_boot_observed_used_bytes": [b["stack_observed_used_bytes"] for b in boots], "image_bytes": boots[0]["image_bytes"], "linked_iram_added_bytes": boots[0]["linked_iram_added_bytes"], "physical_net_static_ram_added_bytes": boots[0]["physical_net_static_ram_added_bytes"], "instruction_cache_bytes": boots[0]["instruction_cache_bytes"], "observed_total_heap_bytes": sorted({h["total_bytes"] for b in boots for h in b["heap"] if h.get("caps") == "all_8bit"}), "per_boot_running_free_bytes": [min((h["free_bytes"] for h in b["heap"] if h.get("caps") == "all_8bit" and h.get("phase") == "running"), default=None) for b in boots], "per_boot_running_region_min_free_sum_bytes": [min((h["region_min_free_sum_bytes"] for h in b["heap"] if h.get("caps") == "all_8bit" and h.get("phase") == "running"), default=None) for b in boots]})
    return rows


def same(actual, expected, path="result"):
    if type(expected) is bool or expected is None or isinstance(expected, str):
        require(actual == expected, path + " differs")
    elif type(expected) in [int, float]:
        require(type(actual) in [int, float] and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9), path + " differs")
    elif isinstance(expected, list):
        require(len(actual) == len(expected), path + " length differs")
        for i, (a, e) in enumerate(zip(actual, expected)):
            same(a, e, path + "." + str(i))
    else:
        for key, value in expected.items():
            same(actual[key], value, path + "." + key)
