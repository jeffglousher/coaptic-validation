"""Verify portable hashes and recompute retained host/WiFi decisions offline."""
from pathlib import Path
import argparse
import json
import common as c
import portable_host

ROOT = Path(__file__).resolve().parent


def source_map(host):
    value = host["effective_inputs"]
    old, new = value["original_normalized"], value["effective"]
    overrides, additions = value["explicit_staged_overrides"], value["explicit_staged_additions"]
    c.require(len(old) == 679 and len(new) == 680 and len(overrides) == 3 and len(additions) == 1, "effective source accounting differs")
    replaced = {z["normalized"] for z in overrides}
    added = {z["normalized"] for z in additions}
    c.require(set(new) == set(old) | added and not set(old) & added and len(set(old) - replaced) == 676, "effective source membership differs")
    for name in new:
        c.relative(name)
        c.require(len(new[name]) == 64 and all(z in "0123456789abcdef" for z in new[name]), "source hash shape differs")
    for z in overrides + additions:
        c.require(old.get(z["normalized"]) == z["original_sha256"] and new[z["normalized"]] == z["effective_sha256"], "source override witness differs")
    c.require(all(old[k] == new[k] for k in old if k not in replaced), "unexplained source change")
    return {"baseline": 679, "effective": 680, "replaced": 3, "added": 1, "unchanged": 676}


def startup_grade(value):
    c.require(value["candidate"] == c.H and value["runtime"] == c.RUNTIME and value["performance_operations_imported"] == 0, "startup source/speed separation differs")
    results = []
    for profile in value["profiles"]:
        join, status, state = profile["join"], profile["status"], profile["state"]
        mode = join["mode"]
        stack = 98304 if mode == "sync" else 196608
        count = sum(len(client["operations"]) for client in profile["clients"])
        verified = all(client["passed"] and len(client["operations"]) == 24 and all(op.get("passed") is True for op in client["operations"]) for client in profile["clients"])
        guards = state.get("stage") == 5 and state.get("worker_result") == 0 and state.get("configured_stack_bytes") == stack and state.get("before_task_largest_bytes", 0) >= stack + 4096
        guards &= bool(profile["network"]) and all(n["stack_capacity_bytes"] == stack and 0 <= n["stack_high_water_bytes"] <= stack and n["dropped"] == n["wait_errors"] == 0 for n in profile["network"])
        guards &= bool(profile["heap"]) and all(8192 <= h["free_bytes"] <= h["total_bytes"] and h["largest_free_block_bytes"] >= 8192 and h["region_min_free_sum_bytes"] >= 12288 for h in profile["heap"])
        qualified = bool(status["passed"] and verified and count == 48 and guards and status["restore_verified"] and status["collection_complete"] and status["performance_comparison_operations"] == 0 and join["performance_operations_imported"] == 0 and join["diagnostic_overhead_bytes"] <= 16)
        c.require(qualified == status["passed"] == join["passed"], "startup producer pass disagrees with exported guards")
        results.append({"mode": mode, "qualification_reads": count, "qualified": qualified, "performance_reads_imported": 0})
    c.require(sorted(z["mode"] for z in results) == ["async", "sync"], "startup mode grid differs")
    return results


def verify(root=ROOT):
    root = Path(root).resolve()
    manifest = c.load(root / "manifest.json")
    c.require(manifest["candidate"] == c.H and manifest["baseline"] == c.BASE and manifest["adopted"] is False and manifest["goal_complete"] is False, "scope/source claim differs")
    data = {}
    for name, expected in manifest["files"].items():
        path = root / c.relative(name)
        c.require(not path.is_symlink() and path.resolve().is_relative_to(root), "file escapes package")
        packed = path.read_bytes()
        c.require(len(packed) == expected["gzip_bytes"], "compressed size differs")
        raw = c.unpack(packed, expected)
        c.require(not c.private(raw), "private field remains in " + name)
        if name.endswith(".json.gz"):
            data[name] = json.loads(raw)
    host = data["host.json.gz"]
    actual_host = portable_host.analyze_records(host["method"], host["records"], host["status"] == "COMPLETE")
    c.same(actual_host, host["expected"], "host")
    maps = source_map(host)
    wifi = data["wifi.json.gz"]
    actual_wifi = c.wifi_grade(wifi)
    actual_wifi["restore_verified"] = wifi["status"].get("restore_verified", False)
    if actual_wifi["verified_complete"]:
        c.require(actual_wifi["resources_passed"], "complete WiFi producer claim disagrees with exported resource/source guards")
        actual_wifi["memory"] = c.wifi_memory(wifi)
    c.same(actual_wifi, wifi["expected"], "wifi")
    startup = startup_grade(data["startup.json.gz"])
    out = {"verified": True, "host_operations": actual_host["completed"], "host_decisions": actual_host["decisions"], "wifi_operations": actual_wifi["operations"], "wifi_decisions": actual_wifi["screen_decisions"], "wifi_stability_passed": actual_wifi["stability_passed"], "wifi_resources_passed": actual_wifi["resources_passed"], "startup": startup, "source_inputs": maps, "adopted": False, "goal_complete": False, "scope": "Offline regrade of full exported latency vectors, numeric guards/memory ledgers and original digest commitments. Physical identity/restoration/API, source-to-binary finalizer/producer proofs and missing configurations remain private attestations. Instruction-cache records are per-image; data-cache defaults are reconstructed only. Startup qualification is excluded from speed statistics."}
    print(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args()
    verify(args.root)
