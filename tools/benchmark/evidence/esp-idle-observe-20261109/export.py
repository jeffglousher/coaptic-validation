"""Export completed exact-H evidence through explicit allowlists after parent releases clocks."""
from pathlib import Path
import argparse
import gzip
import json
import re
import subprocess
import common as c

ROOT = Path(__file__).resolve().parent


def method(value):
    out = c.picked(value, ["schema", "candidate", "baseline", "companion", "cases", "rounds", "seed", "schedule", "limits", "acceptance", "binary_sha256", "executors", "capacity_source", "helper_ast_sha256", "source_digests", "output_budget", "scope"])
    out["peers"] = [{**c.picked(p, ["id", "source_core"]), "server": ["<pinned-server-binary>"] + p["server"][1:], "driver": ["<pinned-driver-binary>"] + p["driver"][1:]} for p in value["peers"]]
    return out


def host(root):
    m = c.load(root / "METHOD-BEFORE.json")
    frozen = c.load(root / "FREEZE.json")
    index = c.load(root / "runtime/index.json")
    expected = c.load(root / "RESULTS.json")
    c.require(index["status"] != "RUNNING", "host clocks not terminal")
    c.require(index["method_sha256"] == c.digest(root / "METHOD-BEFORE.json") and index["freeze_sha256"] == c.digest(root / "FREEZE.json"), "host execution freeze differs")
    records = []
    for witness in index["rows"]:
        path = root / "runtime" / c.relative(witness["file"])
        packed = path.read_bytes()
        raw = c.unpack(packed, {"sha256": witness["gzip_sha256"], "raw_bytes": witness["raw_bytes"], "raw_sha256": witness["raw_sha256"]})
        value = json.loads(raw)
        c.require(value["step"] == witness["step"], "host record/index step differs")
        records.append({"step": value["step"], "capture_complete": value["capture_complete"], "result": c.host_result(value["result"]), "original_raw_sha256": witness["raw_sha256"], "original_gzip_sha256": witness["gzip_sha256"]})
    fields = ["status", "observations", "expected_observations", "completed", "failed", "warmup_failed", "all_complete_capacity_failure_gates", "summary", "comparisons", "decisions"]
    effective = c.load(root / "effective-inputs.json")
    return {"schema": "coaptic-portable-H-host/1", "method": method(m), "status": index["status"], "records": records, "expected": c.picked(expected, fields), "effective_inputs": c.picked(effective, ["candidate", "baseline", "companion", "original_build_sha256", "original_build_script_sha256_at_preparation", "base_input_manifest_sha256", "original_raw_labels", "recorded_raw_labels", "normalized_effective_files", "original_normalized", "effective", "explicit_staged_overrides", "explicit_staged_additions", "scope"]), "freeze": {"python_version": frozen["python_version"], "local_files_sha256": frozen["local_files_sha256"], "external_files": [{"basename": Path(k).name, "sha256": v} for k, v in frozen["external_files_sha256"].items()]}, "source_digests": {name: c.digest(root / name) for name in ["METHOD-BEFORE.json", "FREEZE.json", "RESULTS.json", "runtime/index.json", "host-build.json", "effective-inputs.json"]}, "scope": "Every retained host latency and sanitized resource vector, including failures. Original producer-record digests retained; paths, process identities and non-ledger output omitted. Fresh host loopback workload only; no isolated CPU or per-cell preservation inference from three rounds."}


def wifi_method(value):
    return c.picked(value, ["schema", "core", "runtime", "baseline", "names", "order", "candidate_names", "C_names", "control_pairs", "counts", "primary", "decision", "memory", "capacities", "limits", "source", "claims", "c_service_window_ms", "client_process_timeout_s", "clients_per_boot", "post_ota_settle_s", "capture_bound_s", "C_post_timing_terminal_bound_s", "static_control_deltas"])


def wifi(root):
    method_path = root / "INTEGRATED-IDLE-OBSERVE-METHOD-BEFORE.json"
    result_path = root / "integrated-idle-observe-comparison/result.json"
    analysis_path = root / "integrated-idle-observe-analysis.json"
    m, raw, a = [c.load(p) for p in [method_path, result_path, analysis_path]]
    c.require(raw["status"] != "running", "device clocks not terminal")
    c.require(m["core"] == c.H and m["runtime"] == c.RUNTIME, "source pins differ")
    expected = c.picked(a, ["verified_complete", "operations", "restore_verified", "stability_passed", "summary", "comparisons", "screen_decisions", "memory"])
    if "screen_decisions" in expected:
        expected["screen_decisions"] = [{k: v for k, v in z.items() if k != "scope"} for z in expected["screen_decisions"]]
    observed = {(b["name"], b["round"]): b for b in a.get("boots", [])}
    boots = []
    for index, row in enumerate(raw["cohorts"]):
        rn, slot = index // 6 + 1, index % 6
        name = m["names"][m["order"][rn - 1][slot]]
        b = observed.get((name, rn), {})
        build = row["build"]
        configuration = c.picked(build, ["core", "runtime", "io_mode", "startup_diagnostic_only", "placement_group", "task_stack_reserved_bytes", "task_core", "task_priority", "selected_opt_level", "selected_lto"])
        configuration["sdk"] = c.picked(build.get("sdk", {}), ["ESP_DEFAULT_CPU_FREQ_MHZ", "ESP32S3_INSTRUCTION_CACHE_SIZE", "ESP32S3_ICACHE_ASSOCIATED_WAYS", "ESP32S3_INSTRUCTION_CACHE_LINE_SIZE"])
        boots.append({"name": name, "round": rn, "slot": slot + 1, "mode": b.get("mode", row.get("device_mode")), "passed": row.get("passed", False), "clients": c.clients(row.get("clients", [])), "quality": c.picked(b, ["connections", "unexpected_disconnects", "connect_refusals", "application_dropped", "wait_errors"]), "network": [c.numeric(z) for z in b.get("network", [])], "heap": [{**c.numeric(z), **c.picked(z, ["phase", "caps"])} for z in b.get("heap", [])], **c.picked(b, ["stack_reserved_bytes", "stack_observed_used_bytes", "image_bytes", "settle_seconds", "compiled_task_core", "instruction_cache_bytes", "linked_iram_added_bytes", "physical_net_static_ram_added_bytes", "wifi_signal_dbm", "last_reported_uptime_seconds"]), "task_policy": c.numeric(b.get("task_policy", {})), "C_cleanup": c.numeric(b.get("C_cleanup", {})), "C_terminal": c.numeric(b.get("C_terminal", {})), "pre_timing_running_heap": {**c.numeric(row.get("pre_timing_running_heap", {})), **c.picked(row.get("pre_timing_running_heap", {}), ["phase", "caps"])}, "configuration": configuration, "image_sha256": row.get("ota_sha256"), "original_api_sha256": row.get("api_sha256")})
    return {"schema": "coaptic-portable-H-wifi/1", "method": wifi_method(m), "status": c.picked(raw, ["status", "passed", "collection_complete", "restore_verified", "restoration_attempted", "cleanup_unresolved"]), "boots": boots, "expected": expected, "source_digests": {"method": c.digest(method_path), "result": c.digest(result_path), "analysis": c.digest(analysis_path)}, "scope": "Separate full Ethernet-host/AP/ESP32-S3 WiFi development screen, including every latency and all pass/fail decisions. API/resource/source/restoration joins are private producer attestations. Original stacks/capacities retained. Only instruction-cache settings are frozen per image; data-cache defaults can only be reconstructed and are not per-image attestations. Two boot clusters are not RF/long-duration qualification or qualified tails. No H adoption or goal-completion inference."}


def startup(root):
    join_path = root / "integrated-idle-observe-comparison-startup-joins.json"
    join = c.load(join_path)
    profiles = []
    allowed = ["mode", "passed", "result_sha256", "sealed_startup_method_sha256", "qualifier_script_sha256", "single_probe_manifest_sha256", "production_image_sha256", "probe_image_sha256", "archive_sha256", "same_production_probe_archive_and_SDK", "diagnostic_overhead_bytes", "task_stack_reserved_bytes", "before_task_largest_bytes", "required_before_task_largest_bytes", "observed_lifetime_stack_used_bytes", "stack_observation_is_peak_claim", "min_observed_running_free_bytes", "min_observed_running_largest_bytes", "min_observed_running_low_water_bytes", "qualification_reads_verified", "client_modes", "client_report_sha256", "performance_operations_imported", "normal_restore_verified", "cleanup_unresolved", "evidence_write_errors"]
    for mode in ["sync", "async"]:
        profile = next(z for z in join["profiles"] if z["mode"] == mode)
        path = root / ("integrated-idle-observe-qualification-" + mode) / "result.json"
        q = c.load(path)
        c.require(c.digest(path) == profile["result_sha256"], "startup original result digest differs")
        method_path = root / ("INTEGRATED-IDLE-OBSERVE-" + mode.upper() + "-STARTUP-METHOD-BEFORE.json")
        profiles.append({"join": c.picked(profile, allowed), "status": c.picked(q, ["passed", "status", "restore_verified", "restoration_attempted", "collection_complete", "measurements_passed", "qualification_operations_verified", "performance_comparison_operations", "cleanup_unresolved"]), "state": c.numeric(q.get("startup_state", {})), "network": [c.numeric(z) for z in q.get("network", [])], "heap": [{**c.numeric(z), **c.picked(z, ["phase", "caps"])} for z in q.get("running_heap", [])], "clients": [client for row in q.get("cohorts", []) for client in c.clients(row.get("clients", []))], "method": c.picked(c.load(method_path), ["source", "runtime", "io_mode", "task_stack_reserved_bytes", "production_image_sha256", "prototype_image_sha256", "scope", "qualification_operations_planned", "performance_comparison_operations"]), "original_method_sha256": c.digest(method_path)})
    return {"schema": "coaptic-portable-H-startup/1", "candidate": join["candidate"], "runtime": join["runtime"], "passed": join["passed"], "profiles": profiles, "performance_operations_imported": join["performance_operations_imported"], "original_join_sha256": c.digest(join_path), "scope": "96 separate startup/functional qualification reads only. Every qualification latency is retained separately and excluded from both speed datasets. Numeric guards can be rechecked; source/production-probe/archive/SDK/restoration joins remain private producer attestations, not independent firmware reconstruction or physical proof."}


def git(repo, *args):
    p = subprocess.run(["git", "-c", "safe.directory=" + str(repo), "-C", str(repo), *args], capture_output=True)
    c.require(p.returncode == 0, "source Git query failed")
    return p.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-root", required=True, type=Path)
    parser.add_argument("--core-repo", required=True, type=Path)
    parser.add_argument("--suite-repo", required=True, type=Path)
    parser.add_argument("--runtime-target", required=True)
    parser.add_argument("--parent-clocks-released", action="store_true")
    args = parser.parse_args()
    c.require(args.parent_clocks_released, "parent must release timing clocks before full export")
    c.require(re.fullmatch(r"[0-9a-f]{4,40}", args.runtime_target), "runtime target must be a Git object prefix")
    out = ROOT / "package"
    out.mkdir(exist_ok=False)
    manifest = {"schema": "coaptic-portable-idle-observe/1", "baseline": c.BASE, "candidate": c.H, "compiled_runtime": c.RUNTIME, "adopted": False, "goal_complete": False, "files": {}, "source_patches": [], "scope": "Fresh exact-H host, WiFi and distinct startup qualification. Actual passing/failing gates retained; no success-only filtering. Runtime source finalizer/provenance proofs are private attestations, not full rebuild independence."}
    def save(name, value, raw=False):
        raw_data = value if raw else c.encoded(value)
        c.require(not c.private(raw_data), "private value in " + name)
        packed = gzip.compress(raw_data, compresslevel=9, mtime=0)
        current = sum(p.stat().st_size for p in ROOT.rglob("*") if p.is_file())
        c.require(current + len(packed) < c.BUDGET, "8MiB private output budget exceeded")
        path = out / c.relative(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(packed)
        manifest["files"][name] = {"sha256": c.sha(packed), "raw_sha256": c.sha(raw_data), "raw_bytes": len(raw_data), "gzip_bytes": len(packed)}
    save("host.json.gz", host(args.native_root / "idle-observe-host"))
    save("wifi.json.gz", wifi(args.native_root))
    save("startup.json.gz", startup(args.native_root))
    runtime_target = git(args.suite_repo, "rev-parse", args.runtime_target + "^{commit}").decode().strip()
    for kind, repo, base, target in [("core", args.core_repo, c.BASE, c.H), ("runtime", args.suite_repo, "e602a261fac18d839e92def713ae410f7c78d15d", c.RUNTIME), ("runtime-finalizer", args.suite_repo, c.RUNTIME, runtime_target)]:
        patch = git(repo, "diff", "--binary", base, target, "--")
        c.require(b"GIT binary patch" not in patch, "binary source delta is outside public package")
        name = "sources/" + kind + "-" + target + ".patch.gz"
        save(name, patch, True)
        manifest["source_patches"].append({"kind": kind, "base": base, "target": target, "patch": name, "tree_sha1": git(repo, "rev-parse", target + "^{tree}").decode().strip(), "compiled_image_source_claim": kind != "runtime-finalizer"})
    for name in ["common.py", "portable_host.py", "export.py", "verify.py", "test_export.py", "README.md", ".gitattributes"]:
        (out / name).write_bytes((ROOT / name).read_bytes())
    (out / "manifest.json").write_bytes(c.encoded(manifest))
    print(json.dumps({"exported": True, "compressed_members": len(manifest["files"]), "private_total_bytes": sum(p.stat().st_size for p in ROOT.rglob("*") if p.is_file()), "budget_bytes": c.BUDGET}, indent=2))


if __name__ == "__main__":
    main()
