"""Export completed measurements through explicit allowlists. Never builds or uses hardware."""
from pathlib import Path, PurePosixPath
from collections import Counter
import argparse
import gzip
import hashlib
import json
import re
import subprocess

BASELINE = "a85c51e689607051e36e450567fe051f8f85dc2b"
SUITE_BASE = "e602a261fac18d839e92def713ae410f7c78d15d"
BUDGET = 64 * 1024 * 1024
CPU = ["body-inspection", "snapshot-only", "outlined-async", "cold-async", "compact-expiry", "borrow-path-fill", "handler-request", "request-context"]
HASH = re.compile(r"^[0-9a-f]{64}$")
REF = re.compile(r"^[0-9a-f]{40}$")

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()

def numeric_map(value):
    return {k: v for k, v in value.items() if type(v) in [int, float, bool] or v is None}

def cpu_sample(raw, cell, count):
    kind, profile, security, mode, size = cell
    assert (raw["operations"], raw["security"], raw["payload_bytes"]) == (count, security, size)
    if kind == "retained":
        assert raw["mode"] == mode and raw["storage"] == profile and raw["verified"] == count + 128
        assert raw["requests_per_operation"] == 2 and raw["data_packets_per_operation"] == 11
        field = "cycles"
    elif profile == "small-device":
        assert raw["black_box"] is True and raw["dedup"] == 4
        field = "latencies_cycles"
    else:
        assert raw["black_box"] is True and raw["verified"] == count + 128 and raw["expiry_probe"] == "steady"
        assert raw["server_capacities"]["dedup"] == 64
        assert raw["server_poll_counts"] == [(size + 1023) // 1024] * count
        field = "server_poll_cpu_cycles_sum"
    values = raw[field]
    assert len(values) == count and all(type(v) is int and v > 0 for v in values)
    scalar_keys = ["operations", "warmup", "verified", "black_box", "calibration_samples", "concurrency", "routes", "populated_routes", "calls", "deferred", "security_requests", "associations", "rx_slots", "rx_datagram_bytes", "tx_slots", "tx_datagram_bytes", "dedup", "observe", "rx_body_slots", "tx_body_slots", "app_inline_bytes", "blockwise", "requests_per_operation", "data_packets_per_operation"]
    return {"cycles_sum": sum(values), "cycles_count": len(values), "cycles_min": min(values), "cycles_max": max(values), "counter_field": field, "scalars": {k: raw[k] for k in scalar_keys if k in raw}, "capacities": {k: numeric_map(raw[k]) for k in ["server_capacities", "client_capacities", "sends", "memory"] if k in raw}}

def export_cpu(root, stem):
    analysis_path = root / (stem + "-cpu-analysis.json")
    analysis = load(analysis_path)
    p = root / (stem + "-host")
    method = load(p / "METHOD.json")
    measurement = load(p / "measurement.json")
    assert analysis["verified_complete"] and measurement["status"] == "complete"
    assert method["baseline"] == analysis["baseline"] == BASELINE
    assert method["candidate"] == analysis["candidate"] and method["process_pairs"] == 64
    assert method["orders"] == ["AB", "BA", "BA", "AB"] * 16 and method["cpu"] == 0
    cells = method["cells"]
    assert len(cells) == 28 and len({tuple(c) for c in cells}) == 28
    events_path = p / "process-exits.jsonl"
    events = [json.loads(z) for z in events_path.read_text(encoding="utf-8-sig").splitlines() if z.strip()]
    event_map = {z["label"]: z for z in events}
    assert len(event_map) == len(events) == 3640
    records = []
    def one(label, cell, count, arm, pair):
        path = p / (label + ".json")
        raw_digest = digest(path)
        assert raw_digest == analysis["inputs"]["raw_reports_sha256"][path.name]
        assert (p / (label + ".stderr")).stat().st_size == 0
        raw = load(path)
        event = event_map[label]
        assert event["exit_code"] == 0 and not event.get("timeout")
        assert event["stdout_bytes"] == path.stat().st_size
        value = cpu_sample(raw, cell, count)
        value.update(label=label, cell=cell, arm=arm, pair=pair, raw_report_sha256=raw_digest, exit_code=0, timeout=False)
        records.append(value)
    for cell in cells:
        name = "-".join(map(str, cell))
        for arm in ["A", "B"]:
            one("qualify-" + arm + "-" + name, cell, 8, arm, None)
    for pair, order in enumerate(method["orders"]):
        for cell in cells:
            name = "-".join(map(str, cell))
            for arm in order:
                one("measure-" + str(pair) + "-" + name + "-" + arm, cell, 8192 if cell[-1] in [32, 1024] else 1024, arm, pair)
    assert [r["label"] for r in records] == [z["label"] for z in events]
    assert sum(r["cycles_count"] for r in records if r["pair"] is not None) == analysis["measured_operations"] == 14680064
    return {"schema": "coaptic-cpu-sufficient-statistics/1", "name": stem, "baseline": BASELINE, "candidate": analysis["candidate"], "method": {k: method[k] for k in ["cells", "operations", "warmup", "process_pairs", "orders", "cpu", "binaries"]}, "records": records, "expected": {k: analysis[k] for k in ["runtime_accepted", "measured_processes", "qualification_processes", "measured_operations", "groups", "summary", "failed_cell_guards"]}, "source_digests": {"analysis": digest(analysis_path), "method": digest(p / "METHOD.json"), "measurement": digest(p / "measurement.json"), "process_exits": digest(events_path)}, "scope": "Exact integer sums/counts for every original process, the statistical units used for all aggregate and guard claims. Individual operation cycle vectors and calibration arrays remain privately retained; this export does not reproduce CPU tails or reconstruct full raw reports."}

def host_sample(sample):
    scalar = ["schema", "protocol", "security", "mode", "concurrency", "warmup", "attempted", "completed", "failed", "warmup_failed", "driver_failures", "endpoint_rotations", "verified_bytes", "elapsed_ns"]
    out = {k: sample[k] for k in scalar}
    out["latencies_ns"] = sample["latencies_ns"]
    assert sample["completed"] == len(out["latencies_ns"]) and all(type(z) is int and z > 0 for z in out["latencies_ns"])
    return out

def export_host(root):
    raw = load(root / "runtime.json")
    method = load(root / "RUNTIME-METHOD.json")
    expected = load(root / "RESULTS.json")
    assert raw["status"] == "COMPLETE" and expected["verified_against_raw"] and method["core"] == BASELINE
    rows = []
    for row in raw["rows"]:
        value = row["result"]
        rows.append({"round": row["round"], "peer": row["peer"], "case": row["case"], "sample": host_sample(value["sample"]), "exit_code": value["exit_code"], "loaded_memory": numeric_map(value["loaded"]["after"]["memory"]), "idle_one_core_percent": value["idle"]["one_core_percent"]})
    prov = load(root / "host-provenance.json")
    versions = prov["retained_peer_versions"]
    return {"schema": "coaptic-host-comparison/1", "core": BASELINE, "companion": prov["companion"], "rows": rows, "method": {"rounds": 3, "peers": [p["id"] for p in method["peers"]], "cases": method["cases"]}, "source_pins": {k: versions[k] for k in ["coap_rs", "coap_lite", "libcoap_tag", "libcoap_commit"]}, "binary_sha256": {**prov["new_binaries"], **versions["binaries"]}, "expected": expected["host"], "source_digests": {n: digest(root / n) for n in ["runtime.json", "RUNTIME-METHOD.json", "RESULTS.json", "host-provenance.json"]}, "scope": "Seven implementations, four body sizes, three concurrency levels and three rounds. Complete unprotected operations; throughput is not isolated CPU. Sampled private memory is process memory, not library or peak RAM. Spin burns a busy core while idle."}

def wifi_operation(raw):
    keys = ["passed", "iteration", "path", "bytes", "elapsed_ns", "prepare_ns", "poll_ns", "checkpoint_ns", "take_ns", "verify_ns", "sleep_ns"]
    out = {k: raw[k] for k in keys}
    assert raw["passed"] and type(out["elapsed_ns"]) is int and 0 < out["elapsed_ns"] < 5000000000
    out["request_send_ids"] = [e[4] for e in raw["events"] if e[0] == 2 and e[3] > 4]
    return out

def export_wifi(root, stem):
    analysis_path = root / (stem + "-analysis.json")
    analysis = load(analysis_path)
    p = root / (stem + "-comparison")
    raw_path = p / "result.json"
    raw = load(raw_path)
    method_path = root / ("NATIVE-" + ("HOT" if stem == "native-hot" else "PIPELINE") + "-METHOD-BEFORE.json")
    method = load(method_path)
    assert raw["passed"] and raw["collection_complete"] and raw["restore_verified"] and analysis["verified_complete"] and analysis["restore_verified"]
    boots = []
    for i, row in enumerate(raw["cohorts"]):
        mode = row["device_mode"]
        name = method["names"][method["order"][i // len(method["names"])][i % len(method["names"])]]
        observations = []
        for client in row["clients"]:
            lines = [json.loads(z) for z in Path(client["report_path"]).read_text(encoding="utf-8-sig").splitlines() if z.strip()]
            assert digest(client["report_path"]) == client["source_report_sha256"] and client["passed"] and lines[-1]["passed"]
            ops = [wifi_operation(z) for z in lines if z.get("case") == "complete_operation"]
            observations.append({"mode": client["mode"], "ordinal": client["ordinal"], "operations": ops, "raw_report_sha256": client["source_report_sha256"], "passed": True})
        observed = analysis["boots"][i]
        assert observed["name"] == name
        build = row["build"]
        boots.append({"name": name, "round": row["boot_round"], "slot": row["slot"], "mode": mode, "passed": row["passed"], "clients": observations, "resources": {"network": [numeric_map(z) for z in observed["network"]], "heap": [{**numeric_map(z), **{k: z[k] for k in ["phase", "caps"] if k in z}} for z in observed["heap"]]}, "quality": {k: observed[k] for k in ["connections", "unexpected_disconnects", "connect_refusals", "application_dropped", "wait_errors"]}, "wifi_signal_dbm": observed["wifi_signal_dbm"], "stack_reserved_bytes": observed["stack_reserved_bytes"], "stack_observed_used_bytes": observed["stack_observed_used_bytes"], "image_sha256": row["ota_sha256"], "configuration": {"core": build.get("core"), "runtime": build.get("runtime"), "sdk": build["sdk"], "task_stack_reserved_bytes": build["task_stack_reserved_bytes"], "task_core": build["task_core"], "task_priority": build["task_priority"], "extra_static_bytes": build["prospective_net_ram_added_vs_clean_cache32_bytes"], "linked_iram_added_bytes": build["iram_added_vs_clean_cache32_bytes"]}})
    return {"schema": "coaptic-wifi-comparison/1", "name": stem, "baseline": BASELINE, "core": method["core"], "runtime": method["runtime"], "method": {k: method[k] for k in ["names", "order", "candidate_names", "C_names", "control_pairs"]}, "boots": boots, "expected": {k: analysis[k] for k in ["operations", "stability_passed", "summary", "comparisons", "screen_decisions", "memory"]}, "normal_restored_verified": True, "source_digests": {"analysis": digest(analysis_path), "raw_result": digest(raw_path), "method": digest(method_path)}, "scope": "Separate complete unprotected GET/Block2 Wi-Fi cohort, Ethernet host through AP to ESP32-S3 Wi-Fi. Original96/192KiB Rust workers,16KiB C worker. Rust Constrained8routes(7used),4Calls,0deferred,2x1152B RX/TX,1x4096B RX/TXbody,dedup4,Observe2,8Btoken; C dynamicPDU/session behavior matches fixture, not all-feature/capacity parity. Two opposite boot orders,32reads per client/body cell; descriptive tails, not CI/RF/long-duration qualification. MAC/IP/credentials/runIDs/rawAPI/firmware/ELF omitted. Settling is30safterOTA and>=500msafterreadiness; no imposed500msinteroperation gap."}

def git(repo, *args):
    p = subprocess.run(["git", "-c", "safe.directory=" + str(repo), "-C", str(repo), *args], capture_output=True)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    return p.stdout

def forbidden(raw):
    text = raw.decode("utf-8")
    patterns = [
        r"(?<![a-z])[a-z]:[\\/]", r"/Users/|/home/",
        r"192\.168\.", r"\b10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b",
        r"\b172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b",
        r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b",
        r"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b",
        r"noise_psk|private-checkpoints|t3-thread://|agentboard",
    ]
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def input_map(value):
    assert isinstance(value, dict) and len(value) == 181
    for name, sha in value.items():
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts
        assert ":" not in name and "\\" not in name and path.suffix in [".rs", ".toml", ".lock"]
        assert HASH.fullmatch(sha)
    return value


def export_inputs(root):
    builds = {digest(p): p for p in root.glob("*build*/build.json")}
    rows = []
    for stem in CPU:
        analysis = load(root / (stem + "-cpu-analysis.json"))
        sha = analysis["inputs"]["build_sha256"]
        build = load(builds[sha])
        assert build["passed"] and build["baseline"] == BASELINE and build["candidate"] == analysis["candidate"]
        reused = build.get("baseline_build_manifest_sha256")
        baseline = build.get("inputs_baseline")
        if baseline is None:
            assert HASH.fullmatch(reused)
            baseline = load(builds[reused])["inputs_baseline"]
        flags = {arm: build["host"][arm]["flags"] for arm in ["baseline", "candidate"]}
        assert flags["baseline"] == flags["candidate"] == {"RUSTFLAGS": "-Cforce-frame-pointers=yes", "release_debug": 1, "opt-level": 3, "lto": "thin", "codegen-units": 1}
        rows.append({"name": stem, "baseline": BASELINE, "candidate": build["candidate"], "companion": build["companion"], "runtime": build["runtime"], "passed": True, "device_action": build["device_action"], "source_build_sha256": sha, "baseline_build_manifest_sha256": reused, "inputs_baseline": input_map(baseline), "inputs_candidate": input_map(build["inputs_candidate"]), "flags": flags, "qualification": build.get("qualification")})
    return {"schema": "coaptic-host-input-hashes/1", "cohorts": rows, "scope": "Original 181-file host build closure for each arm/cohort, with exact source-build digests and unchanged host flags. Snapshot-only baseline map follows its explicit reused build digest. Hashes do not recreate absent files or prove execution. Toolchains and dependency lock sources remain required."}


def preflight_fields(value):
    keys = ["scope", "future_smaller", "baseline", "candidate", "baseline_future_bytes", "candidate_future_bytes", "observed_future_growth_bytes", "label", "baseline_log_sha256", "candidate_log_sha256", "device_action", "goal_complete", "limits", "seconds"]
    result = {k: value[k] for k in keys if k in value}
    if "rows" in value:
        result["rows"] = [{k: row[k] for k in ["arm", "bytes", "line", "log_sha256"] if k in row} for row in value["rows"]]
    return result


def export_methods(native, host):
    host_method = load(host / "RUNTIME-METHOD.json")
    versions = load(host / "host-provenance.json")["retained_peer_versions"]
    go = versions["go_binary_modules"]
    go_version = re.search(r"\bgo[0-9]+\.[0-9]+(?:\.[0-9]+)?\b", go).group(0)
    go_modules = [line for line in go.splitlines() if line.startswith(("\tpath\t", "\tmod\t", "\tdep\t", "\tbuild\t"))]
    clang = [line for line in versions["clang"].splitlines() if line.startswith(("clang version", "Target:", "Thread model:"))]
    python = {k: versions["python"][k] for k in ["aiocoap", "python", "exe_sha256", "zip_sha256"]}
    cpu = []
    for stem in CPU:
        p = native / (stem + "-host") / "METHOD.json"
        method = load(p)
        keys = ["primary", "limits", "memory_gate", "output_capture", "interval", "compiler_future_preflight", "raw_output_budget_bytes"]
        cpu.append({"name": stem, "source_method_sha256": digest(p), "method": {k: preflight_fields(method[k]) if k == "compiler_future_preflight" else method[k] for k in keys}})
    wifi = []
    for stem, filename in [("native-hot", "NATIVE-HOT-METHOD-BEFORE.json"), ("native-pipeline", "NATIVE-PIPELINE-METHOD-BEFORE.json")]:
        p = native / filename
        method = load(p)
        keys = ["primary", "decision", "memory", "capacities", "limits", "counts", "c_service_window_ms", "client_process_timeout_s", "clients_per_boot", "post_ota_settle_s", "capture_bound_s", "C_post_timing_terminal_bound_s"]
        wifi.append({"name": stem, "source_method_sha256": digest(p), "method": {k: method[k] for k in keys}})
    result = {"schema": "coaptic-method-provenance/1", "cpu": cpu, "wifi": wifi, "host": {"source_method_sha256": digest(host / "RUNTIME-METHOD.json"), "method": {k: host_method[k] for k in ["seed", "primary", "secondary", "limits", "scope"]}, "versions": {"rustc": versions["rustc"], "clang": clang, "python": python, "go": go_version, "go_module_metadata": go_modules}}, "scope": "Frozen methodology, limits, selected compiler/peer version records and future preflight. Installation/executable/log paths and original endpoint-specific Wi-Fi description omitted. Wi-Fi scope is Ethernet host through access point to ESP32-S3 Wi-Fi. Not a self-contained compiler/dependency/firmware rebuild environment; native archive provenance and original build logs remain private."}
    assert not forbidden(encoded(result)), "Review selected method provenance before exporting"
    return result


def export_fixture(root):
    manifest = load(root / "manifest.json")
    files, omitted = {}, {}
    for name, sha in manifest["files"].items():
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts and ":" not in name and "\\" not in name
        assert path.suffix in [".rs", ".toml", ".lock"] and HASH.fullmatch(sha)
        local = root / "files" / name
        assert local.resolve().is_relative_to(root.resolve()) and not local.is_symlink() and digest(local) == sha
        raw = local.read_bytes()
        if forbidden(raw):
            omitted[name] = {"sha256": sha, "reason": "Private network address literals in fixture tests; original retained privately."}
        else:
            files[name] = {"sha256": sha, "text": raw.decode("utf-8")}
    assert len(files) == 41 and list(omitted) == ["tools/esphome/rust/src/bin/waveshare_peer/timing_server.rs"]
    return {"schema": "coaptic-fixture-source-snapshot/1", "core": manifest["core"], "suite": manifest["suite"], "source_manifest_sha256": manifest["source_manifest_sha256"], "files": files, "omitted": omitted, "scope": "Exact non-core fixture snapshot for request-context dc1/35bac only, captured before later staging. Forty-one complete UTF-8 source/lock files, plus one omitted file digest because its test literals contain private addresses. This is not the source snapshot of every earlier cohort or a complete firmware build bundle. All 42 originals remain privately retained."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-root", required=True, type=Path)
    parser.add_argument("--host-root", required=True, type=Path)
    parser.add_argument("--core-repo", required=True, type=Path)
    parser.add_argument("--suite-repo", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--fixture-snapshot", required=True, type=Path)
    args = parser.parse_args()
    out = args.destination.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert not (out / "manifest.json").exists(), "Preserve existing export"
    manifest = {"schema": "coaptic-speed-evidence/1", "baseline": BASELINE, "suite_baseline": SUITE_BASE, "adopted": False, "goal_complete": False, "files": {}, "source_patches": [], "scope": "Completed datasets only. Eight rejected CPU candidates and two failed native development screens. No new optimization acceptance or merge claim."}
    def save(name, value, raw=False):
        data = value if raw else encoded(value)
        assert not forbidden(data), "Private value in " + name
        path = out / name
        assert not path.exists(), "Preserve " + name
        path.parent.mkdir(parents=True, exist_ok=True)
        packed = gzip.compress(data, mtime=0, compresslevel=9)
        path.write_bytes(packed)
        manifest["files"][name] = {"sha256": hashlib.sha256(packed).hexdigest(), "uncompressed_sha256": hashlib.sha256(data).hexdigest(), "uncompressed_bytes": len(data)}
        assert sum(p.stat().st_size for p in out.rglob("*") if p.is_file()) < BUDGET
    refs = {BASELINE, "c0151713fc187a4a2b8ed3cba1eb0b12df597d00"}
    suite_refs = {"32f8fcac22fc16b1957c35f4f145df6be3a72532", "35bac1e2b131979cd209a4ceb825f1ab081147b4"}
    for stem in CPU:
        data = export_cpu(args.native_root, stem)
        refs.add(data["candidate"])
        save("cpu/" + stem + ".json.gz", data)
        for pre in args.native_root.glob("*METHOD-BEFORE.json"):
            v = load(pre)
            if v.get("candidate") == data["candidate"]:
                for k in ["companion", "runtime"]:
                    if REF.fullmatch(str(v.get(k, ""))):
                        suite_refs.add(v[k])
    save("sources/method-provenance.json.gz", export_methods(args.native_root, args.host_root))
    save("sources/host-inputs.json.gz", export_inputs(args.native_root))
    save("sources/request-context-fixture.json.gz", export_fixture(args.fixture_snapshot))
    save("host.json.gz", export_host(args.host_root))
    for stem in ["native-hot", "native-pipeline"]:
        save("wifi/" + stem + ".json.gz", export_wifi(args.native_root, stem))
    for kind, repo, base, values in [("core", args.core_repo, BASELINE, refs - {BASELINE}), ("suite", args.suite_repo, SUITE_BASE, suite_refs - {SUITE_BASE})]:
        for ref in sorted(values):
            assert REF.fullmatch(ref)
            name = "sources/" + kind + "-" + ref + ".patch.gz"
            patch = git(repo, "diff", "--binary", base, ref, "--")
            assert b"GIT binary patch" not in patch, "Review binary source delta"
            save(name, patch, raw=True)
            manifest["source_patches"].append({"kind": kind, "base": base, "target": ref, "patch": name, "tree_sha1": git(repo, "rev-parse", ref + "^{tree}").decode().strip()})
    (out / "manifest.json").write_bytes(encoded(manifest))
    print(json.dumps({"files": len(manifest["files"]), "compressed_bytes": sum(p.stat().st_size for p in out.rglob("*") if p.is_file()), "adopted": False}, indent=2))

if __name__ == "__main__":
    main()
