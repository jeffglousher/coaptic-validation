"""Verify retained observations independently, without builds or native execution.

Run with Python's standard library: python -B verify.py
Source reconstruction belongs to prepare.py; this script verifies patch/manifest
coherence, exact retained bytes, selected memory records and paired arithmetic.
Resident owners, complete futures and native frames are reported separately.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import math
import re
import statistics
import zipfile


ROOT = Path(__file__).resolve().parent
BASELINE = "fd7d18a72f795779e352443ebdeef9533be7fb27"
MEASURED_BASELINE = "3e592adb1fd52c5e6918af1b4e810bb874413bad"
PHASE = ROOT.parent / "phase-sharing-static-20261106"
OWNERSHIP = ROOT.parent / "response-ownership-20261106"
CELLS = [["ordinary", p, s, m, n]
         for p in ("small-device", "service-fixed", "service-allocated")
         for s in ("unprotected", "oscore") for m in ("sync", "async")
         for n in ([32] if p == "small-device" else [1024, 16384])]
CELLS += [["retained", p, s, m, 11264] for p in ("fixed", "allocated")
          for s in ("unprotected", "oscore") for m in ("sync", "async")]
ORDERS = ["AB", "BA", "BA", "AB"] * 16
CAPACITIES = ("server_capacities", "client_capacities", "routes", "calls",
              "deferred", "security_requests", "associations", "rx_slots",
              "rx_datagram_bytes", "tx_slots", "tx_datagram_bytes", "dedup",
              "observe", "rx_body_slots", "tx_body_slots", "blockwise")
REDUCIBLE = {"app_including_transport_inline_bytes",
             "server_app_including_transport_inline_bytes", "server_pool_requested_heap_bytes",
             "client_app_including_transport_inline_bytes", "client_pool_requested_heap_bytes"}
EXPORTED = ("source-verification.json", "candidate.patch", "METHOD-BEFORE.json",
            "METHOD.json", "measurement.json", "preflight-host.json",
            "dispatch-preflight.json", "memory-preflight.json", "review.json",
            "qualification.json")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def record(archive, name):
    return json.loads(archive.read(name))


def checked_member(directory, archive_name, manifest_name, name):
    expected = read(directory / manifest_name)[name]
    with zipfile.ZipFile(directory / archive_name) as archive:
        data = archive.read(name)
    assert digest(data) == expected, (archive_name, name)
    return data


def interval(ratios):
    assert len(ratios) == 64
    logs = list(map(math.log, ratios))
    mean = statistics.mean(logs)
    return {"ratio": math.exp(mean),
            "upper95": math.exp(mean + 1.67 * statistics.stdev(logs) / 8)}


def close(actual, expected):
    assert all(math.isclose(actual[k], expected[k], rel_tol=1e-12)
               for k in ("ratio", "upper95")), (actual, expected)


def layouts(data):
    pairs = re.findall(r"^print-type-size type: `(.*)`: (\d+) bytes, alignment:",
                       data.decode(), re.M)
    assert len(pairs) == len(dict(pairs)), "Duplicate compiler layout owners"
    return {name: int(size) for name, size in pairs}


def futures(records):
    prefix = "{async fn body of coaptic::app::async_server::<impl coaptic::App<"
    selected = {}
    for name, size in records.items():
        if not name.startswith(prefix) or "::progress_async<" not in name:
            continue
        if "profiles::Constrained, CoreIo, 4, false" in name:
            owner = "SmallDevice"
        elif "profiles::Service, ServiceIo, 32, true" in name:
            owner = "Service allocated" if "::AllocMemory," in name else "Service fixed"
        else:
            continue
        assert owner not in selected
        selected[owner] = size
    assert set(selected) == {"SmallDevice", "Service fixed", "Service allocated"}
    return selected


def symbols(data, marker):
    result = {}
    for chunk in re.split(r"(?=^\s*\d+ \| S_[LG]PROC32)", data.decode(), flags=re.M):
        chunk = chunk.lstrip()
        if marker not in chunk:
            continue
        header = chunk.splitlines()[0]
        name = header.split("`", 1)[1].rstrip("`")
        frame = int(re.search(r"\n +size = (\d+), padding size", chunk)[1])
        code = int(re.search(r"code size = (\d+)", chunk)[1])
        assert name not in result, name
        result[name] = (frame, code)
    assert result, marker
    return result


def dispatch(data):
    result = {}
    for name, values in symbols(data, "dispatch_rx_io_async::async_fn$0<").items():
        profile = ("SmallDevice" if "profiles::Constrained" in name else
                   "Service" if "profiles::Service" in name else "Default")
        storage = "allocated" if "async_fn$0<coaptic::storage::alloc_memory::AllocMemory" in name else "fixed"
        assert (profile, storage) not in result
        result[profile, storage] = values
    assert set(result) == {("SmallDevice", "fixed"), ("Service", "fixed"),
                           ("Default", "allocated"), ("Service", "allocated")}
    return result


def ledger(a, b):
    """Keep nested fields as invariants; do not add them to their owners."""
    for key in CAPACITIES:
        assert (key in a) == (key in b), key
        if key in a:
            assert a[key] == b[key], key
    assert ("memory" in a) == ("memory" in b)
    if "memory" in a:
        assert set(a["memory"]) == set(b["memory"])
        for key, value in a["memory"].items():
            if key in REDUCIBLE:
                assert type(b["memory"][key]) is int and 0 <= b["memory"][key] <= value, key
            else:
                assert b["memory"][key] == value, key
    assert ("app_inline_bytes" in a) == ("app_inline_bytes" in b)
    if "app_inline_bytes" in a:
        assert type(b["app_inline_bytes"]) is int and 0 <= b["app_inline_bytes"] <= a["app_inline_bytes"]


def resident(sample):
    """Only disjoint server App and external requested pool heap bytes."""
    if "memory" not in sample:
        return {"app_inline_bytes": sample["app_inline_bytes"]}
    memory = sample["memory"]
    if "app_including_transport_inline_bytes" in memory:
        return {"app_inline_bytes": memory["app_including_transport_inline_bytes"]}
    inline = memory["server_app_including_transport_inline_bytes"]
    heap = memory["server_pool_requested_heap_bytes"]
    return {"app_inline_bytes": inline, "pool_requested_heap_bytes": heap,
            "server_resident_requested_bytes": inline + heap}


def verify_archive(path, manifest_path, metadata_path=None):
    hashes = read(manifest_path)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)) == len(hashes)
        assert set(names) == set(hashes)
        for name, expected in hashes.items():
            parts = PurePosixPath(name)
            assert not parts.is_absolute() and ".." not in parts.parts and "\\" not in name
            assert parts.name != "OWNER.json" and not parts.name.endswith("-notice.json")
            assert parts.name != "timing-resource-status.json"
            assert digest(archive.read(name)) == expected, name
        size = sum(info.file_size for info in archive.infolist())
    if metadata_path is not None and metadata_path.exists():
        metadata = read(metadata_path)
        assert metadata["members"] == len(hashes)
        assert metadata["uncompressed_bytes"] == size
        assert metadata["archive_sha256"] == digest(path.read_bytes())
    return len(hashes)


def verify_source_manifest(hashes, baseline_hashes, patch):
    """Keep all 148 baseline inputs; prove each added Rust file from its patch."""
    assert len(baseline_hashes) == 148
    assert baseline_hashes.keys() <= hashes.keys(), "Baseline source inputs cannot disappear"
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values())
    if patch is None:
        assert hashes == baseline_hashes
        return
    blocks = {}
    for block in re.split(rb"(?=^diff --git )", patch.replace(b"\r\n", b"\n"), flags=re.M):
        if not block:
            continue
        match = re.match(rb"diff --git a/(.+) b/\1\n", block)
        assert match, "Unsupported patch path header"
        name = match[1].decode()
        assert name not in blocks, name
        blocks[name] = block
    changed = set(blocks)
    added = hashes.keys() - baseline_hashes.keys()
    changed_core_rust = {name for name in changed
                         if name.startswith(("src/", "crates/")) and name.endswith(".rs")}
    assert changed_core_rust <= hashes.keys(), "Patched Rust source is missing from manifest"
    assert changed & hashes.keys() == added | {
        name for name in baseline_hashes if hashes[name] != baseline_hashes[name]}
    for name in added:
        path = PurePosixPath(name)
        assert name.startswith(("src/", "crates/")) and name.endswith(".rs")
        assert not path.is_absolute() and ".." not in path.parts and "\\" not in name
        block = blocks[name]
        assert b"\nnew file mode 100644\n" in block
        assert b"\n--- /dev/null\n+++ b/" + name.encode() + b"\n" in block
        hunks = list(re.finditer(rb"^@@ -0,0 \+1(?:,(\d+))? @@[^\n]*\n", block, re.M))
        assert len(hunks) == 1, "Added Rust files require their complete creation hunk"
        count = int(hunks[0][1] or b"1")
        lines = block[hunks[0].end():].splitlines(keepends=True)
        no_newline = lines[-1:] == [b"\\ No newline at end of file\n"]
        if no_newline:
            lines.pop()
        assert len(lines) == count and all(line.startswith(b"+") for line in lines)
        data = b"".join(line[1:] for line in lines)
        if no_newline:
            assert data.endswith(b"\n")
            data = data[:-1]
        assert digest(data) == hashes[name], name


def verify_source(archive, baseline_source):
    source = record(archive, "source-verification.json")
    before = record(archive, "METHOD-BEFORE.json")
    pin = source["source"]
    assert re.fullmatch(r"[0-9a-f]{40}", pin) and pin != BASELINE
    assert source["baseline"] == before["baseline"] == BASELINE
    assert before["candidate"] == pin
    patch = archive.read("candidate.patch")
    assert digest(patch) == source["patch_sha256"]
    hashes = source["source_file_hashes"]
    baseline_hashes = baseline_source["source_file_hashes"]
    verify_source_manifest(hashes, baseline_hashes, patch)
    # Contextual patches do not contain complete changed files. prepare.py checks
    # their full hashes after reconstructing the pinned baseline plus this patch.
    reuse = record(archive, "baseline-reuse.json")
    assert reuse["merged_baseline"] == BASELINE and reuse["measured_source"] == MEASURED_BASELINE
    assert reuse["exact_source_files"] == 148
    fixture = record(archive, "fixture-sha256.json")
    assert fixture == read(OWNERSHIP / "original-fixture-sha256.json") and len(fixture) == 7
    for name, expected in fixture.items():
        path = ROOT.parent / "dispatch-scratch-20261104/fixture" / name.replace("\\", "/")
        assert digest(path.read_bytes()) == expected, name
    return pin, reuse, len(hashes)


def verify_memory(archive, pin, source_count, baseline_layout, baseline32, baseline_dispatch, baseline_frames):
    current = layouts(archive.read("owner-layout-2.txt"))
    required = {name for name in baseline_layout if name.startswith("coaptic::")}
    assert required <= current.keys()
    assert len([name for name in required if name.startswith("coaptic::App<")]) == 6
    app_rows = [{"owner": name, "baseline": baseline_layout[name], "candidate": current[name]}
                for name in sorted(required)]
    a_future, b_future = futures(baseline_layout), futures(current)
    assert a_future == {"SmallDevice": 15952, "Service fixed": 15496, "Service allocated": 15496}
    future_rows = [{"owner": name + " complete progress future", "baseline": a_future[name],
                    "candidate": b_future[name]} for name in a_future]
    target = layouts(archive.read("layout32/candidate-layout.txt"))
    assert baseline32.keys() <= target.keys()
    target_rows = [{"owner": name, "baseline": size, "candidate": target[name]}
                   for name, size in baseline32.items()]
    frame_rows = {}
    for kind, symbol_file, marker in (("encoder", "candidate-encoder-symbols.txt", "encode_issued<"),
                                      ("reclaim", "reclaim-symbols.txt", "evict_one_dedup_pin<")):
        parsed = symbols(archive.read(symbol_file), marker)
        a = baseline_frames[kind]
        assert parsed.keys() == a.keys()
        declared = record(archive, kind + "-frames.json")
        declared = declared["rows"] if kind == "reclaim" else declared
        assert len(declared) == len(parsed)
        for row in declared:
            name = row["symbol"].split("`", 1)[1].rstrip("`")
            frame = row["candidate"] if kind == "reclaim" else row["frame"]
            assert parsed[name] == (frame, row["code_bytes"])
            assert digest(archive.read(row["assembly"])) == row["sha256"]
        # Producer preserves the closing backtick in its comparison key.
        frame_rows[kind] = [{"symbol": name + "`", "baseline": values[0],
                             "candidate": parsed[name][0]} for name, values in a.items()]
    current_dispatch = dispatch(archive.read("dispatch-symbols.txt"))
    declared_dispatch = record(archive, "dispatch-preflight.json")
    assert len(declared_dispatch["rows"]) == 4
    seen = set()
    for row in declared_dispatch["rows"]:
        key = row["profile"], row["storage"]
        assert key not in seen
        seen.add(key)
        assert current_dispatch[key] == (row["frame_bytes"], row["code_bytes"])
        assert baseline_dispatch[key] == (row["baseline_frame_bytes"], row["baseline_code_bytes"])
    dispatch_ok = all(values[0] <= baseline_dispatch[key][0] for key, values in current_dispatch.items())
    assert declared_dispatch["nongrowth"] == dispatch_ok
    preflight = record(archive, "preflight-host.json")
    for key, actual in (("future_rows", future_rows), ("app_rows", app_rows), ("layout32", target_rows)):
        assert sorted(preflight[key], key=lambda row: row["owner"]) == sorted(actual, key=lambda row: row["owner"]), key
    for kind, actual in frame_rows.items():
        assert sorted(preflight["frames"][kind], key=lambda row: row["symbol"]) == sorted(actual, key=lambda row: row["symbol"])
    assert preflight["source_hashes_verified"] == source_count and preflight["dispatch_nongrowth"] == dispatch_ok
    rows = future_rows + app_rows + target_rows + sum(frame_rows.values(), [])
    accepted = (all(row["candidate"] <= row["baseline"] for row in rows)
                and all(b_future[name] < a_future[name] for name in ("Service fixed", "Service allocated"))
                and dispatch_ok)
    memory = record(archive, "memory-preflight.json")
    assert memory["source"] == pin and memory["memory_accepted"] == accepted
    return {"memory_preflight_accepted": accepted,
            "complete_future_reductions_bytes": {name: a_future[name] - b_future[name] for name in a_future},
            "dispatch_frame_deltas_bytes": {" ".join(key): value[0] - baseline_dispatch[key][0]
                                             for key, value in current_dispatch.items()},
            "host_owner_records": len(app_rows), "thumb_owner_records": len(target_rows)}


def verify_cohort(archive, pin, reuse, baseline_binaries):
    method, result = record(archive, "METHOD.json"), record(archive, "measurement.json")
    assert method["baseline"] == BASELINE and method["candidate"] == pin
    assert method["cells"] == CELLS and method["process_pairs"] == 64
    assert method["orders"] == ORDERS and method["warmup"] == 128 and method["cpu"] == 0
    assert result["status"] == "complete" and len(result["rows"]) == 1792
    for kind, filename in (("ordinary", "dispatch-probe.exe"), ("retained", "retained-probe.exe")):
        assert digest(archive.read("B/" + filename)) == method["binaries"]["B-" + kind]
        assert baseline_binaries[kind] == method["binaries"]["A-" + kind] == reuse["binaries"][filename]
    rows, labels, qualifiers, owners = [], [], {}, {}
    for cell in CELLS:
        label = "-".join(map(str, cell))
        a, b = [record(archive, "qualify-" + arm + "-" + label + ".json") for arm in "AB"]
        ledger(a, b)
        qualifiers[label] = (a, b)
        owners[label] = {"baseline": resident(a), "candidate": resident(b)}
        labels += ["qualify-" + arm + "-" + label for arm in "AB"]
    for pair, order in enumerate(ORDERS):
        for cell in CELLS:
            kind, profile, security, mode, size = cell
            label = "-".join(map(str, cell))
            count = 8192 if size in (32, 1024) else 1024
            means, samples = {}, {}
            for arm in order:
                name = f"measure-{pair}-{label}-{arm}"
                labels.append(name)
                sample = record(archive, name + ".json")
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
                    assert sample["server_capacities"]["dedup"] == 64
                    values = sample["server_poll_cpu_cycles_sum"]
                assert len(values) == count and all(type(value) is int and value > 0 for value in values)
                qualifier = qualifiers[label][0 if arm == "A" else 1]
                for key in CAPACITIES:
                    if key in qualifier:
                        assert qualifier[key] == sample[key]
                assert resident(sample) == resident(qualifier)
                samples[arm], means[arm] = sample, statistics.mean(values)
            ledger(samples["A"], samples["B"])
            rows.append({"pair": pair, "cell": cell, "means": means, "ratio": means["B"] / means["A"]})
    assert rows == result["rows"]
    failures = []
    assert len(result["summary"]) == 28
    for cell in CELLS:
        value = interval([row["ratio"] for row in rows if row["cell"] == cell])
        retained = [row for row in result["summary"] if row["cell"] == cell]
        assert len(retained) == 1
        close(value, retained[0])
        if value["upper95"] > 1.02:
            failures.append(cell)
    groups = {}
    for kind in ("ordinary", "retained", "all"):
        for mode in ("sync", "async", "all"):
            paired = [math.exp(statistics.mean(math.log(row["ratio"]) for row in rows
                      if row["pair"] == pair and (kind == "all" or row["cell"][0] == kind)
                      and (mode == "all" or row["cell"][3] == mode))) for pair in range(64)]
            key = kind + "-" + mode
            groups[key] = interval(paired)
            close(groups[key], result["groups"][key])
    accepted = not failures and all(groups[kind + "-" + mode]["upper95"] <= 1.02
                                   for kind in ("ordinary", "all") for mode in ("sync", "async"))
    assert result["runtime_accepted"] == accepted
    assert failures == [row["cell"] for row in result["failed_point_guards"]]
    events = [json.loads(line) for line in archive.read("process-exits.jsonl").decode().splitlines()]
    assert len(events) == len(set(labels)) == 3640
    assert [event["label"] for event in events] == labels
    assert {name for name in archive.namelist() if name.startswith(("measure-", "qualify-")) and name.endswith(".json")} == {label + ".json" for label in labels}
    for event in events:
        assert event["exit_code"] == 0 and not event.get("timeout", False)
        assert event["stdout_bytes"] == len(archive.read(event["label"] + ".json"))
    return {"runtime_accepted": accepted, "cells": 28, "pairs_per_cell": 64,
            "timing_outputs": 3584, "process_exits": 3640, "failed_cells": failures,
            "groups": groups, "resident_requested_owners": owners}


def verify_retained_diagnostic(archive, pin):
    """Check instrumented work counters without treating their cycles as timing."""
    result = record(archive, "diagnostic/result.json")
    assert result["source"] == pin and result["build_exit_code"] == 0
    assert digest(archive.read("diagnostic/retained-probe.exe")) == result["binary_sha256"]
    cases = [(storage, security, mode) for storage in ("fixed", "allocated")
             for security in ("unprotected", "oscore") for mode in ("sync", "async")]
    assert [(row["storage"], row["security"], row["mode"]) for row in result["rows"]] == cases
    for row, case in zip(result["rows"], cases):
        name = "diagnostic/" + "-".join(case)
        sample = record(archive, name + ".json")
        assert row["exit_code"] == 0 and row["verified"] == sample["verified"] == 136
        assert sample["operations"] == 8 and sample["warmup"] == 128
        assert (sample["storage"], sample["security"], sample["mode"]) == case
        assert sample["payload_bytes"] == 11264 and sample["requests_per_operation"] == 2
        assert sample["data_packets_per_operation"] == 11
        metrics = {key: int(value) for key, value in re.findall(
            r"(\w+): (\d+)", archive.read(name + ".stderr").decode())}
        assert metrics == row["metrics"]
        assert metrics["block_tx_staged_bytes"] == 0
        assert metrics["tx_payload_encoded_bytes"] == (136 * 11264 if case[1] == "unprotected" else 0)
    return {"cases": 8, "verified_operations_each": 136, "block_tx_staged_bytes_each": 0,
            "scope": "Instrumented actual-path work counts only; no timing or total-zero-copy claim"}


def verify_untimed(archive, pin, bundle, memory_accepted):
    """Distinguish a failed preflight from a deliberately unmeasured successor."""
    assert not bundle.startswith("failed-cohort"), "Failed cohorts require retained measurements"
    names = archive.namelist()
    assert "measurement.json" not in names and "process-exits.jsonl" not in names
    assert not any(name.startswith(("measure-", "qualify-")) for name in names)
    decision = record(archive, "result.json")
    assert decision["candidate"] == pin and decision["baseline"] == BASELINE
    assert decision["no_runtime_cohort"] is True
    superseded = decision.get("cohort_status") == "superseded-before-timing"
    if bundle in ("precursor", "precursor2"):
        assert not memory_accepted and not superseded, "Original preflight rejections remain rejected"
    summary = {"no_runtime_cohort": True, "integration_gate_accepted": False}
    if superseded:
        assert bundle.startswith("precursor") and memory_accepted
        reason = decision.get("reason")
        assert isinstance(reason, str) and reason.strip(), "Supersession requires an explicit reason"
        summary.update(cohort_status="superseded-before-timing", reason=reason)
    else:
        assert not memory_accepted, "Missing cohort cannot establish acceptance"
    return summary


def main(failures_only=False):
    baseline_source = read(PHASE / "source-verification.json")
    assert baseline_source["source"] == MEASURED_BASELINE
    baseline_layout = layouts(checked_member(PHASE, "observations.zip", "observation-sha256.json", "candidate/owner-layout.txt"))
    baseline32 = layouts(checked_member(PHASE, "layout32.zip", "layout32-sha256.json", "candidate-layout.txt"))
    baseline_dispatch = dispatch(checked_member(OWNERSHIP, "borrowed-handler.zip", "borrowed-handler-sha256.json", "A-dispatch-symbols.txt"))
    baseline_frames = {kind: symbols(checked_member(PHASE, "diagnostics.zip", "diagnostic-sha256.json", filename), marker)
                       for kind, filename, marker in (("encoder", "candidate-encoder-symbols.txt", "encode_issued<"),
                                                       ("reclaim", "reclaim-symbols.txt", "evict_one_dedup_pin<"))}
    baseline_binaries = {kind: digest(checked_member(PHASE, "observations.zip", "observation-sha256.json", "candidate/B/" + filename))
                         for kind, filename in (("ordinary", "dispatch-probe.exe"), ("retained", "retained-probe.exe"))}
    bundles = [(path.stem, path.stem + "-sha256.json", path.stem + "-archive.json")
               for path in sorted(ROOT.glob("precursor*.zip"))]
    bundles += [(path.stem, path.stem + "-sha256.json", path.stem + "-archive.json")
                for path in sorted(ROOT.glob("failed-cohort*.zip"))]
    if not failures_only:
        bundles.append(("observations", "observation-sha256.json", "archives.json"))
    assert bundles, "No retained attempts to verify"
    output = {}
    for bundle, manifest, metadata in bundles:
        assert (ROOT / manifest).is_file() and (ROOT / metadata).is_file(), bundle
        members = verify_archive(ROOT / (bundle + ".zip"), ROOT / manifest, ROOT / metadata)
        with zipfile.ZipFile(ROOT / (bundle + ".zip")) as archive:
            if bundle == "observations":
                assert (ROOT / metadata).exists()
                for name in EXPORTED:
                    exists = name in archive.namelist()
                    assert exists == (ROOT / name).exists(), name
                    if exists:
                        if name.endswith(".patch"):
                            assert archive.read(name) == (ROOT / name).read_bytes()
                        else:
                            assert record(archive, name) == read(ROOT / name), name
            pin, reuse, source_count = verify_source(archive, baseline_source)
            binary_hashes = {}
            for kind, filename in (("ordinary", "dispatch-probe.exe"), ("retained", "retained-probe.exe")):
                assert reuse["binaries"][filename] == baseline_binaries[kind]
                binary_hashes[kind] = digest(archive.read("B/" + filename))
                assert "B/" + filename.replace(".exe", ".pdb") in archive.namelist()
            summary = {"source": pin, "archive_members": members,
                       "source_manifest_files": source_count,
                       "candidate_binary_sha256": binary_hashes,
                       **verify_memory(archive, pin, source_count, baseline_layout, baseline32, baseline_dispatch, baseline_frames)}
            if "measurement.json" in archive.namelist():
                assert not bundle.startswith("precursor"), "Precursors must remain untimed"
                assert summary["memory_preflight_accepted"], "Timing requires the prospective memory gate"
                summary.update(verify_cohort(archive, pin, reuse, baseline_binaries))
                if bundle.startswith("failed-cohort"):
                    assert not summary["runtime_accepted"], "Failed cohorts must retain their computed rejection"
                summary["integration_gate_accepted"] = summary["runtime_accepted"]
            else:
                summary.update(verify_untimed(archive, pin, bundle, summary["memory_preflight_accepted"]))
            if "qualification.json" in archive.namelist():
                checks = record(archive, "qualification.json")
                assert len(checks) == len({row["name"] for row in checks})
                summary["qualification_exit_codes"] = {row["name"]: row["exit_code"] for row in checks}
            if "diagnostic/result.json" in archive.namelist():
                summary["retained_path_diagnostic"] = verify_retained_diagnostic(archive, pin)
            if "prequalification.json" in archive.namelist():
                prequalification = record(archive, "prequalification.json")
                assert prequalification["source"] == pin
                checks = prequalification["checks"]
                assert len(checks) == len({row["name"] for row in checks})
                summary["prequalification_exit_codes"] = {row["name"]: row["exit_code"] for row in checks}
            output[bundle] = summary
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--failures-only", action="store_true",
                        help="Verify retained rejected and superseded attempts; do not claim a final result.")
    main(failures_only=parser.parse_args().failures_only)
