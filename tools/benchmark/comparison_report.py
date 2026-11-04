"""Offline comparison of widened host and device evidence; never runs workloads.

Keep execution policies and workloads separate. A failed or missing planned
round makes that entire host cell ineligible; successful prefixes are evidence,
not replacements. Input byte hashes identify evidence, not execution truth.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics

from campaign import canonical, integer, validate_sample

MAX_BYTES = 32 * 1024 * 1024
MAX_SAMPLES = 1_000_000
POLICIES = {
    "Coaptic-spin": ("sync", "busy spin", "no executor; never sleeps"),
    "Coaptic-Mio": ("sync", "readiness", "Mio OS readiness"),
    "Coaptic-async": ("async", "readiness", "Tokio current-thread server"),
    "coap-rs": ("async", "readiness", "Tokio two-worker server"),
    "libcoap": ("event loop", "readiness", "libcoap I/O loop"),
    "go-coap": ("goroutines", "readiness", "Go scheduler/netpoll"),
    "aiocoap": ("async", "readiness", "Python asyncio"),
}
RUST_SELECTORS = {"Coaptic-spin": ("coaptic", "coaptic-reusable"),
                  "Coaptic-Mio": ("coaptic-mio",), "Coaptic-async": ("coaptic-async",),
                  "coap-rs": ("coap-rs",)}


def execution_policy(peer):
    command = peer.get("server")
    if not isinstance(command, list) or not command or any(not isinstance(x, str) for x in command):
        raise ValueError("server command must be argv")
    if peer["id"] in RUST_SELECTORS:
        if len(command) < 2 or command[1] not in RUST_SELECTORS[peer["id"]]:
            raise ValueError("peer label contradicts execution selector")
        return POLICIES[peer["id"]]
    # No executor inference from arbitrary user labels for other executables.
    return ("peer-defined", "unknown", "inspect declared server command")


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("report input exceeds byte budget")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    return value, {"name": Path(path).name, "bytes": len(raw),
                   "sha256": hashlib.sha256(raw).hexdigest()}


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("expected finite nonnegative metric")
    return value


def host_summary(method, result):
    rounds = integer(method["rounds"], "rounds", 1, 32)
    peers = [p["id"] for p in method["peers"]]
    policies = {p["id"]: execution_policy(p) for p in method["peers"]}
    commands = {p["id"]: p["server"] for p in method["peers"]}
    cases = method["cases"]
    case_keys = [canonical(c) for c in cases]
    if (not peers or len(peers) > 32 or len(set(peers)) != len(peers)
            or not cases or len(cases) > 128 or len(set(case_keys)) != len(cases)):
        raise ValueError("duplicate/empty/oversize plan")
    groups = defaultdict(dict)
    count = 0
    for row in result["rows"]:
        peer, key, repeat = row["peer"], canonical(row["case"]), row["round"]
        if peer not in peers or key not in case_keys:
            raise ValueError("unplanned cell")
        integer(repeat, "round", 0, rounds - 1)
        if repeat in groups[peer, key]:
            raise ValueError("duplicate planned round")
        sample = row["result"]["sample"]
        count += len(sample.get("latencies_ns", []))
        if count > MAX_SAMPLES:
            raise ValueError("report sample budget")
        validate_sample(sample, row["case"])
        integer(row["result"]["exit_code"], "exit code", 0, 255)
        groups[peer, key][repeat] = row["result"]
    output = []
    for case, key in zip(cases, case_keys):
        for peer in peers:
            rows = list(groups[peer, key].values())
            failed = sum(r["exit_code"] != 0 or r["sample"]["failed"] != 0
                         or r["sample"]["warmup_failed"] != 0 for r in rows)
            missing = rounds - len(rows)
            # No good-round filtering, pooling across modes, or global ranking.
            eligible = not (failed or missing) and result.get("status") == "COMPLETE"
            entry = {"peer": peer, "case": case, "rounds": len(rows),
                     "failed_rounds": failed, "missing_rounds": missing,
                     "eligible": eligible, "policy": policies[peer], "server_command": commands[peer],
                     "ops_s": None, "median_us": None, "process_ops_s": [],
                     "startup_ms": None, "idle_private_bytes": None,
                     "sampled_loaded_private_bytes": None, "resource_ledgers": []}
            if eligible:
                entry["process_ops_s"] = [r["sample"]["completed"] * 1e9 / r["sample"]["elapsed_ns"] for r in rows]
                entry["ops_s"] = statistics.median(entry["process_ops_s"])
                entry["median_us"] = statistics.median(v for r in rows for v in r["sample"]["latencies_ns"]) / 1000
            # Resource/lifecycle snapshots are kept per workload, never added to App layout.
            for name, getter, aggregate in (
                ("startup_ms", lambda r: r.get("startup_first_verified_response_ms"), statistics.median),
                ("idle_private_bytes", lambda r: r.get("idle", {}).get("memory", {}).get("private"), statistics.median),
                ("sampled_loaded_private_bytes", lambda r: r.get("loaded", {}).get("sampled_peak_memory", {}).get("private"), max),
            ):
                values = [getter(r) for r in rows]
                if eligible and all(v is not None for v in values):
                    entry[name] = aggregate(number(v) for v in values)
            for r in rows:
                for line in r.get("server_stdout", "").splitlines():
                    try:
                        ledger = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(ledger, dict) and str(ledger.get("schema", "")).startswith("coaptic-native-") and ledger not in entry["resource_ledgers"]:
                        entry["resource_ledgers"].append(ledger)
            output.append(entry)
    return {"status": result.get("status"), "cells": output, "latencies": count,
            "source_core": method.get("core"), "scope": method.get("scope", "unspecified")}


def device_summary(path):
    result, receipt = load(path)
    if result.get("schema") != "coaptic-esp-server-comparison/1":
        raise ValueError("unsupported device receipt")
    rows, artifacts, seen = [], [receipt], set()
    process_names, process_hashes = set(), set()
    eligible = result.get("status") == "complete" and result.get("measurements_passed") is True
    total_samples = 0
    for cohort in result["cohorts"]:
        mode = cohort["device_mode"]
        if mode in seen:
            raise ValueError("duplicate device cohort")
        seen.add(mode)
        clients = cohort["clients"]
        eligible &= cohort.get("passed") is True
        if [c["mode"] for c in clients] != ["sync", "async", "async", "sync"]:
            raise ValueError("device client order/census")
        groups = defaultdict(list)
        for ordinal, client in enumerate(clients, 1):
            # Use files alongside the supplied receipt; never follow absolute paths
            # embedded by another machine or download artifacts named by evidence.
            name = client["report_path"].replace("\\", "/").rsplit("/", 1)[-1]
            expected_name = f"{cohort['name']}-round-{ordinal}-windows-{client['mode']}.jsonl"
            if (name != expected_name or name in process_names
                    or client["source_report_sha256"] in process_hashes):
                raise ValueError("device duplicate/misbound process artifact")
            process_names.add(name)
            process_hashes.add(client["source_report_sha256"])
            source = Path(path).parent / name
            if source.is_symlink() or source.resolve().parent != Path(path).parent.resolve():
                raise ValueError("device report escapes receipt directory")
            with source.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != client["source_report_sha256"]:
                raise ValueError("device report byte identity")
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
            operations = [r for r in records if r.get("case") == "complete_operation"]
            if (client.get("ordinal") != ordinal or client.get("passed") is not True
                    or client.get("operations") != 24 or len(operations) != 24
                    or any(r.get("passed") is False for r in records)):
                raise ValueError("device failed/incomplete process")
            expected = {(i, p) for i in range(8) for p in ("identity", "test", "large")}
            actual = {(r["iteration"], r["path"]) for r in operations}
            if actual != expected:
                raise ValueError("device duplicate/missing operation")
            for op in operations:
                if op.get("passed") is not True or op["bytes"] != {"identity": 32, "test": 7, "large": 2000}[op["path"]]:
                    raise ValueError("device body/status")
                integer(op["elapsed_ns"], "elapsed", 1, 5_000_000_000)
                for metric in ("poll_ns", "sleep_ns", "recv_ns", "send_ns"):
                    integer(op[metric], metric, 0, op["elapsed_ns"])
                groups[client["mode"], op["path"]].append(op)
            total_samples += len(operations)
            artifacts.append({"name": name, "bytes": len(raw), "sha256": client["source_report_sha256"]})
        for (client_mode, resource), ops in groups.items():
            rows.append({"server": mode, "client": client_mode, "path": resource,
                         "n": len(ops), "mean_ms": statistics.mean(o["elapsed_ns"] for o in ops) / 1e6,
                         "median_ms": statistics.median(o["elapsed_ns"] for o in ops) / 1e6,
                         "client_poll_ms": statistics.mean(o["poll_ns"] for o in ops) / 1e6,
                         "client_wait_ms": statistics.mean(o["sleep_ns"] for o in ops) / 1e6})
    if seen != {"sync", "async", "libcoap-native"} or total_samples != 288:
        raise ValueError("device cohort census")
    if not eligible:
        for row in rows:
            for metric in ("mean_ms", "median_ms", "client_poll_ms", "client_wait_ms"):
                row[metric] = None
    return {"rows": rows, "operations": total_samples, "sources": artifacts, "eligible": eligible,
            "restored": result.get("restore_verified") is True,
            "passed": result.get("passed") is True and result.get("status") == "complete",
            "scope": result["method"]}


def loc_summary(value):
    if value.get("schema") != "coaptic-scoped-loc/1":
        raise ValueError("LOC schema")
    output = []
    for name in ("coaptic", "coap-rs", "libcoap", "go-coap", "aiocoap"):
        group = value["groups"][name]
        total, tests, other = (group[k] for k in ("totals", "recognized_test_files", "other_files_including_inline_tests"))
        for key in ("files", "code", "comment", "blank"):
            for row in (total, tests, other):
                integer(row[key], key, 0, 10_000_000)
            if tests[key] + other[key] != total[key]:
                raise ValueError("LOC subset conservation")
        output.append({"name": name, "code": total["code"], "dedicated_tests": tests["code"],
                       "other_code": other["code"], "comments": total["comment"],
                       "scope": group["scope"], "notes": group["notes"]})
    return output


def render(value):
    # Escape '<' even inside JSON so a source-controlled label cannot terminate script.
    payload = json.dumps(value, allow_nan=False).replace("<", "\\u003c")
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Coaptic comparison explorer</title><style>
body{font:15px var(--font-sans,system-ui);margin:0;color:var(--foreground,#182938)}h1{font-size:23px}h2{font-size:19px;margin-top:28px}p{line-height:1.5}.note{color:var(--muted-foreground,#536576);font-size:13px}label{display:inline-block;margin:6px 18px 6px 0}select{padding:5px;max-width:100%}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:7px;text-align:left;border-bottom:1px solid var(--border,#dbe1e6);overflow-wrap:anywhere}th{background:var(--secondary,#eef2f5)}#host td:nth-child(3){white-space:nowrap}#host td:first-child,#host th:first-child{overflow-wrap:normal}.bar{height:12px;background:var(--chart-1,#28768e);min-width:1px;max-width:100%}.warn{color:var(--warning,#9a371b)}details{margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}section{margin-bottom:24px}#host,#memory,#device,#loc,#espMemory{overflow:auto}
</style><h1>Compare the same work</h1>
<p>Choose workload, execution policy and platform separately. These are descriptive measurements, not a universal library ranking. All planned rounds must succeed to display a host cell.</p>
<section><h2>Windows loopback · complete verified operations</h2><label>Body / concurrency <select id="cell"></select></label><label>Metric <select id="metric"><option value="ops_s">Operations / second · higher is better</option><option value="median_us">Median latency µs · lower is better</option></select></label><label><input type="checkbox" id="spin"> Include busy spin</label><div id="host"></div>
<p class="note">Bars use the selected metric, starting at zero. Throughput is the median of process rates; latency is the median of every operation in that cell. Each process rate remains available in the evidence details. Busy spin consumes CPU while idle and is hidden by default.</p><details><summary>Configurations, capacities and source evidence</summary><pre id="hostDetail"></pre></details></section>
<section id="deviceSection"><h2>Windows → ESP32-S3 · Wi-Fi complete reads</h2><p id="deviceStatus"></p><label>Windows client <select id="client"><option>sync</option><option>async</option></select></label><label>Resource <select id="resource"><option>identity</option><option>test</option><option>large</option></select></label><div id="device"></div><p class="note">Server async = custom FreeRTOS task + select/eventfd; Windows client async = async-io. ESP sync waits in select; it is not Windows busy spin. Client poll and wait durations are diagnostic elapsed time, not device CPU. Async I/O observations can include waiting. Do not subtract them to infer server cost. One boot per server, two processes per client mode, unprotected only.</p></section>
<section><h2>Memory and lifecycle · same selected host workload</h2><div id="memory"></div><p class="note">Windows private commit is not RSS. Loaded memory is a sampled maximum, not a proven peak. Startup includes probe-process launch until the first verified response. Graceful shutdown: not measured. App/pool/layout ledgers are separate and nested; never add them to process memory.</p><div id="espMemory"></div><div id="frames"></div></section>
<section><h2>Source volume and build cost</h2><div id="loc"></div><p class="note">Dedicated test code is a subset of total code. Other code still includes inline tests, optional features and platforms. Comments/rustdoc are separate. Dependencies and package boundaries differ: this is not production-only or feature-equivalent LOC.</p><details><summary>Source boundaries</summary><pre id="locDetail"></pre></details><p id="buildNote"></p><details><summary>Recorded build tasks · diagnostic only</summary><pre id="builds"></pre></details></section>
<details><summary>Evidence identities and limits</summary><pre id="sources"></pre></details>
<script>const D=PAYLOAD;
const $=id=>document.getElementById(id), txt=(tag,s)=>{let e=document.createElement(tag);e.textContent=s;return e};
function table(id,headers,rows){let t=document.createElement('table'),h=document.createElement('tr');headers.forEach(x=>h.append(txt('th',x)));t.append(h);rows.forEach(row=>{let tr=document.createElement('tr');row.forEach(x=>{let td=document.createElement('td');if(x instanceof Node)td.append(x);else td.textContent=x;t.append(tr);tr.append(td)});});$(id).replaceChildren(t)}
const fmt=(n,d=2)=>n==null?'not measured':n.toLocaleString(undefined,{maximumFractionDigits:d});
const cases=[...new Set(D.host.cells.map(r=>JSON.stringify(r.case)))];cases.forEach((s,i)=>{let c=JSON.parse(s),o=txt('option',c.bytes+' B · C'+c.concurrency+' · '+c.security+' · '+c.mode);o.value=i;$('cell').append(o)});
function update(){const key=cases[+$('cell').value], all=D.host.cells.filter(r=>JSON.stringify(r.case)===key), rows=all.filter(r=>$('spin').checked||r.policy[1]!=='busy spin'), metric=$('metric').value, max=Math.max(1,...rows.map(r=>r[metric]||0));
table('host',['Implementation','API / scheduling','Value','Relative scale','Rounds / status'],rows.map(r=>{let b=document.createElement('div');b.className='bar';b.style.width=((r[metric]||0)/max*120)+'px';return [r.peer,r.policy.join(' · '),fmt(r[metric]),b,r.eligible?r.rounds+' complete':r.failed_rounds+' failed, '+r.missing_rounds+' missing; unavailable']}));
table('memory',['Implementation','Idle private MiB','Sampled loaded private MiB','Launch → verified reply ms'],rows.map(r=>[r.peer,fmt(r.idle_private_bytes==null?null:r.idle_private_bytes/1048576),fmt(r.sampled_loaded_private_bytes==null?null:r.sampled_loaded_private_bytes/1048576),fmt(r.startup_ms)]));$('hostDetail').textContent=JSON.stringify(all,null,2);
if(D.device){$('deviceStatus').textContent=(D.device.eligible?'Measurement cohort complete. ':'Measurement cohort failed/incomplete: comparison unavailable. ')+(D.device.restored?'Normal firmware restoration verified.':'WARNING: normal firmware restoration is NOT verified.');let ds=D.device.rows.filter(r=>r.client===$('client').value&&r.path===$('resource').value);table('device',['ESP server','Reads','Mean ms','Median ms','Client poll ms','Client wait ms'],ds.map(r=>[r.server,r.n,fmt(r.mean_ms),fmt(r.median_ms),fmt(r.client_poll_ms),fmt(r.client_wait_ms)]));}else $('deviceSection').hidden=true;
}
['cell','metric','spin','client','resource'].forEach(id=>$(id).addEventListener('change',update));update();
table('loc',['Library/package','Total code','Dedicated tests (subset)','Other code','Comments / docs'],D.loc.map(r=>[r.name,fmt(r.code,0),fmt(r.dedicated_tests,0),fmt(r.other_code,0),fmt(r.comments,0)]));$('locDetail').textContent=JSON.stringify(D.loc,null,2);
if(D.device_memory){table('espMemory',['ESP server','Stack reserved KiB','Used lifetime watermark KiB','Platform free heap KiB','Firmware KiB'],D.device_memory.map(r=>[r.server,fmt(r.task_reserved_bytes/1024),fmt(r.used_stack_high_water_bytes/1024),fmt(r.free_heap_bytes/1024),fmt(r.image_bytes/1024)]));$('espMemory').append(txt('p','ESP heap already includes allocated task stacks. The watermark includes initialization, not just steady-state calls. Pools, allocator policy and supported features differ; these are not minimum-RAM requirements.'));}
if(D.frames){$('frames').append(txt('h2','New ESP implementation · compiled frame evidence'));let holder=document.createElement('div');holder.id='frameTable';$('frames').append(holder);table('frameTable',['Unprotected async component','Before (bytes)','After (bytes)'],D.frames.rows.map(r=>[r.component,fmt(r.before,0),fmt(r.after,0)]));$('frames').append(txt('p',D.frames.scope));}
$('buildNote').textContent='Comparable cold/incremental build costs: not measured. Existing task durations used shared caches, mixed targets and features; they cannot rank languages or be called clean build times.';$('builds').textContent=JSON.stringify(D.builds,null,2);$('sources').textContent=JSON.stringify({sources:D.sources,limits:D.limits,device:D.device?D.device.scope:null},null,2);
</script></html>""".replace("PAYLOAD", payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--device", type=Path)
    parser.add_argument("--device-memory", type=Path, help="source-bound ESP report with named memory owners")
    parser.add_argument("--loc", type=Path)
    parser.add_argument("--builds", type=Path)
    parser.add_argument("--frames", type=Path, help="optional compiled ESP frame inspection; separate from device observations")
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    args = parser.parse_args()
    method, m_hash = load(args.method)
    runtime, r_hash = load(args.runtime)
    result = {"schema": "coaptic-comparison-report/1", "host": host_summary(method, runtime),
              "sources": [m_hash, r_hash], "device": None, "loc": [], "builds": [],
              "limits": ["Descriptive finite samples, no significance/global-winner claim.",
                         "Byte hashes bind inputs; they do not prove runtime execution.",
                         "No production-only LOC, matched clean-build cost or device CPU measurement."]}
    if args.device:
        result["device"] = device_summary(args.device)
    if args.device_memory:
        if not args.device:
            parser.error("--device-memory requires --device")
        memory, identity = load(args.device_memory)
        if memory.get("source_result_sha256") != result["device"]["sources"][0]["sha256"]:
            raise ValueError("device memory source mismatch")
        result["device_memory"] = memory["memory"]
        result["sources"].append(identity)
    if args.loc:
        loc, identity = load(args.loc)
        result["loc"] = loc_summary(loc)
        result["sources"].append(identity)
    if args.builds:
        builds, identity = load(args.builds)
        result["builds"] = [{"task": b["label"], "seconds": number(b["seconds"]), "command": b["argv"]} for b in builds]
        result["sources"].append(identity)
    if args.frames:
        frames, identity = load(args.frames)
        selected = {}
        for arm in frames["arms"]:
            if arm["arm"] not in ("baseline", "borrowed_result"):
                continue
            if arm["arm"] in selected:
                raise ValueError("duplicate compiled frame arm")
            values = {}
            for function in arm["functions"]:
                if "Driver>::run" in function["name"]:
                    values["Serving future (nested in caller)"] = number(function["root_future_bytes"])
                    values["Driver frame"] = number(function["frame_bytes"])
                elif function["name"].endswith("::run_unprotected_async"):
                    values["Caller frame (includes App/future)"] = number(function["frame_bytes"])
            if len(values) != 3:
                raise ValueError("compiled frame census")
            selected[arm["arm"]] = values
        if set(selected) != {"baseline", "borrowed_result"}:
            raise ValueError("compiled frame pair required")
        result["frames"] = {"rows": [{"component": k, "before": v,
                            "after": selected["borrowed_result"][k]} for k, v in selected["baseline"].items()],
                            "scope": frames["scope"] + " Task reservations remain unchanged. Preparation also has its own frame, outside the driver call; these selected frames are not a whole-call-graph peak. Do not add the nested future to its caller."}
        result["sources"].append(identity)
    encoded = json.dumps(result, allow_nan=False, indent=2) + "\n"
    document = render(result)
    if len(encoded.encode()) + len(document.encode()) > 2 * 1024 * 1024:
        raise ValueError("rendered report budget")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "data.json").write_text(encoded, encoding="utf-8")
    (args.output / "index.html").write_text(document, encoding="utf-8")
    print(f"Report: {args.output / 'index.html'}")


if __name__ == "__main__":
    main()
