"""Independent network benchmark sessions; setup and inference are explicit.

Exact in-memory analysis accepts at most 64 MiB of encoded evidence and one
million latency samples in aggregate. Python object overhead is additional;
these input budgets are not a bound on process resident memory. Partition
larger campaigns rather than silently dropping evidence or approximating p99.
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import math
import os
import platform
import random
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from pathlib import Path

SCHEMA = "coaptic-benchmark/1"
MAX_OUTPUT = 32 * 1024 * 1024
MAX_ANALYSIS_BYTES = 64 * 1024 * 1024
MAX_ANALYSIS_SAMPLES = 1_000_000


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def read(path):
    if Path(path).stat().st_size > MAX_OUTPUT:
        raise ValueError("oversize benchmark artifact")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_new(path, value):
    path = Path(path)
    encoded = canonical(value) + "\n"
    if len(encoded.encode("utf-8")) > MAX_OUTPUT:
        raise ValueError("oversize benchmark artifact")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def host():
    return {"hostname": socket.gethostname(), "platform": platform.platform(),
            "machine": platform.machine(), "python": platform.python_version(),
            "cpus": os.cpu_count(), "clock": vars(time.get_clock_info("perf_counter")),
            "runtime_environment": {key: os.environ.get(key) for key in
                ("GOMAXPROCS", "GOMEMLIMIT", "GODEBUG", "PYTHONHASHSEED", "PYTHONMALLOC")}}


def noise():
    value = {"utc": utc(), "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None}
    try:
        import psutil
        value.update(memory_available_bytes=psutil.virtual_memory().available,
                     system_cpu_times=psutil.cpu_times()._asdict())
    except ImportError:
        value["os_resource_sampler"] = "unavailable"
    return value


def process_cpu(pid):
    """Process CPU accounting; sampled outside the independent driver timing."""
    try:
        import psutil
    except ImportError:
        return None
    try:
        value = psutil.Process(pid).cpu_times()
        return {"user_seconds": value.user, "system_seconds": value.system}
    except (psutil.Error, OSError):
        return None


def integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"invalid {name}")
    return value


def validate_manifest(manifest):
    if manifest.get("schema") != SCHEMA or not manifest.get("peers") or not manifest.get("cases"):
        raise ValueError("manifest schema or empty matrix")
    if manifest.get("runtime_environment", host()["runtime_environment"]) != host()["runtime_environment"]:
        raise ValueError("runtime tuning changed since preparation; regenerate manifest")
    ids = set()
    for peer in manifest["peers"]:
        if peer["id"] in ids or not peer["id"].replace("-", "").isalnum():
            raise ValueError("duplicate or unsafe peer id")
        ids.add(peer["id"])
        if peer.get("protocol") not in ("coap", "http3") or not peer.get("identity") or not peer.get("security"):
            raise ValueError("missing protocol or implementation identity")
        for field in ("server", "driver"):
            if not isinstance(peer.get(field), list) or not peer[field] or not all(isinstance(v, str) for v in peer[field]):
                raise ValueError("commands must be argv arrays")
    ids = set()
    for case in manifest["cases"]:
        if case["id"] in ids or not case["id"].replace("-", "").isalnum():
            raise ValueError("duplicate or unsafe case id")
        ids.add(case["id"])
        integer(case["bytes"], "bytes", 1, 1024 * 1024)
        integer(case["concurrency"], "concurrency", 1, 128)
        integer(case["operations"], "operations", 1, 200_000)
        integer(case["warmup"], "warmup", 0, 10_000)
        integer(case["timeout_ms"], "timeout_ms", 1, 60_000)
        if case["mode"] not in (("con", "non") if case.get("protocol") == "coap" else ("warm", "cold")):
            raise ValueError("invalid request mode")
        if case.get("protocol") not in ("coap", "http3") or not case.get("security"):
            raise ValueError("missing case protocol/security stratum")
    return manifest


def command_identity(command):
    result = []
    for index, value in enumerate(command):
        if "{" in value:
            continue
        path = shutil.which(value) if index == 0 else value
        if path and Path(path).is_file():
            result.append({"argument": index, "path": str(Path(path).resolve()), "sha256": digest(path)})
    if not any(entry["argument"] == 0 for entry in result):
        raise ValueError(f"executable unavailable: {command[0]}")
    return result


def peer_identity(peer):
    result = {"server": command_identity(peer["server"]), "driver": command_identity(peer["driver"])}
    trees = []
    for directory in peer.get("dependency_trees", []):
        root = Path(directory)
        files = sorted(path for path in root.rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
        if not files:
            raise ValueError("missing dependency tree")
        trees.append({"path": str(root.resolve()), "sha256": fingerprint([(str(p.relative_to(root)), digest(p)) for p in files])})
    result["dependency_trees"] = trees
    return result


def create_plan(manifest, windows, seed, smoke=False):
    manifest = validate_manifest(manifest)
    integer(windows, "windows", 1, 10_000)
    rng = random.Random(seed)
    cases = list(manifest["cases"])
    if smoke:
        chosen = []
        for protocol in ("coap", "http3"):
            first = next((c for c in cases if c["protocol"] == protocol), None)
            if first:
                chosen.append(dict(first, operations=4, warmup=1, concurrency=1))
        large = next((c for c in cases if c["protocol"] == "coap" and c["bytes"] > 1024 and c["mode"] == "con"
                      and c["id"] not in {item["id"] for item in chosen}), None)
        if large:
            chosen.append(dict(large, operations=1, warmup=0, concurrency=1))
        cold = next((c for c in cases if c["protocol"] == "http3" and c["mode"] == "cold"
                     and c["id"] not in {item["id"] for item in chosen}), None)
        if cold:
            chosen.append(dict(cold, operations=1, warmup=0, concurrency=1))
        cases = chosen
    rng.shuffle(cases)
    orders = {}
    for case in cases:
        order = [p["id"] for p in manifest["peers"] if p["protocol"] == case["protocol"] and p["security"] == case["security"]]
        if not order:
            raise ValueError("case has no compatible peer")
        rng.shuffle(order)
        orders[case["id"]] = order
    schedule = []
    for window in range(windows):
        cells = []
        for case in cases[window % len(cases):] + cases[:window % len(cases)]:
            order = orders[case["id"]]
            rotate = window % len(order)
            order = order[rotate:] + order[:rotate]
            for peer in order:
                cells.append({"case": case["id"], "peer": peer})
        schedule.append(cells)
    identities = {p["id"]: peer_identity(p) for p in manifest["peers"]}
    return {"schema": SCHEMA, "created": utc(), "seed": seed, "smoke": smoke, "runner_sha256": digest(__file__),
            "host": host(), "manifest": manifest, "cases": cases, "identities": identities,
            "schedule": schedule, "inference_unit": "complete independently scheduled session"}


class CapturedProcess:
    """Drain bounded pipes continuously, including during warmup and readiness."""

    def __init__(self, argv):
        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.output = bytearray()
        self.errors = bytearray()
        self.overflow = threading.Event()
        self.readers = []
        for stream, destination in ((self.process.stdout, self.output), (self.process.stderr, self.errors)):
            reader = threading.Thread(target=self._drain, args=(stream, destination), daemon=True)
            reader.start()
            self.readers.append(reader)

    def _drain(self, stream, destination):
        while chunk := stream.read(8192):
            remaining = MAX_OUTPUT - len(destination)
            destination.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self.overflow.set()
                if self.process.poll() is None:
                    self.process.kill()
                break

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=3)
        for reader in self.readers:
            reader.join(timeout=1)
        if any(reader.is_alive() for reader in self.readers):
            raise ValueError("descendant retained output pipe; custom peers must not spawn descendants")
        self.process.stdout.close()
        self.process.stderr.close()


def execute(argv, timeout, health=None):
    captured = CapturedProcess(argv)
    try:
        deadline = time.monotonic() + timeout
        while captured.process.poll() is None:
            if health is not None and not health():
                raise ValueError("server exited or exceeded output cap during driver execution")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("driver process deadline exceeded")
            try:
                captured.process.wait(timeout=min(.05, remaining))
            except subprocess.TimeoutExpired:
                pass
    finally:
        captured.close()
    if captured.overflow.is_set():
        raise ValueError("oversize driver output")
    try:
        value = json.loads(captured.output)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise ValueError(f"malformed driver output; exit={captured.process.returncode}; stderr={bytes(captured.errors[:2048])!r}") from error
    if not isinstance(value, dict):
        raise ValueError("driver output must be a JSON object")
    return captured.process.returncode, value


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


def render(command, values):
    return [argument.format_map(values) for argument in command]


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_cell(peer, case):
    values = dict(case, port=reserve_port(), host="127.0.0.1")
    values["operations"] = 1
    values["warmup"] = 0
    values["concurrency"] = 1
    before = noise()
    with tempfile.TemporaryDirectory(prefix="coaptic-benchmark-cert-") as certificate_root:
        values["certificate"] = str(Path(certificate_root) / "server.pem")
        captured = CapturedProcess(render(peer["server"], values))
        server = captured.process
        try:
            deadline = time.monotonic() + 15
            readiness = None
            last_probe = None
            while time.monotonic() < deadline:
                if captured.overflow.is_set() or server.poll() is not None:
                    raise ValueError("server exited or exceeded output cap before network readiness")
                try:
                    exit_code, probe = execute(render(peer["driver"], values), 3)
                    last_probe = probe
                    probe_case = dict(case, operations=1, warmup=0, concurrency=1)
                    validate_sample(probe, probe_case)
                    if exit_code == 0 and probe["completed"] == 1:
                        readiness = probe
                        break
                except ValueError as error:
                    last_probe = str(error)
                time.sleep(0.02)
            if readiness is None:
                raise ValueError(f"server not externally ready; last probe={last_probe!r}")
            values.update(case)
            timeout = min(86_400, 15 + (case["operations"] + case["warmup"] * case["concurrency"]) * case["timeout_ms"] / 1000)
            cpu_before = process_cpu(server.pid)
            measured_started = time.monotonic()
            exit_code, sample = execute(render(peer["driver"], values), timeout,
                                        lambda: server.poll() is None and not captured.overflow.is_set())
            measured_wall = time.monotonic() - measured_started
            cpu_after = process_cpu(server.pid)
            cpu_accounting = {"before": cpu_before, "after": cpu_after,
                              "driver_process_wall_seconds": measured_wall,
                              "scope": "server CPU over driver startup, warmup, measured requests and driver exit; platform accounting granularity applies"}
            try:
                validate_sample(sample, case)
            except ValueError as error:
                return {"error": str(error), "raw_sample": sample, "exit_code": exit_code,
                        "readiness": readiness, "server_cpu": cpu_accounting,
                        "noise_before": before, "noise_after": noise(), "finished": utc()}
            warmup_failed = integer(sample.get("warmup_failed"), "warmup_failed", 0, case["warmup"] * case["concurrency"])
            if exit_code not in (0, 1) or (exit_code == 0) != (sample["failed"] == 0 and warmup_failed == 0):
                raise ValueError("driver exit contradicts failure accounting")
            if captured.overflow.is_set() or server.poll() is not None:
                raise ValueError("server exited or exceeded output cap during measured workload")
            return {"sample": sample, "readiness": readiness, "noise_before": before,
                    "server_cpu": cpu_accounting, "noise_after": noise(), "finished": utc()}
        except (ValueError, OSError) as error:
            failure = error
        finally:
            captured.close()
        raise ValueError(
            f"{failure}; server_exit={server.returncode}; "
            f"stderr_tail={bytes(captured.errors[-4096:])!r}; "
            f"stdout_tail={bytes(captured.output[-4096:])!r}"
        ) from failure


@contextlib.contextmanager
def campaign_lock(root):
    """Hold an OS-released cross-process lock across the whole comparison block."""
    with (Path(root) / ".run.lock").open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError("campaign already running; overlapping sessions are refused") from error
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def run_window(root, number):
    with campaign_lock(root):
        _run_window(root, number)


def _run_window(root, number):
    root = Path(root)
    plan = read(root / "plan.json")
    if plan.get("runner_sha256") != digest(__file__):
        raise ValueError("runner changed; create a separate campaign")
    integer(number, "window", 0, len(plan["schedule"]) - 1)
    if host() != plan["host"]:
        raise ValueError("host or runtime changed; create a separate campaign")
    manifest = validate_manifest(plan["manifest"])
    peers = {p["id"]: p for p in manifest["peers"]}
    cases = {c["id"]: c for c in plan["cases"]}
    for peer in peers.values():
        now = peer_identity(peer)
        if now != plan["identities"][peer["id"]]:
            raise ValueError("implementation or driver changed; create a separate campaign")
    finished = root / f"window-{number}.json"
    if finished.exists():
        raise ValueError("session already complete; evidence is immutable")
    minimum_gap = manifest.get("campaign_policy", {}).get("minimum_session_gap_seconds", 60)
    integer(minimum_gap, "minimum session gap", 0, 31_536_000)
    if not plan["smoke"]:
        previous = [read(path) for path in root.glob("window-*.json")]
        latest = max((datetime.datetime.fromisoformat(item["finished"]).timestamp() for item in previous), default=0)
        if time.time() - latest < minimum_gap:
            raise ValueError("next independent session is not due; rerun later rather than waiting in the benchmark")
    references = []
    retained = []
    resumed = any((root / f"window-{number}" / f"{cell['case']}--{cell['peer']}.json").exists()
                  for cell in plan["schedule"][number])
    invoked = utc()
    for cell in plan["schedule"][number]:
        path = root / f"window-{number}" / f"{cell['case']}--{cell['peer']}.json"
        if not path.exists():
            record = {"schema": SCHEMA, "plan_sha256": digest(root / "plan.json"),
                      "window": number, **cell, "started": utc()}
            try:
                record.update(run_cell(peers[cell["peer"]], cases[cell["case"]]))
            except (ValueError, OSError) as error:
                record.update(error=str(error), finished=utc())
            write_new(path, record)
        references.append({"path": str(path.relative_to(root)), "sha256": digest(path)})
        retained.append(read(path))
        print(f"saved {path.name}", flush=True)
    write_new(finished, {"schema": SCHEMA, "plan_sha256": digest(root / "plan.json"),
                         "window": number, "started": min(r["started"] for r in retained),
                         "finished": utc(), "invoked": invoked, "resumed": resumed, "cells": references})


def quantile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (position - low)


def descriptive(values):
    return {"count": len(values), "mean": statistics.mean(values) if values else None,
            "p99": quantile(values, .99), "min": min(values) if values else None,
            "max": max(values) if values else None}


def paired_interval(ratios, seed=0, draws=2000):
    if len(ratios) < 5:
        return {"sessions": len(ratios), "ratio": math.exp(statistics.mean(map(math.log, ratios))) if ratios else None,
                "confidence_95": None, "assessment": "insufficient independent sessions"}
    rng = random.Random(seed)
    logs = list(map(math.log, ratios))
    samples = [math.exp(statistics.mean(rng.choices(logs, k=len(logs)))) for _ in range(draws)]
    return {"sessions": len(ratios), "ratio": math.exp(statistics.mean(logs)),
            "confidence_95": [quantile(samples, .025), quantile(samples, .975)],
            "assessment": "paired session bootstrap; no automatic winner"}


def analyze(root, reference):
    root = Path(root)
    input_bytes = 0
    latency_samples = 0

    def charge(path):
        nonlocal input_bytes
        input_bytes += Path(path).stat().st_size
        if input_bytes > MAX_ANALYSIS_BYTES:
            raise ValueError("aggregate analysis input budget exceeded; partition the campaign")

    charge(root / "plan.json")
    plan = read(root / "plan.json")
    if plan.get("runner_sha256") != digest(__file__):
        raise ValueError("runner changed; analyze with the original runner or create a separate campaign")
    plan_hash = digest(root / "plan.json")
    cells = {}
    periods = []
    for window_file in sorted(root.glob("window-*.json")):
        charge(window_file)
        window = read(window_file)
        if window["plan_sha256"] != plan_hash:
            raise ValueError("session belongs to another plan")
        periods.append({"window": window["window"], "started": window["started"], "finished": window["finished"],
                        "resumed": window.get("resumed", False), "comparison_eligible": not window.get("resumed", False)})
        expected = plan["schedule"][window["window"]]
        observed = []
        for entry in window["cells"]:
            path = root / entry["path"]
            charge(path)
            if digest(path) != entry["sha256"]:
                raise ValueError("session evidence changed")
            record = read(path)
            if isinstance(record.get("sample"), dict):
                latencies = record["sample"].get("latencies_ns", [])
                if isinstance(latencies, list):
                    latency_samples += len(latencies)
                if latency_samples > MAX_ANALYSIS_SAMPLES:
                    raise ValueError("aggregate analysis latency budget exceeded; partition the campaign")
            if record["plan_sha256"] != plan_hash or record["window"] != window["window"]:
                raise ValueError("cell belongs to another plan/session")
            key = (record["case"], record["peer"], record["window"])
            if key in cells:
                raise ValueError("duplicate comparison cell")
            observed.append({"case": record["case"], "peer": record["peer"]})
            cells[key] = record
        if observed != expected:
            raise ValueError("incomplete comparison session")
    previous_finish = None
    gap = plan["manifest"].get("campaign_policy", {}).get("minimum_session_gap_seconds", 60)
    for period in sorted(periods, key=lambda p: p["started"]):
        start = datetime.datetime.fromisoformat(period["started"]).timestamp()
        finish = datetime.datetime.fromisoformat(period["finished"]).timestamp()
        if finish < start:
            raise ValueError("invalid session chronology")
        if previous_finish is not None and start - previous_finish < gap:
            period["comparison_eligible"] = False
            for prior in periods:
                if prior["window"] != period["window"] and prior["started"] <= period["started"] <= prior["finished"]:
                    prior["comparison_eligible"] = False
        previous_finish = max(previous_finish or finish, finish)
    eligible_periods = {p["window"] for p in periods if p["comparison_eligible"]}
    summary = []
    peers = {p["id"]: p for p in plan["manifest"]["peers"]}
    for case in plan["cases"]:
        for peer in peers.values():
            if peer["protocol"] != case["protocol"] or peer["security"] != case["security"]:
                continue
            records = [r for (c, p, _), r in cells.items() if c == case["id"] and p == peer["id"]]
            good = [r for r in records if "sample" in r]
            for record in good:
                validate_sample(record["sample"], case)
            rates = [r["sample"]["completed"] * 1e9 / r["sample"]["elapsed_ns"] for r in good]
            session_stats = [{"window": r["window"], "completed": r["sample"]["completed"],
                              "failed": r["sample"]["failed"],
                              "latency_ns": descriptive(r["sample"]["latencies_ns"]),
                              "completed_per_second": rate}
                             for r, rate in zip(good, rates)]
            row = {"case": case["id"], "peer": peer["id"], "protocol": case["protocol"], "security": case["security"],
                   "sessions": len(records), "invalid_sessions": len(records) - len(good),
                   "failed_requests": sum(r["sample"]["failed"] for r in good),
                   "warmup_failures": sum(r["sample"].get("warmup_failed", 0) for r in good),
                   "driver_failures": sum(r["sample"].get("driver_failures", 0) for r in good),
                   "median_completed_per_second": statistics.median(rates) if rates else None,
                   "median_goodput_bytes_per_second": statistics.median(rates) * case["bytes"] if rates else None,
                   "median_session_p50_ns": statistics.median(quantile(r["sample"]["latencies_ns"], .5) for r in good if r["sample"]["completed"]) if any(r["sample"]["completed"] for r in good) else None,
                   "median_session_p99_ns": statistics.median(quantile(r["sample"]["latencies_ns"], .99) for r in good if r["sample"]["completed"]) if any(r["sample"]["completed"] for r in good) else None}
            row["successful_request_latency_ns"] = descriptive(
                [latency for r in good for latency in r["sample"]["latencies_ns"]])
            row["session_mean_latency_ns"] = descriptive(
                [s["latency_ns"]["mean"] for s in session_stats if s["completed"]])
            row["session_completed_per_second"] = descriptive(rates)
            row["session_statistics"] = session_stats
            ratios = []
            for record in good:
                if record["window"] not in eligible_periods:
                    continue
                baseline = cells.get((case["id"], reference, record["window"]))
                if not baseline or "sample" not in baseline:
                    continue
                candidate, base = record["sample"], baseline["sample"]
                if candidate["failed"] or base["failed"] or candidate.get("warmup_failed") or base.get("warmup_failed") or not base["completed"]:
                    continue
                if peers[reference]["driver"] != peer["driver"]:
                    continue
                ratios.append((candidate["completed"] / candidate["elapsed_ns"]) / (base["completed"] / base["elapsed_ns"]))
            row["completed_rate_vs_reference"] = paired_interval(ratios)
            row["excluded_comparison_pairs"] = len(records) - len(ratios)
            row["comparison_eligible"] = not plan["smoke"] and len(ratios) == len(records) and len(ratios) >= 5
            row["successful_latency_samples"] = sum(r["sample"]["completed"] for r in good)
            summary.append(row)
    return {"schema": SCHEMA, "plan_sha256": plan_hash, "reference": reference, "smoke": plan["smoke"],
            "sessions": periods, "summary": summary,
            "limits": ["closed-loop concurrency; not an offered-load or coordinated-omission-corrected latency claim",
                       "request latency summaries pool successful requests only; failures are reported separately",
                       "session summaries give each recorded session equal weight; request p99 is not an average of session p99s",
                       "session intervals are not guaranteed independent; inspect actual timestamps and host noise",
                       "confidence intervals do not eliminate systematic driver, scheduler or colocated-host bias",
                       "HTTP3 TLS and plaintext CoAP are separate security/protocol strata",
                       "correctness smokes and sparse sessions cannot establish throughput leadership"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("plan")
    create.add_argument("--manifest", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--windows", type=int, default=12)
    create.add_argument("--seed", type=int, default=20261005)
    create.add_argument("--smoke", action="store_true")
    run = sub.add_parser("run")
    run.add_argument("--campaign", type=Path, required=True)
    run.add_argument("--window", type=int, required=True)
    report = sub.add_parser("analyze")
    report.add_argument("--campaign", type=Path, required=True)
    report.add_argument("--reference", default="coaptic")
    report.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "plan":
        write_new(args.output / "plan.json", create_plan(read(args.manifest), args.windows, args.seed, args.smoke))
    elif args.action == "run":
        run_window(args.campaign, args.window)
    else:
        write_new(args.output, analyze(args.campaign, args.reference))


if __name__ == "__main__":
    main()
