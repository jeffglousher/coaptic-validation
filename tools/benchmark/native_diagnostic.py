"""Coaptic-only complete-operation diagnostic, not a comparative campaign.

Gates keep CPU/RSS samples outside operation clocks. Resource windows include
control IPC/sampling overhead; CPU accounting is quantized. RSS high-water marks
cover the process lifetime, not solely measurement. Kernel socket memory and
allocator overhead are not derived from the core's requested heap quota.
Each control phase has an explicit wall-clock deadline (300s by default),
independent of the client's operation bounds. If it expires, the observation
is invalid and attempted/completed activity is unknown unless a report arrived.
"""
import argparse
import hashlib
import json
import math
import platform
import queue
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import sys

import psutil


SERVER_KINDS = ("coaptic-reusable", "coaptic-mio", "coaptic-ready", "coaptic-async", "coaptic-blocking")


def server_resources(log_path, server_kind, *, deadline, server):
    """Await one bounded startup line before resource gates, without touching writer offsets.

    ``deadline`` is an absolute monotonic time; ``server`` supplies Popen.poll().
    Partial writes remain unparsed until newline. The independently opened reader
    never seeks or reads the file description inherited by the server.
    """
    if server_kind not in ("coaptic-async", "coaptic-blocking"):
        return None
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("server startup ledger needs a finite monotonic deadline")
    raw = bytearray()
    with Path(log_path).open("rb") as reader:
        while True:
            raw.extend(reader.readline(4097 - len(raw)))
            if len(raw) > 4096:
                raise ValueError("server startup ledger exceeded allowance")
            if raw.endswith(b"\n"):
                break
            if server.poll() is not None:
                raise RuntimeError("server exited before complete startup ledger")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("server startup ledger deadline")
            time.sleep(min(.01, remaining))
    record = json.loads(raw)
    if not isinstance(record, dict):
        raise ValueError("invalid server startup ledger")
    if server_kind == "coaptic-blocking":
        fields = ("udp_scratch_bytes", "staged_datagram_capacity", "stage_cache_metadata_bytes", "adapter_inline_bytes",
                  "app_including_adapter_bytes", "read_timeout_max_us", "send_timeout_us")
        if (record.get("schema") != "coaptic-native-blocking-resources/1"
                or record.get("server_kind") != server_kind
                or any(type(record.get(key)) is not int or not 0 < record[key] < 2**64
                       for key in fields)
                or record["udp_scratch_bytes"] != 2049
                or record["staged_datagram_capacity"] != 1
                or record["stage_cache_metadata_bytes"] > 64
                or not record["udp_scratch_bytes"] + record["stage_cache_metadata_bytes"]
                <= record["adapter_inline_bytes"] <= record["app_including_adapter_bytes"]
                or record["read_timeout_max_us"] != 5000 or record["send_timeout_us"] != 1000
                or record.get("timeouts_soft") is not True
                or any(key in record for key in ("loop_future_borrowing_app_bytes",
                                                 "loop_future_including_app_bytes"))
                or any(key not in record or record[key] is not None
                       for key in ("runtime_heap_bytes", "runtime_stack_bytes"))):
            raise ValueError("invalid blocking server startup ledger")
        return record
    if record.get("schema") != "coaptic-native-server-resources/2":
        raise ValueError("async server startup ledger requires borrowing schema coaptic-native-server-resources/2")
    if "loop_future_including_app_bytes" in record:
        raise ValueError("async server startup ledger uses obsolete owned-App loop future field")
    fields = ("udp_scratch_bytes", "adapter_inline_bytes", "app_including_adapter_bytes",
              "loop_future_borrowing_app_bytes")
    if (record.get("server_kind") != server_kind
            or any(type(record.get(key)) is not int or not 0 < record[key] < 2**64
                   for key in fields)
            or record["udp_scratch_bytes"] != 2049
            or not record["udp_scratch_bytes"] <= record["adapter_inline_bytes"]
            <= record["app_including_adapter_bytes"]
            or any(key not in record or record[key] is not None
                   for key in ("runtime_heap_bytes", "runtime_stack_bytes"))):
        raise ValueError("invalid async server startup ledger")
    return record


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_identity(path):
    def git(*args):
        return subprocess.run(["git", *args], cwd=path, capture_output=True,
                              text=True, check=True).stdout.strip()
    return dict(revision=git("rev-parse", "HEAD"), tree=git("rev-parse", "HEAD^{tree}"),
                status=git("status", "--porcelain"))


def snapshot(process):
    cpu = process.cpu_times()
    return dict(cpu_user_seconds=cpu.user, cpu_system_seconds=cpu.system,
                memory=process.memory_info()._asdict())


def control_line(stream, timeout, limit=128):
    """Bounded wait for a child handshake, including on Windows anonymous pipes."""
    result = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: result.put(stream.readline(limit + 1)), daemon=True).start()
    try:
        line = result.get(timeout=timeout)
    except queue.Empty as error:
        raise TimeoutError("native client control deadline") from error
    if len(line) > limit or not line.endswith("\n"):
        raise RuntimeError("native client line exceeded bound or ended incompletely")
    return line.strip()


def cpu_cost(before, after, completed):
    """Process-accounted user/kernel time; not machine-wide interrupt attribution."""
    if type(completed) is not int or completed <= 0:
        raise ValueError("CPU denominator must be verified completions")
    result = {}
    for name in before:
        user = after[name]["cpu_user_seconds"] - before[name]["cpu_user_seconds"]
        system = after[name]["cpu_system_seconds"] - before[name]["cpu_system_seconds"]
        if min(user, system) < 0:
            raise ValueError("process CPU counter regressed")
        result[name] = dict(user_seconds=user, system_seconds=system,
                            total_seconds=user + system,
                            ns_per_verified_operation=(user + system) * 1e9 / completed)
    return result


def validate_report(report, size, operations, policy, security, rate=None,
                    concurrency=1, message_type="con"):
    if not isinstance(report, dict):
        raise ValueError("native diagnostic report must be an object")
    if (report.get("schema") != "coaptic-native-complete/1"
            or type(report.get("bytes")) is not int or type(report.get("completed")) is not int
            or report.get("bytes") != size or report.get("completed") != operations
            or report.get("policy") != policy or report.get("security") != security
            or type(report.get("concurrency")) is not int or report["concurrency"] != concurrency
            or report.get("message_type") != message_type
            or type(concurrency) is not int or not 1 <= concurrency <= 4
            or message_type not in ("con", "non") or (concurrency > 1 and message_type != "non")):
        raise ValueError("mismatched native diagnostic report")
    for name, expected in (("requested_operations", operations), ("attempted", operations),
                           ("failed", 0), ("unattempted", 0), ("cancelled_inflight", 0),
                           ("rx_body_slots", concurrency), ("pacing_dropped_operations", 0)):
        if type(report.get(name)) is not int or report[name] != expected:
            raise ValueError("incomplete native operation accounting")
    if report.get("failure") is not None or "failure" not in report:
        raise ValueError("native campaign reported a failure")
    if (report.get("scheduled_rate_ops_per_second") != rate
            or (rate is not None and type(report.get("scheduled_rate_ops_per_second")) is not int)
            or "scheduled_rate_ops_per_second" not in report):
        raise ValueError("mismatched requested operation rate")
    values = report.get("latencies_ns")
    if (not isinstance(values, list) or len(values) != operations
            or any(type(v) is not int or not 0 <= v < 2**64 for v in values)):
        raise ValueError("incomplete native diagnostic timing")
    for key in ("elapsed_ns", "received_datagrams", "sent_datagrams",
                "core_heap_limit_bytes", "app_inline_bytes", "verification_heap_bytes",
                "timing_heap_bytes", "udp_scratch_bytes", "pending_call_metadata_bytes"):
        if type(report.get(key)) is not int or report[key] <= 0:
            raise ValueError("missing native diagnostic cost")
    minimum = operations * ((size + 1023) // 1024)
    if (type(report.get("warmup")) is not int or not 0 <= report["warmup"] <= 1000
            or type(report.get("total_sent_datagrams")) is not int
            or not report["sent_datagrams"] + report["warmup"] * ((size + 1023) // 1024)
            <= report["total_sent_datagrams"] <= 60_000
            or type(report.get("peak_pending")) is not int
            or not 1 <= report["peak_pending"] <= min(concurrency, operations)):
        raise ValueError("inconsistent bounded native resources")
    # Latencies may overlap: at most C Calls contribute time at any instant.
    # Each individual latency must still fit inside the measured window.
    if (report["received_datagrams"] < minimum or report["sent_datagrams"] < minimum
            or max(values) > report["elapsed_ns"]
            or sum(values) > concurrency * report["elapsed_ns"]):
        raise ValueError("incomplete native diagnostic traffic")
    achieved = report.get("achieved_ops_per_second")
    expected_rate = operations * 1e9 / report["elapsed_ns"]
    if (type(achieved) not in (int, float) or not math.isfinite(achieved)
            or not math.isclose(achieved, expected_rate, rel_tol=1e-9)):
        raise ValueError("inconsistent achieved operation rate")
    span = None if rate is None else (operations - 1) * 1_000_000_000 // rate
    if report.get("scheduled_dispatch_span_ns") != span or "scheduled_dispatch_span_ns" not in report:
        raise ValueError("inconsistent dispatch schedule")
    if span is not None and report["elapsed_ns"] < span:
        raise ValueError("campaign ended before its dispatch schedule")
    for key in ("pacing_late_operations", "pacing_missed_period_operations",
                "pacing_total_lateness_ns", "pacing_max_lateness_ns"):
        if type(report.get(key)) is not int or report[key] < 0:
            raise ValueError("missing pacing accounting")
    if (report["pacing_missed_period_operations"] > report["pacing_late_operations"]
            or report["pacing_late_operations"] > operations
            or report["pacing_max_lateness_ns"] > report["pacing_total_lateness_ns"]):
        raise ValueError("inconsistent pacing accounting")


def measure(server, client, size, operations, warmup, timeout_ms, policy, security,
            *, server_kind="coaptic-reusable", rate=None, cpu_gated=False,
            phase_timeout_seconds=300, concurrency=1, message_type="con"):
    if not (1 <= size <= 65536 and 1 <= operations <= 60_000 and 0 <= warmup <= 1000
            and (operations + warmup) * ((size + 1023) // 1024) <= 60_000
            and 1 <= timeout_ms <= 60000 and policy in ("spin", "sleep1")
            and security in ("unprotected", "oscore")
            and type(concurrency) is int and 1 <= concurrency <= 4
            and message_type in ("con", "non") and (concurrency == 1 or message_type == "non")
            and server_kind in SERVER_KINDS
            and type(phase_timeout_seconds) is int and 1 <= phase_timeout_seconds <= 3600
            and (rate is None or (type(rate) is int and 1 <= rate <= 1_000_000
                                  and operations / rate <= 120))):
        raise ValueError("diagnostic bounds")
    with tempfile.TemporaryDirectory(prefix="coaptic-native-diagnostic-") as directory:
        credentials = Path(directory) / "credentials"
        credentials.write_bytes(secrets.token_bytes(24))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        command = [str(Path(server).resolve()), server_kind, "127.0.0.1",
                   str(port), str(size), "1472"]
        if security == "oscore":
            command.append(str(credentials))
        child = None
        report = None
        server_log_path = Path(directory) / "server.log"
        with server_log_path.open("wb") as server_log:
            sut = subprocess.Popen(command, stdout=server_log, stderr=server_log)
            try:
                # Readiness sends no protected traffic and consumes no sequence.
                for _ in range(100):
                    if sut.poll() is not None:
                        raise RuntimeError("server exited before readiness")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        try:
                            probe.bind(("127.0.0.1", port))
                        except OSError:
                            break
                    time.sleep(.01)
                else:
                    raise RuntimeError("server bind deadline")
                command = [str(Path(client).resolve()), str(port), str(size),
                           str(operations), str(warmup), str(timeout_ms), policy, security]
                if security == "oscore":
                    command.append(str(credentials))
                if rate is not None:
                    command.extend(["--rate", str(rate)])
                command.extend(["--concurrency", str(concurrency), "--message-type", message_type])
                command.append("--cpu-gated" if cpu_gated else "--gated")
                child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True)
                ready_line = control_line(child.stderr, phase_timeout_seconds)
                if ready_line != "ready":
                    raise RuntimeError("client initialization/warmup refused: " + ready_line)
                startup = server_resources(server_log_path, server_kind,
                                           deadline=time.monotonic() + phase_timeout_seconds,
                                           server=sut)
                peers = {"client": psutil.Process(child.pid), "server": psutil.Process(sut.pid)}
                before = {name: snapshot(p) for name, p in peers.items()}
                started = time.perf_counter_ns()
                child.stdin.write("run\n")
                child.stdin.flush()
                if cpu_gated:
                    if control_line(child.stderr, phase_timeout_seconds) != "measured":
                        raise RuntimeError("client measurement failed before CPU boundary")
                    after = {name: snapshot(p) for name, p in peers.items()}
                    resource_window_ns = time.perf_counter_ns() - started
                    child.stdin.write("report\n")
                    child.stdin.flush()
                output = control_line(child.stdout, phase_timeout_seconds, 16 * 1024 * 1024)
                if not output:
                    raise RuntimeError("client refused measured operation")
                report = json.loads(output)
                validate_report(report, size, operations, policy, security, rate, concurrency, message_type)
                if report["warmup"] != warmup:
                    raise ValueError("mismatched warmup")
                if not cpu_gated:
                    after = {name: snapshot(p) for name, p in peers.items()}
                    resource_window_ns = time.perf_counter_ns() - started
                child.stdin.write("exit\n")
                child.stdin.flush()
                if child.wait(timeout=5):
                    raise RuntimeError("client exit failed")
                return dict(schema="coaptic-native-cost/1", report=report,
                            resource_window_ns=resource_window_ns, before=before, after=after,
                            cpu_cost=cpu_cost(before, after, report["completed"]),
                            cpu_boundary=("post-warmup ready/run to measured/report; excludes JSON formatting"
                                          if cpu_gated else "ready/run through JSON formatting"),
                            server_kind=server_kind, requested_operations_per_second=rate,
                            server_resources=startup,
                            concurrency=concurrency, message_type=message_type,
                            phase_timeout_seconds=phase_timeout_seconds,
                            cpu_attribution_limit="OS-accounted process user and system CPU; quantized; IPC/snapshot boundary overhead included; machine-wide interrupts/DPCs and unrelated kernel work not attributed; client reported separately",
                            server_sha256=digest(server), client_sha256=digest(client),
                            method=__doc__, psutil_version=psutil.__version__,
                            platform=platform.platform(), python=sys.version,
                            observed_sources={
                                "suite": source_identity(Path(__file__).resolve().parents[2]),
                                "core": source_identity(Path(__file__).resolve().parents[2] / "coaptic")},
                            source_identity_limit="checkout observations, not an independent binary build attestation")
            except Exception as error:
                if child is not None and child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)
                with server_log_path.open("rb") as reader:
                    server_output = reader.read(65536).decode("utf-8", errors="replace")
                error.diagnostic = dict(
                    server_log=server_output,
                    client_log=child.stderr.read(65536) if child is not None else "",
                    partial_report=report,
                    accounting_status=("partial report retained; not an accepted complete observation"
                                       if report is not None else "no report; measured activity unknown"),
                    phase_timeout_seconds=phase_timeout_seconds,
                    size=size, operations=operations, policy=policy, security=security,
                    concurrency=concurrency, message_type=message_type)
                raise
            finally:
                if child is not None and child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)
                sut.terminate()
                sut.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bytes", type=int, default=65536)
    parser.add_argument("--operations", type=int, default=256)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--policy", choices=("spin", "sleep1"), required=True)
    parser.add_argument("--security", choices=("unprotected", "oscore"), required=True)
    parser.add_argument("--server-kind", choices=SERVER_KINDS,
                        default="coaptic-reusable")
    parser.add_argument("--rate", type=int)
    parser.add_argument("--concurrency", type=int, choices=range(1, 5), default=1)
    parser.add_argument("--message-type", choices=("con", "non"), default="con")
    parser.add_argument("--cpu-gated", action="store_true")
    parser.add_argument("--phase-timeout-seconds", type=int, default=300,
                        help="finite control-phase wall deadline, 1..3600s; expiry invalidates observation")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; preserve prior observations")
    try:
        report = measure(args.server, args.client, args.bytes, args.operations, args.warmup,
                         args.timeout_ms, args.policy, args.security,
                         server_kind=args.server_kind, rate=args.rate, cpu_gated=args.cpu_gated,
                         phase_timeout_seconds=args.phase_timeout_seconds,
                         concurrency=args.concurrency, message_type=args.message_type)
    except Exception as error:
        args.output.write_text(json.dumps(dict(passed=False, error_type=type(error).__name__,
                                              reason=str(error),
                                              diagnostic=getattr(error, "diagnostic", None))),
                               encoding="utf-8")
        raise
    args.output.write_text(json.dumps(dict(passed=True, **report)), encoding="utf-8")


if __name__ == "__main__":
    main()
