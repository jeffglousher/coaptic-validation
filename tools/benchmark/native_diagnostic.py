"""Coaptic-only complete-operation diagnostic, not a comparative campaign.

Gates keep CPU/RSS samples outside operation clocks. Resource windows include
control IPC/sampling overhead; CPU accounting is quantized. Optional kernel memory
high-water observations cover process lifetime, not solely measurement. Kernel socket memory and
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
from native_profiles import dimensions, validate_concurrency


SERVER_KINDS = ("coaptic-reusable", "coaptic-mio", "coaptic-ready", "coaptic-async",
                "coaptic-blocking", "coaptic-staged-ready", "coaptic-staged-mio", "coaptic-mio-direct")


def server_resources(log_path, server_kind, *, deadline, server,
                     resource_profile="host-control", size=None, security=None, rx_bytes=1472):
    """Await one bounded startup line before resource gates, without touching writer offsets.

    ``deadline`` is an absolute monotonic time; ``server`` supplies Popen.poll().
    Partial writes remain unparsed until newline. The independently opened reader
    never seeks or reads the file description inherited by the server.
    """
    if server_kind not in ("coaptic-async", "coaptic-blocking", "coaptic-staged-ready", "coaptic-staged-mio",
                           "coaptic-mio", "coaptic-mio-direct"):
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
    if server_kind in ("coaptic-mio", "coaptic-mio-direct"):
        fields = ("adapter_inline_bytes", "app_including_adapter_bytes", "poll_inline_bytes",
                  "events_inline_bytes", "event_capacity")
        if (record.get("schema") != "coaptic-native-mio-resources/1"
                or record.get("server_kind") != server_kind
                or any(type(record.get(key)) is not int or not 0 < record[key] < 2**64 for key in fields)
                or type(record.get("udp_scratch_bytes")) is not int
                or record["udp_scratch_bytes"] != (0 if server_kind.endswith("-direct") else 2049)
                or not record["udp_scratch_bytes"] <= record["adapter_inline_bytes"]
                <= record["app_including_adapter_bytes"]
                or record["event_capacity"] != 8
                or any(type(record.get(key)) is not int or record[key] != 0
                       for key in ("worker_threads", "pending_kernel_operations"))
                or any(key not in record or record[key] is not None
                       for key in ("runtime_heap_bytes", "runtime_stack_bytes", "kernel_bytes"))
                or any(type(record.get(key)) is not str or not 0 < len(record[key]) <= 1024
                       for key in ("nesting", "limits"))):
            raise ValueError("invalid Mio server startup ledger")
        # Old retained host ledgers remain readable. New profile windows must
        # identify every actual configured dimension before the CPU gate opens.
        if "resource_profile" in record or resource_profile != "host-control":
            if size is None or (resource_profile != "host-control" and server_kind != "coaptic-mio"):
                raise ValueError("profile ledger requires selected representation and Mio")
            for key, expected in dimensions(resource_profile, size, rx_bytes).items():
                if type(record.get(key)) is not type(expected) or record[key] != expected:
                    raise ValueError("mismatched Mio profile ledger: " + key)
            heap = record.get("app_requested_heap_bytes")
            payloads = sum(record[n] * record[b] for n, b in
                           (("rx_slots", "rx_datagram_bytes"), ("tx_slots", "tx_datagram_bytes"),
                            ("rx_body_slots", "rx_body_bytes"), ("tx_body_slots", "tx_body_bytes")))
            if (type(heap) is not int or heap < 0
                    or (record["storage"] == "fixed" and heap != 0)
                    or (record["storage"] == "allocated" and heap < payloads)
                    or record.get("security") not in ("unprotected", "oscore")
                    or (security is not None and record["security"] != security)
                    or any(key not in record or record[key] is not None for key in
                           ("allocator_overhead_bytes", "initialization_stack_bytes", "events_heap_bytes"))):
                raise ValueError("invalid Mio profile owner ledger")
        return record
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
    if server_kind == "coaptic-staged-mio":
        fields = ("udp_scratch_bytes", "staged_datagram_capacity", "stage_metadata_bytes",
                  "driver_inline_bytes", "adapter_inline_bytes", "app_including_adapter_bytes")
        if (record.get("schema") != "coaptic-native-server-resources/2"
                or record.get("server_kind") != server_kind
                or any(type(record.get(key)) is not int or not 0 < record[key] < 2**64
                       for key in fields)
                or record["udp_scratch_bytes"] != 2049
                or record["staged_datagram_capacity"] != 1
                or record["stage_metadata_bytes"] > 64
                or not record["udp_scratch_bytes"] + record["stage_metadata_bytes"]
                <= record["adapter_inline_bytes"] <= record["app_including_adapter_bytes"]
                or record.get("send_policy") != "immediate_send_to"
                or any(key in record for key in ("loop_future_borrowing_app_bytes",
                                                 "loop_future_including_app_bytes",
                                                 "stage_cache_metadata_bytes", "read_timeout_max_us",
                                                 "send_timeout_us", "timeouts_soft"))
                or any(key not in record or record[key] is not None
                       for key in ("runtime_heap_bytes", "runtime_stack_bytes"))
                or any(type(record.get(key)) is not str or not 0 < len(record[key]) <= 1024
                       for key in ("nesting", "limits"))):
            raise ValueError("invalid staged Mio server startup ledger")
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
    if server_kind == "coaptic-staged-ready":
        fields = ("staged_datagram_capacity", "stage_metadata_bytes", "driver_inline_bytes")
        if (any(type(record.get(key)) is not int or not 0 < record[key] < 2**64
                for key in fields)
                or record["staged_datagram_capacity"] != 1
                or record["stage_metadata_bytes"] > 64
                or record["udp_scratch_bytes"] + record["stage_metadata_bytes"]
                > record["adapter_inline_bytes"]
                or record.get("send_policy") != "immediate_try_send_to"
                or any(key in record for key in ("stage_cache_metadata_bytes", "read_timeout_max_us",
                                                 "send_timeout_us", "timeouts_soft"))):
            raise ValueError("invalid staged ready server startup ledger")
    return record


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_identity(path):
    def git(*args):
        return subprocess.run(["git", *args], cwd=path, capture_output=True,
                              text=True, check=True).stdout.strip()
    return dict(revision=git("rev-parse", "HEAD"), tree=git("rev-parse", "HEAD^{tree}"),
                status=git("status", "--porcelain"))


PROC_MEMORY_READ_LIMIT = 8192  # Per file, including the refusal sentinel byte.
PROC_MEMORY_RESULT_LIMIT = 1024  # Compact ASCII JSON, including member overhead.


def _proc_memory_fields(raw, source):
    """Parse only four status fields or one limits row; no general /proc parser."""
    if len(raw) >= PROC_MEMORY_READ_LIMIT:
        raise ValueError("read_limit")
    if not raw or not raw.endswith(b"\n"):
        raise ValueError("incomplete")
    fields = {}
    start = 0
    while start < len(raw):
        end = raw.find(b"\n", start)
        line = raw[start:end]
        start = end + 1
        if source == "status":
            key, separator, value = line.partition(b":")
            if key not in (b"VmHWM", b"VmPeak", b"VmStk", b"Threads"):
                continue
            if not separator or len(line) > 128:
                raise ValueError("malformed")
            tokens = value.split()
            if key == b"Threads":
                if len(tokens) != 1:
                    raise ValueError("malformed")
                fields_key, scale = "threads", 1
            else:
                if len(tokens) != 2 or tokens[1] != b"kB":
                    raise ValueError("malformed")
                fields_key, scale = {b"VmHWM": "vm_hwm_bytes", b"VmPeak": "vm_peak_bytes",
                                     b"VmStk": "vm_stk_bytes"}[key], 1024
            values = (tokens[0],)
        else:
            if not line.startswith(b"Max stack size"):
                continue
            if len(line) > 128:
                raise ValueError("malformed")
            tokens = line.split()
            if len(tokens) != 6 or tokens[:3] != [b"Max", b"stack", b"size"] or tokens[5] != b"bytes":
                raise ValueError("malformed")
            fields_key, scale, values = "stack_limit", 1, tokens[3:5]
        if fields_key in fields:
            raise ValueError("duplicate")
        numbers = []
        for token in values:
            if source == "limits" and token == b"unlimited":
                numbers.append("unlimited")
            elif not 1 <= len(token) <= 20 or not token.isdigit() or int(token) * scale >= 2**64:
                raise ValueError("malformed")
            else:
                numbers.append(int(token) * scale)
        if fields_key == "threads" and numbers[0] == 0:
            raise ValueError("malformed")
        fields[fields_key] = numbers[0] if source == "status" else numbers
    if len(fields) != (4 if source == "status" else 1):
        raise ValueError("missing")
    if source == "limits":
        soft, hard = fields.pop("stack_limit")
        if hard != "unlimited" and (soft == "unlimited" or soft > hard):
            raise ValueError("malformed")
        fields = dict(stack_soft_bytes=soft, stack_hard_bytes=hard)
    return dict(available=True, **fields)


def process_memory_evidence(pid):
    """Optional read-only Linux metadata for an owned, unreaped child at a gate.

    Reads are serial, non-atomic and never used for CPU/memory acceptance. Callers
    retain PID custody; this helper neither polls/reaps nor acts on any PID.
    """
    result = dict(schema="coaptic-proc-memory/1", available=False)
    if sys.platform != "linux":
        return dict(result, reason="unsupported_platform")
    if type(pid) is not int or not 0 < pid < 2**31:
        return dict(result, reason="invalid_pid")
    result["pid"] = pid
    for source in ("status", "limits"):
        try:
            # Unbuffered: the file wrapper cannot read ahead beyond this cap.
            with Path(f"/proc/{pid}/{source}").open("rb", buffering=0) as reader:
                raw = reader.read(PROC_MEMORY_READ_LIMIT - 1)
                if reader.read(1):
                    # Even a newline-ended short read must prove EOF, rather
                    # than accepting a prefix that happens to contain our fields.
                    raise ValueError("read_limit" if len(raw) == PROC_MEMORY_READ_LIMIT - 1 else "incomplete")
            result[source] = _proc_memory_fields(raw, source)
        except OSError:
            result[source] = dict(available=False, reason="read_failed")
        except ValueError as error:
            reason = str(error)
            result[source] = dict(available=False, reason=reason if reason in
                                 ("read_limit", "incomplete", "malformed", "duplicate", "missing") else "malformed")
        finally:
            raw = None  # Release this file's bytes before the next bounded read.
    result["available"] = all(result[source]["available"] for source in ("status", "limits"))
    if len(json.dumps(result, separators=(",", ":"), ensure_ascii=True)) + len(',"process_memory":') > PROC_MEMORY_RESULT_LIMIT:
        return dict(schema="coaptic-proc-memory/1", available=False, reason="result_limit")
    return result


def snapshot(process):
    cpu = process.cpu_times()
    memory = process.memory_info()._asdict()
    return dict(cpu_user_seconds=cpu.user, cpu_system_seconds=cpu.system,
                memory=memory, process_memory=process_memory_evidence(process.pid))


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


ADMISSION_DIAGNOSTIC_LIMIT = 2048  # Includes the report member name and comma.


def validate_admission_diagnostics(report, selected=False):
    """Bounded local-interval accounting; never a causal or CPU qualification."""
    if type(selected) is not bool:
        raise ValueError("admission diagnostics selection must be boolean")
    if not selected:
        if "admission_diagnostics" in report:
            raise ValueError("unrequested admission diagnostics")
        return
    if (type(report.get("concurrency")) is not int or report["concurrency"] != 1
            or type(report.get("scheduled_rate_ops_per_second")) is not int
            or not 1 <= report["scheduled_rate_ops_per_second"] <= 1_000_000):
        raise ValueError("admission diagnostics require paced concurrency 1")
    value = report.get("admission_diagnostics")
    counts = ("admissions", "first_admissions", "first_missed", "prior_forced_missed")
    fields = {"schema", "storage_bytes", "option_storage_bytes", "first_lateness_ns",
              "idle_sleep", "no_idle_sleep", *counts}
    if (not isinstance(value, dict) or set(value) != fields
            or value["schema"] != "coaptic-admission-interval/1"):
        raise ValueError("malformed admission diagnostics schema")
    for key in (*counts, "storage_bytes", "option_storage_bytes", "first_lateness_ns"):
        if type(value[key]) is not int or not 0 <= value[key] < 2**(128 if key.endswith("_ns") else 64):
            raise ValueError("invalid admission diagnostics counter")
    if not 0 < value["storage_bytes"] <= value["option_storage_bytes"] <= ADMISSION_DIAGNOSTIC_LIMIT:
        raise ValueError("invalid admission diagnostics storage")
    for name in ("idle_sleep", "no_idle_sleep"):
        bucket = value[name]
        if not isinstance(bucket, dict) or set(bucket) != {"admissions", "positive", "crossed_missed", "total_ns", "max_ns"}:
            raise ValueError("malformed admission residual schema")
        for key, number in bucket.items():
            if type(number) is not int or not 0 <= number < 2**(128 if key.endswith("_ns") else 64):
                raise ValueError("invalid admission residual counter")
        if (not bucket["crossed_missed"] <= bucket["positive"] <= bucket["admissions"]
                or not bucket["positive"] <= bucket["total_ns"]
                or not bucket["max_ns"] <= bucket["total_ns"] <= bucket["positive"] * bucket["max_ns"]
                or bool(bucket["positive"]) != bool(bucket["max_ns"])):
            raise ValueError("inconsistent admission residual accounting")
    slept, awake = value["idle_sleep"], value["no_idle_sleep"]
    count = value["admissions"]
    period = 1_000_000_000 // report["scheduled_rate_ops_per_second"]
    residual_total = slept["total_ns"] + awake["total_ns"]
    if (type(report.get("attempted")) is not int or not 0 <= count == report["attempted"] <= 60_000
            or value["first_admissions"] != int(count > 0)
            or (count == 0 and value["first_lateness_ns"] != 0)
            or value["first_missed"] > value["first_admissions"]
            or value["first_missed"] != int(value["first_lateness_ns"] >= period)
            or value["first_admissions"] + slept["admissions"] + awake["admissions"] != count
            or value["prior_forced_missed"] > count - value["first_admissions"]
            or value["first_missed"] + value["prior_forced_missed"]
            + slept["crossed_missed"] + awake["crossed_missed"] != report["pacing_missed_period_operations"]
            or residual_total + value["first_lateness_ns"] > report["pacing_total_lateness_ns"]
            or slept["positive"] + awake["positive"] + int(value["first_lateness_ns"] > 0)
            > report["pacing_late_operations"]
            or max(slept["max_ns"], awake["max_ns"], value["first_lateness_ns"]) > report["pacing_max_lateness_ns"]):
        raise ValueError("inconsistent admission diagnostics accounting")
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
    if len(encoded) + len(',"admission_diagnostics":') > ADMISSION_DIAGNOSTIC_LIMIT:
        raise ValueError("admission diagnostics exceeds byte allowance")


def validate_endpoint_report(report, concurrency, selected, *, require_overlap=False):
    """Pair ownership evidence is mandatory; a C parameter alone proves nothing."""
    ledger = report.get("endpoint_transport")
    if not selected:
        if ledger is not None or "overlapping_completions" in report or "verified_completions" in report:
            raise ValueError("independent endpoint evidence in a shared endpoint cohort")
        return
    if not isinstance(ledger, dict) or ledger.get("schema") != "coaptic-local-pairs/1":
        raise ValueError("missing actual endpoint ownership")
    ports = ledger.get("local_ports")
    if (not isinstance(ports, list) or len(ports) != concurrency
            or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
            or len(set(ports)) != concurrency):
        raise ValueError("independent endpoints need distinct actual local ports")
    server = ledger.get("server")
    if not isinstance(server, str) or not server.startswith("127.0.0.1:"):
        raise ValueError("endpoint ledger needs one actual loopback server")
    try:
        if not 1 <= int(server.split(":")[1]) <= 65535:
            raise ValueError()
    except (ValueError, IndexError):
        raise ValueError("invalid actual server port") from None
    for key, expected in (("socket_count", concurrency), ("scratch_bytes", 1473),
                          ("receive_attempt_bound", concurrency), ("packet_queues", 0),
                          ("workers", 0), ("requested_heap_bytes", 0)):
        if type(ledger.get(key)) is not int or ledger[key] != expected:
            raise ValueError("invalid bounded endpoint owner: " + key)
    if (type(ledger.get("adapter_inline_bytes")) is not int
            or not 1473 <= ledger["adapter_inline_bytes"] <= report.get("app_inline_bytes", 0)
            or any(k not in ledger or ledger[k] is not None for k in ("kernel_bytes", "peak_stack_bytes"))
            or any(type(report.get(k)) is not int or report[k] != 5 for k in ("client_rx_slots", "client_tx_slots"))):
        raise ValueError("invalid client endpoint resource accounting")
    for key in ("sent", "received", "measured_sent_datagrams", "measured_received_datagrams"):
        values = ledger.get(key)
        if (not isinstance(values, list) or len(values) != concurrency
                or any(type(v) is not int or not 0 <= v <= 60_000 for v in values)):
            raise ValueError("invalid per-lane service")
    if (sum(ledger["sent"]) != report.get("total_sent_datagrams")
            or sum(ledger["received"]) < report.get("received_datagrams", 0)
            or sum(ledger["measured_sent_datagrams"]) != report.get("sent_datagrams")
            or sum(ledger["measured_received_datagrams"]) != report.get("received_datagrams")
            or any(m > t for key in ("sent", "received") for m, t in
                   zip(ledger["measured_" + key + "_datagrams"], ledger[key]))):
        raise ValueError("global socket accounting mismatch")
    overlap = report.get("overlapping_completions")
    verified = report.get("verified_completions")
    if (not isinstance(verified, list) or len(verified) != concurrency
            or any(type(v) is not int or not 0 <= v <= report.get("completed", 0) for v in verified)
            or sum(verified) != report.get("completed")
            or any(type(report.get(k)) is not int or report[k] <= 0 for k in
                   ("window_metadata_bytes", "lane_counter_snapshot_bytes", "peer_keys_bytes"))
            or report["lane_counter_snapshot_bytes"] != 64):
        raise ValueError("invalid per-lane verified completion accounting")
    if (not isinstance(overlap, list) or len(overlap) != concurrency
            or any(type(v) is not int or not 0 <= v <= report.get("completed", 0) for v in overlap)
            or sum(overlap) > report.get("completed", 0)
            or any(o > v for o, v in zip(overlap, verified))):
        raise ValueError("invalid observed Call overlap")
    if require_overlap and (report.get("peak_pending") != concurrency
                            or sum(overlap) < concurrency - 1
                            or any(v == 0 for v in verified)):
        raise ValueError("configured endpoint count did not demonstrate actual overlap/service")


def validate_report(report, size, operations, policy, security, rate=None,
                    concurrency=1, message_type="con", admission_diagnostics=False, independent_endpoints=False):
    if not isinstance(report, dict):
        raise ValueError("native diagnostic report must be an object")
    validate_concurrency(concurrency, message_type, independent_endpoints)
    validate_endpoint_report(report, concurrency, independent_endpoints)
    if (report.get("schema") != "coaptic-native-complete/1"
            or type(report.get("bytes")) is not int or type(report.get("completed")) is not int
            or report.get("bytes") != size or report.get("completed") != operations
            or report.get("policy") != policy or report.get("security") != security
            or type(report.get("concurrency")) is not int or report["concurrency"] != concurrency
            or report.get("message_type") != message_type
            or type(concurrency) is not int or not 1 <= concurrency <= 4
            or message_type not in ("con", "non")):
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
    validate_admission_diagnostics(report, admission_diagnostics)


def measure(server, client, size, operations, warmup, timeout_ms, policy, security,
            *, server_kind="coaptic-reusable", rate=None, cpu_gated=False,
            phase_timeout_seconds=300, concurrency=1, message_type="con", admission_diagnostics=False, independent_endpoints=False):
    validate_concurrency(concurrency, message_type, independent_endpoints)
    if independent_endpoints and (server_kind != "coaptic-mio" or (size > 1024 and concurrency > 2)):
        raise ValueError("host diagnostic independent CON requires Mio and at most two concurrent bodies")
    if not (1 <= size <= 65536 and 1 <= operations <= 60_000 and 0 <= warmup <= 1000
            and (operations + warmup) * ((size + 1023) // 1024) <= 60_000
            and 1 <= timeout_ms <= 60000 and policy in ("spin", "sleep1")
            and security in ("unprotected", "oscore")
            and type(concurrency) is int and 1 <= concurrency <= 4
            and type(admission_diagnostics) is bool
            and (not admission_diagnostics or (concurrency == 1 and rate is not None))
            and message_type in ("con", "non") and (concurrency == 1 or message_type == "non" or independent_endpoints)
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
                if independent_endpoints:
                    command.append("--independent-endpoints")
                if admission_diagnostics:
                    command.append("--admission-diagnostics")
                command.append("--cpu-gated" if cpu_gated else "--gated")
                child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True)
                ready_line = control_line(child.stderr, phase_timeout_seconds)
                if ready_line != "ready":
                    raise RuntimeError("client initialization/warmup refused: " + ready_line)
                startup = server_resources(server_log_path, server_kind,
                                           deadline=time.monotonic() + phase_timeout_seconds,
                                           server=sut, size=size, security=security)
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
                validate_report(report, size, operations, policy, security, rate, concurrency, message_type,
                                admission_diagnostics, independent_endpoints=independent_endpoints)
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
                            concurrency=concurrency, message_type=message_type, independent_endpoints=independent_endpoints,
                            admission_diagnostics=admission_diagnostics,
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
                    concurrency=concurrency, message_type=message_type, independent_endpoints=independent_endpoints,
                    admission_diagnostics=admission_diagnostics)
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
    parser.add_argument("--admission-diagnostics", action="store_true",
                        help="paced C1 local admission intervals; instrumentation, not CPU qualification")
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
    parser.add_argument("--independent-endpoints", action="store_true")
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
                         concurrency=args.concurrency, message_type=args.message_type, independent_endpoints=args.independent_endpoints,
                         admission_diagnostics=args.admission_diagnostics)
    except Exception as error:
        args.output.write_text(json.dumps(dict(passed=False, error_type=type(error).__name__,
                                              reason=str(error),
                                              diagnostic=getattr(error, "diagnostic", None))),
                               encoding="utf-8")
        raise
    args.output.write_text(json.dumps(dict(passed=True, **report)), encoding="utf-8")


if __name__ == "__main__":
    main()
