"""Coaptic-only complete-operation diagnostic, not a comparative campaign.

Gates keep CPU/RSS samples outside operation clocks. Resource windows include
control IPC/sampling overhead; CPU accounting is quantized. RSS high-water marks
cover the process lifetime, not solely measurement. Kernel socket memory and
allocator overhead are not derived from the core's requested heap quota.
"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import sys

import psutil


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


def validate_report(report, size, operations, policy, security):
    if not isinstance(report, dict):
        raise ValueError("native diagnostic report must be an object")
    if (report.get("schema") != "coaptic-native-complete/1"
            or type(report.get("bytes")) is not int or type(report.get("completed")) is not int
            or report.get("bytes") != size or report.get("completed") != operations
            or report.get("policy") != policy or report.get("security") != security):
        raise ValueError("mismatched native diagnostic report")
    values = report.get("latencies_ns")
    if (not isinstance(values, list) or len(values) != operations
            or any(type(v) is not int or v < 0 for v in values)):
        raise ValueError("incomplete native diagnostic timing")
    for key in ("elapsed_ns", "received_datagrams", "sent_datagrams",
                "core_heap_limit_bytes", "app_inline_bytes", "verification_heap_bytes",
                "timing_heap_bytes", "udp_scratch_bytes"):
        if type(report.get(key)) is not int or report[key] <= 0:
            raise ValueError("missing native diagnostic cost")
    minimum = operations * ((size + 1023) // 1024)
    if (report["received_datagrams"] < minimum or report["sent_datagrams"] < minimum
            or sum(values) > report["elapsed_ns"]):
        raise ValueError("incomplete native diagnostic traffic")


def measure(server, client, size, operations, warmup, timeout_ms, policy, security):
    if not (1 <= size <= 65536 and 1 <= operations <= 20000 and 0 <= warmup <= 1000
            and 1 <= timeout_ms <= 60000 and policy in ("spin", "sleep1")
            and security in ("plaintext", "oscore")):
        raise ValueError("diagnostic bounds")
    with tempfile.TemporaryDirectory(prefix="coaptic-native-diagnostic-") as directory:
        credentials = Path(directory) / "credentials"
        credentials.write_bytes(secrets.token_bytes(24))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        command = [str(Path(server).resolve()), "coaptic-reusable", "127.0.0.1",
                   str(port), str(size), "1472"]
        if security == "oscore":
            command.append(str(credentials))
        child = None
        with tempfile.TemporaryFile() as server_log:
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
                command.append("--gated")
                child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True)
                if child.stderr.readline().strip() != "ready":
                    raise RuntimeError("client initialization/warmup refused")
                peers = {"client": psutil.Process(child.pid), "server": psutil.Process(sut.pid)}
                before = {name: snapshot(p) for name, p in peers.items()}
                started = time.perf_counter_ns()
                child.stdin.write("run\n")
                child.stdin.flush()
                output = child.stdout.readline()
                if not output:
                    raise RuntimeError("client refused measured operation")
                report = json.loads(output)
                validate_report(report, size, operations, policy, security)
                after = {name: snapshot(p) for name, p in peers.items()}
                resource_window_ns = time.perf_counter_ns() - started
                child.stdin.write("exit\n")
                child.stdin.flush()
                if child.wait(timeout=5):
                    raise RuntimeError("client exit failed")
                return dict(schema="coaptic-native-cost/1", report=report,
                            resource_window_ns=resource_window_ns, before=before, after=after,
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
                server_log.seek(0)
                error.diagnostic = dict(
                    server_log=server_log.read(65536).decode("utf-8", errors="replace"),
                    client_log=child.stderr.read(65536) if child is not None else "",
                    size=size, operations=operations, policy=policy, security=security)
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
    parser.add_argument("--security", choices=("plaintext", "oscore"), required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; preserve prior observations")
    try:
        report = measure(args.server, args.client, args.bytes, args.operations, args.warmup,
                         args.timeout_ms, args.policy, args.security)
    except Exception as error:
        args.output.write_text(json.dumps(dict(passed=False, error_type=type(error).__name__,
                                              reason=str(error),
                                              diagnostic=getattr(error, "diagnostic", None))),
                               encoding="utf-8")
        raise
    args.output.write_text(json.dumps(dict(passed=True, **report)), encoding="utf-8")


if __name__ == "__main__":
    main()
