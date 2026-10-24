"""Finite same-source Mio trace-off/on diagnostic; never primary CPU acceptance.

The native endpoints and verification are the existing linux_cpu.window path.
Aya 0.14 TracePoint::attach opens its perf event on CPU0; this does not prove
kernel callback coverage. BOTH arms pin the single-thread server there for
this initial diagnostic. VDSO calls and non-target filtering costs
are not attributed. Independent entry/exit boundaries must not be balanced.
"""
import argparse
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import time

import linux_cpu as cpu
import native_diagnostic as native

META, LOG, OUTPUT = 16 * 1024, 16 * 1024, 16 * cpu.MIB
MAX_CPUS, COUNTERS = 64, 82
CLASSES = ("enter", "exit_ok", "exit_eagain", "exit_eintr", "exit_other_error")
BINS = ("read", "write", "poll", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "epoll_wait", "epoll_pwait", "recvmmsg", "sendmmsg", "pselect6", "ppoll",
        "clock_gettime", "epoll_pwait2", "other")


def load(path, limit=META):
    return json.loads(cpu.bounded_read(path, limit))


def regular(path, maximum):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_nlink != 1:
        raise ValueError("observer input must be a bounded regular unlinked file")
    return path


def target_identity(target):
    if not isinstance(target, cpu.OwnedProcess) or target.poll() is not None:
        raise RuntimeError("observer requires a live reserved owned target")
    # scheduler_snapshot already bounds proc input and validates identity twice.
    record = cpu.scheduler_snapshot(target.pid)
    if not record["available"] or record["threads"] != 1:
        raise RuntimeError("observer requires exactly one target thread and schedstat")
    if os.sched_getaffinity(target.pid) != {0}:
        raise RuntimeError("CPU0 target affinity changed")
    return {key: record[key] for key in ("pid", "start_ticks", "threads")}


def validate_counts(report):
    values = report.get("counts")
    if (report.get("event") != "disabled" or report.get("bins") != list(BINS)
            or report.get("classes") != list(CLASSES) or not isinstance(values, list)
            or len(values) != COUNTERS
            or any(type(n) is not int or not 0 <= n < 2**64 - 1 for n in values)
            or values[-2:] != [0, 0] or sum(values[:-2]) == 0):
        raise ValueError("invalid, empty, saturated or read-error syscall counts")
    for name in ("loader_lifetime_user_us", "loader_lifetime_system_us", "loader_lifetime_maxrss_kib"):
        if type(report.get(name)) is not int or report[name] < 0:
            raise ValueError("missing bounded helper resource readout")
    # No invariant relates entries to exits: gates may split an in-flight syscall.
    return {name: dict(zip(CLASSES, values[index * 5:index * 5 + 5]))
            for index, name in enumerate(BINS)}


class Capture(dict):
    def __init__(self, owner, target, directory):
        super().__init__(arm=owner.arm, cpu=0, available=False,
                         diagnostic_only=True, boundary_censoring=True,
                         scope="counts/op, not time/CPU shares; vDSO absent; CPU0 non-target filter overhead unassigned")
        self.owner, self.target, self.directory = owner, target, directory
        self.identity = target_identity(target)
        self.helper = self.log = None
        self.phase = 0
        self.deadline = time.monotonic() + 55
        self.scheduler_before = None
        self.closed = False

    def check(self):
        if self.owner.cancel is not None and self.owner.cancel.is_set():
            raise InterruptedError("syscall capture cancelled")
        if target_identity(self.target) != self.identity:
            raise RuntimeError("syscall target identity changed")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("syscall capture deadline")

    def reply(self, event):
        self.check()
        try:
            line = native.control_line(self.helper.stdout,
                                       min(5, self.deadline - time.monotonic()), META - 1)
        except TimeoutError as error:
            raise TimeoutError(f"syscall helper {event} ACK deadline") from error
        value = json.loads(line)
        if value.get("event") != event:
            raise ValueError("syscall helper protocol order")
        self.check()
        return value

    def start(self):
        self.check()
        if self.owner.arm == "off":
            self.update(available=True, attached=False)
            return
        self.log = (self.directory / "syscall-helper.log").open("wb")
        args = ["sudo", "-n", "--", "prlimit", f"--fsize={LOG}:{LOG}",
                "--as=134217728:134217728", "--stack=1048576:1048576", "--cpu=30:30",
                "--nofile=64:64", "--", "timeout", "--foreground", "--signal=TERM",
                "--kill-after=2", "60", str(self.owner.loader), str(self.owner.object),
                str(self.target.pid), str(self.identity["start_ticks"]), str(os.getuid()), "55"]
        self["command"] = args
        self.helper = cpu.spawn(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=self.log, text=True, file_limit=LOG)
        ready = self.reply("ready")
        if (ready.get("pid") != self.target.pid or ready.get("start_ticks") != self.identity["start_ticks"]
                or ready.get("uid") != os.getuid() or ready.get("cpu") != 0
                or type(ready.get("possible_cpus")) is not int
                or not 1 <= ready["possible_cpus"] <= MAX_CPUS
                or ready.get("map_value_bytes") != 8 + 8 * COUNTERS * ready["possible_cpus"]):
            raise ValueError("syscall helper identity/resource gate")
        cpu.save(self.directory / "syscall-ready.json", ready, META)
        self.update(attached=True, ready_file="syscall-ready.json", possible_cpus=ready["possible_cpus"],
                    map_value_bytes=ready["map_value_bytes"],
                    kernel_map_link_metadata_bytes=None,
                    helper_limits=dict(address_space_bytes=128*cpu.MIB, stack_bytes=cpu.MIB,
                                       cpu_seconds=30, wall_seconds=60, log_bytes=LOG),
                    memory_scope="fixed map values/capped program memlock; kernel metadata/peak stack unknown; whole-memory acceptance open")

    def enable(self):
        if self.phase != 0:
            raise ValueError("syscall enable phase")
        self.check()
        self.scheduler_before = cpu.scheduler_snapshot(self.target.pid)
        self["enable_attempt_ns"] = time.monotonic_ns()
        if self.helper is not None:
            self.helper.stdin.write("enable\n")
            self.helper.stdin.flush()
            self.reply("enabled")
        self["enable_ack_ns"] = time.monotonic_ns()
        self.phase = 1

    def finish(self):
        if self.phase != 1:
            raise ValueError("syscall disable phase")
        self.check()
        self["disable_attempt_ns"] = time.monotonic_ns()
        if self.helper is not None:
            self.helper.stdin.write("disable\n")
            self.helper.stdin.flush()
            final = self.reply("disabled")
            cpu.save(self.directory / "syscall-counts.json", final, META)
            self["counts_file"] = "syscall-counts.json"
            validate_counts(final)
        self["disable_ack_ns"] = time.monotonic_ns()
        after = cpu.scheduler_snapshot(self.target.pid)
        cpu.save(self.directory / "syscall-scheduler.json",
                 dict(before=self.scheduler_before, after=after,
                      delta=cpu.scheduler_delta(self.scheduler_before, after)), META)
        self.update(available=True, scheduler_file="syscall-scheduler.json")
        self.phase = 2

    def close(self):
        if self.closed:
            return
        self.closed = True
        primary = None
        if self.helper is not None:
            try:
                if self.phase == 2 and self.helper.wait(timeout=5) != 0:
                    raise RuntimeError("syscall helper exit failure")
            except BaseException as error:
                primary = error
            try:
                cpu.stop(self.helper, elevated=True)
            except BaseException as error:
                self.owner.unresolved = True
                self["cleanup_unresolved"] = True
                error.cleanup_unresolved = True
                if primary is None:
                    primary = error
                else:
                    primary.cleanup_unresolved = True
                    primary.add_note("syscall helper cleanup: " + str(error)[:512])
            for stream in (self.helper.stdin, self.helper.stdout, self.log):
                try:
                    stream.close()
                except BaseException as error:
                    self.owner.unresolved = True
                    self["cleanup_unresolved"] = True
                    error.cleanup_unresolved = True
                    if primary is None:
                        primary = error
                    else:
                        primary.cleanup_unresolved = True
                        primary.add_note("syscall stream close: " + str(error)[:512])
        if self.phase != 2:
            self["available"] = False
        if primary is not None:
            raise primary


class Observer:
    def __init__(self, arm, loader, object_path, *, cancel=None):
        if arm not in ("off", "on"):
            raise ValueError("syscall observer arm")
        self.arm, self.loader, self.object = arm, Path(loader), Path(object_path)
        self.cancel, self.unresolved = cancel, False
        self.capture = None

    def prepare_target(self, target, directory):
        if self.unresolved:
            raise RuntimeError("previous privileged observer cleanup unresolved")
        if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() == 0
                or 0 not in os.sched_getaffinity(target.pid)):
            raise RuntimeError("observer requires unprivileged Linux x86_64 target with allowed CPU0")
        os.sched_setaffinity(target.pid, {0})
        target_identity(target)
        self.capture = Capture(self, target, directory)
        try:
            self.capture.start()
        except BaseException as error:
            error.syscall_capture = self.capture
            raise

    def close(self):
        if self.capture is not None:
            self.capture.close()

    @contextmanager
    def __call__(self, target, directory):
        capture = self.capture
        if capture is None or capture.target is not target:
            raise RuntimeError("observer not prepared before warmup")
        primary = None
        try:
            yield capture
        except BaseException as error:
            error.syscall_capture = capture
            primary = error
            raise
        finally:
            try:
                capture.close()
            except BaseException as error:
                if primary is None:
                    raise
                primary.add_note("syscall independent cleanup: " + str(error)[:512])
                if getattr(error, "cleanup_unresolved", False):
                    primary.cleanup_unresolved = True


def diagnostic_gate(result, tick):
    # Use the existing load, operation, endpoint and CPU-resolution gates for
    # overhead evidence only. The original result ALWAYS remains ineligible.
    check = dict(result)
    check.pop("syscall_diagnostic", None)
    return cpu.accepted(check, tick) and result.get("syscall_trace", {}).get("available") is True


def comparison(off, on, tick):
    output = dict(eligible=False, diagnostic_only=True, server_cpu_ratio=None,
                  limits="same-source instrumentation overhead; never optimization acceptance or transport/CPU shares")
    if not all(item.get("passed") and item.get("syscall_trace", {}).get("available") for item in (off,on)):
        output["reason"] = "native verification or trace gate failed; raw windows retained"
        return output
    values = {arm: sorted(cpu.report_latencies(item)) for arm, item in (("off", off), ("on", on))}
    latency = latency_guard(values)
    matched = abs(on["report"]["achieved_ops_per_second"] / off["report"]["achieved_ops_per_second"] - 1) <= .05
    cpu_qualified = diagnostic_gate(off,tick) and diagnostic_gate(on,tick)
    eligible = latency["passed"] and matched and cpu_qualified
    output.update(latency_delta_ns=latency, achieved_rates_matched=matched,
                  native_cpu_load_trace_gates_passed=cpu_qualified, eligible=eligible)
    if eligible:
        costs = {arm: item["cpu_cost"]["server"]["total_seconds"] / item["report"]["completed"]
                 for arm,item in (("off",off),("on",on))}
        output["server_cpu_ratio"] = costs["on"] / costs["off"]
    return output


def latency_guard(values):
    stats = {arm:dict(median=v[len(v)//2] if len(v)%2 else (v[len(v)//2-1]+v[len(v)//2])/2,
                      p99=v[math.ceil(.99*len(v))-1]) for arm,v in values.items()}
    delta={key:stats["on"][key]-stats["off"][key] for key in ("median","p99")}
    return dict(**delta,passed=delta["median"]<=2000 and delta["p99"]<=10000)


def pooled(results, pairs, repeats):
    output=[]
    for security in ("unprotected","oscore"):
        groups={arm:[r for r in results if r["security"]==security and r["arm"]==arm] for arm in ("off","on")}
        row=dict(security=security,eligible=False,server_cpu_ratio=None,diagnostic_only=True)
        if all(len(group)==repeats and all(r.get("passed") for r in group) for group in groups.values()):
            values={arm:sorted(v for r in group for v in cpu.report_latencies(r)) for arm,group in groups.items()}
            guard=latency_guard(values)
            selected=[p for p in pairs if p["security"]==security]
            eligible=len(selected)==repeats and all(p["eligible"] for p in selected) and guard["passed"]
            row.update(latency_pooled_guard=guard,eligible=eligible)
            if eligible:
                costs={arm:sum(r["cpu_cost"]["server"]["total_seconds"] for r in group)/sum(r["report"]["completed"] for r in group)
                       for arm,group in groups.items()}
                row["server_cpu_ratio"]=costs["on"]/costs["off"]
        output.append(row)
    return output


def run(args):
    if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() == 0
            or not 2 <= args.seconds <= 30 or not 1 <= args.rate <= 10000 or args.repeats not in (2, 4)
            or args.rate * args.seconds + cpu.WARMUP > cpu.DATAGRAM_BUDGET):
        raise ValueError("finite syscall diagnostic requires unprivileged Linux x86_64,2..30s,C1CON,2/4pairs")
    cpu.sha40(args.core_sha)
    cpu.validate_profile(args.resource_profile,"coaptic-mio",args.bytes,concurrency=1,message_type="con")
    core, suite = cpu.identity(cpu.SUITE/"coaptic"), cpu.identity(cpu.SUITE)
    if core["revision"] != args.core_sha or core["status"] or suite["status"]:
        raise ValueError("clean exact current source required")
    build = load(regular(args.build_record, cpu.SUMMARY_LIMIT), cpu.SUMMARY_LIMIT)
    bpf_build = load(regular(args.bpf_build_record, cpu.SUMMARY_LIMIT), cpu.SUMMARY_LIMIT)
    if build["core"] != core or build["suite"] != suite or bpf_build["suite"] != suite:
        raise ValueError("native/BPF build source identity differs from current checkout")
    # Trace ELF has no reachable Coaptic code; its path dependency can be built
    # against the explicitly recorded current syn3 core, while the SAME native
    # SUT/client use accepted d23 and native_lock's unchanged core-selected input.
    cpu.sha40(bpf_build["core"]["revision"])
    if bpf_build["core"]["status"]:
        raise ValueError("dirty BPF build core")
    binaries = build["binaries"]
    server = regular(binaries["bench-rust-server"]["path"], 128*cpu.MIB)
    client = regular(binaries["bench-native-client"]["path"],128*cpu.MIB)
    loader = regular(args.loader, 32*cpu.MIB)
    object_path = regular(args.object, cpu.MIB)
    for path, expected in ((server,binaries["bench-rust-server"]["sha256"]),
                           (client,binaries["bench-native-client"]["sha256"]),
                           (loader,bpf_build["loader_sha256"]),(object_path,bpf_build["object_sha256"])):
        if cpu.digest(path) != expected:
            raise ValueError("source-matched binary input changed")
    for name in ("classifier", "loader", "ebpf"):
        relative = f"tools/bpf-ingress/{name}/Cargo.lock"
        if bpf_build["lock_sha256"].get(relative) != cpu.digest(cpu.SUITE/relative):
            raise ValueError("BPF source-matched lock differs")
    if bpf_build.get("native_toolchain") != "1.99.0" or bpf_build.get("bpf_toolchain") != "nightly-2026-10-13":
        raise ValueError("BPF/native toolchain identity missing")
    output = args.output.absolute()
    if output.exists() or output.is_relative_to(cpu.SUITE.resolve()):
        raise ValueError("fresh output outside source required")
    planned = 1024*1024
    planned += 4*args.repeats*(cpu.report_limit(args.rate*args.seconds)+10*META)
    if planned > OUTPUT:
        raise ValueError("syscall evidence plan exceeds16MiB")
    output.mkdir(parents=True)
    cpu.save(output/"manifest.json",dict(schema="coaptic-syscall-diagnostic/1",core=core,suite=suite,
        build_record_sha256=cpu.digest(args.build_record),bpf_build_record_sha256=cpu.digest(args.bpf_build_record),
        bpf_build_core=bpf_build["core"],
        loader_sha256=cpu.digest(loader),object_sha256=cpu.digest(object_path),hardware=cpu.hardware(),
        cpu=0,ordinary_mio=True,primary_acceptance=False,whole_memory_acceptance="OPEN",
        evidence_budget_bytes=OUTPUT,planned_bytes=planned,seconds=args.seconds,rate=args.rate,
        repeats=args.repeats,resource_profile=args.resource_profile,bytes=args.bytes,
        rotation="off/on then on/off; security separately; same exact SUT/client; both server arms CPU0"))
    results, comparisons = [], []
    failure = None
    try:
        for repeat in range(args.repeats):
            for security in ("unprotected", "oscore"):
                pair = {}
                for arm in (("off","on") if repeat%2 == 0 else ("on","off")):
                    observer = Observer(arm,loader,object_path)
                    result = cpu.window(server,client,(security,args.bytes,args.rate,"coaptic-mio"),
                        args.rate*args.seconds,output/f"window-{len(results):02}","clean",
                        resource_profile=args.resource_profile,syscall_observer=observer)
                    result.update(core_sha=args.core_sha,arm=arm,repeat=repeat,syscall_diagnostic=True)
                    if result.get("passed") and arm == "on" and result.get("syscall_trace", {}).get("available"):
                        window_path = output/f"window-{len(results):02}"
                        counts = validate_counts(load(window_path/"syscall-counts.json"))
                        denominator = result["report"]["completed"]
                        cpu.save(window_path/"syscall-per-operation.json",
                            dict(verified_complete_operations=denominator, counts=counts,
                                 per_verified_operation={name:{key:value/denominator for key,value in fields.items()}
                                                         for name,fields in counts.items()},
                                 scope="independent gate-boundary counts; not CPU time/shares; vDSO absent"),META)
                        result["syscall_per_operation_file"] = "syscall-per-operation.json"
                    cpu.save_window(output/f"window-{len(results):02}",result)
                    pair[arm]=result
                    results.append(result)
                    if cpu.unresolved_cleanup(result) or observer.unresolved:
                        raise RuntimeError("syscall helper cleanup unresolved; refuse next helper")
                    if result.get("syscall_trace", {}).get("available") is not True:
                        raise RuntimeError("syscall control/platform prerequisite unavailable; refuse next helper")
                    if cpu.upload_bytes(output)>OUTPUT:
                        raise RuntimeError("syscall evidence quota exceeded")
                    if cpu.identity(cpu.SUITE)!=suite or cpu.identity(cpu.SUITE/"coaptic")!=core:
                        raise RuntimeError("source changed during syscall diagnostic")
                comparisons.append(dict(security=security,repeat=repeat,
                    **comparison(pair["off"],pair["on"],1/os.sysconf("SC_CLK_TCK"))))
    except BaseException as error:
        failure=dict(type=type(error).__name__,reason=str(error)[:512])
        raise
    finally:
        cpu.save(output/"summary.json",dict(schema="coaptic-syscall-diagnostic/1",primary_acceptance=False,
            failure=failure,windows=len(results),failed_windows=[i for i,r in enumerate(results) if not r.get("passed")],
            comparisons=comparisons,pooled=pooled(results,comparisons,args.repeats),
            functional_passed=failure is None and len(results)==4*args.repeats and all(r.get("passed") for r in results),
            scope="counts and controlled instrumentation overhead, never primary650 acceptance"))
    return all(r.get("passed") for r in results)


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("build-record","bpf-build-record","loader","object","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--core-sha",type=cpu.sha40,required=True)
    p.add_argument("--seconds",type=int,default=10)
    p.add_argument("--rate",type=int,default=1000)
    p.add_argument("--repeats",type=int,default=2)
    p.add_argument("--resource-profile",default="small-device")
    p.add_argument("--bytes",type=int,default=32)
    return p

if __name__=="__main__":
    def terminate(signum, frame):
        raise InterruptedError("syscall diagnostic terminated by signal")
    signal.signal(signal.SIGTERM, terminate)
    raise SystemExit(0 if run(parser().parse_args()) else 1)
