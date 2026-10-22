"""Portable validation and conservative aggregation checks; no Cargo or perf."""
import argparse
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import select
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock, Mock

import linux_cpu as cpu


def options(**overrides):
    values = dict(sizes="64,1024", rates="100,1000", seconds=10,
                  repeats=4, server_kind="coaptic-reusable", perf=True)
    values.update(overrides)
    return argparse.Namespace(**values)


def observation(root, label, repeat, *, security="unprotected", size=64, mode="clean"):
    report = dict(completed=1000, achieved_ops_per_second=100,
                  pacing_missed_period_operations=0, latencies_ns=[1000] * 1000)
    path = root / f"{label}-{repeat}-{security}-{size}-{mode}.json"
    cpu.retain_report(path, json.dumps(report), 1000)
    return dict(revision_label=label, repeat=repeat, security=security, bytes=size,
                mode=mode, rate=100, operations=1000, server_kind="coaptic-reusable", passed=True,
                report=cpu.report_summary(report), report_file=str(path),
                cpu_cost={who: dict(user_seconds=.8 if label == "baseline" else .4,
                                    system_seconds=.2 if label == "baseline" else .1,
                                    total_seconds=1 if label == "baseline" else .5)
                          for who in ("server", "client")})


def pairs(root):
    return [observation(root, label, repeat) for repeat in range(2)
            for label in ("baseline", "candidate")]


class ValidationTests(unittest.TestCase):
    def test_only_immutable_full_commits(self):
        self.assertEqual(cpu.sha40("A" * 40), "a" * 40)
        for value in ("main", "a" * 39, "g" * 40, "a" * 41, " a" * 20,
                      "a" * 40 + "\n", "$(touch unwanted)"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                cpu.sha40(value)

    def test_default_plan_and_finite_campaign_limits(self):
        args = options()
        self.assertEqual(len(cpu.configuration(args)), 8)
        plan = cpu.rotation(args, cpu.configuration(args))
        self.assertEqual(sum(mode == "clean" for mode, *_ in plan), 64)
        self.assertEqual(sum(mode != "clean" for mode, *_ in plan), 32)
        for override in (dict(sizes="32"), dict(sizes="64,64"), dict(rates="0"),
                         dict(rates="100,0100"), dict(rates="100001"),
                         dict(rates="100000", seconds=2), dict(rates="x"),
                         dict(seconds=31), dict(seconds=1), dict(repeats=9),
                         dict(repeats=1), dict(server_kind="all"),
                         dict(seconds=30, rates="1,2,3", repeats=8),
                         dict(rates="10000", seconds=10, repeats=4)):
            with self.subTest(override=override), self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                cpu.configuration(options(**override))
        self.assertEqual(len(cpu.configuration(options(sizes="65536", rates="2", server_kind="all"))), 6)

    def test_every_clean_and_profile_window_counts_warmup_and_blocks(self):
        for size, rate, seconds, perf, mode in (("65536", "100", 10, False, "clean"),
                                               ("64", "6000", 10, False, "clean"),
                                               ("65536", "200", 2, True, "record")):
            with self.subTest(size=size, rate=rate, mode=mode), self.assertRaisesRegex(ValueError, mode):
                cpu.configuration(options(sizes=size, rates=rate, seconds=seconds, perf=perf))
        # Clean 400-operation windows fit, but five-second profiles do not.
        self.assertEqual(len(cpu.configuration(options(sizes="65536", rates="200", seconds=2, perf=False))), 2)
        self.assertEqual(len(cpu.configuration(options(sizes="65536", rates="10,50"))), 4)
        for size, rate, seconds in (("1024", "29990", 2), ("65536", "458", 2)):
            self.assertEqual(len(cpu.configuration(options(sizes=size, rates=rate, seconds=seconds,
                                                           repeats=2, perf=False))), 2)

    def test_invalid_profile_plan_fails_before_platform_checks_or_builds(self):
        with patch.object(cpu, "build") as build, self.assertRaisesRegex(ValueError, "record"):
            cpu.run(options(sizes="65536", rates="200", seconds=2))
        build.assert_not_called()

    def test_parser_defaults_match_valid_documented_workload(self):
        args = cpu.argument_parser().parse_args(["--baseline-sha", "a" * 40,
                                                "--candidate-sha", "b" * 40,
                                                "--build-lane", "unused", "--output", "unused"])
        self.assertEqual(args.sizes, "64,1024")
        cpu.configuration(args)

    def test_perf_is_pid_scoped_bounded_and_has_no_memory_dump(self):
        for mode in ("record", "stat"):
            argv = cpu.perf_command(mode, 4321, 5, Path("/tmp/profile"), 12345)
            self.assertEqual(argv[:11], ["sudo", "-n", "--", "prlimit", "--fsize=12345:12345", "--",
                                        "timeout", "--signal=TERM", "--kill-after=5", "15", "perf"])
            self.assertEqual(argv[-5:], ["-p", "4321", "--", "sleep", "5"])
            self.assertNotIn("-a", argv)
            self.assertNotIn("dwarf", argv)
            self.assertNotIn("--sample-regs-user", argv)
        self.assertIn("fp", cpu.perf_command("record", 1, 5, Path("data"), 1024))

    def test_refusal_is_retained_without_changing_clean_availability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = unittest.mock.Mock()
            fake.wait.return_value = 255
            fake.returncode = 255
            with patch.object(cpu, "spawn", return_value=fake), patch.object(cpu, "stop"):
                with cpu.perf_pass("record", 123, 5, root, 4096) as state:
                    self.assertEqual(state["mode"], "record")
            saved = json.loads((root / "perf.json").read_text())
            self.assertEqual(saved["returncode"], 255)
            self.assertFalse(saved["available"])
            self.assertNotIn("cleanup_error", saved)
            self.assertFalse(cpu.unresolved_cleanup(dict(perf=saved)))
            self.assertTrue((root / "perf-command.log").exists())
            with cpu.perf_pass("clean", 123, 5, root, 4096) as state:
                self.assertEqual(state["mode"], "clean")


class BuildTests(unittest.TestCase):
    def test_explicit_host_target_ignores_configured_target_and_stale_top_level_binaries(self):
        host, configured = "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"
        revision = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite, lane, out = root / "source", root / "lane", root / "evidence"
            for directory in (suite / ".cargo", lane / "release", lane / configured / "release", out):
                directory.mkdir(parents=True)
            (suite / ".cargo/config.toml").write_text(f'[build]\ntarget = "{configured}"\n')
            names = ("bench-rust-server", "bench-native-client")
            for name in names:
                (lane / "release" / name).write_bytes(b"stale host binary")
                (lane / configured / "release" / name).write_bytes(b"configured cross binary")

            def compile(argv, stream, **kwargs):
                if argv[0] == "cargo":
                    self.assertEqual(argv[argv.index("--target") + 1], host)
                    self.assertEqual(kwargs["env"]["CARGO_BUILD_TARGET"], configured)
                    destination = lane / host / "release"
                    destination.mkdir(parents=True)
                    for name in names:
                        (destination / name).write_bytes((revision + name).encode("ascii"))

            rustc = f"rustc 1.99.0\nhost: {host}\nLLVM version: 22.1.0"
            with patch.object(cpu, "SUITE", suite), \
                    patch.object(cpu, "identity", return_value=dict(status="", revision=revision)), \
                    patch.object(cpu, "command", side_effect=[rustc, "cargo 1.99.0"]), \
                    patch.object(cpu, "run_logged", side_effect=compile) as logged, \
                    patch.object(cpu, "digest", return_value="hash"), \
                    patch.dict(os.environ, CARGO_BUILD_TARGET=configured):
                record = cpu.build(options(build_lane=lane), "baseline", revision, out)
            self.assertEqual(logged.call_count, 3)
            self.assertEqual(record["target"], host)
            self.assertEqual(json.loads((out / "build-baseline.json").read_text())["target"], host)
            for name in names:
                self.assertEqual(Path(record["binaries"][name]["path"]).read_bytes(),
                                 (revision + name).encode("ascii"))
                self.assertEqual((lane / "release" / name).read_bytes(), b"stale host binary")

    def test_missing_duplicate_or_unsafe_rustc_host_fails_before_build(self):
        for rustc in ("rustc 1.99.0", "host: ../release", "host: /tmp/target",
                      "host: a-b\nhost: a-b", "host: a-b/../../release", "host: a-b "):
            with self.subTest(rustc=rustc), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(cpu, "identity", return_value=dict(status="")), \
                        patch.object(cpu, "command", return_value=rustc), \
                        patch.object(cpu, "run_logged") as logged, \
                        self.assertRaisesRegex(ValueError, "host target"):
                    cpu.build(options(build_lane=root), "baseline", "a" * 40, root)
                logged.assert_not_called()
                self.assertFalse((root / "binaries").exists())


class AggregationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def pairs(self):
        return pairs(self.root)

    def test_verified_cpu_denominators_and_latency_are_separate(self):
        summary = cpu.aggregate(self.pairs(), repeats=2, tick=.01)[0]
        self.assertTrue(summary["comparable"])
        self.assertEqual(summary["server_cpu_ratio"], .5)
        baseline = summary["cpu_ns_per_verified_operation"]["baseline"]
        self.assertEqual(baseline["server"]["total_ns"], 1_000_000)
        self.assertEqual(baseline["client"]["system_ns"], 200_000)
        self.assertEqual(baseline["verified_operations"], 2000)
        self.assertEqual(baseline["p99_latency_ns"], 1000)

    def test_no_ratio_for_failure_missing_duplicate_or_quantized_pairs(self):
        mutations = []
        failed = self.pairs()
        failed[0] = dict(failed[0], passed=False)
        mutations.append(failed)
        mutations.append(self.pairs()[:-1])
        duplicate = self.pairs()
        duplicate[-1]["repeat"] = 0
        mutations.append(duplicate)
        low_cpu = self.pairs()
        low_cpu[1]["cpu_cost"]["server"]["total_seconds"] = .01
        mutations.append(low_cpu)
        late = self.pairs()
        late[0]["report"]["pacing_missed_period_operations"] = 11
        mutations.append(late)
        overloaded = self.pairs()
        overloaded[1]["report"]["achieved_ops_per_second"] = 90
        mutations.append(overloaded)
        unmatched = self.pairs()
        unmatched[0]["report"]["achieved_ops_per_second"] = 104
        unmatched[1]["report"]["achieved_ops_per_second"] = 96
        mutations.append(unmatched)
        for values in mutations:
            with self.subTest(values=values):
                summary = cpu.aggregate(values, repeats=2, tick=.01)[0]
                self.assertFalse(summary["comparable"])
                self.assertIsNone(summary["server_cpu_ratio"])

    def test_security_adapter_body_and_rate_strata_never_pool(self):
        values = self.pairs()
        for changes in (dict(security="oscore"), dict(bytes=1024), dict(rate=1000),
                        dict(server_kind="coaptic-ready")):
            for item in self.pairs():
                item.update(changes)
                values.append(item)
        self.assertEqual(len(cpu.aggregate(values, repeats=2, tick=.01)), 5)

    def test_profiler_timings_are_excluded_even_when_they_look_faster(self):
        values = self.pairs()
        profile = deepcopy(values[1])
        profile.update(mode="record", repeat=0)
        profile["cpu_cost"]["server"]["total_seconds"] = .000001
        profile["report_file"] = "must-never-read-profiling-samples"
        self.assertEqual(cpu.aggregate(values + [profile], 2, .01), cpu.aggregate(values, 2, .01))
        self.assertEqual(cpu.aggregate([profile], 2, .01), [])

    def test_incomplete_campaign_or_profile_cleanup_invalidates_complete_clean_pairs(self):
        values = self.pairs()
        self.assertTrue(cpu.aggregate(values, 2, .01)[0]["comparable"])
        profile = dict(mode="record", perf=dict(cleanup_error="TimeoutExpired"))
        for summary in (cpu.aggregate(values, 2, .01, campaign_complete=False),
                        cpu.aggregate(values + [profile], 2, .01)):
            self.assertFalse(summary[0]["comparable"])
            self.assertIsNone(summary[0]["server_cpu_ratio"])
            self.assertNotIn("cpu_ns_per_verified_operation", summary[0])


class MetadataTests(unittest.TestCase):
    def test_campaign_maxima_fit_reserve_even_at_maximum_sample_width(self):
        maximum = (22 * 2_000_000 + 192 * (cpu.SUMMARY_LIMIT + 4 * cpu.WINDOW_LIMIT)
                   + 96 * cpu.WINDOW_LIMIT + 7 * cpu.SUMMARY_LIMIT + 2 * cpu.BUILD_LOG_LIMIT)
        self.assertEqual(maximum, 75_391_744)
        self.assertLessEqual(maximum, cpu.METADATA_BUDGET)

    def test_valid_high_sample_campaign_has_explicit_safe_reserve(self):
        args = options(sizes="64", rates="10000", seconds=2, repeats=2, server_kind="all")
        plan = cpu.rotation(args, cpu.configuration(args))
        operations = [cell[2] * (args.seconds if mode == "clean" else cpu.PROFILE_SECONDS)
                      for mode, _, cell, _ in plan]
        self.assertEqual(sum(operations), 1_680_000)
        self.assertEqual(sum(op for op, (mode, *_) in zip(operations, plan) if mode != "clean"), 1_200_000)
        allowance = cpu.metadata_allowance(plan, args.seconds)
        self.assertGreater(sum(cpu.report_limit(op) for op in operations), 4 * cpu.MIB)
        self.assertLessEqual(allowance, 96 * cpu.MIB)
        slots = sum(mode != "clean" for mode, *_ in plan)
        quota = min(8 * cpu.MIB, (cpu.PERF_BUDGET - cpu.METADATA_BUDGET) // (2 * slots))
        self.assertLessEqual(allowance + 2 * slots * quota, cpu.PERF_BUDGET)
        with patch.object(cpu, "METADATA_BUDGET", 1), self.assertRaisesRegex(ValueError, "metadata"):
            cpu.configuration(args)

    def test_max_width_samples_are_retained_once_and_fit_derived_bound(self):
        operations = 59_980
        report = dict(latencies_ns=[2**64 - 1] * operations, completed=operations)
        raw = json.dumps(report)
        self.assertLessEqual(len(raw.encode("utf-8")) + 1, cpu.report_limit(operations))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "client.json"
            cpu.retain_report(path, raw, operations)
            summary = cpu.report_summary(report)
            self.assertNotIn("latencies_ns", summary)
            cpu.save(root / "result.json", dict(report=summary), cpu.WINDOW_LIMIT)
            cpu.save(root / "index.json", dict(report=summary), cpu.WINDOW_LIMIT)
            self.assertEqual(path.read_bytes(), (raw + "\n").encode("utf-8"))
            for name in ("result.json", "index.json"):
                self.assertNotIn(b"18446744073709551615", (root / name).read_bytes())
            self.assertEqual(len(cpu.report_latencies(dict(report_file=str(path), operations=operations,
                                                           report=summary))), operations)

    def test_oversize_encoding_and_raw_reads_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metadata.json"
            path.write_bytes(b"original evidence")
            for value in ({"large": "x" * 1000}, {"unicode": "\U0001f680" * 100}, {"bad": float("nan")}):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    cpu.save(path, value, 128)
                self.assertEqual(path.read_bytes(), b"original evidence")
            with self.assertRaises(ValueError):
                cpu.bounded_read(path, 2)
            with self.assertRaises(ValueError):
                cpu.retain_report(path, "x" * (cpu.report_limit(1) + 1), 1)
            self.assertEqual(path.read_bytes(), b"original evidence")
            with self.assertRaisesRegex(ValueError, "u64"):
                cpu.report_summary(dict(latencies_ns=[2**64]))

    def test_oversize_window_metadata_still_retains_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = dict(passed=True, mode="clean", security="oscore", bytes=64,
                          rate=100, server_kind="coaptic-ready", operations=1000,
                          report={"huge": "x" * cpu.WINDOW_LIMIT})
            cpu.save_window(root, result)
            self.assertFalse(result["passed"])
            self.assertEqual(json.loads((root / "result.json").read_text()), result)
            self.assertLessEqual((root / "result.json").stat().st_size, cpu.WINDOW_LIMIT)

    def test_oversize_fallback_preserves_all_fatal_cleanup_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            errors = [dict(process=name, type="TimeoutExpired", reason="unreaped")
                      for name in ("client", "server")]
            perf = dict(cleanup_error="PermissionError", cleanup_reason="kill refused", returncode=1)
            result = dict(passed=False, mode="record", cleanup_errors=errors, perf=perf,
                          report=dict(huge="x" * cpu.WINDOW_LIMIT))
            cpu.save_window(root, result)
            saved = json.loads((root / "result.json").read_text())
            self.assertTrue(saved["cleanup_unresolved"])
            self.assertEqual(saved["cleanup_errors"], errors)
            self.assertEqual(saved["perf"], perf)
            self.assertLessEqual((root / "result.json").stat().st_size, cpu.WINDOW_LIMIT)


class CampaignTests(unittest.TestCase):
    def exercise(self, *, failure_index=None, oversize=False, target_mismatch=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite, lane, out = root / "source", root / "lane", root / "evidence"
            suite.mkdir()
            lane.mkdir()
            args = options(sizes="64", rates="100", repeats=2, build_lane=lane, output=out,
                           baseline_sha="a" * 40, candidate_sha="b" * 40)
            calls = []

            def build(args, label, revision, out):
                return dict(core=dict(revision=revision), native_lock_sha256="lock", flags=cpu.FLAGS,
                            native_manifest_sha256="manifest", rustc="rustc", cargo="cargo",
                            target=label if target_mismatch else "x86_64-unknown-linux-gnu",
                            binaries={name: dict(path=str(out / label / name))
                                      for name in ("bench-rust-server", "bench-native-client")})

            def window(server, client, cell, operations, directory, mode, quota):
                index = len(calls)
                calls.append((server, client, mode))
                directory.mkdir()
                label = server.parent.name
                result = observation(directory, label, index, security=cell[0], mode=mode)
                Path(result["report_file"]).rename(directory / "client.json")
                result["report_file"] = str(directory / "client.json")
                if mode != "clean":
                    # Permission refusal with a terminated/reaped process is nonfatal.
                    result["perf"] = dict(available=False, returncode=255)
                if index == failure_index:
                    if mode == "clean":
                        result["cleanup_errors"] = [dict(process="client", type="TimeoutExpired", reason="unreaped")]
                    else:
                        result["perf"].update(cleanup_error="PermissionError", cleanup_reason="kill refused")
                    result.update(passed=False, cleanup_unresolved=True)
                    if oversize:
                        result["extra"] = "x" * cpu.WINDOW_LIMIT
                if mode != "clean":
                    cpu.save(directory / "perf.json", result["perf"], cpu.WINDOW_LIMIT)
                cpu.save_window(directory, result)
                return result

            with patch.object(cpu, "SUITE", suite), patch.object(cpu.sys, "platform", "linux"), \
                    patch.object(cpu.os, "sysconf", return_value=100, create=True), \
                    patch.object(cpu, "hardware", return_value={}), \
                    patch.object(cpu, "identity", return_value=dict(status="")), \
                    patch.object(cpu.importlib.metadata, "version", return_value="7.0.0"), \
                    patch.object(cpu, "digest", return_value="hash"), \
                    patch.object(cpu, "build", side_effect=build), patch.object(cpu, "window", side_effect=window), \
                    patch("builtins.print"):
                if failure_index is not None or target_mismatch:
                    with self.assertRaisesRegex((ValueError, RuntimeError), "target|termination unresolved"):
                        cpu.run(args)
                    self.assertTrue((out / "failure.json").exists())
                else:
                    self.assertTrue(cpu.run(args))
            summary = json.loads((out / "summary.json").read_text())
            if calls:
                entries = [json.loads(line) for line in (out / "windows.jsonl").read_text().splitlines()]
                self.assertEqual(len(entries), len(calls))
                for index in range(len(calls)):
                    directory = out / f"window-{index:03}"
                    self.assertEqual(json.loads((directory / "client.json").read_text())["completed"], 1000)
                    result = json.loads((directory / "result.json").read_text())
                    if index == failure_index:
                        self.assertTrue(cpu.unresolved_cleanup(result))
                        self.assertTrue(cpu.unresolved_cleanup(entries[index]))
                self.assertTrue(all(client.parent.name == "baseline" for _, client, _ in calls))
            return summary, calls

    def test_cleanup_failure_aborts_after_first_window_even_with_oversize_metadata(self):
        for oversize in (False, True):
            with self.subTest(oversize=oversize):
                summary, calls = self.exercise(failure_index=0, oversize=oversize)
                self.assertEqual(len(calls), 1)
                self.assertTrue(summary["cleanup_unresolved"])
                self.assertFalse(summary["campaign_complete"])
                self.assertEqual(summary["failed_windows"], [0])

    def test_profile_cleanup_aborts_and_suppresses_preceding_complete_strata_ratios(self):
        summary, calls = self.exercise(failure_index=8)
        self.assertEqual(len(calls), 9)
        self.assertTrue(summary["cleanup_unresolved"])
        self.assertFalse(summary["campaign_complete"])
        self.assertEqual(len(summary["comparisons"]), 2)
        for comparison in summary["comparisons"]:
            self.assertFalse(comparison["comparable"])
            self.assertIsNone(comparison["server_cpu_ratio"])

    def test_clean_perf_refusal_allows_complete_campaign_and_clean_ratios(self):
        summary, calls = self.exercise()
        self.assertEqual(len(calls), 16)
        self.assertFalse(summary["cleanup_unresolved"])
        self.assertTrue(summary["campaign_complete"])
        self.assertEqual(summary["unavailable_profiles"], list(range(8, 16)))
        self.assertTrue(all(item["comparable"] for item in summary["comparisons"]))

    def test_build_targets_must_match_before_any_window(self):
        summary, calls = self.exercise(target_mismatch=True)
        self.assertEqual(calls, [])
        self.assertFalse(summary["campaign_complete"])
        self.assertEqual(summary["comparisons"], [])


class ProcessTests(unittest.TestCase):
    def setUp(self):
        # Exercise Linux signalling decisions on Windows without sending signals.
        if not hasattr(cpu.signal, "SIGKILL"):
            self.addCleanup(patch.stopall)
            patch.object(cpu.signal, "SIGKILL", 9, create=True).start()
            patch.object(cpu.signal, "Signals", side_effect=lambda value:
                         SimpleNamespace(name="SIGKILL" if value == 9 else "SIGTERM")).start()

    def owned(self):
        process = Mock(pid=4321, returncode=0)
        process.wait.return_value = 0
        return cpu.OwnedProcess(process)

    def test_every_spawn_owns_a_session_and_limits_regular_file_output(self):
        process = Mock(pid=4321)
        resource = Mock(RLIMIT_FSIZE=1)
        with patch.object(cpu.subprocess, "Popen", return_value=process) as popen, \
                patch.dict(sys.modules, {"resource": resource}):
            child = cpu.spawn(["no-command-executed"], file_limit=12345)
            self.assertEqual(child.group, 4321)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            popen.call_args.kwargs["preexec_fn"]()
        resource.setrlimit.assert_called_once_with(1, (12345, 12345))

    def test_build_log_quota_is_enforced_without_limiting_compiler_artifacts(self):
        for output in (b"small", b"x" * 100):
            with self.subTest(output_bytes=len(output)):
                child = Mock(stdout=io.BytesIO(output))
                child.wait.return_value = 0
                stream = io.BytesIO(b"prefix")
                stream.seek(0, 2)
                with patch.object(cpu, "spawn", return_value=child) as spawn, \
                        patch.object(cpu, "stop") as stop:
                    if len(output) > 10:
                        with self.assertRaisesRegex(ValueError, "build log"):
                            cpu.run_logged(["cargo", "build"], stream, timeout=1, limit=16)
                    else:
                        cpu.run_logged(["cargo", "build"], stream, timeout=1, limit=16)
                self.assertIsNone(spawn.call_args.kwargs["file_limit"])
                self.assertLessEqual(len(stream.getvalue()), 16)
                stop.assert_called_once_with(child)

    def test_timeout_terminates_and_kills_owned_group_then_reaps(self):
        child = self.owned()
        child.process.wait.side_effect = [cpu.subprocess.TimeoutExpired("cargo", 900),
                                          cpu.subprocess.TimeoutExpired("cargo", 5), -9]
        with patch.object(cpu, "spawn", return_value=child), \
                patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                patch.object(cpu.os, "killpg", create=True) as kill:
            with self.assertRaises(cpu.subprocess.TimeoutExpired):
                cpu.run_owned(["cargo", "build"], timeout=900)
        self.assertEqual(kill.call_args_list, [unittest.mock.call(4321, cpu.signal.SIGTERM),
                                               unittest.mock.call(4321, 0),
                                               unittest.mock.call(4321, cpu.signal.SIGKILL)])
        self.assertEqual(child.process.wait.call_args_list,
                         [unittest.mock.call(timeout=900), unittest.mock.call(timeout=5), unittest.mock.call(timeout=5)])
        self.assertTrue(child.stopped)

    def test_exited_leader_does_not_leave_owned_descendants(self):
        child = self.owned()
        with patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                patch.object(cpu.os, "killpg", create=True) as kill:
            cpu.stop(child)
            cpu.stop(child)
        self.assertEqual([call.args[1] for call in kill.call_args_list],
                         [cpu.signal.SIGTERM, 0, cpu.signal.SIGKILL])
        self.assertEqual(child.process.wait.call_count, 2)

    def test_unowned_groups_are_never_signalled(self):
        with patch.object(cpu.os, "getpgrp", return_value=4321, create=True), \
                patch.object(cpu.os, "killpg", create=True) as kill:
            with self.assertRaises(ValueError):
                cpu.stop(Mock(pid=4322))
            with self.assertRaises(ValueError):
                cpu.signal_group(self.owned(), cpu.signal.SIGTERM, False)
        kill.assert_not_called()

    def test_elevated_cleanup_targets_only_owned_group_and_escalates(self):
        child = self.owned()
        with patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                patch.object(cpu.os, "killpg", side_effect=PermissionError, create=True), \
                patch.object(cpu, "run_owned") as run:
            cpu.stop(child, elevated=True)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["sudo", "-n", "--", "kill", "-TERM", "--", "-4321"],
                          ["sudo", "-n", "--", "kill", "-KILL", "--", "-4321"]])
        self.assertEqual(child.process.wait.call_count, 2)

    def test_perf_timeout_escalates_reaps_and_retains_failure(self):
        child = self.owned()
        child.process.returncode = -9
        child.process.wait.side_effect = [cpu.subprocess.TimeoutExpired("perf", 15),
                                          cpu.subprocess.TimeoutExpired("perf", 5), -9]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(cpu, "spawn", return_value=child), \
                    patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                    patch.object(cpu.os, "killpg", create=True) as kill:
                with cpu.perf_pass("record", 123, 5, root, 4096):
                    pass
            result = json.loads((root / "perf.json").read_text())
        self.assertTrue(result["deadline_exceeded"])
        self.assertFalse(result["available"])
        self.assertEqual(result["returncode"], -9)
        self.assertIn(unittest.mock.call(4321, cpu.signal.SIGKILL), kill.call_args_list)
        self.assertEqual(child.process.wait.call_count, 3)

    def test_run_owned_preserves_fatal_cleanup_status_with_or_without_primary_failure(self):
        for primary_failure in (False, True):
            with self.subTest(primary_failure=primary_failure):
                child = Mock()
                if primary_failure:
                    child.wait.side_effect = cpu.subprocess.TimeoutExpired("helper", 5)
                else:
                    child.wait.return_value = 0
                with patch.object(cpu, "spawn", return_value=child), \
                        patch.object(cpu, "stop", side_effect=TimeoutError("helper not reaped")), \
                        self.assertRaises((TimeoutError, cpu.subprocess.TimeoutExpired)) as failure:
                    cpu.run_owned(["helper"], timeout=5)
                self.assertTrue(failure.exception.cleanup_unresolved)

    def test_perf_output_helper_refusal_and_resolved_timeout_are_distinct_from_unresolved_cleanup(self):
        for timeout, cleanup_failure in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(timeout=timeout, cleanup_failure=cleanup_failure), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "perf.data").write_bytes(b"profile")
                profiler, helper = Mock(returncode=0), Mock(returncode=1)
                profiler.wait.return_value = 0
                helper.wait.return_value = 1
                if timeout:
                    helper.wait.side_effect = cpu.subprocess.TimeoutExpired("chmod", 5)
                cleanup = TimeoutError("chmod not reaped") if cleanup_failure else None
                with patch.object(cpu, "spawn", side_effect=[profiler, helper]), \
                        patch.object(cpu, "stop", side_effect=[None, cleanup]) as stop:
                    with cpu.perf_pass("record", 123, 5, root, 4096):
                        pass
                state = json.loads((root / "perf.json").read_text())
                self.assertEqual(cpu.unresolved_cleanup(dict(perf=state)), cleanup_failure)
                self.assertEqual("output_error" in state, timeout or cleanup_failure)
                self.assertEqual(stop.call_args_list,
                                 [unittest.mock.call(profiler, elevated=True), unittest.mock.call(helper)])


@unittest.skipUnless(sys.platform == "linux", "real session/file-limit checks require Linux")
class LinuxProcessTests(unittest.TestCase):
    def test_real_owned_group_kills_term_resistant_descendant_and_preserves_other_session(self):
        script = ("import signal,subprocess,sys,time; "
                  "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                  "child=subprocess.Popen([sys.executable,'-c',"
                  "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)']); "
                  "print(child.pid,flush=True); time.sleep(30)")
        sentinel = cpu.spawn([sys.executable, "-c", "import time; time.sleep(30)"])
        child = None
        try:
            child = cpu.spawn([sys.executable, "-c", script], stdout=cpu.subprocess.PIPE, text=True)
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "child readiness deadline")
            descendant = int(child.stdout.readline(128))
            self.assertEqual(os.getpgid(child.pid), child.group)
            cpu.stop(child)
            self.assertEqual(child.returncode, -cpu.signal.SIGKILL)
            stat = Path(f"/proc/{descendant}/stat")
            if stat.exists():
                self.assertEqual(stat.read_text().split(") ", 1)[1].split()[0], "Z")
            self.assertIsNone(sentinel.poll())
        finally:
            try:
                cpu.stop(child)
            finally:
                cpu.stop(sentinel)
                if child is not None:
                    child.stdout.close()

    def test_real_child_file_output_cannot_exceed_its_quota(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "output.log"
            with path.open("wb") as stream:
                with self.assertRaises(cpu.subprocess.CalledProcessError):
                    cpu.run_owned([sys.executable, "-c", "import os; os.write(1,b'x'*4096); os.write(1,b'y')"],
                                  timeout=5, file_limit=1024, stdout=stream, stderr=cpu.subprocess.DEVNULL)
            self.assertLessEqual(path.stat().st_size, 1024)


class RetentionTests(unittest.TestCase):
    def exercise(self, report, *, invalid=True, cleanup_errors=None, tail_error=None, mode="clean"):
        native = Mock()
        native.control_line.side_effect = ["ready", "measured", json.dumps(report)]
        native.validate_report.side_effect = ValueError("incomplete operations") if invalid else None
        native.snapshot.return_value = {"cpu_user_seconds": 0, "cpu_system_seconds": 0}
        native.cpu_cost.return_value = {"server": {"total_seconds": 1}, "client": {"total_seconds": 1}}
        server, client = MagicMock(), MagicMock()
        for child in (server, client):
            child.poll.return_value = None
            child.wait.return_value = 0
        client.stderr.read.return_value = "raw native failure\n"
        profiler = Mock(returncode=255)
        profiler.wait.return_value = 255
        reserve, probe = MagicMock(), MagicMock()
        reserve.getsockname.return_value = ("127.0.0.1", 12345)
        probe.bind.side_effect = OSError("bound by fixture")
        reserve.__enter__.return_value = reserve
        probe.__enter__.return_value = probe
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "window"
            with patch.dict(sys.modules, {"psutil": Mock(), "native_diagnostic": native}), \
                    patch.object(cpu, "spawn", side_effect=[server, client, profiler]), \
                    patch.object(cpu, "stop", side_effect=cleanup_errors) as stop, \
                    patch.object(cpu, "stderr_tail", return_value=b"raw native failure\n", side_effect=tail_error), \
                    patch.object(cpu.socket, "socket", side_effect=[reserve, probe]), \
                    patch.object(cpu.os, "getloadavg", return_value=(0, 0, 0), create=True):
                result = cpu.window(Path("server"), Path("client"),
                                    ("oscore", 64, 100, "coaptic-reusable"), 10, out, mode=mode)
            self.assertEqual(json.loads((out / "client.json").read_text()), report)
            self.assertEqual(json.loads((out / "result.json").read_text()), json.loads(json.dumps(result)))
            self.assertEqual(result["report"], cpu.report_summary(report))
            self.assertNotIn("latencies_ns", result["report"])
            if not tail_error:
                self.assertIn("raw native failure", (out / "client.stderr").read_text())
            self.assertEqual(stop.call_args_list,
                             ([] if mode == "clean" else [unittest.mock.call(profiler, elevated=True)])
                             + [unittest.mock.call(client), unittest.mock.call(server)])
            if mode != "clean":
                self.assertEqual(json.loads((out / "perf.json").read_text()), result["perf"])
            self.assertNotIn("credentials", {p.name for p in out.iterdir()})
            command = client.stdin.write.call_args_list
            self.assertEqual([call.args[0] for call in command],
                             ["run\n", "report\n"] + ([] if invalid else ["exit\n"]))
            self.assertLessEqual((out / "result.json").stat().st_size, cpu.WINDOW_LIMIT)
        return result

    def test_invalid_native_report_keeps_raw_bytes_and_stops_both_children(self):
        result = self.exercise(dict(completed=9, requested_operations=10, failure="body mismatch",
                                    latencies_ns=[1234] * 9))
        self.assertFalse(result["passed"])

    def test_client_and_server_cleanup_errors_do_not_skip_each_other_or_evidence(self):
        errors = [cpu.subprocess.TimeoutExpired("client", 5), RuntimeError("server stop failed")]
        result = self.exercise(dict(completed=9, failure="body mismatch"), cleanup_errors=errors,
                               tail_error=OSError("pipe unavailable"))
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_unresolved"])
        self.assertEqual([error["process"] for error in result["cleanup_errors"]], ["client", "server"])
        self.assertEqual(result["stderr_retention_error"], "OSError")
        self.assertEqual(result["reason"], "incomplete operations")

    def test_perf_cleanup_failure_survives_invalid_report_and_both_other_cleanup_failures(self):
        errors = [PermissionError("perf kill refused"), cpu.subprocess.TimeoutExpired("client", 5),
                  RuntimeError("server stop failed")]
        result = self.exercise(dict(completed=9, failure="body mismatch"), cleanup_errors=errors,
                               mode="record")
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_unresolved"])
        self.assertEqual(result["perf"]["cleanup_error"], "PermissionError")
        self.assertEqual([error["process"] for error in result["cleanup_errors"]], ["client", "server"])
        self.assertEqual(result["reason"], "incomplete operations")

    def test_perf_cleanup_failure_marks_otherwise_successful_window_fatal(self):
        result = self.exercise(dict(completed=10, latencies_ns=[1234] * 10), invalid=False,
                               cleanup_errors=[PermissionError("perf kill refused"), None, None], mode="record")
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_unresolved"])
        self.assertNotIn("cleanup_errors", result)

    def test_successful_window_keeps_samples_only_in_raw_report(self):
        result = self.exercise(dict(completed=10, latencies_ns=[123456789] * 10), invalid=False)
        self.assertTrue(result["passed"])
        self.assertNotIn("123456789", cpu.bounded_bytes(result, cpu.WINDOW_LIMIT).decode("ascii"))


if __name__ == "__main__":
    unittest.main()
