import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import development_suite as suite


def cargo_environment(root, **overrides):
    # Isolate build inputs in this module without mutating process os.environ.
    # Keep unrelated launch settings such as PATH and SYSTEMROOT.
    environment = {key: value for key, value in suite.os.environ.items()
                   if not key.startswith("CARGO_") and key not in (
                       "RUSTFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
                       "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP")}
    environment.update(CARGO_HOME=str(Path(root) / "cargo-home"),
                       CARGO_TARGET_DIR=str(Path(root) / "target"))
    environment.update(overrides)
    return patch.object(suite, "os", SimpleNamespace(**(vars(suite.os) | {"environ": environment})))


def core_report(profile="small-device", security="unprotected"):
    row = dict(operations=16, warmup=128, verified=144, black_box=True, security=security,
               concurrency=1, message_type="CON", calibration_samples=4096,
               clock_calibration_ns=[1] * 4096, memory={"scope": "fixture"})
    if profile == "small-device":
        row.update(suite.dimensions(profile, 32))
        row.update(profile="SmallDevice", storage="fixed", payload_bytes=32,
                   latencies_ns=list(range(16)))
    else:
        row.update(profile="Service", storage="allocated" if profile.endswith("allocated") else "fixed",
                   payload_bytes=16384, server_poll_wall_sum_ns=list(range(16)),
                   server_poll_counts=[16] * 16,
                   sends=dict(client=2304, server=2304, combined=4608),
                   server_capacities=dict(routes=32, populated_routes=1, calls=4, deferred=8,
                       associations=1, security_requests=4, rx_slots=32, tx_slots=32,
                       datagram_bytes=1472, dedup=64, observe=32, rx_body_slots=4,
                       tx_body_slots=4, body_bytes=16384, blockwise=True))
    return row


def observe_report(security="unprotected"):
    server = suite.dimensions("small-observe", 4096) | dict(datagram_bytes=1152)
    return dict(schema="coaptic-native-observe-proof/1", cohort="small-device-blockwise-observe",
        security=security, success=True, functional_only=True, body_bytes=4096, completed=6,
        verified_bytes=24576, initial_registrations=1, changed_notifications=1, recovery_registrations=1,
        fresh_gets=1, deregistrations=2, local_cancellations=1, controlled_undelivered_datagrams=1,
        call_capacity_refusals=2, poll_calls=80, server=server,
        bounds=dict(rounds_per_operation=128, deadline_ms_per_operation=3000,
                    combined_send_limit=256, combined_receive_limit=256, json_limit_bytes=16384),
        counts=dict(server_sent=24, server_received=26, client_sent=26, client_received=24,
                    server_protected_sent=24 if security=="oscore" else 0,
                    client_protected_sent=24 if security=="oscore" else 0, client_controls_sent=1),
        memory=dict(server_pool_requested_heap_bytes=0, client_pool_requested_heap_bytes=16000,
            server_app_including_transport_inline_bytes=28000, client_app_including_transport_inline_bytes=17000,
            each_transport_nested_in_app_inline_bytes=1600))


def profile_reliability(profile):
    size=dict(suite.PROFILES)[profile]
    return [dict(profile=profile, security=mode, size=size, completed=2,
                 oversized_bytes=suite.dimensions(profile,size)["rx_datagram_bytes"]+1,
                 expected_client_refusals=2 if mode=="oscore" else 1,
                 ledger=suite.dimensions(profile,size)) for mode in suite.SECURITY]


def socket_fixture(profile, security):
    size = dict(suite.PROFILES)[profile]
    options = suite.socket_options(profile)
    concurrency = options["concurrency"]
    blocks = (size + 1023) // 1024
    report = dict(schema="coaptic-native-complete/1", bytes=size, completed=32,
        requested_operations=32, attempted=32, failed=0, unattempted=0, failure=None,
        concurrency=concurrency, message_type="con", peak_pending=concurrency, cancelled_inflight=0,
        pending_call_metadata_bytes=256, rx_body_slots=concurrency, warmup=4,
        total_sent_datagrams=36 * blocks, pacing_dropped_operations=0,
        scheduled_rate_ops_per_second=None, achieved_ops_per_second=32e9 / 1000,
        scheduled_dispatch_span_ns=None, pacing_late_operations=0,
        pacing_missed_period_operations=0, pacing_total_lateness_ns=0,
        pacing_max_lateness_ns=0, policy="spin", security=security,
        latencies_ns=[10] * 32, elapsed_ns=1000, received_datagrams=32 * blocks,
        sent_datagrams=32 * blocks, core_heap_limit_bytes=37076, app_inline_bytes=16000,
        verification_heap_bytes=32768, timing_heap_bytes=256, udp_scratch_bytes=1473)
    if concurrency > 1:
        ledger = dict(schema="coaptic-local-pairs/1", local_ports=list(range(13000, 13000+concurrency)),
            server="127.0.0.1:5683", socket_count=concurrency, scratch_bytes=1473,
            receive_attempt_bound=concurrency, packet_queues=0, workers=0, requested_heap_bytes=0,
            adapter_inline_bytes=1600, kernel_bytes=None, peak_stack_bytes=None,
            sent=[36*blocks//concurrency]*concurrency, received=[36*blocks//concurrency]*concurrency,
            measured_sent_datagrams=[32*blocks//concurrency]*concurrency,
            measured_received_datagrams=[32*blocks//concurrency]*concurrency)
        report.update(endpoint_transport=ledger, client_rx_slots=5, client_tx_slots=5,
            overlapping_completions=[32//concurrency]*concurrency,
            verified_completions=[32//concurrency]*concurrency,
            window_metadata_bytes=100, lane_counter_snapshot_bytes=64, peer_keys_bytes=64)
    return dict(report=report, server_resources=suite.dimensions(profile, size) |
        dict(app_including_adapter_bytes=16000,
             app_requested_heap_bytes=282640 if profile=="service-allocated" else 0))


class ExpandedCoverage(unittest.TestCase):
    def test_observe_table_capacity_without_lifecycle_proof_does_not_pass(self):
        row = observe_report("oscore")
        suite.validate_observe(row, "oscore")
        for key, value in (("changed_notifications", 0), ("deregistrations", 0),
                           ("local_cancellations", 0), ("verified_bytes", 4096), ("security", "unprotected")):
            changed = copy.deepcopy(row); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                suite.validate_observe(changed, "oscore")
        row["server"]["observe"] = 2
        with self.assertRaises(ValueError):
            suite.validate_observe(row, "oscore")

    def test_eight_fixed_rows_have_feature_and_concurrency_breadth(self):
        self.assertEqual(len(suite.PROFILES), 8)
        config = suite.configuration()
        rows = {r["resource_profile"]:r for r in config["profiles"]}
        self.assertFalse(rows["small-device"]["blockwise"])
        self.assertFalse(rows["service-datagram"]["blockwise"])
        self.assertEqual(rows["service-datagram"]["rx_body_slots"], 0)
        self.assertEqual(rows["small-observe"]["observe"], 1)
        self.assertEqual([rows[p]["concurrency"] for p in ("device-fixed","gateway-fixed","service-fixed")], [2,2,4])
        self.assertEqual(config["core_concurrency"], 1)
        self.assertEqual(len(config["unsupported_core_profiles"]), 5)

    def test_concurrency_flag_without_actual_overlap_or_unique_ports_refuses(self):
        row = socket_fixture("service-fixed", "oscore")
        suite.validate_socket(row, "service-fixed", "oscore")
        for key, value in (("peak_pending", 1), ("overlapping_completions", [0]*4),
                           ("verified_completions", [32,0,0,0])):
            changed = copy.deepcopy(row);changed["report"][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):
                suite.validate_socket(changed, "service-fixed", "oscore")
        row["report"]["endpoint_transport"]["local_ports"]=[13000]*4
        with self.assertRaises(ValueError):
            suite.validate_socket(row, "service-fixed", "oscore")


class CoreValidation(unittest.TestCase):
    def test_profiles_and_modes(self):
        for profile in ("small-device", "service-fixed", "service-allocated"):
            for mode in suite.SECURITY:
                self.assertEqual(suite.validate_core(core_report(profile, mode), profile, mode)["median_ns"], 7.5)

    def test_incomplete_authentication_or_work_refused(self):
        for key, bad in (("verified", 143), ("security", "oscore"), ("black_box", False),
                         ("clock_calibration_ns", [1]), ("concurrency", 2)):
            with self.subTest(key=key):
                row = core_report(); row[key] = bad
                with self.assertRaises(ValueError):
                    suite.validate_core(row, "small-device", "unprotected")

    def test_capacity_and_storage_not_substituted(self):
        for key, bad in (("rx_slots", 1), ("blockwise", True), ("storage", "allocated")):
            row = core_report(); row[key] = bad
            with self.assertRaises(ValueError):
                suite.validate_core(row, "small-device", "unprotected")

    def test_service_blocks_and_send_bound(self):
        for key, bad in (("server_poll_counts", [1] * 16), ("sends", dict(client=40000, server=40000, combined=80000))):
            row = core_report("service-fixed"); row[key] = bad
            with self.assertRaises(ValueError):
                suite.validate_core(row, "service-fixed", "unprotected")

    def test_timing_cannot_be_boolean_or_negative(self):
        for bad in (True, -1, float("inf")):
            row = core_report(); row["latencies_ns"][0] = bad
            with self.assertRaises(ValueError):
                suite.validate_core(row, "small-device", "unprotected")


class PreparedInputs(unittest.TestCase):
    def make_bundle(self, directory):
        path = Path(directory)
        binaries = {}
        for role in suite.BINARIES:
            binary = path / role
            binary.write_bytes(role.encode())
            binaries[role] = dict(file=role, bytes=binary.stat().st_size, sha256=suite.digest(binary))
        row = dict(schema=suite.SCHEMA, kind="prepared", passed=True, binaries=binaries,
                   host=suite.host_identity(), harness=suite.harness_identity())
        suite.save(path / "prepared.json", row)
        return row

    def test_binary_mutation_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_bundle(d)
            suite.verify_prepared(d)
            (Path(d) / "server").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "binary changed"):
                suite.verify_prepared(d)

    def test_harness_and_host_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as d:
            row = self.make_bundle(d)
            row["harness"]["development_suite.py"] = "wrong"
            (Path(d) / "prepared.json").write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, "harness"):
                suite.verify_prepared(d)
            row["harness"] = suite.harness_identity()
            row["host"]["hostname"] = "elsewhere"
            (Path(d) / "prepared.json").write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, "host"):
                suite.verify_prepared(d)

    def test_binary_path_escape_refused(self):
        with tempfile.TemporaryDirectory() as d:
            row = self.make_bundle(d)
            row["binaries"]["server"]["file"] = "../server"
            (Path(d) / "prepared.json").write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, "escapes"):
                suite.verify_prepared(d)

    def test_no_overwrite_or_unbounded_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "receipt"
            suite.save(p, {"ok": True})
            with self.assertRaises(FileExistsError):
                suite.save(p, {"ok": False})
            p.write_bytes(b" " * 50)
            with self.assertRaises(ValueError):
                suite.load(p, 32)

    def test_build_failure_preserves_receipt_and_restores_context(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "failed"
            source = dict(commit="a" * 40)
            with cargo_environment(d), \
                 patch.object(suite, "cargo_inputs", return_value={}), \
                 patch.object(suite, "identity", return_value=source), \
                 patch.object(suite, "resolved_core", return_value=Path(d)), \
                 patch.object(suite, "toolchain", return_value=("compiler", "cargo", dict(cargo=dict(path="cargo"), rustc=dict(path="rustc")))), \
                 patch.object(suite, "native_lock") as lock, \
                 patch.object(suite, "task", side_effect=RuntimeError("build failed")):
                with self.assertRaisesRegex(RuntimeError, "build failed"):
                    suite.prepare(out, "a" * 40)
                self.assertTrue(lock.return_value.__exit__.called)
                self.assertFalse(suite.load(out / "prepared.json")["passed"])


class RunFailure(unittest.TestCase):
    def test_core_failure_preserves_completed_socket_and_later_not_run(self):
        bundle = dict(harness={}, host={}, compiler="x", cargo="x", flags={}, sources=dict(suite=dict(tree="same")))
        def work(spec, **kwargs):
            kind = spec["kind"]
            if kind == "core":
                raise TimeoutError("core timeout")
            if kind == "reliability-profile":
                raw = b'\n'.join(json.dumps(r).encode() for r in profile_reliability(spec['profile']))
            elif kind == "observe":
                raw = json.dumps(observe_report(spec["security"])).encode()
            elif kind == "socket":
                raw = json.dumps(socket_fixture(spec["profile"], spec["security"])).encode()
            else:
                raw = b"independent proof"
            return SimpleNamespace(stdout=raw, duration_seconds=.01)
        with tempfile.TemporaryDirectory() as d, \
             patch.object(suite, "verify_prepared", return_value=(bundle, {"client": "unused"})), \
             patch.object(suite, "task", side_effect=work):
            p = Path(d) / "partial.json"
            with self.assertRaisesRegex(TimeoutError, "core timeout"):
                suite.run_suite("unused", p)
            result = suite.load(p)
            self.assertEqual(len(result["not_run"]), 15)
            self.assertEqual(result["cells"][0]["status"], "failed")
            self.assertIn("socket", result["cells"][0])
            self.assertIn("core:", result["failed_phase"])

    def test_first_failure_keeps_all_pending_cells(self):
        bundle = dict(harness={}, host={}, compiler="x", cargo="x", flags={}, sources=dict(suite=dict(tree="same")))
        with tempfile.TemporaryDirectory() as d, \
             patch.object(suite, "verify_prepared", return_value=(bundle, {"client": "unused"})), \
             patch.object(suite, "task", side_effect=TimeoutError("owned deadline")):
            p = Path(d) / "run.json"
            with self.assertRaisesRegex(TimeoutError, "owned deadline"):
                suite.run_suite("unused", p)
            report = suite.load(p)
            self.assertFalse(report["passed"])
            self.assertEqual(len(report["not_run"]), 16)
            self.assertEqual(report["error"]["type"], "TimeoutError")

    def test_comparison_does_not_rescue_failed_run(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "failed"
            suite.save(p, dict(schema=suite.SCHEMA, kind="run", passed=False))
            with self.assertRaises(ValueError):
                suite.compare(p, p)

    def test_configuration_digest_changes_with_capacity(self):
        a = suite.configuration(); b = copy.deepcopy(a)
        b["profiles"][0]["rx_slots"] += 1
        self.assertNotEqual(suite.fingerprint(a), suite.fingerprint(b))


class ComparisonTests(unittest.TestCase):
    def test_cli_summary_reports_actual_expanded_coverage(self):
        import contextlib
        import io
        value = self.observation() | dict(total_seconds=12.0, within_minute=True)
        stream = io.StringIO()
        with patch.object(suite, "run_suite", return_value=value), patch.object(suite.sys, "argv",
                ["suite", "run", "--prepared", "unused", "--output", "unused.json"]), \
                contextlib.redirect_stdout(stream):
            self.assertEqual(suite.main(), 0)
        summary = json.loads(stream.getvalue())
        self.assertEqual((summary["socket_cells"], summary["core_cells"], summary["unsupported_core_cells"],
                          summary["observe_lifecycle_cells"]), (16, 6, 10, 2))

    @staticmethod
    def observation():
        prep = dict(harness={}, compiler="rust", cargo="cargo", flags={},
                    native_manifest_sha256="native", server_manifest_sha256="server",
                    sources=dict(core=dict(commit="a" * 40), suite=dict(tree="fixed fixtures")))
        client = dict(binaries=dict(client=dict(file="client", bytes=10, sha256="frozen")))
        rows = []
        for profile, size in suite.PROFILES:
            for security in suite.SECURITY:
                socket_value = socket_fixture(profile, security)
                core = dict(status="unsupported")
                if profile in suite.CORE_PROFILES:
                    raw = core_report(profile, security)
                    core = dict(status="passed", concurrency=1, report=raw,
                                summary=suite.validate_core(raw, profile, security))
                rows.append(dict(profile=profile, security=security, status="passed", core=core,
                                 socket=socket_value))
        return dict(schema=suite.SCHEMA, kind="run", passed=True,
                    configuration=suite.configuration(), configuration_sha256=suite.fingerprint(suite.configuration()),
                    cells=rows, reliability=[dict(kind="independent-body-corruption-and-security-recovery",passed=True)] +
                        [dict(profile=p,passed=True,cells=profile_reliability(p)) for p,_ in suite.PROFILES],
                    not_run=[], host={"host": "same"},
                    observe=[dict(security=mode, passed=True, report=observe_report(mode)) for mode in suite.SECURITY],
                    preparation=prep, client_preparation=client)

    def compare(self, a, b):
        with tempfile.TemporaryDirectory() as d:
            x, y = Path(d) / "a", Path(d) / "b"
            suite.save(x, a); suite.save(y, b)
            return suite.compare(x, y)

    def test_complete_matching_rows_compare_without_acceptance_claim(self):
        a, b = self.observation(), self.observation()
        b["preparation"]["sources"]["core"]["commit"] = "b" * 40
        out = self.compare(a, b)
        self.assertEqual(len(out["rows"]), 16)
        self.assertIn("not a gain", out["interpretation"])

    def test_host_client_harness_capacity_and_missing_rows_refused(self):
        def host(r): r["host"]["host"] = "other"
        def client(r): r["client_preparation"]["binaries"]["client"]["sha256"] = "other"
        def harness(r): r["preparation"]["harness"] = {"changed": "yes"}
        def capacity(r): r["cells"][0]["socket"]["server_resources"]["calls"] = 2
        def missing(r): r["cells"].pop()
        def failure(r): r["cells"][0]["socket"]["report"]["failed"] = 1
        def duplicate(r): r["cells"][1] = r["cells"][0]
        def reliability(r): r["reliability"][0]["passed"] = False
        def proof_identity(r): r["reliability"][2] = r["reliability"][1]
        def fixture(r): r["preparation"]["sources"]["suite"]["tree"] = "changed native server"
        for change in (host, client, harness, capacity, missing, failure, duplicate, reliability, proof_identity, fixture):
            a, b = self.observation(), self.observation(); change(b)
            with self.subTest(change=change.__name__), self.assertRaises(ValueError):
                self.compare(a, b)


class TaskTemporaryOwnership(unittest.TestCase):
    def test_only_build_tasks_request_compiler_auxiliary_settlement(self):
        from types import SimpleNamespace
        for kind in ("build", "core", "socket", "observe", "reliability-profile", "reliability-common"):
            with self.subTest(kind=kind), patch.object(suite, "run_worker", return_value=
                    SimpleNamespace(returncode=0)) as worker:
                suite.task({"kind": kind}, 1)
                self.assertEqual(worker.call_args.kwargs["settle_build_auxiliaries"], kind == "build")

    def test_nested_helpers_use_owned_temp_and_cleanup_after_settlement(self):
        paths = []
        def failed(command, **kwargs):
            environment = kwargs["env"]
            directory = Path(environment["TEMP"])
            self.assertEqual(environment["TMP"], str(directory))
            self.assertEqual(environment["TMPDIR"], str(directory))
            (directory / "helper-credentials").write_bytes(b"temporary fixture")
            paths.append(directory)
            raise TimeoutError("settled timeout")
        with patch.object(suite, "run_worker", side_effect=failed):
            with self.assertRaisesRegex(TimeoutError, "settled timeout"):
                suite.task({"kind": "core"}, 1)
        self.assertFalse(paths[0].exists())

    def test_unresolved_custody_retains_temp_and_primary(self):
        error = TimeoutError("original timeout")
        error.cleanup_unresolved = True
        def failed(command, **kwargs):
            (Path(kwargs["env"]["TEMP"]) / "helper-log").write_text("retain")
            raise error
        try:
            with patch.object(suite, "run_worker", side_effect=failed):
                with self.assertRaises(TimeoutError) as caught:
                    suite.task({"kind": "core"}, 1)
            self.assertIs(caught.exception, error)
            retained = Path(error.temporary_directory)
            self.assertTrue((retained / "helper-log").exists())
        finally:
            # Mocked failure created no process/consumer; clean this exact test owner.
            if getattr(error, "temporary_directory", None):
                retained = Path(error.temporary_directory).resolve()
                self.assertEqual(retained.parent, Path(tempfile.gettempdir()).resolve())
                self.assertTrue(retained.name.startswith("coaptic-suite-task-"))
                suite.shutil.rmtree(retained)


class CargoBuildInputs(unittest.TestCase):
    def test_target_specific_environment_flags_refuse(self):
        with tempfile.TemporaryDirectory() as d, cargo_environment(
                d, CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-Copt-level=0"):
            with self.assertRaisesRegex(ValueError, "ambient CARGO"):
                suite.cargo_inputs()

    def test_configured_target_refuses_instead_of_copying_old_host_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text('[build]\ntarget="some-other-target"\n')
            stale = root / "target/release/bench-core"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"old host output")
            ambient = dict(suite.os.environ, CARGO_TERM_COLOR="always")
            with patch.object(suite, "SUITE", root), patch.object(
                    suite, "os", SimpleNamespace(**(vars(suite.os) | {"environ": ambient}))):
                # Match workflow discovery: the real guard still refuses color.
                with self.assertRaisesRegex(ValueError, "ambient CARGO"):
                    suite.cargo_inputs()
                with cargo_environment(root):
                    self.assertNotIn("CARGO_TERM_COLOR", suite.os.environ)
                    for key in ("PATH", "SYSTEMROOT"):
                        self.assertEqual(suite.os.environ.get(key), ambient.get(key))
                    with self.assertRaisesRegex(ValueError, "Cargo build/target"):
                        suite.cargo_inputs()
                self.assertIs(suite.os.environ, ambient)
                self.assertEqual(ambient["CARGO_TERM_COLOR"], "always")
            self.assertEqual(stale.read_bytes(), b"old host output")

    def test_only_complete_cargo_reported_artifacts_are_used(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            rows = [dict(reason="compiler-artifact", target=dict(name=n, kind=["bin"]),
                         executable=str(root / "reported" / n))
                    for n in suite.BINARIES.values()]
            done = dict(reason="build-finished", success=True)
            raw = b'\n'.join(json.dumps(v).encode() for v in [*rows, done])
            actual = suite.cargo_artifacts(raw, root)
            self.assertEqual(actual["bench-core"], root / "reported/bench-core")
            for values in ([*rows], [*rows, dict(done, success=False)], [*rows[:-1], done],
                           [dict(rows[0], executable=str(root.parent / "stale")), *rows[1:], done]):
                with self.assertRaises(ValueError):
                    suite.cargo_artifacts(b'\n'.join(json.dumps(v).encode() for v in values), root)


if __name__ == "__main__":
    unittest.main()
