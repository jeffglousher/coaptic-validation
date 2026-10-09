"""Coverage accounting must reject omissions rather than inflate tested surface."""
import ast
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from capabilities import load_manifest, evaluate, validate_manifest
import run
from run import expect_refusal


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.digest = load_manifest()
        self.outcomes = [{"name": row["id"], "passed": True, "evidence": {"oracle": "fixture"}}
                         for row in self.manifest["cases"]]

    def check(self, outcomes, enabled=True, system="linux"):
        return evaluate(self.manifest, outcomes, libcoap_dtls=enabled, libcoap_oscore=enabled, system=system)

    def test_full_and_explicitly_limited_inventory(self):
        full = self.check(self.outcomes)
        self.assertTrue(full["complete"])
        self.assertEqual(full["enabled_cases"], 166)
        excluded = {row["id"] for row in self.manifest["cases"] if row["requires"]}
        limited = self.check([row for row in self.outcomes if row["name"] not in excluded], False, "windows")
        self.assertTrue(limited["complete"])
        self.assertEqual(limited["enabled_cases"], 137)
        self.assertEqual(sum(row["status"] == "build-excluded" for row in limited["cases"]), 29)
        self.assertEqual(limited["unqualified"], full["unqualified"])
        self.assertEqual(len(self.digest), 64)

    def test_oscore_exclusion_is_separate_from_dtls(self):
        excluded = {row["id"] for row in self.manifest["cases"] if "libcoap-oscore" in row["requires"]}
        result = evaluate(self.manifest, [row for row in self.outcomes if row["name"] not in excluded],
                          libcoap_dtls=True, libcoap_oscore=False, system="linux")
        self.assertTrue(result["complete"])
        self.assertEqual(result["enabled_cases"], 154)
        self.assertFalse(evaluate(self.manifest, self.outcomes, libcoap_dtls=True,
                                  libcoap_oscore=False, system="linux")["complete"])

    def runner_inventory(self, flags):
        source = Path(run.__file__)
        tree = ast.parse(source.read_text(encoding="utf-8"))
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        executor = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == "case")
        executor.body = ast.parse('report["cases"].append({"name": name, "passed": True, '
                                  '"evidence": {"oracle": "case admission"}})').body
        namespace = vars(run).copy()
        exec(compile(ast.fix_missing_locations(ast.Module(body=[main], type_ignores=[])),
                     str(source), "exec"), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            peers = []
            for name in ("coaptic", "coap-rs", "libcoap"):
                executable = root / name
                executable.write_bytes(b"inventory fixture")
                peers.extend([f"--{name}", str(executable)])
            output = root / "report.json"
            with patch("sys.argv", [str(source), *peers, "--iterations", "1", "--output", str(output), *flags]), \
                 patch.dict(namespace, {"source_identity": lambda: {"source": "fixture-library", "dirty": False, "suite_source": "fixture-suite", "suite_dirty": False, "suite_locks": {}}}), \
                 patch("run.platform.platform", return_value="inventory-test"), \
                 patch("run.platform.system", return_value="linux"), redirect_stdout(io.StringIO()):
                status = namespace["main"]()
            return status, json.loads(output.read_text(encoding="utf-8"))

    def check_runner_inventory(self, flags, excluded, count):
        status, report = self.runner_inventory(flags)
        names = [row["name"] for row in report["cases"]]
        expected = {row["id"] for row in self.manifest["cases"] if not excluded.intersection(row["requires"])}
        self.assertIn("observe-oscore:coaptic->coaptic", names)
        self.assertIn("observe-dtls:coaptic->coaptic", names)
        self.assertEqual(report["coverage"]["enabled_cases"], count)
        self.assertCountEqual(names, expected)
        self.assertTrue(report["passed"], report["coverage"]["problems"])
        self.assertEqual(status, 0)
        return names

    def test_runner_full_security_inventory_is_unchanged(self):
        self.check_runner_inventory([], set(), 166)

    def test_runner_oscore_exclusion_preserves_c_dtls_observe(self):
        names = self.check_runner_inventory(["--libcoap-oscore-unavailable"], {"libcoap-oscore"}, 154)
        self.assertIn("observe-dtls:coaptic->libcoap", names)
        self.assertIn("observe-dtls:libcoap->coaptic", names)

    def test_runner_udp_only_excludes_c_secure_observe(self):
        self.check_runner_inventory(["--libcoap-udp-only"], {"libcoap-dtls", "libcoap-oscore"}, 137)

    def test_runner_combined_exclusions_preserve_enabled_inventory(self):
        self.check_runner_inventory(["--libcoap-udp-only", "--libcoap-oscore-unavailable"],
                                    {"libcoap-dtls", "libcoap-oscore"}, 137)

    def test_missing_empty_duplicate_and_undeclared_runs_fail(self):
        variants = [[], self.outcomes[1:], self.outcomes + [self.outcomes[0]],
                    self.outcomes + [{"name": "invented", "passed": True, "evidence": {"x": 1}}]]
        for rows in variants:
            with self.subTest(rows=len(rows)):
                result = self.check(rows)
                self.assertFalse(result["complete"])
                self.assertTrue(result["problems"])

    def test_disabled_execution_and_undeclared_platform_fail(self):
        self.assertFalse(self.check(self.outcomes, False)["complete"])
        self.assertFalse(self.check(self.outcomes, system="darwin")["complete"])

    def test_bad_results_and_absent_evidence_fail(self):
        for value in (False, None, 1, "true"):
            rows = copy.deepcopy(self.outcomes)
            rows[0]["passed"] = value
            self.assertFalse(self.check(rows)["complete"])
        for evidence in (None, {}, []):
            rows = copy.deepcopy(self.outcomes)
            rows[0]["evidence"] = evidence
            self.assertFalse(self.check(rows)["complete"])

    def test_manifest_rejects_silent_scope_mutations(self):
        mutations = [lambda m: m.update(cases=[]),
                     lambda m: m["cases"].append(m["cases"][0]),
                     lambda m: m["cases"][0].update(positive_proof=[]),
                     lambda m: m["cases"][0].update(requires=["libcoap-dtls"]),
                     lambda m: m["gaps"][0].update(status="passed"),
                     lambda m: m["gaps"][0].update(executable_cases=["fake"])]
        for mutate in mutations:
            manifest = copy.deepcopy(self.manifest)
            mutate(manifest)
            with self.assertRaises(ValueError):
                validate_manifest(manifest)

    def test_declared_executables_resolve_to_real_function_definitions(self):
        root = Path(__file__).resolve().parents[2]
        for case in self.manifest["cases"]:
            filename, function = case["executable"].split(":")
            tree = ast.parse((root / filename).read_text(encoding="utf-8"))
            names = set()
            def walk(node, prefix=""):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    prefix = f"{prefix}.{node.name}" if prefix else node.name
                    names.add(prefix)
                for child in ast.iter_child_nodes(node):
                    walk(child, prefix)
            walk(tree)
            self.assertIn(function, names)

    def test_process_crash_or_setup_error_cannot_count_as_auth_refusal(self):
        for code in (0, 2, -9, 3221225477, True):
            with self.assertRaises(AssertionError):
                expect_refusal({"event": "error", "exit_code": code, "message": "handshake timeout"}, handshake=True)
        for message in ("invalid arguments", "unsupported transport", "connection reset"):
            with self.assertRaises(AssertionError):
                expect_refusal({"event": "error", "exit_code": 1, "message": message}, handshake=True)
        for message in ("handshake failed", "decrypt error", "alert received", "deadline elapsed"):
            expect_refusal({"event": "error", "exit_code": 1, "message": message}, handshake=True)
        expect_refusal({"event": "error", "exit_code": 1, "message": "request timed out"})
        with self.assertRaises(AssertionError):
            expect_refusal({"event": "response", "exit_code": 1, "message": "timeout"})


if __name__ == "__main__":
    unittest.main()
