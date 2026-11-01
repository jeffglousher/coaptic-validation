import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_prepared_capture as capture


class PreparedCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="coaptic-prepared-capture-test-")
        self.addCleanup(self.temporary.cleanup)
        self.suite = Path(self.temporary.name) / "suite"
        (self.suite / "coaptic").mkdir(parents=True)
        self.report = Path(self.temporary.name) / "prepared.json"
        self.core_revision = "a" * 40
        self.suite_revision = "b" * 40
        self.report.write_text(json.dumps(dict(suite_dirty=True)), encoding="utf-8")
        self.report_original = self.report.read_bytes()
        for name in capture.CAPTURE_LOCKS:
            path = self.suite / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + "\n").encode())
        self.checkpoint = dict(core=self.core_revision, suite=self.suite_revision,
                               prepared_files=8, tracked_files=17, native_active=False)

    def git(self, root, *args):
        if args == ("rev-parse", "HEAD"):
            return (self.core_revision if Path(root) == self.suite / "coaptic"
                    else self.suite_revision).encode()
        self.assertEqual(args, ("status", "--porcelain"))
        return b"" if Path(root) == self.suite / "coaptic" else b" M Cargo.lock\n"

    def identity(self):
        return capture.capture_identity(self.suite, self.core_revision,
                                        self.suite_revision, self.report)

    def test_independent_gate_precedes_identity_and_hashes_cover_all_eight_locks(self):
        ordered = []

        def gate(*args):
            ordered.append("gate")
            self.assertEqual(args, (self.suite.resolve(), self.suite / "coaptic",
                                   self.core_revision, self.suite_revision, self.report.resolve()))
            return self.checkpoint

        def git(*args):
            self.assertTrue(ordered)
            ordered.append("identity")
            return self.git(*args)

        with patch.object(capture, "verify_prepared", side_effect=gate), \
                patch.object(capture, "git", side_effect=git):
            encoded = self.identity()
        value = json.loads(encoded)
        self.assertEqual(ordered[0], "gate")
        self.assertEqual(ordered[-1], "gate")
        self.assertEqual(value["schema"], capture.SCHEMA)
        self.assertEqual(value["core"], dict(revision=self.core_revision, dirty=False))
        self.assertEqual(value["suite"]["revision"], self.suite_revision)
        self.assertIs(value["suite"]["dirty"], True)
        prepared = value["suite"]["prepared_checkpoint"]
        self.assertEqual(prepared["verification"], self.checkpoint)
        self.assertEqual(prepared["report_bytes"], len(self.report_original))
        self.assertEqual(prepared["report_sha256"], hashlib.sha256(self.report_original).hexdigest())
        self.assertEqual(prepared["locks"], {
            name: hashlib.sha256((self.suite / name).read_bytes()).hexdigest()
            for name in capture.CAPTURE_LOCKS})
        self.assertLess(len(encoded.encode()), capture.OUTPUT_BYTES)
        self.assertEqual(self.report.read_bytes(), self.report_original)

    def test_foreign_source_refuses_before_identity_or_output(self):
        output = io.StringIO()
        with patch.object(capture, "verify_prepared", side_effect=ValueError("foreign tracked source")), \
                patch.object(capture, "git") as git, contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(ValueError, "foreign tracked source"):
                self.identity()
        git.assert_not_called()
        self.assertEqual(output.getvalue(), "")

    def test_mismatched_or_missing_revisions_refuse_before_gate(self):
        for core, suite in ((None, self.suite_revision), (self.core_revision, None),
                            ("main", self.suite_revision), (self.core_revision, "B" * 40),
                            (self.core_revision, "b" * 39)):
            with self.subTest(core=core, suite=suite), patch.object(capture, "verify_prepared") as gate:
                with self.assertRaisesRegex(ValueError, "immutable full revisions"):
                    capture.capture_identity(self.suite, core, suite, self.report)
                gate.assert_not_called()

    def test_observed_revision_or_core_dirtiness_cannot_replace_checked_identity(self):
        for bad_call, bad_value in ((("rev-parse", "HEAD"), b"c" * 40),
                                     (("status", "--porcelain"), b" M src/lib.rs\n")):
            def git(root, *args):
                if Path(root) == self.suite / "coaptic" and args == bad_call:
                    return bad_value
                return self.git(root, *args)
            with self.subTest(bad_call=bad_call), \
                    patch.object(capture, "verify_prepared", return_value=self.checkpoint), \
                    patch.object(capture, "git", side_effect=git):
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    self.identity()

    def test_dirty_suite_is_not_relabelled_clean_from_report(self):
        self.report.write_text(json.dumps(dict(suite_dirty=False)), encoding="utf-8")
        with patch.object(capture, "verify_prepared", return_value=self.checkpoint), \
                patch.object(capture, "git", side_effect=self.git):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                self.identity()

    def test_report_change_during_first_gate_refuses_before_identity(self):
        def mutate(*args):
            self.report.write_bytes(self.report_original + b"\n")
            return self.checkpoint
        with patch.object(capture, "verify_prepared", side_effect=mutate), \
                patch.object(capture, "git") as git:
            with self.assertRaisesRegex(ValueError, "report changed"):
                self.identity()
        git.assert_not_called()

    def test_report_change_or_source_refusal_at_final_gate_never_emits_success(self):
        for failure in (False, True):
            self.report.write_bytes(self.report_original)
            calls = 0

            def gate(*args):
                nonlocal calls
                calls += 1
                if calls == 2:
                    if failure:
                        raise ValueError("late foreign source")
                    self.report.write_bytes(self.report_original + b"\n")
                return self.checkpoint

            with self.subTest(failure=failure), \
                    patch.object(capture, "verify_prepared", side_effect=gate), \
                    patch.object(capture, "git", side_effect=self.git):
                with self.assertRaises(ValueError):
                    self.identity()
            self.assertEqual(calls, 2)

    def test_report_budget_or_directory_refuses_before_gate(self):
        self.report.write_bytes(b"x" * (capture.REPORT_BYTES + 1))
        for path in (self.report, self.report.parent):
            with self.subTest(path=path), patch.object(capture, "verify_prepared") as gate:
                with self.assertRaisesRegex(ValueError, "bounded regular file"):
                    capture.capture_identity(self.suite, self.core_revision, self.suite_revision, path)
                gate.assert_not_called()

    def test_cli_requires_all_three_arguments_and_has_no_dirty_bypass(self):
        complete = ["--expected-core", self.core_revision, "--expected-suite", self.suite_revision,
                    "--prepared-report", str(self.report)]
        for args in (complete[:2], complete[:4], complete + ["--allow-dirty"]):
            with self.subTest(args=args), patch.object(capture, "capture_identity") as identity, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    capture.main(args)
                self.assertEqual(error.exception.code, 2)
                identity.assert_not_called()

    def test_cli_emits_only_verified_bounded_json(self):
        result = '{"schema":"checked"}'
        output = io.StringIO()
        with patch.object(capture, "capture_identity", return_value=result) as identity, \
                contextlib.redirect_stdout(output):
            capture.main(["--expected-core", self.core_revision, "--expected-suite", self.suite_revision,
                          "--prepared-report", str(self.report)])
        identity.assert_called_once_with(capture.ROOT, self.core_revision,
                                         self.suite_revision, self.report)
        self.assertEqual(output.getvalue(), result + "\n")

    def test_default_rust_path_stays_clean_and_prepared_path_is_explicit_and_rechecked(self):
        source = (capture.ROOT / "crates/coaptic-plugtest/src/dtls/record_policy.rs").read_text()
        clean = source[source.index("fn identity("):source.index("fn source_identity(")]
        self.assertIn('assert!(status.is_empty(), "capture requires clean source")', clean)
        self.assertIn('serde_json::json!({"revision":revision,"dirty":false})', clean)
        selected = source[source.index("fn source_identity("):source.index("#[test]", source.index("fn source_identity("))]
        self.assertIn("configured.iter().all(Option::is_none)", selected)
        self.assertIn("configured.iter().all(Option::is_some)", selected)
        self.assertIn('"tools/verify_prepared_capture.py"', selected)
        self.assertEqual(source.count("source_identity(root)"), 2)
        self.assertLess(source.rindex("source_identity(root)"), source.index('"complete":true'))

    def test_workflow_opt_in_is_only_the_plugtest_capture_step(self):
        workflow = (capture.ROOT / ".github/workflows/validation.yml").read_text()
        expected = {
            "COAPTIC_PREPARED_CAPTURE_REPORT": "${{ runner.temp }}/validation-source.json",
            "COAPTIC_PREPARED_CAPTURE_CORE": "${{ inputs.library_revision }}",
            "COAPTIC_PREPARED_CAPTURE_SUITE": "${{ inputs.suite_revision }}",
        }
        plugtest = workflow[workflow.index("  plugtest:"):workflow.index("  esphome-configuration:")]
        step = plugtest[plugtest.index("      - run: cargo test --locked -p coaptic-plugtest --features dtls,oscore"):
                        plugtest.index("      - run: cargo test --locked -p coaptic-plugtest --features edhoc")]
        for key, value in expected.items():
            self.assertEqual(workflow.count(key + ":"), 1)
            self.assertIn(key + ": " + value, step)


if __name__ == "__main__":
    unittest.main()
