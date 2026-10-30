"""Portable source/lock tests; no Cargo, network, or checkout mutation."""
from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import lock_selection as selection

ROOT = Path(__file__).resolve().parents[2]
BASE = subprocess.check_output(["git", "-C", str(ROOT), "show", "HEAD:" + selection.CANONICAL])
ALT = (ROOT / selection.ALTERNATE).read_bytes()
NATIVE = subprocess.check_output(["git", "-C", str(ROOT), "show", "HEAD:" + selection.NATIVE])
SOURCE = b'[package]\nname = "coaptic-io"\nversion = "0.0.10"\n[dependencies.syn]\nversion = "2"\nfeatures = ["full"]\n'


class LockSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / selection.CANONICAL
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(BASE)
        self.source = SOURCE
        self.alternate = ALT
        self.base = BASE
        self.dirty = b""
        self.head = b"a" * 40

    def git(self, root, *args):
        if args == ("rev-parse", "HEAD"):
            return self.head
        if args == ("status", "--porcelain"):
            return self.dirty
        if args == ("show", "HEAD:" + selection.CANONICAL):
            return self.base
        if args == ("show", "HEAD:" + selection.NATIVE):
            return NATIVE
        self.fail(str(args))

    def checked(self, root, path):
        return self.source if path == selection.MANIFEST else self.alternate if path == selection.ALTERNATE else b"script"

    def run_selection(self):
        with patch.object(selection, "git", side_effect=self.git), patch.object(selection, "checked", side_effect=self.checked):
            return json.loads(selection.select(self.root, "a" * 40, "a" * 40, ci_prepare=True))

    def test_actual_graph_and_pins(self):
        selection.validate_graph(BASE, ALT, NATIVE)
        self.assertEqual(selection.digest(BASE), selection.BASE_HASH)
        self.assertEqual(selection.digest(ALT), selection.ALTERNATE_HASH)
        # Independent semantic conservation assertion, including all edge fields.
        expected = deepcopy(selection.parse(BASE))
        expected["package"] = [p for p in expected["package"] if not (p["name"] == "syn" and p["version"] == "3.0.9")]
        for p in expected["package"]:
            if "dependencies" in p:
                p["dependencies"] = ["syn" if d in ("syn 2.0.119", "syn 3.0.9") else d for d in p["dependencies"]]
        self.assertEqual(selection.parse(ALT), expected)

    def test_both_selections_and_stateless_reentry(self):
        for major, selected in (("2", ALT), ("2", ALT), ("3", BASE), ("3", BASE)):
            self.source = SOURCE.replace(b'version = "2"', ('version = "' + major + '"').encode())
            report = self.run_selection()
            self.assertEqual(self.path.read_bytes(), selected)
            self.assertEqual(report["selected_lock_sha256"], selection.digest(selected))
            self.assertEqual(report["declared_major"], major)

    def test_foreign_and_prepared_incoming_preserved(self):
        for incoming in (BASE + b"# edit\n", BASE.replace(b'version = "0.0.10"', b'version = "0.0.11"')):
            self.path.write_bytes(incoming)
            with self.assertRaises(ValueError):
                self.run_selection()
            self.assertEqual(self.path.read_bytes(), incoming)

    def test_manifest_failures_before_write(self):
        for source in (b"broken [", SOURCE.replace(b'"2"', b'"^2"'), SOURCE.replace(b'"0.0.10"', b'"0.0.11"'), SOURCE.replace(b'[dependencies.syn]', b'[dev-dependencies.syn]'), SOURCE + b'path = "foreign"\n', SOURCE + b'[target.x.dependencies.syn]\nversion = "3"\n', SOURCE + b'[dependencies.alias]\npackage = "syn"\nversion = "3"\n'):
            with self.subTest(source=source):
                self.source = source
                with self.assertRaises((ValueError, KeyError)):
                    self.run_selection()
                self.assertEqual(self.path.read_bytes(), BASE)

    def test_graph_corruption(self):
        cases = [(BASE, ALT.replace(b'"1.5.1"', b'"1.5.2"'), NATIVE),
                 (BASE.replace(selection.SYN2_CHECKSUM.encode(), b"0" * 64), ALT, NATIVE),
                 (BASE.replace(b'"syn 2.0.119"', b'"syn 3.0.9"'), ALT, NATIVE),
                 (BASE + b'\n[[package]]\nname = "coaptic-io"\nversion = "0.0.10"\n', ALT, NATIVE),
                 (BASE.replace(b'name = "coaptic-io"', b'name = "missing"'), ALT, NATIVE),
                 (BASE, ALT, NATIVE.replace(selection.SYN2_CHECKSUM.encode(), b"0" * 64))]
        for base, alt, native in cases:
            with self.subTest(base=selection.digest(base), alt=selection.digest(alt)):
                with self.assertRaises(ValueError):
                    selection.validate_graph(base, alt, native)

    def test_identity_hash_and_dirty_failures(self):
        for field, value in (("head", b"b" * 40), ("dirty", b" M Cargo.toml"), ("base", BASE + b"\n"), ("alternate", ALT + b"\n")):
            old = getattr(self, field)
            setattr(self, field, value)
            with self.assertRaises(ValueError):
                self.run_selection()
            self.assertEqual(self.path.read_bytes(), BASE)
            setattr(self, field, old)

    def test_staging_and_report_failure_preserve_input(self):
        for name, error in (("os.replace", OSError("replace failed")), ("json.dumps", ValueError("report failed")), ("os.fsync", OSError("flush failed"))):
            with patch("lock_selection." + name, side_effect=error):
                with self.assertRaises(type(error)):
                    self.run_selection()
            self.assertEqual(self.path.read_bytes(), BASE)
            self.assertEqual(list(self.path.parent.glob(".lock-selection-*")), [])

    def test_checked_source_modified_or_missing(self):
        p = self.root / "input"
        p.write_bytes(b"a\r\n")
        with patch.object(selection, "git", return_value=b"a\n"):
            self.assertEqual(selection.checked(self.root, "input"), b"a\r\n")
        with patch.object(selection, "git", return_value=b"foreign"):
            with self.assertRaises(ValueError):
                selection.checked(self.root, "input")
        with self.assertRaises(FileNotFoundError):
            selection.checked(self.root, "missing")

    def test_staging_detects_concurrent_edit_without_overwrite(self):
        foreign = BASE + b"# concurrent edit\n"
        with patch.object(selection.os, "fsync", side_effect=lambda fd: self.path.write_bytes(foreign)):
            with self.assertRaisesRegex(ValueError, "changed during"):
                self.run_selection()
        self.assertEqual(self.path.read_bytes(), foreign)
        self.assertEqual(list(self.path.parent.glob(".lock-selection-*")), [])

    def test_explicit_cli(self):
        with patch.object(selection, "select", return_value='{"ok": true}') as mocked, contextlib.redirect_stdout(io.StringIO()) as output:
            selection.main(["--suite", str(self.root), "--expected-suite-revision", "a" * 40, "--expected-revision", "b" * 40, "--ci-prepare"])
        mocked.assert_called_once_with(self.root, "a" * 40, "b" * 40, ci_prepare=True)
        self.assertEqual(json.loads(output.getvalue()), {"ok": True})
        with self.assertRaises(ValueError):
            selection.select(self.root, "a" * 40, "b" * 40)

    def test_workflow_order_and_lf_filter(self):
        text = (ROOT / ".github/workflows/validation.yml").read_text()
        job = text.split("  esphome-configuration:")[1].split("  supervisor-tests:")[0]
        self.assertEqual(text.count("run: python tools/esphome/lock_selection.py"), 1)
        self.assertLess(job.index("path: coaptic"), job.index("run: python tools/esphome/lock_selection.py"))
        self.assertLess(job.index("run: python tools/esphome/lock_selection.py"), job.index("run: python tools/prepare.py"))
        self.assertLess(job.index("run: python tools/prepare.py"), job.index("clippy --locked"))
        self.assertIn('--expected-suite-revision "$SUITE_REVISION"', job)
        self.assertIn('--expected-revision "$LIBRARY_REVISION"', job)
        # Git's real attribute/filter pipeline, with no index/ref mutation.
        for mode in ("true", "input", "false"):
            result = subprocess.check_output(["git", "-C", str(ROOT), "-c", "core.autocrlf=" + mode, "hash-object", "--path=" + selection.ALTERNATE, "--stdin"], input=ALT.replace(b"\n", b"\r\n"))
            expected = subprocess.check_output(["git", "-C", str(ROOT), "hash-object", "--stdin"], input=ALT)
            self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
