"""A split suite must reject stale sources without changing dependency pins."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import prepare
import source_identity

class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.suite = Path(self.temporary.name)
        self.library = self.suite / "coaptic"
        self.library.mkdir()
        self.fixture = Path("tests/plugtest/td-coap4/base.yml")
        for root in (self.suite, self.library):
            (root / self.fixture).parent.mkdir(parents=True)
            (root / self.fixture).write_text("TD_COAP_CORE_01: {}\n")
        (self.library / "Cargo.toml").write_text('[package]\nname = "coaptic"\nversion = "0.0.10"\n')
        self.lock = '[[package]]\nname = "coaptic"\nversion = "0.1.0"\n\n[[package]]\nname = "peer"\nversion = "0.1.0"\nchecksum = "keep-me"\n'
        for relative in source_identity.LOCKS:
            path = self.suite / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.lock)
        subprocess.run(["git", "init", str(self.library)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.library), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.library), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture"], check=True, capture_output=True)
        self.revision = subprocess.check_output(["git", "-C", str(self.library), "rev-parse", "HEAD"], text=True).strip()
        self.addCleanup(patch.stopall)
        patch.object(prepare, "SUITE", self.suite).start()
        patch.object(prepare, "LIBRARY", self.library).start()

    def run_prepare(self, revision):
        with contextlib.redirect_stdout(io.StringIO()):
            prepare.prepare(revision)

    def assert_untouched(self):
        for relative in source_identity.LOCKS:
            self.assertEqual((self.suite / relative).read_text(), self.lock)

    def test_wrong_revision_leaves_all_locks_unchanged(self):
        with self.assertRaisesRegex(ValueError, "revision differs"):
            self.run_prepare("0" * 40)
        self.assert_untouched()

    def test_fixture_drift_leaves_all_locks_unchanged(self):
        (self.suite / self.fixture).write_text("changed inventory\n")
        with self.assertRaisesRegex(ValueError, "fixture differs"):
            self.run_prepare(self.revision)
        self.assert_untouched()

    def test_modified_library_is_rejected(self):
        (self.library / "Cargo.toml").write_text("changed manifest\n")
        with self.assertRaisesRegex(ValueError, "uncommitted changes"):
            self.run_prepare(self.revision)
        self.assert_untouched()

    def test_only_library_version_changes(self):
        self.run_prepare(self.revision)
        expected = self.lock.replace('name = "coaptic"\nversion = "0.1.0"', 'name = "coaptic"\nversion = "0.0.10"')
        for relative in source_identity.LOCKS:
            self.assertEqual((self.suite / relative).read_text(), expected)

    def test_missing_fixture_is_rejected(self):
        (self.suite / self.fixture).unlink()
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.run_prepare(self.revision)
        self.assert_untouched()

if __name__ == "__main__":
    unittest.main()
