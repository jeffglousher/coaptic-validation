"""Temporary fixed TOML fixtures only: no Cargo, source checkout, or build lane."""
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from native_lock import native_lock


BASE = b'''# Fixed fixture; unrelated syn edges must stay byte-identical.
version = 4

[[package]]
name = "other"
version = "1.0.0"
dependencies = ["syn 2.0.119"]

[[package]]
name = "coaptic-io"
version = "0.0.10"
dependencies = [
 "proc-macro2",
 "syn 2.0.119",
]

[[package]]
name = "syn"
version = "2.0.119"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "syn"
version = "3.0.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
SYN3 = BASE.replace(b' "syn 2.0.119",', b' "syn 3.0.9",')
MANIFEST = b'''[package]
name = "coaptic-io"
version = "0.0.10"
[dependencies]
syn = { version = "2", features = ["full", "visit-mut"] }
'''


class NativeLockTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.core, self.native = self.root / "core", self.root / "native"
        self.native.mkdir()
        self.manifest = self.core / "crates/coaptic-io/Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.base = self.native / "Cargo.lock"
        self.alt = self.native / "Cargo.syn3.lock"
        self.fixture("2")

    def fixture(self, requirement, base=BASE, alternate=SYN3):
        self.base.write_bytes(base)
        self.alt.write_bytes(alternate)
        self.manifest.write_bytes(MANIFEST.replace(b'version = "2"',
                                                 f'version = "{requirement}"'.encode()))
        return (self.base.read_bytes(), self.alt.read_bytes(), self.manifest.read_bytes())

    def assert_inputs(self, expected):
        self.assertEqual(tuple(p.read_bytes() for p in (self.base, self.alt, self.manifest)), expected)

    def test_both_selections_restore_success_cargo_failure_and_keyboard_interrupt(self):
        for requirement in ("2", "3"):
            for failure in (None, subprocess.CalledProcessError(1, ["cargo", "build", "--locked"]),
                            KeyboardInterrupt()):
                with self.subTest(requirement=requirement, failure=type(failure).__name__):
                    original = self.fixture(requirement)
                    try:
                        with native_lock(self.core, self.native) as selected:
                            expected = BASE if requirement == "2" else SYN3
                            self.assertEqual(self.base.read_bytes(), expected)
                            path = self.base if requirement == "2" else self.alt
                            self.assertEqual(Path(selected["selected_path"]), path)
                            self.assertEqual(selected["syn_requirement"], requirement)
                            self.assertEqual(selected["selected_sha256"], sha256(expected).hexdigest())
                            self.assertEqual(sha256(self.base.read_bytes()).hexdigest(), selected["selected_sha256"])
                            self.assertEqual(selected["core_manifest_sha256"], sha256(original[2]).hexdigest())
                            self.assertEqual(Path(selected["core_manifest_path"]), self.manifest)
                            self.assertEqual(Path(selected["canonical_path"]), self.base)
                            self.assertEqual(selected["canonical_base_sha256"], sha256(BASE).hexdigest())
                            self.assertEqual(selected["syn3_sha256"], sha256(SYN3).hexdigest())
                            if failure is not None:
                                raise failure
                    except BaseException as error:
                        self.assertIs(error, failure)
                    else:
                        self.assertIsNone(failure)
                    # This is the caller's post-context identity/measurement boundary.
                    self.assert_inputs(original)

    def test_syn2_does_not_write_canonical(self):
        with patch.object(Path, "write_bytes", side_effect=AssertionError("unneeded write")):
            with native_lock(self.core, self.native):
                pass

    def test_checkout_eol_uses_actual_selected_bytes_and_restores_exact_base(self):
        for base_eol in (b"\n", b"\r\n"):
            for alt_eol in (b"\n", b"\r\n"):
                for requirement in ("2", "3"):
                    with self.subTest(base=base_eol, alternate=alt_eol, requirement=requirement):
                        original = self.fixture(requirement, BASE.replace(b"\n", base_eol),
                                                SYN3.replace(b"\n", alt_eol))
                        with native_lock(self.core, self.native) as selected:
                            data = original[0 if requirement == "2" else 1]
                            self.assertEqual(self.base.read_bytes(), data)
                            self.assertEqual(Path(selected["selected_path"]).read_bytes(), data)
                            self.assertEqual(selected["selected_sha256"], sha256(data).hexdigest())
                        self.assert_inputs(original)

    def test_unknown_manifest_requirement_refused_before_staging(self):
        for requirement in ("1", "4", "^3", "=3.0.9", "3.0", "*", ""):
            with self.subTest(requirement=requirement):
                original = self.fixture(requirement)
                with self.assertRaisesRegex(ValueError, "unsupported.*syn.version"):
                    with native_lock(self.core, self.native):
                        self.fail("unknown manifest yielded")
                self.assert_inputs(original)
        self.manifest.write_bytes(b'[dependencies]\nsyn = "2"\n')
        with self.assertRaisesRegex(ValueError, "unsupported.*syn.version"):
            with native_lock(self.core, self.native):
                self.fail("non-table syn yielded")

    def test_unexpected_other_lock_diff_refused_before_staging(self):
        for changed in (SYN3 + b"# unrelated\n", SYN3.replace(b'"other"', b'"changed"'),
                        SYN3.replace(b'"syn 2.0.119"', b'"syn 3.0.9"')):
            with self.subTest(changed=changed):
                original = self.fixture("3", alternate=changed)
                with self.assertRaisesRegex(ValueError, "differ only"):
                    with native_lock(self.core, self.native):
                        self.fail("unrelated change yielded")
                self.assert_inputs(original)

    def test_required_packages_and_canonical_edge_validated(self):
        for changed in (BASE.replace(b'version = "3.0.9"', b'version = "3.0.8"'),
                        BASE.replace(b'version = "2.0.119"', b'version = "2.0.118"'),
                        BASE + b'\n[[package]]\nname = "syn"\nversion = "3.0.9"\n',
                        SYN3, BASE.replace(b'name = "coaptic-io"', b'name = "missing"'),
                        BASE.replace(b' "syn 2.0.119",', b' "syn 2.0.119", "syn 3.0.9",')):
            with self.subTest(changed=changed):
                original = self.fixture("3", base=changed)
                with self.assertRaises(ValueError):
                    with native_lock(self.core, self.native):
                        self.fail("invalid package/edge yielded")
                self.assert_inputs(original)

    def test_other_inputs_changed_are_fatal_but_base_restored(self):
        for requirement in ("2", "3"):
            for which in ("alt", "manifest"):
                with self.subTest(requirement=requirement, which=which):
                    original = self.fixture(requirement)
                    path = getattr(self, which)
                    changed = path.read_bytes() + b"# concurrent input edit\n"
                    with self.assertRaisesRegex(RuntimeError, "input changed"):
                        with native_lock(self.core, self.native):
                            path.write_bytes(changed)
                    self.assertEqual(self.base.read_bytes(), original[0])
                    self.assertEqual(path.read_bytes(), changed)

    def test_concurrent_canonical_edit_is_preserved_and_refused(self):
        for requirement in ("2", "3"):
            with self.subTest(requirement=requirement):
                self.fixture(requirement)
                changed = b"# concurrent canonical edit\n" + BASE
                with self.assertRaisesRegex(RuntimeError, "restoration/verification failed.*input changed"):
                    with native_lock(self.core, self.native):
                        self.base.write_bytes(changed)
                self.assertEqual(self.base.read_bytes(), changed)

    def test_primary_exception_preserved_with_restoration_refusal_note(self):
        for primary in (subprocess.CalledProcessError(1, ["cargo", "build", "--locked"]),
                        KeyboardInterrupt()):
            with self.subTest(primary=type(primary).__name__):
                self.fixture("3")
                changed = b"# unexpected canonical edit\n" + SYN3
                with self.assertRaises(type(primary)) as caught:
                    with native_lock(self.core, self.native):
                        self.base.write_bytes(changed)
                        raise primary
                self.assertIs(caught.exception, primary)
                self.assertIn("restoration/verification failed", " ".join(primary.__notes__))
                self.assertEqual(self.base.read_bytes(), changed)

    def test_primary_exception_preserved_with_restore_write_failure_note(self):
        self.fixture("3")
        primary = RuntimeError("Cargo failed")
        original_write = Path.write_bytes

        def write_or_fail(path, data):
            if data == BASE:
                raise OSError("restore denied")
            return original_write(path, data)

        with self.assertRaises(RuntimeError) as caught:
            with patch.object(Path, "write_bytes", autospec=True, side_effect=write_or_fail):
                with native_lock(self.core, self.native):
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertIn("restore denied", " ".join(primary.__notes__))
        self.assertEqual(self.base.read_bytes(), SYN3)

    def test_failed_initial_staging_preserves_error_and_never_enters_body(self):
        original_write = Path.write_bytes
        for partial in (False, True):
            with self.subTest(partial=partial):
                self.fixture("3")
                primary = OSError("staging denied")
                writes = []

                def stage_or_fail(path, data):
                    writes.append((path, data))
                    if path == self.base:
                        if partial:
                            original_write(path, b"partial staging bytes")
                        raise primary
                    return original_write(path, data)

                with patch.object(Path, "write_bytes", autospec=True, side_effect=stage_or_fail):
                    with self.assertRaises(OSError) as caught:
                        with native_lock(self.core, self.native):
                            self.fail("failed staging entered the build body")
                self.assertIs(caught.exception, primary)
                self.assertEqual(writes, [(self.base, SYN3)])
                self.assertEqual(self.base.read_bytes(), b"partial staging bytes" if partial else BASE)
                self.assertIn("restoration/verification failed", " ".join(primary.__notes__))

    def test_restore_write_failure_after_successful_body_is_fatal(self):
        self.fixture("3")
        original_write = Path.write_bytes
        body_entered = False

        def restore_or_fail(path, data):
            if path == self.base and data == BASE:
                raise OSError("restore denied after successful build")
            return original_write(path, data)

        with patch.object(Path, "write_bytes", autospec=True, side_effect=restore_or_fail):
            with self.assertRaisesRegex(RuntimeError, "restore denied after successful build"):
                with native_lock(self.core, self.native):
                    body_entered = True
        self.assertTrue(body_entered)
        self.assertEqual(self.base.read_bytes(), SYN3)

    def test_primary_exception_preserved_when_other_input_changes(self):
        self.fixture("3")
        primary = KeyboardInterrupt()
        changed = SYN3 + b"# changed input\n"
        with self.assertRaises(KeyboardInterrupt) as caught:
            with native_lock(self.core, self.native):
                self.alt.write_bytes(changed)
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIn("input changed", " ".join(primary.__notes__))
        self.assertEqual(self.base.read_bytes(), BASE)
        self.assertEqual(self.alt.read_bytes(), changed)


if __name__ == "__main__":
    unittest.main()
