"""Checked dependency graphs and preparation fail before writing unknown inputs."""
from copy import deepcopy
import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import macro_lock_selection as locks
import prepare

ROOT = Path(__file__).resolve().parents[1]
def head_bytes(name):
    return subprocess.check_output(["git", "-C", str(ROOT), "show", "HEAD:" + name])


CANONICAL_INPUTS = frozenset(prepare.LOCKS) | {row[0] for row in locks.INPUTS}


def fixture_input(name):
    # CI discovery runs after source preparation. Canonical lock fixtures must
    # describe HEAD, even when the working checkout already holds selected pins.
    return head_bytes(name) if name in CANONICAL_INPUTS or name == locks.NATIVE else (ROOT / name).read_bytes()


NATIVE = head_bytes(locks.NATIVE)
BASES = {row[0]: head_bytes(row[0]) for row in locks.INPUTS}
ALTERNATES = {row[0]: (ROOT / row[1]).read_bytes() for row in locks.INPUTS}


class GraphTests(unittest.TestCase):
    def test_canonical_fixture_reads_ignore_prepared_worktree(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("prepared working lock read")):
            for name in CANONICAL_INPUTS:
                self.assertEqual(fixture_input(name), head_bytes(name))

    def test_native_command_groups_preserve_existing_commands(self):
        # Frozen original command vectors, independent of shallow history and
        # of the current workflow's replacement wrapper steps.
        lines = """cargo fmt --manifest-path tools/benchmark/native/Cargo.toml -p bench-profile -- --check
cargo clippy --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-profile --all-targets -- -D warnings
cargo test --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-profile
cargo fmt --manifest-path tools/benchmark/native/Cargo.toml -p bench-rust-server -- --check
cargo clippy --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-rust-server --all-targets -- -D warnings
cargo test --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-rust-server --bin bench-native-client
cargo build --release --locked --manifest-path tools/benchmark/native/Cargo.toml -p bench-rust-server
python tools/benchmark/protected/network_check.py --server target/benchmark-native/release/bench-rust-server
python tools/benchmark/native_check.py --server target/benchmark-native/release/bench-rust-server --client target/benchmark-native/release/bench-native-client"""
        expected = [shlex.split(line) for line in lines.splitlines()]
        for command in expected:
            if command[0] == "python":
                command[0] = locks.sys.executable
        self.assertEqual(locks.native_commands("profile") + locks.native_commands("fixtures"), expected)
        with self.assertRaisesRegex(ValueError, "unknown fixed"):
            locks.native_commands("arbitrary-command")

    def test_actual_graphs_preserve_all_other_resolved_packages(self):
        for name, base in BASES.items():
            with self.subTest(name=name):
                locks.validate_graph(base, ALTERNATES[name], NATIVE)
                original, selected = locks.parse(base), locks.parse(ALTERNATES[name])
                self.assertEqual(original["version"], selected["version"])
                if name == "Cargo.lock":
                    expected = deepcopy(original)
                    io_row = locks.one(expected["package"], "coaptic-io")
                    io_row["dependencies"] = ["syn 3.0.5" if d == "syn 2.0.119" else d
                                              for d in io_row["dependencies"]]
                    self.assertEqual(selected, expected)
                else:
                    before = {(p["name"], p["version"]): p for p in original["package"]}
                    after = {(p["name"], p["version"]): p for p in selected["package"]}
                    self.assertEqual(set(after) - set(before), {("syn", "3.0.9")})
                    removed = {("syn", "2.0.119")} if name == "fuzz/Cargo.lock" else set()
                    self.assertEqual(set(before) - set(after), removed)
                    for key, row in before.items():
                        if key[0] != "coaptic-io" and key not in removed:
                            expected = deepcopy(row)
                            if "dependencies" in expected:
                                expected["dependencies"] = ["syn 2.0.119" if d == "syn" else d
                                                            for d in expected["dependencies"]]
                            self.assertEqual(after[key], expected)

    def test_fuzz_replaces_the_only_syn_user_without_orphan_packages(self):
        before = locks.parse(BASES["fuzz/Cargo.lock"])["package"]
        after = locks.parse(ALTERNATES["fuzz/Cargo.lock"])["package"]
        self.assertEqual(len(before), 36)
        self.assertEqual(len(after), 36)
        self.assertEqual([p for p in before if p["name"] not in ("syn", "coaptic-io")],
                         [p for p in after if p["name"] not in ("syn", "coaptic-io")])
        self.assertEqual([p["version"] for p in after if p["name"] == "syn"], ["3.0.9"])
        self.assertEqual(locks.one(after, "coaptic-io")["dependencies"],
                         ["proc-macro2", "quote", "syn"])
        by_name = {p["name"]: p for p in after}
        self.assertEqual(len(by_name), len(after))
        reachable, pending = set(), ["coaptic-fuzz"]
        while pending:
            name = pending.pop()
            if name not in reachable:
                reachable.add(name)
                pending.extend(d.split()[0] for d in by_name[name].get("dependencies", []))
        self.assertEqual(reachable, set(by_name))

    def test_another_syn2_user_prevents_pruning_and_keeps_qualified_edges(self):
        base = BASES["fuzz/Cargo.lock"]
        needle = b'name = "coaptic-fuzz"\nversion = "0.0.0"\ndependencies = [\n'
        self.assertEqual(base.count(needle), 1)
        rows = locks.expected_graph(base.replace(needle, needle + b' "syn",\n'), NATIVE)["package"]
        self.assertEqual(sorted(p["version"] for p in rows if p["name"] == "syn"),
                         ["2.0.119", "3.0.9"])
        self.assertIn("syn 2.0.119", locks.one(rows, "coaptic-fuzz")["dependencies"])
        self.assertIn("syn 3.0.9", locks.one(rows, "coaptic-io")["dependencies"])

    def test_unknown_edge_or_package_change_is_rejected(self):
        for name, data in ALTERNATES.items():
            with self.subTest(name=name):
                bad = data.replace(b'"quote"', b'"foreign-quote"', 1)
                with self.assertRaisesRegex(ValueError, "alternate changes"):
                    locks.validate_graph(BASES[name], bad, NATIVE)

    def test_duplicate_package_and_source_override_are_rejected(self):
        base = BASES["fuzz/Cargo.lock"]
        repeated = base + b'\n[[package]]\nname="syn"\nversion="2.0.119"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n'
        with self.assertRaisesRegex(ValueError, "duplicate"):
            locks.expected_graph(repeated, NATIVE)
        bad = base.replace(b'checksum = "872831', b'checksum = "072831')
        with self.assertRaisesRegex(ValueError, "Syn package"):
            locks.expected_graph(bad, NATIVE)

    def test_explicit_macro_source_contract(self):
        template = '[package]\nname="coaptic-io"\nversion="0.0.10"\n[dependencies]\nsyn={version="%s"}\n'
        for major in ("2", "3"):
            self.assertEqual(locks.declared_major((template % major).encode()), major)
        for major in ("4", "^3", "3.0.9", "*"):
            with self.assertRaises(ValueError):
                locks.declared_major((template % major).encode())
        for extra in (', git="https://example.invalid/syn"', ', path="../syn"',
                      ', package="syn"', ', workspace=true'):
            data = (template % "3").replace('version="3"}', 'version="3"' + extra + '}')
            with self.assertRaises(ValueError):
                locks.declared_major(data.encode())
        with self.assertRaisesRegex(ValueError, "multiple"):
            locks.declared_major(((template % "3") + '[dev-dependencies]\nsyn={version="3"}\n').encode())


class CheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="coaptic-macro-lock-test-")
        self.temporary_path = Path(self.temporary.name).resolve()
        self.addCleanup(self.cleanup)
        self.suite = self.temporary_path / "suite"
        self.suite.mkdir()
        self.core = self.suite / "coaptic"
        self.core.mkdir()
        (self.suite / ".gitignore").write_text("coaptic/\n__pycache__/\n")
        names = set(prepare.LOCKS) | {row[1] for row in locks.INPUTS} | {
            "fuzz/Cargo.lock", locks.NATIVE, "tools/prepare.py", "tools/macro_lock_selection.py", ".gitattributes",
            "tools/benchmark/native_lock.py", "tools/source_identity.py",
            "tools/esphome/lock_selection.py", "tools/esphome/rust/Cargo.syn2.lock"}
        for name in names:
            path = self.suite / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(fixture_input(name))
        fixture = Path("tests/plugtest/td-coap4/base.yml")
        for root in (self.suite, self.core):
            path = root / fixture
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture: {}\n")
        (self.core / "Cargo.toml").write_text('[package]\nname="coaptic"\nversion = "9.8.7"\n')
        path = self.core / locks.MANIFEST
        path.parent.mkdir(parents=True)
        path.write_text('[package]\nname="coaptic-io"\nversion="0.0.10"\n[dependencies]\nsyn={version="3",features=["full"]}\n')
        for root in (self.suite, self.core):
            self.git(root, "init")
            self.commit(root)
        self.revision = self.git(self.core, "rev-parse", "HEAD").decode().strip()
        self.initial = self.snapshot()

    def cleanup(self):
        if (self.temporary_path.parent != Path(tempfile.gettempdir()).resolve()
                or not self.temporary_path.name.startswith("coaptic-macro-lock-test-")):
            raise AssertionError("refuse cleanup outside owned fixture")
        self.temporary.cleanup()

    def git(self, root, *args):
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

    def commit(self, root):
        self.git(root, "add", ".")
        self.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-m", "fixture")

    def snapshot(self):
        return {name: (self.suite / name).read_bytes()
                for name in dict.fromkeys((*prepare.LOCKS, *(r[0] for r in locks.INPUTS)))}

    def select(self):
        return locks.select(self.suite, self.core, self.revision)

    def set_major(self, major):
        path = self.core / locks.MANIFEST
        path.write_text(path.read_text().replace('version="3",features', 'version="' + major + '",features'))
        self.commit(self.core)
        self.revision = self.git(self.core, "rev-parse", "HEAD").decode().strip()

    def identity(self):
        return dict(source=self.revision, dirty=bool(self.git(self.core, "status", "--porcelain")),
                    suite_source=self.git(self.suite, "rev-parse", "HEAD").decode().strip(),
                    suite_dirty=bool(self.git(self.suite, "status", "--porcelain")),
                    suite_locks={name: locks.digest((self.suite / name).read_bytes())
                                 for name in prepare.LOCKS})

    def run_prepare(self, **kwargs):
        output = kwargs.pop("output", self.temporary_path / "report.json")
        with patch.object(prepare, "SUITE", self.suite), patch.object(prepare, "LIBRARY", self.core), \
                patch.object(prepare, "source_identity", side_effect=self.identity), \
                contextlib.redirect_stdout(io.StringIO()):
            prepare.prepare(self.revision, output, select_macro_locks=True, **kwargs)
        return json.loads(output.read_text())

    def test_selection_is_pure_and_syn3_uses_checked_alternates(self):
        selected, report = self.select()
        self.assertEqual(selected, ALTERNATES)
        self.assertEqual(report["declared_syn_major"], "3")
        self.assertEqual(self.snapshot(), self.initial)

    def test_syn2_preserves_all_canonical_graphs(self):
        self.set_major("2")
        selected, report = self.select()
        self.assertEqual(selected, BASES)
        self.assertEqual(report["declared_syn_major"], "2")
        self.assertEqual(self.snapshot(), self.initial)

    def test_modified_last_alternate_leaves_all_canonical_locks_unchanged(self):
        path = self.suite / "fuzz/Cargo.syn3.lock"
        path.write_bytes(path.read_bytes() + b"# foreign edit\n")
        with self.assertRaisesRegex(ValueError, "modified source"):
            self.select()
        self.assertEqual(self.snapshot(), self.initial)

    def test_modified_canonical_or_helper_refuses_without_overwrite(self):
        for name in ("Cargo.lock", "tools/macro_lock_selection.py"):
            path = self.suite / name
            before = path.read_bytes()
            path.write_bytes(before + b"# foreign edit\n")
            incoming = self.snapshot()
            with self.assertRaisesRegex(ValueError, "modified source"):
                self.select()
            self.assertEqual(self.snapshot(), incoming)
            path.write_bytes(before)

    def test_modified_index_is_not_accepted_even_with_original_working_bytes(self):
        path = self.suite / "Cargo.lock"
        before = path.read_bytes()
        path.write_bytes(before + b"# staged edit\n")
        self.git(self.suite, "add", "Cargo.lock")
        path.write_bytes(before)
        with self.assertRaisesRegex(ValueError, "modified index"):
            self.select()
        self.assertEqual(self.snapshot(), self.initial)

    def test_wrong_core_and_unknown_clean_major_refuse(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            locks.select(self.suite, self.core, "0" * 40)
        self.set_major("4")
        with self.assertRaisesRegex(ValueError, "unsupported explicit"):
            self.select()
        self.assertEqual(self.snapshot(), self.initial)

    def test_symlink_input_refuses(self):
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(ValueError, "symlink"):
                locks.safe_path(self.suite.resolve(), "Cargo.lock")

    def test_preparation_reports_final_actual_fuzz_hash_and_versions(self):
        report = self.run_prepare()
        self.assertEqual(report["library_version"], "9.8.7")
        for row in report["macro_lock_selection"]["locks"]:
            actual = (self.suite / row["path"]).read_bytes()
            self.assertEqual(row["final_sha256"], hashlib.sha256(actual).hexdigest())
            coaptic = locks.one(locks.parse(actual)["package"], "coaptic")
            self.assertEqual(coaptic["version"], "9.8.7")
        self.assertEqual(report["suite_locks"], self.identity()["suite_locks"])
        self.assertTrue(report["suite_dirty"])

    def test_syn2_preparation_only_aligns_path_versions(self):
        self.set_major("2")
        report = self.run_prepare()
        self.assertEqual(report["macro_lock_selection"]["declared_syn_major"], "2")
        for name, base in BASES.items():
            expected = locks.parse(base)
            locks.one(expected["package"], "coaptic")["version"] = "9.8.7"
            self.assertEqual(locks.parse((self.suite / name).read_bytes()), expected)

    def test_existing_esphome_preselection_survives_syn2_preparation(self):
        self.set_major("2")
        alternate = (self.suite / "tools/esphome/rust/Cargo.syn2.lock").read_bytes()
        path = self.suite / "tools/esphome/rust/Cargo.lock"
        path.write_bytes(alternate)
        report = self.run_prepare()
        expected = locks.parse(alternate)
        locks.one(expected["package"], "coaptic")["version"] = "9.8.7"
        self.assertEqual(locks.parse(path.read_bytes()), expected)
        self.assertEqual(report["suite_locks"]["tools/esphome/rust/Cargo.lock"], locks.digest(path.read_bytes()))

    def test_alternates_keep_lf_bytes_through_checkout_filters(self):
        for mode in ("true", "input", "false"):
            for _, name, _, expected_hash in locks.INPUTS:
                filtered = self.git(self.suite, "-c", "core.autocrlf=" + mode,
                                    "cat-file", "--filters", "HEAD:" + name)
                self.assertEqual(locks.digest(filtered), expected_hash)

    def test_serialization_failure_precedes_all_lock_writes(self):
        with patch.object(prepare.json, "dumps", side_effect=TypeError("report failure")):
            with self.assertRaisesRegex(TypeError, "report failure"):
                self.run_prepare()
        self.assertEqual(self.snapshot(), self.initial)

    def test_late_input_change_refuses_before_any_lock_write(self):
        path = self.suite / "fuzz/Cargo.syn3.lock"
        dumps = json.dumps
        changed = False

        def mutate_then_serialize(*args, **kwargs):
            nonlocal changed
            if not changed:
                path.write_bytes(path.read_bytes() + b"# late foreign edit\n")
                changed = True
            return dumps(*args, **kwargs)

        with patch.object(prepare.json, "dumps", side_effect=mutate_then_serialize):
            with self.assertRaisesRegex(ValueError, "modified source"):
                self.run_prepare()
        self.assertEqual(self.snapshot(), self.initial)

    def test_other_lock_preflight_failure_precedes_selected_staging(self):
        path = self.suite / "tools/security-profile/Cargo.lock"
        path.write_bytes(path.read_bytes().replace(b'name = "coaptic"', b'name = "foreign-coaptic"'))
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "exactly one Coaptic"):
            self.run_prepare()
        self.assertEqual(self.snapshot(), before)

    def test_output_cannot_overwrite_a_selected_lock(self):
        with self.assertRaisesRegex(ValueError, "overlaps"):
            self.run_prepare(output=self.suite / "fuzz/Cargo.lock")
        self.assertEqual(self.snapshot(), self.initial)

    def native_checkpoint(self):
        path = self.core / "Cargo.toml"
        path.write_text(path.read_text().replace('version = "9.8.7"', 'version = "0.0.10"'))
        self.commit(self.core)
        self.revision = self.git(self.core, "rev-parse", "HEAD").decode().strip()
        report = self.run_prepare()
        suite_revision = self.git(self.suite, "rev-parse", "HEAD").decode().strip()
        return self.temporary_path / "report.json", suite_revision, report

    def verify_checkpoint(self, report_path, suite_revision):
        return locks.verify_prepared(self.suite, self.core, self.revision, suite_revision, report_path)

    def test_native_checkpoint_rejects_foreign_tracked_and_untracked_source(self):
        report, revision, _ = self.native_checkpoint()
        self.verify_checkpoint(report, revision)
        path = self.suite / "tools/source_identity.py"
        old = path.read_bytes()
        path.write_bytes(old + b"# foreign edit\n")
        with self.assertRaisesRegex(ValueError, "foreign tracked"):
            self.verify_checkpoint(report, revision)
        path.write_bytes(old)
        (self.suite / "foreign-source.py").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "foreign untracked"):
            self.verify_checkpoint(report, revision)

    def test_native_checkpoint_accepts_checked_esphome_syn2_preparation(self):
        self.set_major("2")
        path = self.suite / "tools/esphome/rust/Cargo.lock"
        path.write_bytes((self.suite / "tools/esphome/rust/Cargo.syn2.lock").read_bytes())
        report, revision, _ = self.native_checkpoint()
        self.verify_checkpoint(report, revision)

    def test_native_checkpoint_rejects_wrong_ref_core_and_self_described_hashes(self):
        report, revision, _ = self.native_checkpoint()
        with self.assertRaisesRegex(ValueError, "suite identity"):
            self.verify_checkpoint(report, "0" * 40)
        with self.assertRaisesRegex(ValueError, "core identity"):
            locks.verify_prepared(self.suite, self.core, "0" * 40, revision, report)
        value = json.loads(report.read_text())
        value["suite_locks"]["Cargo.lock"] = "0" * 64
        report.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "lock hashes"):
            self.verify_checkpoint(report, revision)

    def test_fixed_native_commands_restore_prepared_lock_on_success(self):
        report, revision, _ = self.native_checkpoint()
        path = self.suite / "tools/benchmark/native/Cargo.lock"
        old = path.read_bytes()
        commands, run = [], subprocess.run

        def mock(command, *args, **kwargs):
            if command[0] == "cargo" or command[0] == locks.sys.executable:
                commands.append(command)
                io_row = locks.one(locks.parse(path.read_bytes())["package"], "coaptic-io")
                self.assertIn("syn 3.0.9", io_row["dependencies"])
                return subprocess.CompletedProcess(command, 0)
            return run(command, *args, **kwargs)

        with patch.object(locks.subprocess, "run", side_effect=mock), contextlib.redirect_stdout(io.StringIO()):
            locks.run_native_checks("fixtures", self.suite, self.revision, revision, report)
        self.assertEqual(commands, locks.native_commands("fixtures"))
        self.assertEqual(path.read_bytes(), old)
        self.verify_checkpoint(report, revision)

    def test_cargo_failure_restores_native_lock_without_replacing_primary(self):
        report, revision, _ = self.native_checkpoint()
        path = self.suite / "tools/benchmark/native/Cargo.lock"
        old = path.read_bytes()
        run = subprocess.run
        failure = subprocess.CalledProcessError(101, ["cargo", "clippy"])

        def mock(command, *args, **kwargs):
            if command[0] == "cargo":
                if command[1] == "clippy":
                    raise failure
                return subprocess.CompletedProcess(command, 0)
            return run(command, *args, **kwargs)

        with patch.object(locks.subprocess, "run", side_effect=mock):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                locks.run_native_checks("profile", self.suite, self.revision, revision, report)
        self.assertIs(caught.exception, failure)
        self.assertEqual(path.read_bytes(), old)
        self.verify_checkpoint(report, revision)

    def test_foreign_native_edit_is_preserved_and_primary_keeps_cleanup_notes(self):
        report, revision, _ = self.native_checkpoint()
        path = self.suite / "tools/benchmark/native/Cargo.lock"
        run = subprocess.run
        failure = subprocess.CalledProcessError(101, ["cargo", "fmt"])
        foreign = b"foreign native bytes\n"

        def mock(command, *args, **kwargs):
            if command[0] == "cargo":
                path.write_bytes(foreign)
                raise failure
            return run(command, *args, **kwargs)

        with patch.object(locks.subprocess, "run", side_effect=mock):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                locks.run_native_checks("profile", self.suite, self.revision, revision, report)
        self.assertIs(caught.exception, failure)
        self.assertEqual(path.read_bytes(), foreign)
        self.assertTrue(any("restoration/verification" in note for note in failure.__notes__))
        self.assertTrue(any("checkpoint finally" in note for note in failure.__notes__))

    def test_native_helper_implementation_ast_is_unchanged(self):
        path = "tools/benchmark/native_lock.py"
        original = subprocess.check_output(["git", "-C", str(ROOT), "show", "HEAD:" + path])
        before = ast.parse(original.decode())
        after = ast.parse((ROOT / path).read_text())
        self.assertEqual(ast.dump(ast.Module(body=before.body[1:], type_ignores=[])),
                         ast.dump(ast.Module(body=after.body[1:], type_ignores=[])))

    def test_workflow_selects_before_every_provenance_capture(self):
        text = (ROOT / ".github/workflows/validation.yml").read_text()
        lines = [line for line in text.splitlines() if "tools/prepare.py " in line]
        self.assertEqual(len(lines), 14)
        self.assertEqual(sum("tools/prepare.py --select-macro-locks --expected-revision" in line for line in lines), 13)
        jobs = [job for job in re.split(r"(?m)(?=^  [a-zA-Z0-9_-]+:\n)", text)
                if "tools/prepare.py --select-macro-locks" in job]
        self.assertEqual(len(jobs), 13)
        for job in jobs:
            before = job.split("tools/prepare.py --select-macro-locks")[0]
            self.assertIn("uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1", before)
            self.assertIn("python-version: '3.13'", before)
            self.assertEqual(before.count("uses: actions/checkout@"), 2)
        container = text.split("    name: protected Linux container", 1)[1].split("  host-platforms:", 1)[0]
        self.assertNotIn("--select-macro-locks", container)
        self.assertIn("--prepared-source \"$RUNNER_TEMP/validation-source.json\"", text)
        self.assertIn("--expected-suite-revision \"$SUITE_REVISION\"", text)
        self.assertIn("--native-checks profile", text)
        self.assertIn("--native-checks fixtures", text)
        self.assertIn("CARGO_TARGET_DIR: target/benchmark-native", text)
        self.assertNotIn("cargo clippy --locked --manifest-path tools/benchmark/native/Cargo.toml", text)


if __name__ == "__main__":
    unittest.main()
