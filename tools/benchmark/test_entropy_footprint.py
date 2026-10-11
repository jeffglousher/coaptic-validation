import json
from pathlib import Path
import unittest
import tempfile
from entropy_footprint import EXPECTED, SUITE, library_artifact, publish_provenance


class ArtifactIdentity(unittest.TestCase):
    def record(self, **updates):
        row = dict(reason="compiler-artifact", target={"name": "coaptic"},
                   manifest_path=str(Path("coaptic/Cargo.toml").resolve()),
                   features=["alloc", "std"], filenames=["out/libcoaptic.rlib", "out/libcoaptic.rmeta"])
        row.update(updates)
        return json.dumps(row)

    def test_exact_artifact_survives_relative_dep_info_and_diagnostic_lines(self):
        self.assertEqual(library_artifact("diagnostic\n" + self.record(), Path("coaptic/Cargo.toml"), ["std", "alloc"]), Path("out/libcoaptic.rlib"))

    def test_wrong_source_and_features_refuse(self):
        for output in (self.record(manifest_path=str(Path("other/Cargo.toml").resolve())), self.record(features=["std"])):
            with self.assertRaises(ValueError):
                library_artifact(output, Path("coaptic/Cargo.toml"), ["std", "alloc"])

    def test_missing_or_ambiguous_rlib_refuses(self):
        for output in (self.record(filenames=[]), self.record() + "\n" + self.record()):
            with self.assertRaises(ValueError):
                library_artifact(output, Path("coaptic/Cargo.toml"), ["std", "alloc"])


class FinalSourceCheck(unittest.TestCase):
    def check(self, changed):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            suite = output / "baseline"
            calls = []
            active_change = None

            def run(args, cwd, label):
                calls.append(label)
                core = cwd.name == "coaptic"
                value = (EXPECTED["baseline"] if core else SUITE) if args[1] == "rev-parse" else ""
                if core and args[1] == "status" and active_change == "dirty":
                    value = " M src/app/identity.rs"
                if core and args[1] == "rev-parse" and active_change == "revision":
                    value = "0" * 40
                (output / (label + ".log")).write_text(value, encoding="utf-8")
                return value

            # Initial identity is accepted before the simulated measurement.
            self.assertEqual(run(["git", "status", "--porcelain"], suite / "coaptic", "initial-clean"), "")
            self.assertEqual(run(["git", "rev-parse", "HEAD"], suite / "coaptic", "initial-revision"), EXPECTED["baseline"])
            calls.clear()
            active_change = changed
            if changed:
                with self.assertRaisesRegex(ValueError, "provenance refused"):
                    publish_provenance(run, [("baseline", suite)], output, {"clean": True})
                self.assertFalse((output / "provenance.json").exists())
                self.assertTrue((output / "baseline-final-clean-core.log").exists())
            else:
                publish_provenance(run, [("baseline", suite)], output, {"clean": True})
                self.assertEqual(json.loads((output / "provenance.json").read_text()), {"clean": True})
                self.assertEqual(len(calls), 4)

    def test_clean_final_sources_publish(self):
        self.check(None)

    def test_changed_source_or_revision_refuses_final_publication(self):
        for changed in ("dirty", "revision"):
            with self.subTest(changed=changed):
                self.check(changed)
