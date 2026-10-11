import json
from pathlib import Path
import unittest
from entropy_footprint import library_artifact


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
