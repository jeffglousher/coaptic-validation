"""Coverage accounting rejects missing evidence and invalid denominators."""
import json
from pathlib import Path
import unittest
from coverage import artifacts, source_totals


class CoverageTests(unittest.TestCase):
    def test_artifacts_require_actual_test_executables(self):
        row = {"reason": "compiler-artifact", "profile": {"test": True}, "executable": "test-bin"}
        self.assertEqual(artifacts(json.dumps(row) + "\n" + json.dumps(row)), ["test-bin"])
        for stdout in ("", "test result: ok.", json.dumps(dict(row, executable=None)),
                       json.dumps(dict(row, profile={"test": False}))):
            with self.assertRaises(ValueError):
                artifacts(stdout)

    def fixture(self):
        root = Path.cwd()
        summary = {key: {"count": 10, "covered": 3} for key in ("lines", "regions", "functions")}
        return root, {"data": [{"files": [{"filename": str(root / "src" / "lib.rs"), "summary": summary}]}]}

    def test_only_source_tree_contributes_to_totals(self):
        root, export = self.fixture()
        export["data"][0]["files"].append({"filename": str(root / "dependency" / "lib.rs"), "summary": {}})
        files, totals = source_totals(export, root)
        self.assertEqual(len(files), 1)
        self.assertEqual(totals["lines"], {"count": 10, "covered": 3, "percent": 30.0})

    def test_empty_duplicate_or_invalid_metrics_fail(self):
        root, export = self.fixture()
        with self.assertRaises(ValueError):
            source_totals({"data": []}, root)
        export["data"][0]["files"] *= 2
        with self.assertRaises(ValueError):
            source_totals(export, root)
        for n, hit in ((0, 0), (1, 2), (-1, 0), (True, 0)):
            root, export = self.fixture()
            export["data"][0]["files"][0]["summary"]["lines"] = {"count": n, "covered": hit}
            with self.assertRaises(ValueError):
                source_totals(export, root)


if __name__ == "__main__":
    unittest.main()
