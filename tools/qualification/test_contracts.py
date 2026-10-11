import copy
import hashlib
import json
import unittest
from contracts import MANIFEST, evaluate, load_and_evaluate


class ContractEvidenceTests(unittest.TestCase):
    def test_current_manifest_loader_requires_each_named_upload_proof(self):
        raw = MANIFEST.read_bytes()
        manifest = json.loads(raw)
        names = {name for row in manifest["requirements"] for name in row["tests"]}
        output = "\n".join(f"test {name} ... ok" for name in sorted(names))
        result = load_and_evaluate(output)
        self.assertTrue(result["passed"])
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        contracts = {row["id"]: row for row in result["requirements"]}
        for identity in ("conditional-upload-refusal", "fragmented-if-match", "classic-block1-if-none-match",
                         "classic-block1-error-no-response", "qblock1-if-none-match", "fragmented-fetch-etag", "qblock1-server-error-no-response", "deferred-fetch-validator", "bounded-dedup-history", "qblock1-fetch-etag", "qblock1-con-success-no-response", "deferred-qblock2-snapshot", "deferred-qblock2-repeated-selection", "oscore-context-replacement-lifecycle", "deferred-qblock2-initial-selectors", "qblock1-non-success-pacing", "deferred-observe-registration"):
            self.assertIn(identity, contracts)
            for name in contracts[identity]["tests"]:
                for replacement in ("", f"test {name} ... ignored", f"test {name} ... FAILED"):
                    changed = output.replace(f"test {name} ... ok", replacement)
                    refused = load_and_evaluate(changed)
                    self.assertFalse(refused["passed"], (identity, name, replacement))
                    row = next(row for row in refused["requirements"] if row["id"] == identity)
                    self.assertEqual(row["missing"], [name])

    def test_old_refusal_names_cannot_substitute_for_current_execution(self):
        manifest = json.loads(MANIFEST.read_bytes())
        names = {name for row in manifest["requirements"] for name in row["tests"]}
        for identity, current, old in (
            ("conditional-upload-refusal",
             "app::tests::fragmented_etag_refuses_instead_of_becoming_unconditional",
             "app::tests::fragmented_if_none_match_and_etag_refuse_instead_of_becoming_unconditional"),
            ("classic-block1-if-none-match",
             "fragmented_etag_refusal_cancel_and_deadline_reclaim_before_recovery",
             "if_none_match_q_refusal_cancel_and_deadline_reclaim_before_recovery"),
        ):
            self.assertIn(current, names)
            self.assertNotIn(old, names)
            output = "\n".join(f"test {name} ... ok" for name in sorted((names - {current}) | {old}))
            result = load_and_evaluate(output)
            self.assertFalse(result["passed"])
            row = next(row for row in result["requirements"] if row["id"] == identity)
            self.assertEqual(row["missing"], [current])

    def fixture(self):
        return {"schema": "coaptic-contracts/1", "scope": "fixture", "requirements": [
            {"id": "request", "rfc": 7252, "section": "5.4.1", "tests": ["positive", "refusal"]}]}

    def test_every_named_proof_must_execute(self):
        manifest = self.fixture()
        self.assertTrue(evaluate(manifest, "test positive ... ok\ntest refusal ... ok")["passed"])
        for output in ["", "test positive ... ok", "test positive ... ok\ntest refusal ... ignored",
                       "test positive ... ok\ntest refusal ... FAILED"]:
            self.assertFalse(evaluate(manifest, output)["passed"])

    def test_invalid_or_silent_inventory_fails(self):
        for change in [lambda m: m.update(requirements=[]),
                       lambda m: m["requirements"].append(copy.deepcopy(m["requirements"][0])),
                       lambda m: m["requirements"][0].update(tests=[]),
                       lambda m: m["requirements"][0].update(rfc=True)]:
            manifest = self.fixture()
            change(manifest)
            with self.assertRaises(ValueError):
                evaluate(manifest, "")


if __name__ == "__main__":
    unittest.main()
