import copy
import unittest
from contracts import evaluate


class ContractEvidenceTests(unittest.TestCase):
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
