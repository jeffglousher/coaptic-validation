import hashlib
import json
from pathlib import Path
import re

MANIFEST = Path(__file__).with_name("contracts.json")


def evaluate(manifest, stdout):
    if manifest.get("schema") != "coaptic-contracts/1" or not manifest.get("scope"):
        raise ValueError("invalid contract manifest")
    requirements = manifest.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("empty requirement inventory")
    passed = set(re.findall(r"^test (\S+) \.\.\. ok$", stdout, re.MULTILINE))
    ids = set()
    results = []
    for row in requirements:
        identity = row.get("id")
        tests = row.get("tests")
        if not isinstance(identity, str) or not identity or identity in ids:
            raise ValueError("missing or duplicate contract id")
        ids.add(identity)
        if type(row.get("rfc")) is not int or not isinstance(row.get("section"), str) or not row["section"]:
            raise ValueError("missing RFC reference")
        if not isinstance(tests, list) or not tests or len(set(tests)) != len(tests) or any(not isinstance(test, str) or not test for test in tests):
            raise ValueError("missing or duplicate proof tests")
        missing = sorted(set(tests) - passed)
        results.append({"id": identity, "rfc": row["rfc"], "section": row["section"],
                        "tests": tests, "passed": not missing, "missing": missing})
    return {"scope": manifest["scope"], "passed": all(row["passed"] for row in results), "requirements": results}


def load_and_evaluate(stdout):
    raw = MANIFEST.read_bytes()
    result = evaluate(json.loads(raw), stdout)
    result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return result
