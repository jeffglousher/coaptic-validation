"""Declared process cases and fail-closed, source-bound coverage accounting."""
import hashlib
import json
from collections import Counter
from pathlib import Path

MANIFEST = Path(__file__).with_name("capabilities.json")


def load_manifest(path=MANIFEST):
    raw = Path(path).read_bytes()
    manifest = json.loads(raw)
    validate_manifest(manifest)
    return manifest, hashlib.sha256(raw).hexdigest()


def validate_manifest(manifest):
    if manifest.get("schema") != "coaptic-capabilities/1":
        raise ValueError("unsupported capability manifest schema")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("capability manifest must declare executable cases")
    capabilities = manifest.get("required_capabilities")
    if capabilities != ["libcoap-dtls", "libcoap-oscore"]:
        raise ValueError("unknown build capability policy")
    ids = set()
    for case in cases:
        for field in ("id", "client", "server", "transport", "security", "address_family", "executable"):
            if not isinstance(case.get(field), str) or not case[field]:
                raise ValueError(f"missing case field {field}")
        if case["id"] in ids:
            raise ValueError(f"duplicate declared case {case['id']}")
        ids.add(case["id"])
        if case["client"] not in ("coaptic", "coap-rs", "libcoap") or case["server"] not in ("coaptic", "coap-rs", "libcoap"):
            raise ValueError("unknown peer")
        if (case["transport"], case["security"]) not in (("udp", "none"), ("dtls", "psk-dtls"), ("udp", "oscore")):
            raise ValueError("undeclared transport/security combination")
        expected = ["libcoap-dtls"] if case["transport"] == "dtls" and "libcoap" in (case["client"], case["server"]) else []
        if case["security"] == "oscore" and "libcoap" in (case["client"], case["server"]):
            expected = ["libcoap-oscore"]
        if case.get("requires") != expected:
            raise ValueError("case build exclusion does not match peer/transport")
        for field in ("features", "positive_proof", "failure_proof", "execution_platforms"):
            values = case.get(field)
            if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
                raise ValueError(f"missing assertion/platform list {field}")
    gaps = manifest.get("gaps")
    if not isinstance(gaps, list) or not gaps:
        raise ValueError("explicit unqualified surface inventory is required")
    for gap in gaps:
        if gap.get("status") not in ("unqualified", "fixture-unsupported") or gap.get("executable_cases") != []:
            raise ValueError("unqualified surface cannot claim executable coverage")
        for field in ("feature", "role", "transport_security", "peers", "reason"):
            if not isinstance(gap.get(field), str) or not gap[field]:
                raise ValueError(f"missing gap field {field}")
        if type(gap.get("issue")) is not int or gap["issue"] <= 0:
            raise ValueError("gap requires tracking issue")


def evaluate(manifest, outcomes, *, libcoap_dtls, system, libcoap_oscore=True):
    """An omitted, duplicate, undeclared, disabled or failed case cannot pass."""
    validate_manifest(manifest)
    if type(libcoap_dtls) is not bool or type(libcoap_oscore) is not bool:
        raise ValueError("build capability must be explicit")
    def is_excluded(case):
        return ("libcoap-dtls" in case["requires"] and not libcoap_dtls) or ("libcoap-oscore" in case["requires"] and not libcoap_oscore)
    counts = Counter(row.get("name") for row in outcomes)
    results = {row.get("name"): row for row in outcomes}
    declared = {row["id"] for row in manifest["cases"]}
    problems = [f"undeclared case: {name}" for name in counts if name not in declared]
    coverage = []
    for case in manifest["cases"]:
        name = case["id"]
        excluded = is_excluded(case)
        if excluded:
            state = "build-excluded"
            if counts[name]:
                problems.append(f"excluded case unexpectedly executed: {name}")
                state = "invalid"
        elif system not in case["execution_platforms"]:
            state = "platform-unqualified"
            problems.append(f"undeclared execution platform for {name}: {system}")
        elif counts[name] == 0:
            state = "missing"
            problems.append(f"missing case: {name}")
        elif counts[name] != 1:
            state = "invalid"
            problems.append(f"duplicate case: {name}")
        elif results[name].get("passed") is not True:
            state = "failed"
            problems.append(f"failed case: {name}")
        elif not isinstance(results[name].get("evidence"), dict) or not results[name]["evidence"]:
            state = "invalid"
            problems.append(f"missing evidence: {name}")
        else:
            state = "passed"
        coverage.append({"case": name, "status": state})
    return {"schema": "coaptic-process-coverage/1", "complete": not problems,
            "enabled_cases": sum(not is_excluded(case) for case in manifest["cases"]),
            "cases": coverage, "problems": problems,
            "unqualified": manifest["gaps"],
            "meaning": "Enabled cases passed once."}
