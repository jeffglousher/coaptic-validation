"""Finite independent method-3 profile checks; no timing campaign."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import time

from edhoc import CAPACITY, Peer, binary_field, require, validate_completion


VECTORS = ((32768, 0, 16), (65535, 23, 33), (32768, 24, 64),
           (32768, 255, 16), (32768, 256, 16))


def validate_profile(coaptic, native, role, suite, ead):
    result = validate_completion(coaptic, native, role, suite=suite)
    for record, current_role in ((coaptic, role), (native, "responder" if role == "initiator" else "initiator")):
        expected = ([0, 3, 0, 3], 10) if current_role == "initiator" else ([3, 0, 3, 0], 4)
        if not ead:
            expected = ([0, 0, 0, 0], 0)
        require(record.get("ead_received") == expected[0], "incorrect ordered EAD receipts")
        require(record.get("ead_authenticated") == expected[1], "incorrect authenticated EAD stages")
        exports = record.get("exports")
        require(isinstance(exports, list) and len(exports) == len(VECTORS), "missing exporter vectors")
        for value, (label, context_length, length) in zip(exports, VECTORS):
            require(value.get("label") == label and value.get("length") == length, "wrong exporter request")
            require(binary_field(value, "context", context_length) == bytes(range(256))[:context_length], "wrong exporter context")
            binary_field(value, "hex", length)
    require(coaptic["exports"] == native["exports"], "independent exporter disagreement")
    result["checks"] += ["private_label_exporter_context_boundaries", "ordered_ead_presence_and_authentication"]
    return result


async def session(args, role, suite, ead, critical_stage=0):
    extra = ["--suite", str(suite)] + (["--ead"] if ead else [])
    native_extra = extra + (["--critical-stage", str(critical_stage)] if critical_stage else [])
    coaptic = Peer(args.coaptic, "coaptic", role, args.timeout, extra)
    native = Peer(args.libedhoc, "libedhoc", "responder" if role == "initiator" else "initiator", args.timeout, native_extra)
    initiator, responder = (coaptic, native) if role == "initiator" else (native, coaptic)
    record = {"role": role, "suite": suite, "ead": ead, "critical_stage": critical_stage,
              "messages": [], "processes": [coaptic.record, native.record]}
    try:
        await coaptic.start()
        await native.start()
        require(await responder.read() == {"ready": True}, "missing readiness")
        for number, sender, receiver in ((1, initiator, responder), (2, responder, initiator),
                                         (3, initiator, responder), (4, responder, initiator)):
            value = await sender.read()
            require(value is not None and value.get("message") == number, "missing protocol message")
            payload = binary_field(value, "hex")
            require(0 < len(payload) <= CAPACITY, "message capacity exceeded")
            record["messages"].append({"message": number, "hex": payload.hex()})
            await receiver.send(payload)
            if number == critical_stage:
                require(receiver is coaptic, "critical EAD did not target Coaptic")
                rejected = await coaptic.read()
                require(rejected is None or "error" in rejected, "critical EAD accepted")
                await coaptic.wait()
                require(coaptic.process.returncode == 1, "incorrect refusal exit")
                require(coaptic.record["stderr"] and "panicked" not in coaptic.record["stderr"].lower(), "missing refusal or panic")
                require(not any(item.get("complete") for item in coaptic.record["records"]), "refused session exported")
                record["refusal"] = "unknown critical EAD; raw API error, not a wire-error proof"
                record["status"] = "passed"
                return record
        record["validated"] = validate_profile(await coaptic.read(), await native.read(), role, suite, ead)
        for peer in (coaptic, native):
            await peer.wait()
            require(peer.process.returncode == 0 and not peer.record["stderr"], "completion process failed")
        record["status"] = "passed"
    except Exception as error:
        record["status"], record["error"] = "failed", repr(error)
    finally:
        await coaptic.stop()
        await native.stop()
    return record


def source_identity(path):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()
    require(not git("status", "--porcelain"), f"unclean source: {path}")
    return {"path": str(path), "commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}")}


def native_build_identity(args):
    binary_hash = hashlib.sha256(args.libedhoc.read_bytes()).hexdigest()
    for path in sorted((args.libedhoc.parent / "evidence").glob("*/manifest.json"), reverse=True):
        metadata = json.loads(path.read_text(encoding="utf-8"))
        if metadata.get("result") != "passed" or metadata.get("executable", {}).get("sha256") != binary_hash:
            continue
        fixture = args.companion / "tools/interop/libedhoc"
        for name, digest in metadata["fixture_sha256"].items():
            require(hashlib.sha256((fixture / name).read_bytes()).hexdigest() == digest, "native fixture source changed since build")
        return {"manifest": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "source_revisions": metadata["source_revisions"], "configuration": metadata["configuration"],
                "fixture_sha256": metadata["fixture_sha256"], "python_packages": metadata["python_packages"]}
    raise ValueError("missing matching successful independent build manifest")


async def run(args):
    sources = {name: source_identity(path) for name, path in (("core", args.core), ("companion", args.companion))}
    report = {"schema": "coaptic-edhoc-selected-profiles/1", "sources": sources, "native_build": native_build_identity(args),
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "scope": "Independent raw EDHOC method 3, suites 2/3, both roles, message 4, EAD and private-label exporters. No wire-error, device, installation or full-u64 exporter claim.",
              "suite3_backend": "public libedhoc custom descriptor; upstream suite-2 P-256/SHA-256 methods plus PSA AES-CCM with 16-byte tag",
              "fixtures": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                           for name, path in (("coaptic", args.coaptic), ("libedhoc", args.libedhoc))},
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": []}
    def save():
        report["passed"] = sum(case["status"] == "passed" for case in report["cases"])
        report["failed"] = len(report["cases"]) - report["passed"]
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    secrets = set()
    async def append(role, suite, ead, stage=0):
        case = await session(args, role, suite, ead, stage)
        if case.get("validated"):
            secret = case["validated"]["master_secret"]
            if secret in secrets:
                case["status"], case["error"] = "failed", "fresh session repeated master secret"
            secrets.add(secret)
        report["cases"].append(case)
        save()
    for suite in (2, 3):
        for role in ("initiator", "responder"):
            for ead in (False, True):
                await append(role, suite, ead)
        for stage in range(1, 5):
            role = "responder" if stage % 2 else "initiator"
            await append(role, suite, True, stage)
            await append(role, suite, True)
    report["sources_after"] = {name: source_identity(Path(identity["path"])) for name, identity in sources.items()}
    require(report["sources_after"] == sources, "sources changed during capture")
    report["result"] = "passed" if not report["failed"] else "failed"
    save()
    print(json.dumps({key: report[key] for key in ("passed", "failed", "result")}))
    return bool(report["failed"])


def main():
    parser = argparse.ArgumentParser()
    for name in ("coaptic", "libedhoc", "core", "companion", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    require(args.timeout > 0, "positive timeout required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
