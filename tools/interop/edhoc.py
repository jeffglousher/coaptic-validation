import argparse
import asyncio
import hashlib
import hmac
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

import blake3


DOMAIN = "https://github.com/jeffglousher/coaptic credential fingerprint v1"
CAPACITY = 192
PUBLIC_KEYS = {
    "initiator": bytes.fromhex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    ),
    "responder": bytes.fromhex(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
    ),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def credential(role):
    kid = 0 if role == "initiator" else 1
    public = PUBLIC_KEYS[role]
    return bytes.fromhex("a108a101a501020241") + bytes([kid]) + bytes.fromhex(
        "2001215820"
    ) + public[:32] + bytes.fromhex("225820") + public[32:]


def binary_field(record, name, length=None):
    require(isinstance(record.get(name), str), f"missing string field {name}")
    value = bytes.fromhex(record[name])
    require(value.hex() == record[name], f"noncanonical hex field {name}")
    if length is not None:
        require(len(value) == length, f"incorrect length for {name}")
    return value


def derive(secret, salt, identifier, label, length):
    require(len(identifier) <= 1 and label in ("Key", "IV"), "unsupported derivation")
    encoded_label = label.encode("ascii")
    info = bytes([0x85, 0x40 + len(identifier)]) + identifier + bytes(
        [0xF6, 10, 0x60 + len(encoded_label)]
    ) + encoded_label + bytes([length])
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


class Peer:
    def __init__(self, executable, implementation, role, timeout, extra_arguments=()):
        self.command = [str(executable), role, *extra_arguments]
        self.implementation = implementation
        self.role = role
        self.timeout = timeout
        self.process = None
        self.stderr_task = None
        self.record = {
            "implementation": implementation,
            "role": role,
            "command": self.command,
            "stdin": [],
            "stdout": [],
            "records": [],
        }

    async def start(self):
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=8192,
            **options,
        )
        self.stderr_task = asyncio.create_task(self.process.stderr.read())

    def capture(self, line):
        text = line.decode("utf-8", errors="strict").rstrip("\r\n")
        self.record["stdout"].append(text)
        value = json.loads(text)
        require(isinstance(value, dict), "peer output is not a JSON object")
        self.record["records"].append(value)
        return value

    async def read(self):
        line = await asyncio.wait_for(self.process.stdout.readline(), self.timeout)
        if not line:
            return None
        return self.capture(line)

    async def send(self, value):
        self.record["stdin"].append(value.hex())
        self.process.stdin.write(value.hex().encode("ascii") + b"\n")
        await asyncio.wait_for(self.process.stdin.drain(), self.timeout)

    async def wait(self):
        await asyncio.wait_for(self.process.wait(), self.timeout)
        while True:
            value = await self.read()
            if value is None:
                break
        self.record["exit_code"] = self.process.returncode
        self.record["stderr"] = (await self.stderr_task).decode("utf-8", errors="replace")

    async def stop(self):
        if self.process is None:
            return
        if self.process.returncode is None:
            self.record["cleanup_killed"] = True
            self.process.kill()
        try:
            await self.wait()
        except BaseException as error:
            self.record["cleanup_error"] = repr(error)


def validate_completion(coaptic, independent, coaptic_role, connection_ids=(0, 1)):
    require(coaptic is not None and coaptic.get("complete") is True, "missing Coaptic completion")
    require(independent is not None, "missing libedhoc exporter result")
    for result in (coaptic, independent):
        require(result.get("method") == 3 and result.get("suite") == 2, "wrong EDHOC profile")
        require(result.get("message4") is True, "message 4 was not confirmed")
    secret = binary_field(independent, "master_secret", 16)
    salt = binary_field(independent, "master_salt", 8)
    independent_role = "responder" if coaptic_role == "initiator" else "initiator"
    peer_credential = binary_field(independent, "peer_credential", 82)
    local_credential = binary_field(independent, "local_credential", 82)
    require(peer_credential == credential(coaptic_role), "libedhoc trusted a different Coaptic pin")
    require(local_credential == credential(independent_role), "libedhoc generated a different identity")
    require(len(connection_ids) == 2 and all(isinstance(value, int) and 0 <= value <= 23 for value in connection_ids)
            and connection_ids[0] != connection_ids[1], "invalid expected connection IDs")
    initiator_id, responder_id = map(lambda value: bytes([value]), connection_ids)
    sender_id = responder_id if coaptic_role == "initiator" else initiator_id
    recipient_id = initiator_id if coaptic_role == "initiator" else responder_id
    require(binary_field(coaptic, "sender_id", 1) == sender_id, "wrong Coaptic sender ID")
    require(binary_field(coaptic, "recipient_id", 1) == recipient_id, "wrong Coaptic recipient ID")
    require(binary_field(independent, "sender_id", 1) == recipient_id, "wrong libedhoc sender ID")
    require(binary_field(independent, "recipient_id", 1) == sender_id, "wrong libedhoc recipient ID")
    for name, identifier, label, length in (
        ("sender_key", sender_id, "Key", 16),
        ("recipient_key", recipient_id, "Key", 16),
        ("common_iv", b"", "IV", 13),
    ):
        expected = derive(secret, salt, identifier, label, length)
        require(hmac.compare_digest(binary_field(coaptic, name, length), expected), f"{name} mismatch")
    principal = blake3.blake3(local_credential, derive_key_context=DOMAIN).digest()
    require(hmac.compare_digest(binary_field(coaptic, "principal", 32), principal), "full principal mismatch")
    return {
        "profile": "EDHOC method 3, suite 2, mandatory message 4, fixed mutual pins, no EAD",
        "coaptic_role": coaptic_role,
        "master_secret": secret.hex(),
        "master_salt": salt.hex(),
        "connection_ids": list(connection_ids),
        "principal": principal.hex(),
        "local_credential": peer_credential.hex(),
        "authenticated_peer_credential": local_credential.hex(),
        "checks": ["message4", "both_full_credentials", "both_connection_ids", "sender_key", "recipient_key", "common_iv", "full_principal"],
    }


def mutate(message, attack, transcript):
    output = bytearray(message)
    if attack == "invalid-gx":
        require(output[:4] == bytes.fromhex("03025820"), "unexpected message 1 encoding")
        output[4:36] = b"\xff" * 32
    elif attack == "invalid-gy":
        require(len(output) >= 34 and output[0] == 0x58, "unexpected message 2 encoding")
        output[2:34] = b"\xff" * 32
    elif attack == "wrong-method":
        require(output[0] == 3, "unexpected message 1 method")
        output[0] = 0
    elif attack == "wrong-suite":
        require(output[:2] == bytes.fromhex("0302"), "unexpected message 1 suite")
        output[1] = 0
    elif attack.startswith("corrupt-"):
        output[-1] ^= 1
    elif attack.startswith("truncated-"):
        output = output[:1]
    elif attack.startswith("trailing-"):
        output.append(0)
    elif attack.startswith("replay-"):
        require(transcript is not None, "missing replay reference")
        output = bytearray.fromhex(transcript[int(attack[-1]) - 1]["hex"])
        require(output != message, "replay reference was not from a different handshake")
    else:
        raise ValueError(f"unknown attack {attack}")
    return bytes(output)


async def case(arguments, coaptic_role, repetition=None, attack=None, number=None, replay=None):
    independent_role = "responder" if coaptic_role == "initiator" else "initiator"
    coaptic = Peer(arguments.coaptic, "coaptic", coaptic_role, arguments.timeout)
    independent = Peer(arguments.libedhoc, "libedhoc", independent_role, arguments.timeout,
                       ("wrong-identity",) if attack == "wrong-identity" else ())
    initiator = coaptic if coaptic_role == "initiator" else independent
    responder = independent if coaptic_role == "initiator" else coaptic
    record = {
        "coaptic_role": coaptic_role,
        "name": attack or "complete-handshake",
        "repetition": repetition,
        "messages": [],
        "processes": [coaptic.record, independent.record],
    }
    started = time.perf_counter_ns()
    try:
        await coaptic.start()
        await independent.start()
        require(await responder.read() == {"ready": True}, "missing responder readiness")
        for step, sender, receiver in (
            (1, initiator, responder), (2, responder, initiator),
            (3, initiator, responder), (4, responder, initiator),
        ):
            output = await sender.read()
            require(output is not None and output.get("message") == step, f"missing message {step}")
            message = binary_field(output, "hex")
            require(0 < len(message) <= CAPACITY, f"invalid length for message {step}")
            record["messages"].append({"message": step, "hex": message.hex(), "length": len(message)})
            if number == step:
                require(receiver is coaptic, "attack did not target Coaptic")
                if attack == "wrong-identity":
                    record["peer_configuration"] = "same expected kid, different static private scalar 3 and public credential"
                else:
                    message = mutate(message, attack, replay)
                    record["mutation"] = {"message": step, "hex": message.hex(), "length": len(message)}
            await receiver.send(message)
            if number == step:
                output = await receiver.read()
                require(output is None or "error" in output, "attacked Coaptic continued processing")
                await receiver.wait()
                require(receiver.process.returncode == 1, "rejection did not have the fixture's error exit")
                require(receiver.record["stderr"], "rejection had no diagnostic")
                require(not any(value.get("complete") or "master_secret" in value for value in receiver.record["records"]), "attacked peer exported a session")
                require("panicked" not in receiver.record["stderr"].lower(), "attacked peer panicked")
                record["rejection"] = {"exit_code": receiver.process.returncode, "stderr": receiver.record["stderr"], "output": output}
                record["status"] = "passed"
                return record
        result = validate_completion(await coaptic.read(), await independent.read(), coaptic_role)
        await coaptic.wait()
        await independent.wait()
        for peer in (coaptic, independent):
            require(peer.process.returncode == 0, f"{peer.implementation} failed after completion")
            require(not peer.record["stderr"], f"{peer.implementation} emitted an unexpected diagnostic")
        record["validated"] = result
        record["status"] = "passed"
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = repr(error)
    finally:
        await coaptic.stop()
        await independent.stop()
        record["wall_ns"] = time.perf_counter_ns() - started
    return record


async def run(arguments):
    report = {
        "schema": "coaptic-edhoc-independent/1",
        "scope": "host EDHOC core interoperability and OSCORE key derivation; no network transport, durable store, device or full release qualification",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version,
        "platform": platform.platform(),
        "blake3_python_version": importlib.metadata.version("blake3"),
        "resource_profile": {"max_message_bytes": CAPACITY, "connection_id_bytes": 1, "credential_bytes": 82},
        "fixtures": {},
        "cases": [],
        "coaptic_build_profile": arguments.coaptic_build_profile,
    }
    for name, path in (("coaptic", arguments.coaptic), ("libedhoc", arguments.libedhoc)):
        report["fixtures"][name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    report["runner_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    build_manifests = sorted((arguments.libedhoc.parent / "evidence").glob("*/manifest.json"), reverse=True)
    for path in build_manifests:
        metadata = json.loads(path.read_text(encoding="utf-8"))
        if metadata.get("result") == "passed" and metadata.get("executable", {}).get("sha256") == report["fixtures"]["libedhoc"]["sha256"]:
            report["libedhoc_build"] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "source_revisions": metadata["source_revisions"], "configuration": metadata["configuration"], "fixture_sha256": metadata["fixture_sha256"]}
            break
    arguments.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        report["passed"] = sum(item["status"] == "passed" for item in report["cases"])
        report["failed"] = sum(item["status"] == "failed" for item in report["cases"])
        report["result"] = "passed" if report["cases"] and not report["failed"] else "failed"
        timing = {
            "definition": "process startup, EDHOC exchange, key and pin validation, process exit and cleanup; elapsed wall time, not CPU utilization or App throughput",
            "roles": {},
        }
        for role in ("initiator", "responder"):
            samples = [item["wall_ns"] for item in report["cases"] if item["name"] == "complete-handshake" and item["coaptic_role"] == role and item["status"] == "passed"]
            if samples:
                timing["roles"][role] = {"all_samples_ns": samples, "mean_ns": statistics.mean(samples), "median_ns": statistics.median(samples), "min_ns": min(samples), "max_ns": max(samples)}
        report["handshake_wall_timing"] = timing
        arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    references = {}
    secrets = set()
    salts = set()
    for repetition in range(1, arguments.repetitions + 1):
        for role in (("initiator", "responder") if repetition % 2 else ("responder", "initiator")):
            record = await case(arguments, role, repetition=repetition)
            report["cases"].append(record)
            if record["status"] == "passed":
                for name, seen in (("master_secret", secrets), ("master_salt", salts)):
                    if record["validated"][name] in seen:
                        record["status"] = "failed"
                        record["error"] = f"fresh handshake repeated {name}"
                    seen.add(record["validated"][name])
                references.setdefault(role, record)
            save()
    attacks = (
        ("responder", "invalid-gx", 1), ("responder", "wrong-method", 1),
        ("responder", "wrong-suite", 1), ("responder", "trailing-m1", 1),
        ("initiator", "invalid-gy", 2), ("initiator", "corrupt-m2", 2),
        ("initiator", "trailing-m2", 2), ("responder", "corrupt-m3", 3),
        ("responder", "truncated-m3", 3), ("responder", "trailing-m3", 3),
        ("initiator", "corrupt-m4", 4), ("initiator", "truncated-m4", 4),
        ("initiator", "trailing-m4", 4), ("initiator", "replay-m2", 2),
        ("responder", "replay-m3", 3), ("initiator", "replay-m4", 4),
        ("initiator", "wrong-identity", 2), ("responder", "wrong-identity", 3),
    )
    for role, attack, number in attacks:
        replay = references.get(role, {}).get("messages")
        report["cases"].append(await case(arguments, role, attack=attack, number=number, replay=replay))
        save()
    print(json.dumps({"passed": report["passed"], "failed": report["failed"], "output": str(arguments.output)}))
    return 1 if report["failed"] else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--libedhoc", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--coaptic-build-profile", default="unspecified", help="record the Coaptic fixture build profile for interpreting process-inclusive timings")
    arguments = parser.parse_args()
    require(arguments.repetitions >= 2 and arguments.timeout > 0, "expected at least two repetitions and a positive timeout")
    arguments.coaptic = arguments.coaptic.resolve(strict=True)
    arguments.libedhoc = arguments.libedhoc.resolve(strict=True)
    return asyncio.run(run(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
