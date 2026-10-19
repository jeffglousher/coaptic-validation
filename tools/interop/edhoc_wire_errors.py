"""Independent RFC 9528 error codecs across the existing sequential UDP bridge."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path

import aiocoap
from edhoc import Peer, binary_field, require
from edhoc_profiles import source_identity, native_build_identity
from edhoc_udp import (Fixture, Wire, bootstrap_request, bootstrap_response,
                       endpoint_parse, independent_message, options,
                       validate_bootstrap_request, validate_bootstrap_response,
                       case as recovery_case)


async def codec(args, code, payload=None):
    peer = Peer(args.libedhoc, "libedhoc-error-codec", "error-compose" if payload is None else "error-process", args.timeout, [str(code)])
    try:
        await peer.start()
        if payload is not None:
            await peer.send(payload)
        value = await peer.read()
        require(value is not None, "missing independent error codec output")
        if payload is None:
            require(value.get("message") == 0, "wrong codec output")
            result = binary_field(value, "hex")
        else:
            require(value.get("error_received") == code, "independent parser disagrees with error code")
            result = value
        await peer.wait()
        require(peer.process.returncode == 0 and not peer.record["stderr"], "independent error codec failed")
        return result, peer.record
    finally:
        await peer.stop()


async def error_case(args, code, direction):
    role = "initiator" if direction == "to-coaptic" else "responder"
    record = {"code": code, "direction": direction, "datagrams": []}
    wire = Wire(record)
    fixture = Fixture(args.coaptic, role, ("127.0.0.1", 0), wire.local, args.timeout)
    native = Peer(args.libedhoc, "libedhoc", "responder" if role == "initiator" else "initiator", args.timeout,
                  ["--unknown-kid"] if direction == "from-coaptic" and code == 3 else [])
    record["processes"] = [fixture.record, native.record]
    try:
        await fixture.start()
        await native.start()
        ready = await fixture.event(lambda value: value.get("ready") is True)
        remote = endpoint_parse(ready["local"])
        if direction == "to-coaptic":
            require(await native.read() == {"ready": True}, "missing native responder readiness")
            _, request = await wire.receive(remote, "message-1", args.timeout)
            first = validate_bootstrap_request(request, 1)
            if code == 3:
                await native.send(first)
                await wire.send(bootstrap_response(await independent_message(native, 2), request), remote, "message-2")
                _, request = await wire.receive(remote, "message-3", args.timeout)
                validate_bootstrap_request(request, 3)
            payload, encoded = await codec(args, code)
            record["error_codec"] = encoded
            response = bootstrap_response(payload, request)
            response.code = aiocoap.BAD_REQUEST
            await wire.send(response, remote, "independently-encoded-error")
            receipt = await fixture.event(lambda value: "peer_error" in value)
            require(receipt["peer_error"] == code, "wrong retained peer error")
            require(receipt["diagnostic_hex"] == (b"independent refusal".hex() if code == 1 else ""), "wrong diagnostic")
            require(receipt["suites"] == ([2, 3] if code == 2 else []), "wrong advisory suites")
            record["receipt"] = receipt
        else:
            first = bytearray(await independent_message(native, 1))
            if code == 1:
                first[0] = 0  # Unsupported method; syntactically valid CBOR.
            elif code == 2:
                first[1] = 0  # Unsupported selected suite; no suite fallback.
            request = bootstrap_request(bytes(first), 1, 41000, b"errors")
            await wire.send(request, remote, "message-1")
            _, response = await wire.receive(remote, "message-2-or-error", args.timeout)
            if code == 3:
                await native.send(validate_bootstrap_response(response, request))
                request = bootstrap_request(await independent_message(native, 3), 3, 41001, b"errors")
                await wire.send(request, remote, "unknown-kid-message-3")
                _, response = await wire.receive(remote, "unknown-kid-error", args.timeout)
            require(response.mtype == aiocoap.ACK and (int(response.code) >> 5) == 4, "wrong error response envelope")
            require((response.mid, response.token) == (request.mid, request.token), "error operation mismatch")
            require(options(response) == [(12, b"@")], "wrong error content format")
            _, decoded = await codec(args, code, response.payload)
            record["error_codec"] = decoded
        await asyncio.wait_for(fixture.process.wait(), args.timeout)
        await fixture.stop()
        require(fixture.record["exit_code"] == 1 and "panicked" not in fixture.record["stderr"].lower(), "unclean error termination")
        require(not any(value.get("complete") or value.get("handled") or value.get("response") for value in fixture.record["records"]), "error admitted a session or application")
        record["status"] = "passed"
    except Exception as error:
        record["status"], record["error"] = "failed", repr(error)
    finally:
        await fixture.stop()
        await native.stop()
        wire.close()
    return record


async def run(args):
    sources = {name: source_identity(path) for name, path in (("core", args.core), ("companion", args.companion))}
    report = {"schema": "coaptic-edhoc-wire-errors/1", "sources": sources, "native_build": native_build_identity(args), "cases": [],
              "scope": "Independent error compose/parse plus actual sequential UDP error handling; errors remain unauthenticated; recovery explicitly restarts both peers",
              "fixtures": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                           for name, path in (("coaptic", args.coaptic), ("libedhoc", args.libedhoc))}}
    def save():
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for direction in ("to-coaptic", "from-coaptic"):
        for code in (1, 2, 3):
            report["cases"].append(await error_case(args, code, direction))
            save()
            role = "initiator" if direction == "to-coaptic" else "responder"
            report["cases"].append(await recovery_case(args, role))
            save()
    require(sources == {name: source_identity(Path(value["path"])) for name, value in sources.items()}, "sources changed during capture")
    report["passed"] = sum(case["status"] == "passed" for case in report["cases"])
    report["failed"] = len(report["cases"]) - report["passed"]
    save()
    print(json.dumps({key: report[key] for key in ("passed", "failed")}))
    return bool(report["failed"])


def main():
    parser = argparse.ArgumentParser()
    for name in ("coaptic", "libedhoc", "core", "companion", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    require(args.timeout > 0, "positive timeout required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
