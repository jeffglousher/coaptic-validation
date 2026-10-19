"""Finite CoAP option boundary with independent native libedhoc cryptography."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path

import aiocoap
from aiocoap.optiontypes import OpaqueOption

from edhoc import Peer, require, validate_completion
from edhoc_profiles import source_identity, native_build_identity
from edhoc_recovery import command
from edhoc_udp import (
    Fixture, Wire, VolatileContext, bootstrap_request, bootstrap_response,
    endpoint_parse, independent_message, incoming_application,
    outgoing_application, options, validate_bootstrap_request,
    validate_bootstrap_response,
)


def extra(message, critical=False, changed=False):
    # Zero is reserved: deliberate receiver robustness, not compliant sending.
    for number, value in ((0, b""), (10, b"before"), (12, b"\x7f"), (14, b""), (14, b"\x01"),
                          (2048, b"changed" if changed else b"after")):
        message.opt.add_option(OpaqueOption(number, value))
    if critical:
        message.opt.add_option(OpaqueOption(99, b"unsupported"))
    return message


async def silence(wire, remote, label):
    try:
        await wire.receive(remote, label, 0.15)
    except TimeoutError:
        return
    raise ValueError(f"{label}: unexpected datagram")


def control(message, kind, mid):
    require((message.mtype, message.code, message.mid, message.token,
             options(message), message.payload) ==
            (kind, aiocoap.EMPTY, mid, b"", [], b""),
            "control differs from exact empty ACK/RST")


async def fresh_stats(fixture):
    offset = len(fixture.record["records"])
    await command(fixture, "stats")
    async def wait():
        while True:
            fixture.changed.clear()
            for value in fixture.record["records"][offset:]:
                if value.get("stats") is True:
                    return value
            require(not fixture.reader.done(), "fixture exited before fresh stats")
            await fixture.changed.wait()
    return await asyncio.wait_for(wait(), fixture.timeout)


async def initial_refusal(args, wire, fixture, remote, first, record):
    before = await fresh_stats(fixture)
    request = extra(bootstrap_request(first, 1, 40000, b"critical"), critical=True)
    packet = await wire.send(request, remote, "critical-initial-M1")
    response_packet, response = await wire.receive(remote, "exact-4.02", args.timeout)
    require((response.mtype, response.code, response.mid, response.token,
             options(response), response.payload) ==
            (aiocoap.ACK, aiocoap.BAD_OPTION, request.mid, request.token, [], b""),
            "initial refusal differs from exact 4.02")
    after = await fresh_stats(fixture)
    require(before["candidate"] is False and after["candidate"] is False,
            "critical initial request allocated a candidate")
    require(before["sessions"] == after["sessions"] == 0 and
            before["owners"] == after["owners"], "initial refusal changed session count or installed grant ownership")
    await wire.send(packet, remote, "exact-refused-request-replay")
    replay, _ = await wire.receive(remote, "exact-refusal-replay", args.timeout)
    require(replay == response_packet, "refusal replay changed wire bytes")
    record["initial_stats"] = {"before": before, "after": after}


async def case(args, group, kind=aiocoap.ACK, critical_stage=None):
    role = "responder" if group in ("elective-request", "critical-initial") else "initiator"
    recovery = group == "critical-initial"
    record = {"group": group, "response_type": int(kind), "critical_stage": critical_stage, "coaptic_role": role, "datagrams": []}
    wire = Wire(record)
    fixture = Fixture(args.recovery if recovery else args.coaptic, role,
                      ("127.0.0.1", 0), wire.local, args.timeout)
    peer = Peer(args.libedhoc, "libedhoc", "initiator" if role == "responder" else "responder", args.timeout)
    record["processes"] = [fixture.record, peer.record]
    try:
        await fixture.start()
        await peer.start()
        ready = await fixture.event(lambda value: value.get("ready") is True)
        remote = endpoint_parse(ready["local"])
        if role == "initiator":
            require(await peer.read() == {"ready": True}, "native responder not ready")
        for number in (1, 3):
            if role == "responder":
                bare = await independent_message(peer, number)
                if recovery and number == 1:
                    await initial_refusal(args, wire, fixture, remote, bare, record)
                request = extra(bootstrap_request(bare, number, 41000 + number, b"options"))
                packet = await wire.send(request, remote, f"elective-M{number}")
                response_packet, response = await wire.receive(remote, f"M{number + 1}", args.timeout)
                bare_response = validate_bootstrap_response(response, request)
                if group == "elective-request":
                    changed = extra(bootstrap_request(bare, number, request.mid, request.token), changed=True)
                    await wire.send(changed, remote, "changed-ignored-option-same-MID")
                    await silence(wire, remote, "changed-option-must-not-replace-owner")
                    await wire.send(packet, remote, "exact-original-request-replay")
                    replay, _ = await wire.receive(remote, "exact-original-response", args.timeout)
                    require(replay == response_packet, "exact replay changed response bytes")
                await peer.send(bare_response)
            else:
                _, request = await wire.receive(remote, f"M{number}", args.timeout)
                await peer.send(validate_bootstrap_request(request, number))
                bare = await independent_message(peer, number + 1)
                response = bootstrap_response(bare, request)
                response.mtype = kind
                if kind != aiocoap.ACK:
                    response.mid = 42000 + number
                if group == "critical-response" and number + 1 == critical_stage:
                    bad = extra(bootstrap_response(bare, request), critical=True)
                    bad.mtype, bad.mid = kind, response.mid
                    await wire.send(bad, remote, f"critical-M{number + 1}")
                    if kind == aiocoap.CON:
                        _, rst = await wire.receive(remote, "critical-separate-exact-RST", args.timeout)
                        control(rst, aiocoap.RST, bad.mid)
                        # Refused MID remains owned; valid recovery uses a new MID.
                        response.mid += 100
                    else:
                        await silence(wire, remote, "critical-ACK-or-NON-ignored")
                await wire.send(extra(response), remote, f"valid-elective-M{number + 1}")
                if kind == aiocoap.CON:
                    _, ack = await wire.receive(remote, "separate-response-exact-ACK", args.timeout)
                    control(ack, aiocoap.ACK, response.mid)
        native = await peer.read()
        completed = await fixture.event(lambda value: value.get("complete") is True and "sender_key" in value)
        record["validated"] = validate_completion(completed, native, role)
        await peer.wait()
        require(peer.process.returncode == 0 and not peer.record["stderr"], "native peer failed")
        context = VolatileContext(native)
        require(context.recipient_key.hex() == completed["sender_key"] and
                context.sender_key.hex() == completed["recipient_key"] and
                context.common_iv.hex() == completed["common_iv"], "independent OSCORE keys differ")
        if role == "initiator":
            await outgoing_application(args, wire, fixture, context, remote, record)
        await incoming_application(args, wire, fixture, context, remote, record, 59000, 1)
        if recovery:
            record["final_stats"] = await fresh_stats(fixture)
            require(record["final_stats"]["sessions"] == 1 and
                    record["final_stats"]["candidate"] is False,
                    "fresh recovery did not complete exactly one session")
        record["status"] = "passed"
    except Exception as error:
        record["status"], record["error"] = "failed", repr(error)
    finally:
        await fixture.stop()
        await peer.stop()
        wire.close()
    if record["status"] == "passed":
        if fixture.record.get("exit_code") != 0 or fixture.record.get("stderr"):
            record["status"], record["error"] = "failed", "unclean Coaptic fixture termination"
    return record


async def run(args):
    sources = {name: source_identity(path) for name, path in (("core", args.core), ("companion", args.companion))}
    report = {"schema": "coaptic-edhoc-options/1", "sources": sources,
              "native_build": native_build_identity(args), "cases": [],
              "scope": "Independent native libedhoc cryptography with custom aiocoap CoAP envelope; finite option handling, not a complete independent CoAP stack or sustained fairness proof",
              "fixtures": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                           for name, path in (("coaptic", args.coaptic), ("recovery", args.recovery), ("libedhoc", args.libedhoc))}}
    def save():
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    inventory = [("elective-request", aiocoap.ACK, None), ("critical-initial", aiocoap.ACK, None)]
    inventory += [("elective-response", kind, None) for kind in (aiocoap.ACK, aiocoap.CON, aiocoap.NON)]
    # One retained refusal slot per owner: independent M2/M4 refusal cases.
    inventory += [("critical-response", kind, stage) for stage in (2, 4)
                  for kind in (aiocoap.ACK, aiocoap.CON, aiocoap.NON)]
    for group, kind, stage in inventory:
        report["cases"].append(await case(args, group, kind, stage))
        save()
    require(sources == {name: source_identity(Path(value["path"])) for name, value in sources.items()},
            "sources changed during capture")
    report["passed"] = sum(value["status"] == "passed" for value in report["cases"])
    report["failed"] = len(inventory) - report["passed"]
    save()
    print(json.dumps({key: report[key] for key in ("passed", "failed")}))
    return bool(report["failed"])


def main():
    parser = argparse.ArgumentParser()
    for name in ("coaptic", "recovery", "libedhoc", "core", "companion", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    require(args.timeout > 0, "positive timeout required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
