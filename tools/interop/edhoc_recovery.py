import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path
import secrets
import sys
import time
import traceback

import aiocoap
from aiocoap.message import Direction

from edhoc import Peer, binary_field, require, validate_completion
from edhoc_udp import (
    Fixture, Wire, VolatileContext, bootstrap_request, bootstrap_response,
    endpoint_parse, endpoint_text, independent_message, incoming_application,
    metadata, outgoing_application, plain_request, protect,
    validate_bootstrap_request, validate_bootstrap_response,
)


async def command(fixture, value):
    fixture.record["stdin"].append(value)
    fixture.process.stdin.write((value + "\n").encode("ascii"))
    await fixture.process.stdin.drain()


def operation(state):
    while True:
        mid = secrets.randbelow(48000)
        if mid not in state["mids"] and mid + 1 not in state["mids"]:
            state["mids"].update((mid, mid + 1))
            return mid, secrets.token_bytes(8)


async def cached_control(arguments, wire, fixture, remote, previous, phase):
    if "cached_m3" in previous:
        await wire.send(bytes.fromhex(previous["cached_m3"]), remote, "old-exact-M3-during-candidate")
        packet, _ = await wire.receive(remote, "old-cached-M4-during-candidate", arguments.timeout)
        require(packet.hex() == previous["cached_m4"], "candidate replaced old completion reply")
        collision = aiocoap.Message.decode(bytes.fromhex(previous["cached_m3"]))
    else:
        collision = aiocoap.Message.decode(bytes.fromhex(previous["cached_m4"]))
        await wire.send(bytes.fromhex(previous["cached_m4"]), remote, "old-exact-M4-during-candidate")
        await wire.quiet(remote, "old-piggyback-M4-needs-no-ACK")
    collision.direction = Direction.OUTGOING
    collision.token = b"changed"
    collision.payload = collision.payload[:-1] + bytes([collision.payload[-1] ^ 1])
    await wire.send(collision, remote, "old-MID-with-changed-token-and-body")
    await wire.quiet(remote, "completion-MID-collision-refusal")
    phase.setdefault("checks", []).extend(("exact_old_completion_cache", "changed_old_MID_does_not_consume_candidate"))


async def handshake(arguments, wire, fixture, role, ids, generation, phase, state,
                    previous=None, old_context=None, old_count=None, lost_m4=False):
    independent_role = "responder" if role == "initiator" else "initiator"
    independent = Peer(arguments.libedhoc, "libedhoc", independent_role, arguments.timeout,
                       ("--cid", str(ids[1] if independent_role == "responder" else ids[0])))
    phase["processes"] = [independent.record]
    messages = []
    ready = await fixture.event(lambda value: value.get("ready") is True)
    remote = endpoint_parse(ready["local"])
    phase["coaptic_endpoint"] = endpoint_text(remote)
    try:
        await independent.start()
        if role == "initiator":
            require(await independent.read() == {"ready": True}, "independent responder not ready")
            if generation > 1:
                await command(fixture, "recover")
                await fixture.event(lambda value: value.get("recover_started") is True)
            for number in (1, 3):
                request_packet, request = await wire.receive(remote, f"generation-{generation}-M{number}", arguments.timeout)
                bare = validate_bootstrap_request(request, number, *ids)
                await independent.send(bare)
                response_bare = await independent_message(independent, number + 1)
                response = bootstrap_response(response_bare, request)
                messages.extend(({"message": number, "hex": bare.hex()}, {"message": number + 1, "hex": response_bare.hex()}))
                if number == 1 and previous:
                    await cached_control(arguments, wire, fixture, remote, previous, phase)
                    await incoming_application(arguments, wire, fixture, old_context, remote, previous, 57000 + old_count, old_count)
                if number == 3 and lost_m4:
                    phase["dropped_M4"] = response.encode().hex()
                    retry, _ = await wire.receive(remote, "candidate-M3-exact-retry-after-lost-M4", arguments.timeout)
                    require(retry == request_packet, "candidate retransmission changed message 3")
                if number == 1:
                    await wire.send(response, remote, "wrong-endpoint-candidate-M2", wrong_endpoint=True)
                await wire.send(response, remote, f"generation-{generation}-M{number + 1}")
                if number == 3:
                    phase["cached_m4"] = response.encode().hex()
        else:
            mid, token = operation(state)
            for number in (1, 3):
                bare = await independent_message(independent, number)
                request = bootstrap_request(bare, number, mid + (number == 3), token, ids[1])
                validate_bootstrap_request(request, number, *ids)
                if number == 1:
                    await wire.send(request, remote, "wrong-endpoint-candidate-M1", wrong_endpoint=True)
                request_packet = await wire.send(request, remote, f"generation-{generation}-M{number}")
                response_packet, response = await wire.receive(remote, f"generation-{generation}-M{number + 1}", arguments.timeout)
                response_bare = validate_bootstrap_response(response, request)
                messages.extend(({"message": number, "hex": bare.hex()}, {"message": number + 1, "hex": response_bare.hex()}))
                if number == 1 and previous:
                    await cached_control(arguments, wire, fixture, remote, previous, phase)
                    await incoming_application(arguments, wire, fixture, old_context, remote, previous, 57000 + old_count, old_count)
                if number == 3 and lost_m4:
                    phase["dropped_M4"] = response_packet.hex()
                    await asyncio.sleep(2.05)
                    await wire.send(request_packet, remote, "candidate-exact-M3-after-lost-M4")
                    retry, retry_response = await wire.receive(remote, "candidate-cached-M4-after-handoff", arguments.timeout)
                    require(retry == response_packet, "new completion cache changed message 4")
                    validate_bootstrap_response(retry_response, request)
                await independent.send(response_bare)
                if number == 3:
                    phase["cached_m3"], phase["cached_m4"] = request_packet.hex(), response_packet.hex()
        completion = await independent.read()
        coaptic = await fixture.event(lambda value: value.get("complete") is True and value.get("generation") == generation)
        phase["validated"] = validate_completion(coaptic, completion, role, ids)
        phase["coaptic_completion"] = coaptic
        phase["messages"] = messages
        await independent.wait()
        require(independent.process.returncode == 0 and not independent.record["stderr"], "independent handshake did not exit cleanly")
        context = VolatileContext(completion)
        require(context.recipient_key.hex() == coaptic["sender_key"] and context.sender_key.hex() == coaptic["recipient_key"]
                and context.common_iv.hex() == coaptic["common_iv"], "aiocoap derived different fresh keys")
        if role == "initiator":
            await outgoing_application(arguments, wire, fixture, context, remote, phase, generation)
        return remote, context
    finally:
        await independent.stop()


async def wrong_pin(arguments, wire, fixture, role, previous, context, state, phase):
    ids = (1, 3) if role == "initiator" else (0, 2)
    independent_role = "responder" if role == "initiator" else "initiator"
    independent = Peer(arguments.libedhoc, "libedhoc", independent_role, arguments.timeout,
                       ("wrong-identity", "--cid", str(ids[1] if role == "initiator" else ids[0])))
    phase["processes"] = [independent.record]
    remote = endpoint_parse(previous["coaptic_endpoint"])
    try:
        await independent.start()
        if role == "initiator":
            require(await independent.read() == {"ready": True}, "wrong-pin responder not ready")
            await command(fixture, "recover")
            _, request = await wire.receive(remote, "wrong-pin-candidate-M1", arguments.timeout)
            await independent.send(validate_bootstrap_request(request, 1, *ids))
            response = bootstrap_response(await independent_message(independent, 2), request)
            await wire.send(response, remote, "wrong-pin-candidate-M2")
        else:
            mid, token = operation(state)
            request = bootstrap_request(await independent_message(independent, 1), 1, mid, token)
            await wire.send(request, remote, "wrong-pin-candidate-M1")
            _, response = await wire.receive(remote, "wrong-pin-candidate-M2", arguments.timeout)
            await independent.send(validate_bootstrap_response(response, request))
            request = bootstrap_request(await independent_message(independent, 3), 3, mid + 1, token, ids[1])
            await wire.send(request, remote, "wrong-pin-candidate-M3")
        failed = await fixture.event(lambda value: value.get("candidate_failed") is True)
        require(failed.get("sessions") == 1 and "Authentication" in failed.get("error", ""), "wrong pin did not fail authentication before handoff")
        phase["failure"] = failed
        await wire.quiet(remote, "wrong-pin-refusal")
        await incoming_application(arguments, wire, fixture, context, remote, previous, 57002, 2)
        await cached_control(arguments, wire, fixture, remote, previous, phase)
        phase["checks"] = phase.get("checks", []) + ["wrong_pin_preserves_live_App_and_replay_state"]
    finally:
        await independent.stop()


async def old_ciphertext_control(wire, context, remote, old_packet, phase):
    old = aiocoap.Message.decode(old_packet)
    old.direction = Direction.OUTGOING
    old.mtype, old.mid, old.token = aiocoap.NON, 58000, b"old-key"
    await wire.send(old, remote, "old-context-ciphertext-after-handoff")
    await wire.quiet(remote, "old-context-refusal")
    require(old.opt.oscore[0] & 8 and len(context.sender_id) == 1, "missing old OSCORE kid")
    old.opt.oscore = old.opt.oscore[:-1] + context.sender_id
    old.mid, old.token = 58001, b"old-route"
    await wire.send(old, remote, "old-ciphertext-routed-to-new-CID")
    await wire.quiet(remote, "old-key-authentication-refusal")
    phase.setdefault("checks", []).extend(("old_context_refused", "old_ciphertext_refused_at_new_recipient_ID"))


async def scenario(arguments, role, repetition=None, fault=None):
    record = {"name": "one-sided-independent-peer-restart", "coaptic_role": role,
              "repetition": repetition, "fault": fault, "phases": [], "datagrams": []}
    wire = Wire(record)
    fixture = Fixture(arguments.coaptic, role, ("127.0.0.1", 0), wire.local, arguments.timeout)
    record["coaptic_process"] = fixture.record
    state = {"mids": set()}
    started = time.perf_counter_ns()
    try:
        await fixture.start()
        first = {"generation": 1}
        record["phases"].append(first)
        remote, old_context = await handshake(arguments, wire, fixture, role, (0, 1), 1, first, state)
        old_packet = await incoming_application(arguments, wire, fixture, old_context, remote, first, 57001, 1)
        if fault == "wrong-pin":
            failed = {"wrong_pin": True}
            record["phases"].append(failed)
            await wrong_pin(arguments, wire, fixture, role, first, old_context, state, failed)
            ids, old_count, final_count = ((2, 3) if role == "initiator" else (0, 3)), 3, 4
        else:
            ids, old_count, final_count = ((1, 3) if role == "initiator" else (0, 2)), 2, 3
        second = {"generation": 2}
        record["phases"].append(second)
        remote, fresh_context = await handshake(arguments, wire, fixture, role, ids, 2, second, state,
                                               first, old_context, old_count, fault == "lost-M4")
        require(first["validated"]["master_secret"] != second["validated"]["master_secret"]
                and first["validated"]["master_salt"] != second["validated"]["master_salt"], "recovery reused exporters")
        require(first["coaptic_completion"]["recipient_id"] != second["coaptic_completion"]["recipient_id"], "surviving peer reused its live recipient ID")
        await old_ciphertext_control(wire, fresh_context, remote, old_packet, second)
        await cached_control(arguments, wire, fixture, remote, first, second)
        await incoming_application(arguments, wire, fixture, fresh_context, remote, second, 57000 + final_count, final_count)
        plaintext = plain_request(58002, b"plain")
        plaintext.mtype = aiocoap.NON
        await wire.send(plaintext, remote, "plaintext-after-recovery")
        await wire.quiet(remote, "plaintext-refusal-after-recovery")
        replay = aiocoap.Message.decode(old_packet)
        replay.direction = Direction.OUTGOING
        replay.mtype, replay.mid, replay.token = aiocoap.NON, 58003, b"replay"
        await wire.send(replay, remote, "old-replay-after-recovery")
        await wire.quiet(remote, "old-replay-refusal")
        await command(fixture, "stats")
        stats = await fixture.event(lambda value: value.get("stats") is True and value.get("sessions") == 2)
        require(stats.get("handled") == final_count and stats.get("responses") == (2 if role == "initiator" else 0), "negative controls changed admission counts")
        record["stats"] = stats
        record["coaptic_pid_survived"] = fixture.process.pid
        record["status"] = "passed"
    except BaseException as error:
        record["status"], record["error"], record["traceback"] = "failed", repr(error), traceback.format_exc()
    finally:
        await fixture.stop()
        wire.close()
    if record.get("status") == "passed" and (fixture.record.get("exit_code") != 0 or fixture.record.get("stderr")):
        record["status"], record["error"] = "failed", "surviving Coaptic process did not exit cleanly"
    record["wall_ns"] = time.perf_counter_ns() - started
    return record


async def restarted_scenario(arguments, role):
    record = {"name": "one-sided-Coaptic-process-restart", "coaptic_role": role,
              "phases": [], "datagrams": [], "coaptic_processes": []}
    wire = Wire(record)
    state = {"mids": set()}
    fixture = None
    started = time.perf_counter_ns()
    try:
        fixture = Fixture(arguments.coaptic, role, ("127.0.0.1", 0), wire.local, arguments.timeout)
        record["coaptic_processes"].append(fixture.record)
        await fixture.start()
        first = {"generation": 1}
        record["phases"].append(first)
        remote, context = await handshake(arguments, wire, fixture, role, (0, 1), 1, first, state)
        old_packet = await incoming_application(arguments, wire, fixture, context, remote, first, 57100, 1)
        old_pid = fixture.process.pid
        await fixture.stop()
        require(fixture.record.get("exit_code") == 0 and not fixture.record.get("stderr"), "old Coaptic process did not stop cleanly")
        fixture = Fixture(arguments.coaptic, role, remote, wire.local, arguments.timeout)
        record["coaptic_processes"].append(fixture.record)
        await fixture.start()
        second = {"generation": 1}
        record["phases"].append(second)
        ids = (0, 2) if role == "initiator" else (2, 0)
        restarted_remote, fresh = await handshake(arguments, wire, fixture, role, ids, 1, second, state)
        require(restarted_remote == remote and fixture.process.pid != old_pid, "Coaptic did not restart at the same endpoint")
        require(first["validated"]["master_secret"] != second["validated"]["master_secret"]
                and first["validated"]["master_salt"] != second["validated"]["master_salt"], "one-sided process restart reused exporters")
        require(first["coaptic_completion"]["sender_id"] != second["coaptic_completion"]["sender_id"], "surviving independent peer reused its live recipient ID")
        await incoming_application(arguments, wire, fixture, fresh, remote, second, 57101, 1)
        await old_ciphertext_control(wire, fresh, remote, old_packet, second)
        stale = first.get("cached_m3", first["cached_m4"])
        await wire.send(bytes.fromhex(stale), remote, "stale-completion-after-one-sided-process-restart")
        await wire.quiet(remote, "stale-completion-cannot-replace-fresh-App")
        await incoming_application(arguments, wire, fixture, fresh, remote, second, 57102, 2)
        await command(fixture, "stats")
        stats = await fixture.event(lambda value: value.get("stats") is True and value.get("handled") == 2)
        require(stats.get("sessions") == 1 and stats.get("responses") == (1 if role == "initiator" else 0), "restart controls changed admission counts")
        record["stats"] = stats
        record["pids"] = [old_pid, fixture.process.pid]
        record["status"] = "passed"
    except BaseException as error:
        record["status"], record["error"], record["traceback"] = "failed", repr(error), traceback.format_exc()
    finally:
        if fixture is not None:
            await fixture.stop()
        wire.close()
    if record.get("status") == "passed" and any(process.get("exit_code") != 0 or process.get("stderr") for process in record["coaptic_processes"]):
        record["status"], record["error"] = "failed", "Coaptic process restart cleanup failed"
    record["wall_ns"] = time.perf_counter_ns() - started
    return record


async def run(arguments):
    report = {"schema": "coaptic-independent-edhoc-recovery/1", "scope": "real IPv4 UDP; surviving Coaptic process and old secured App; independent libedhoc fresh peer sessions and aiocoap OSCORE; public test identities; explicit caller liveness trigger; no production monotonic storage, device or throughput qualification",
              "python": sys.version, "python_executable": sys.executable, "python_search_path": sys.path,
              "platform": platform.platform(), "cases": [],
              "versions": {name: importlib.metadata.version(name) for name in ("aiocoap", "blake3")},
              "binaries": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in (("coaptic", arguments.coaptic), ("libedhoc", arguments.libedhoc))},
              "resource_profile": {"packet_bytes": 1280, "bootstrap_bytes": 384, "completion_or_retired_slots": 4, "compact_connection_ids": 24, "local_mid_slots": 16, "nstart": 1, "app": "profiles::Constrained, block_wise=false"}}
    def save():
        report["passed"] = sum(case["status"] == "passed" for case in report["cases"])
        report["failed"] = sum(case["status"] == "failed" for case in report["cases"])
        report["result"] = "passed" if report["cases"] and not report["failed"] else "failed"
        arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for repetition in range(arguments.repetitions):
        roles = ("initiator", "responder") if repetition % 2 == 0 else ("responder", "initiator")
        for role in roles:
            report["cases"].append(await scenario(arguments, role, repetition))
            save()
    for role in ("initiator", "responder"):
        for fault in ("lost-M4", "wrong-pin"):
            report["cases"].append(await scenario(arguments, role, fault=fault))
            save()
        report["cases"].append(await restarted_scenario(arguments, role))
        save()
    print(json.dumps({"result": report["result"], "passed": report["passed"], "failed": report["failed"], "output": str(arguments.output)}))
    return 0 if report["result"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description="Qualify bounded one-sided EDHOC recovery against independent libedhoc and aiocoap over real UDP.")
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--libedhoc", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", default=5, type=int)
    parser.add_argument("--timeout", default=10, type=float)
    arguments = parser.parse_args()
    require(arguments.repetitions >= 1 and arguments.timeout > 0, "positive repetitions and timeout required")
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    return asyncio.run(run(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
