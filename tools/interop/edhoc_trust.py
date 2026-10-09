import argparse
import asyncio
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys
import time
import traceback

import aiocoap

from edhoc import Peer, require
from edhoc_recovery import command, handshake, operation
from edhoc_udp import (
    Fixture, Wire, REQUEST, RESPONSE, bootstrap_request, bootstrap_response,
    independent_message, incoming_application, metadata, options, plain_request,
    protect, validate_application, validate_bootstrap_request,
    validate_bootstrap_response,
)


async def no_packet(wire, remote, label, timeout=0.15):
    try:
        await wire.receive(remote, label, timeout)
    except TimeoutError:
        return
    raise ValueError(f"invalidated owner emitted a datagram: {label}")


async def disabled_controls(arguments, wire, fixture, context, remote, previous,
                            phase, generation, handled, responses, pending=None,
                            late_candidate=None):
    if "cached_m3" in previous:
        await wire.send(bytes.fromhex(previous["cached_m3"]), remote, "revoked-exact-cached-M3")
    else:
        await wire.send(bytes.fromhex(previous["cached_m4"]), remote, "revoked-old-M4")
    await no_packet(wire, remote, "revoked-completion-cache-silent")
    request = plain_request(59000 + generation, b"revoked")
    request.mtype = aiocoap.NON
    protected, _ = protect(context, request)
    await wire.send(protected, remote, "revoked-fresh-valid-protected-request")
    await no_packet(wire, remote, "revoked-App-silent")
    if pending is not None:
        message, request_id = pending
        response = aiocoap.Message(code=aiocoap.CHANGED, payload=RESPONSE)
        response.mtype, response.mid, response.token = aiocoap.ACK, message.mid, message.token
        response.opt.content_format = 42
        encrypted, _ = protect(context, response, request_id)
        await wire.send(encrypted, remote, "revoked-valid-pending-response")
    if late_candidate is not None:
        await wire.send(late_candidate, remote, "revoked-valid-late-handshake-message")
    await no_packet(wire, remote, "revoked-CON-retry-and-handshake-silent", 3.15)
    await command(fixture, "stats")
    stats = await fixture.event(lambda event: event.get("stats") is True
                                and event.get("trust_generation") == generation)
    require(stats.get("handled") == handled and stats.get("responses") == responses
            and stats.get("owners") is False and stats.get("candidate") is False,
            "revoked traffic changed admission counts or retained owners")
    phase["disabled_stats"] = stats
    phase["checks"] = ["all_datagrams_stopped", "completion_cache_discarded",
                       "fresh_authenticated_App_request_refused", "full_CON_retry_deadline_silent",
                       "handler_and_response_counts_unchanged"]


async def pending_probe(arguments, wire, fixture, context, remote, phase):
    await command(fixture, "probe")
    _, message = await wire.receive(remote, "pending-Coaptic-CON-before-revoke", arguments.timeout)
    require(message.mtype == aiocoap.CON and message.code == aiocoap.POST
            and options(message) == [(9, message.opt.oscore)], "invalid pending protected request")
    unprotected, request_id = context.unprotect(message)
    validate_application(unprotected)
    require(unprotected.payload == REQUEST, "pending request payload changed")
    phase["pending_request"] = metadata(unprotected)
    await command(fixture, "recover")
    phase["nstart_guard"] = await fixture.event(lambda event: event.get("recover_blocked") is True)
    require(phase["nstart_guard"].get("reason") == "outgoing-CON", "recovery violated NSTART=1")
    return message, request_id


async def pending_candidate(arguments, wire, fixture, role, remote, state, phase):
    independent_role = "responder" if role == "initiator" else "initiator"
    independent = Peer(arguments.libedhoc, "libedhoc", independent_role,
                       arguments.timeout, ("--cid", "3"))
    phase["processes"] = [independent.record]
    try:
        await independent.start()
        if role == "initiator":
            require(await independent.read() == {"ready": True}, "candidate responder not ready")
            await command(fixture, "recover")
            await fixture.event(lambda event: event.get("recover_started") is True)
            _, request = await wire.receive(remote, "candidate-M1-before-ambiguous-commit", arguments.timeout)
            await independent.send(validate_bootstrap_request(request, 1, 1, 3))
            late = bootstrap_response(await independent_message(independent, 2), request)
        else:
            mid, token = operation(state)
            request = bootstrap_request(await independent_message(independent, 1), 1, mid, token)
            validate_bootstrap_request(request, 1, 3, 1)
            await wire.send(request, remote, "candidate-M1-before-ambiguous-commit")
            _, response = await wire.receive(remote, "candidate-M2-before-ambiguous-commit", arguments.timeout)
            await independent.send(validate_bootstrap_response(response, request))
            late = bootstrap_request(await independent_message(independent, 3), 3, mid + 1, token, 1)
        phase["late_candidate"] = metadata(late)
        return late
    finally:
        await independent.stop()


async def scenario(arguments, role):
    record = {"name": "trust-revocation-and-ambiguous-commit", "coaptic_role": role,
              "phases": [], "datagrams": []}
    wire = Wire(record)
    fixture = Fixture(arguments.coaptic, role, ("127.0.0.1", 0), wire.local, arguments.timeout)
    record["coaptic_process"] = fixture.record
    state = {"mids": set()}
    started = time.perf_counter_ns()
    try:
        await fixture.start()
        first = {"generation": 1, "trust_generation": 1}
        record["phases"].append(first)
        remote, old = await handshake(arguments, wire, fixture, role, (0, 1), 1, first, state)
        await incoming_application(arguments, wire, fixture, old, remote, first, 57001, 1)
        revoked = {"trust_generation": 2}
        record["phases"].append(revoked)
        pending = await pending_probe(arguments, wire, fixture, old, remote, revoked)
        await command(fixture, "revoke")
        revoked["transition"] = await fixture.event(lambda event: event.get("trust_changed") is True
                                                    and event.get("trust_generation") == 2)
        require(revoked["transition"].get("enabled") is False, "revocation retained authorization")
        await fixture.event(lambda event: event.get("owners_dropped") is True
                            and event.get("trust_generation") == 2)
        await disabled_controls(arguments, wire, fixture, old, remote, first, revoked,
                                2, 1, 1 if role == "initiator" else 0, pending=pending)
        await command(fixture, "regrant")
        await fixture.event(lambda event: event.get("owners_admitted") is True
                            and event.get("trust_generation") == 3)
        second = {"generation": 2, "trust_generation": 3}
        record["phases"].append(second)
        remote, current = await handshake(arguments, wire, fixture, role,
                                          (0, 2) if role == "initiator" else (2, 0),
                                          2, second, state)
        await incoming_application(arguments, wire, fixture, current, remote, second, 57002, 2)
        ambiguous = {"trust_generation": 4}
        record["phases"].append(ambiguous)
        late = await pending_candidate(arguments, wire, fixture, role, remote, state, ambiguous)
        await command(fixture, "lost-ack")
        ambiguous["transition"] = await fixture.event(lambda event: event.get("trust_blocked") is True
                                                      and event.get("trust_generation") == 4)
        await fixture.event(lambda event: event.get("owners_dropped") is True
                            and event.get("trust_generation") == 4)
        await disabled_controls(arguments, wire, fixture, current, remote, second, ambiguous,
                                4, 2, 2 if role == "initiator" else 0, late_candidate=late)
        require(ambiguous["disabled_stats"].get("trust_blocked") is True,
                "ambiguous durable commit did not fail closed")
        await command(fixture, "restore")
        await fixture.event(lambda event: event.get("trust_restored") is True
                            and event.get("trust_generation") == 4)
        await fixture.event(lambda event: event.get("owners_admitted") is True
                            and event.get("trust_generation") == 4)
        third = {"generation": 3, "trust_generation": 4}
        record["phases"].append(third)
        remote, fresh = await handshake(arguments, wire, fixture, role,
                                        (0, 3) if role == "initiator" else (3, 0),
                                        3, third, state)
        await incoming_application(arguments, wire, fixture, fresh, remote, third, 57003, 3)
        require(len({phase["validated"]["master_secret"] for phase in (first, second, third)}) == 3
                and len({phase["validated"]["master_salt"] for phase in (first, second, third)}) == 3,
                "trust transitions reused exporters")
        await command(fixture, "stats")
        stats = await fixture.event(lambda event: event.get("stats") is True
                                    and event.get("sessions") == 3)
        require(stats.get("handled") == 3 and stats.get("responses") == (3 if role == "initiator" else 0)
                and stats.get("trust_generation") == 4 and stats.get("trust_blocked") is False
                and stats.get("owners") is True, "verified restoration did not resume fresh service")
        record["stats"], record["status"] = stats, "passed"
    except BaseException as error:
        record["status"], record["error"], record["traceback"] = "failed", repr(error), traceback.format_exc()
    finally:
        await fixture.stop()
        wire.close()
    if record.get("status") == "passed" and (fixture.record.get("exit_code") != 0 or fixture.record.get("stderr")):
        record["status"], record["error"] = "failed", "Coaptic fixture did not stop cleanly"
    record["wall_ns"] = time.perf_counter_ns() - started
    return record


async def run(arguments):
    report = {"schema": "coaptic-independent-edhoc-trust/1",
              "scope": "real IPv4 UDP, independent libedhoc/aiocoap; public test identities; in-memory compare-and-swap authority and lost acknowledgment simulation; no power-loss storage or authenticated management channel qualification",
              "python": sys.version, "python_executable": sys.executable, "python_search_path": sys.path,
              "platform": platform.platform(), "cases": [],
              "versions": {name: importlib.metadata.version(name) for name in ("aiocoap", "blake3")},
              "binaries": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                           for name, path in (("coaptic", arguments.coaptic), ("libedhoc", arguments.libedhoc))},
              "resource_profile": {"packet_bytes": 1280, "bootstrap_bytes": 384, "completion_or_retired_slots": 4,
                                   "compact_connection_ids": 24, "local_mid_slots": 16, "nstart": 1,
                                   "app": "profiles::Constrained, block_wise=false"}}
    for role in ("initiator", "responder"):
        report["cases"].append(await scenario(arguments, role))
        report["passed"] = sum(case["status"] == "passed" for case in report["cases"])
        report["failed"] = sum(case["status"] == "failed" for case in report["cases"])
        report["result"] = "passed" if report["cases"] and not report["failed"] else "failed"
        arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("result", "passed", "failed")}))
    return 0 if report["result"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description="Check generation-bound trust invalidation before all App/bootstrap UDP I/O.")
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--libedhoc", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", default=10, type=float)
    arguments = parser.parse_args()
    require(arguments.timeout > 0, "positive timeout required")
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    return asyncio.run(run(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
