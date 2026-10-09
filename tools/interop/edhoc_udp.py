import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import platform
import secrets
import socket
import statistics
import subprocess
import sys
import time
import traceback

import aiocoap
from aiocoap import oscore
from aiocoap.message import Direction

from edhoc import Peer, binary_field, require, validate_completion


REQUEST = b"coaptic-edhoc-udp-request\x00\xff"
RESPONSE = b"coaptic-edhoc-udp-response\xff\x00"
PATH = ("provisioned",)
BOOTSTRAP_PATH = (".well-known", "edhoc")


def endpoint_text(value):
    return f"{value[0]}:{value[1]}"


def endpoint_parse(value):
    host, port = value.rsplit(":", 1)
    require(host == "127.0.0.1" and 0 < int(port) <= 65535, "invalid fixture endpoint")
    return host, int(port)


def metadata(message):
    return {
        "type": None if message.mtype is None else int(message.mtype),
        "code": int(message.code),
        "mid": message.mid,
        "token": message.token.hex(),
        "options": [{"number": int(item.number), "hex": item.encode().hex()}
                    for item in message.opt.option_list()],
        "payload": message.payload.hex(),
    }


def options(message):
    return [(int(item.number), item.encode()) for item in message.opt.option_list()]


def plain_request(mid, token, payload=REQUEST):
    message = aiocoap.Message(code=aiocoap.PUT, payload=payload)
    message.mtype, message.mid, message.token = aiocoap.CON, mid, token
    message.opt.uri_path = PATH
    message.opt.content_format = 42
    return message


def bootstrap_request(message, number, mid, token, responder_id=1):
    result = aiocoap.Message(code=aiocoap.POST, payload=(b"\xf5" if number == 1 else bytes([responder_id])) + message)
    result.mtype, result.mid, result.token = aiocoap.CON, mid, token
    result.opt.uri_path = BOOTSTRAP_PATH
    result.opt.content_format = 65
    return result


def bootstrap_response(message, request):
    result = aiocoap.Message(code=aiocoap.CHANGED, payload=message)
    result.mtype, result.mid, result.token = aiocoap.ACK, request.mid, request.token
    result.opt.content_format = 64
    return result


def oversized_packet(size, protected=False):
    message = aiocoap.Message(code=aiocoap.POST)
    message.mtype, message.mid, message.token = aiocoap.NON, 61000 + size % 1000, b"large"
    if protected:
        message.opt.oscore = b"\x09\x7f\x01"
    else:
        message.opt.uri_path = BOOTSTRAP_PATH
        message.opt.content_format = 65
    message.payload = b"\x00"
    message.payload = b"\x00" * (size - len(message.encode()) + 1)
    packet = message.encode()
    require(len(packet) == size, "oversized probe has incorrect length")
    return packet


def validate_bootstrap_request(message, number, initiator_id=0, responder_id=1):
    require(message.mtype == aiocoap.CON and message.code == aiocoap.POST, "wrong bootstrap request type/code")
    require(options(message) == [(11, b".well-known"), (11, b"edhoc"), (12, b"A")], "wrong bootstrap request options")
    prefix = b"\xf5" if number == 1 else bytes([responder_id])
    require(message.payload.startswith(prefix), "wrong EDHOC connection prefix")
    require(0 < len(message.payload) - 1 <= 192, "wrong EDHOC message length")
    if number == 1:
        require(message.payload[1:5] == bytes.fromhex("03025820") and message.payload[-1:] == bytes([initiator_id]), "wrong method, suite, point encoding or C_I")
    return message.payload[1:]


def validate_bootstrap_response(message, request):
    require(message.mtype == aiocoap.ACK and message.code == aiocoap.CHANGED, "wrong bootstrap response type/code")
    require((message.mid, message.token) == (request.mid, request.token), "bootstrap response operation mismatch")
    require(options(message) == [(12, b"@")], "wrong bootstrap response options")
    require(0 < len(message.payload) <= 192, "wrong bootstrap response length")
    return message.payload


def validate_application(message, response=False):
    expected = (aiocoap.CHANGED, [(12, b"*")], RESPONSE) if response else (
        aiocoap.PUT, [(11, b"provisioned"), (12, b"*")], REQUEST)
    require((message.code, options(message), message.payload) == expected, "authenticated application code/options/body mismatch")


class VolatileContext(oscore.CanProtect, oscore.CanUnprotect, oscore.SecurityContextUtils):
    def __init__(self, completion):
        self.alg_aead = oscore.algorithms["AES-CCM-16-64-128"]
        self.hashfun = oscore.hashfunctions["sha256"]
        self.sender_id = binary_field(completion, "sender_id", 1)
        self.recipient_id = binary_field(completion, "recipient_id", 1)
        self.id_context = None
        self.sender_sequence_number = 0
        self.echo_recovery = None
        self.recipient_replay_window = oscore.ReplayWindow(64, lambda: None)
        self.recipient_replay_window.initialize_empty()
        self.derive_keys(binary_field(completion, "master_salt", 8), binary_field(completion, "master_secret", 16))

    def post_seqnoincrease(self):
        pass


class Fixture:
    def __init__(self, executable, role, local, peer, timeout):
        self.command = [str(executable), role, endpoint_text(local), endpoint_text(peer)]
        self.timeout = timeout
        self.record = {"implementation": "coaptic", "role": role, "command": self.command,
                       "stdin": [], "stdout": [], "records": []}
        self.process = None
        self.reader = None
        self.stderr_reader = None
        self.changed = asyncio.Event()

    async def start(self):
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        self.process = await asyncio.create_subprocess_exec(
            *self.command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=8192, **options)
        self.reader = asyncio.create_task(self.read_all())
        self.stderr_reader = asyncio.create_task(self.process.stderr.read())

    async def read_all(self):
        try:
            async for line in self.process.stdout:
                value = line.decode("utf-8", errors="strict").rstrip("\r\n")
                self.record["stdout"].append(value)
                record = json.loads(value)
                require(isinstance(record, dict), "fixture output is not an object")
                self.record["records"].append(record)
                self.changed.set()
        finally:
            self.changed.set()

    async def event(self, predicate, timeout=None):
        async def find():
            while True:
                self.changed.clear()
                for record in self.record["records"]:
                    if predicate(record):
                        return record
                if self.reader.done():
                    await self.reader
                    raise ValueError("fixture exited before expected event")
                await self.changed.wait()
        return await asyncio.wait_for(find(), self.timeout if timeout is None else timeout)

    async def stop(self):
        if self.process is None:
            return
        try:
            if self.process.returncode is None:
                self.record["stdin"].append("stop")
                self.process.stdin.write(b"stop\n")
                await self.process.stdin.drain()
                await asyncio.wait_for(self.process.wait(), 2)
            await self.reader
        except BaseException as error:
            self.record["cleanup_error"] = repr(error)
            if self.process.returncode is None:
                self.record["cleanup_killed"] = True
                self.process.kill()
                await self.process.wait()
        self.record["exit_code"] = self.process.returncode
        self.record["stderr"] = (await self.stderr_reader).decode("utf-8", errors="replace")


class Wire:
    def __init__(self, record):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        self.socket.bind(("127.0.0.1", 0))
        self.local = self.socket.getsockname()
        self.record = record
        self.started = time.perf_counter_ns()

    def capture(self, direction, packet, source, destination, label):
        entry = {"elapsed_ns": time.perf_counter_ns() - self.started, "direction": direction,
                 "source": endpoint_text(source), "destination": endpoint_text(destination),
                 "hex": packet.hex(), "length": len(packet), "label": label}
        try:
            entry["coap"] = metadata(aiocoap.Message.decode(packet))
        except BaseException as error:
            entry["decode_error"] = repr(error)
        self.record["datagrams"].append(entry)

    async def send(self, message, peer, label, wrong_endpoint=False):
        packet = message if isinstance(message, bytes) else message.encode()
        if wrong_endpoint:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.bind(("127.0.0.1", 0))
            try:
                self.capture("send", packet, sock.getsockname(), peer, label)
                await asyncio.get_running_loop().sock_sendto(sock, packet, peer)
                deadline = asyncio.get_running_loop().time() + 0.15
                while True:
                    try:
                        data, source = await asyncio.wait_for(asyncio.get_running_loop().sock_recvfrom(sock, 2048), deadline - asyncio.get_running_loop().time())
                    except TimeoutError:
                        break
                    self.capture("receive", data, source, sock.getsockname(), label)
                    decoded = aiocoap.Message.decode(data)
                    require(decoded.code in (aiocoap.EMPTY, aiocoap.UNAUTHORIZED, aiocoap.BAD_REQUEST, aiocoap.BAD_OPTION), "wrong endpoint received an application response")
            finally:
                sock.close()
        else:
            self.capture("send", packet, self.local, peer, label)
            await asyncio.get_running_loop().sock_sendto(self.socket, packet, peer)
        return packet

    async def receive(self, peer, label, timeout):
        packet, source = await asyncio.wait_for(asyncio.get_running_loop().sock_recvfrom(self.socket, 2048), timeout)
        self.capture("receive", packet, source, self.local, label)
        require(source == peer, "datagram arrived from an unexpected endpoint")
        require(len(packet) <= 1280, "Coaptic datagram exceeded packet capacity")
        return packet, aiocoap.Message.decode(packet)

    async def quiet(self, peer, label, timeout=0.15):
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            try:
                _, message = await self.receive(peer, label, deadline - asyncio.get_running_loop().time())
            except TimeoutError:
                return
            require(message.code in (aiocoap.EMPTY, aiocoap.UNAUTHORIZED, aiocoap.BAD_REQUEST, aiocoap.BAD_OPTION), "negative probe received an application response")

    def close(self):
        self.socket.close()


def protect(context, message, request_id=None):
    output, identifier = context.protect(message, request_id)
    output.mtype, output.mid, output.token = message.mtype, message.mid, message.token
    require(options(output) == [(9, output.opt.oscore)], "unexpected outer protected options")
    return output, identifier


async def independent_message(peer, number):
    value = await peer.read()
    require(value is not None and value.get("message") == number, f"missing independent message {number}")
    output = binary_field(value, "hex")
    require(0 < len(output) <= 192, "independent EDHOC message exceeded capacity")
    return output


async def handshake(arguments, wire, fixture, independent, role, fault, record):
    ready = await fixture.event(lambda value: value.get("ready") is True)
    remote = endpoint_parse(ready["local"])
    record["coaptic_endpoint"] = endpoint_text(remote)
    for size in (385, 1281, 8192):
        await wire.send(oversized_packet(size), remote, f"oversized-{size}-before-bootstrap-wrong-endpoint", wrong_endpoint=True)
    messages = []
    if role == "responder":
        token = secrets.token_bytes(8)
        mid = secrets.randbelow(50000)
        for number in (1, 3):
            bare = await independent_message(independent, number)
            request = bootstrap_request(bare, number, mid + (number == 3), token)
            if number == 1:
                await wire.send(request, remote, "wrong-endpoint-M1", wrong_endpoint=True)
            packet = await wire.send(request, remote, f"message-{number}")
            response_packet, response = await wire.receive(remote, f"message-{number + 1}", arguments.timeout)
            bare_response = validate_bootstrap_response(response, request)
            messages.extend([{"message": number, "hex": bare.hex()}, {"message": number + 1, "hex": bare_response.hex()}])
            if number == 3 and fault == "lost-M4":
                record["dropped"] = {"message": 4, "hex": response_packet.hex()}
                await asyncio.sleep(2 + secrets.randbelow(1001) / 1000)
                retransmission = await wire.send(packet, remote, "retransmit-exact-M3-after-lost-M4")
                cached_packet, cached = await wire.receive(remote, "cached-M4-after-handoff", arguments.timeout)
                require(retransmission == packet and cached_packet == response_packet, "lost M4 retransmission changed cached bytes")
                validate_bootstrap_response(cached, request)
            await independent.send(bare_response)
            if number == 3:
                record["cached_m3"] = packet.hex()
                record["cached_m4"] = response_packet.hex()
    else:
        require(await independent.read() == {"ready": True}, "missing libedhoc responder readiness")
        first_mid = None
        for number in (1, 3):
            request_packet, request = await wire.receive(remote, f"message-{number}", arguments.timeout)
            bare = validate_bootstrap_request(request, number)
            if first_mid is not None:
                require(request.mid != first_mid, "sequential EDHOC requests reused a MID")
            else:
                first_mid = request.mid
            await independent.send(bare)
            bare_response = await independent_message(independent, number + 1)
            response = bootstrap_response(bare_response, request)
            if number == 1:
                await wire.send(response, remote, "wrong-endpoint-M2", wrong_endpoint=True)
            response_packet = response.encode()
            messages.extend([{"message": number, "hex": bare.hex()}, {"message": number + 1, "hex": bare_response.hex()}])
            if number == 3 and fault == "lost-M4":
                record["dropped"] = {"message": 4, "hex": response_packet.hex()}
                retry_packet, retry = await wire.receive(remote, "Coaptic-retransmit-M3", arguments.timeout)
                require(retry_packet == request_packet, "Coaptic retransmission changed M3 bytes")
                validate_bootstrap_request(retry, number)
            await wire.send(response_packet, remote, f"message-{number + 1}")
            if number == 3:
                record["old_bootstrap_reply"] = response_packet.hex()
    completion = await independent.read()
    coaptic = await fixture.event(lambda value: value.get("complete") is True and "sender_key" in value)
    record["validated"] = validate_completion(coaptic, completion, role)
    record["messages"] = messages
    await independent.wait()
    require(independent.process.returncode == 0 and not independent.record["stderr"], "independent peer did not exit cleanly")
    context = VolatileContext(completion)
    require(context.recipient_key.hex() == coaptic["sender_key"] and context.sender_key.hex() == coaptic["recipient_key"] and context.common_iv.hex() == coaptic["common_iv"], "aiocoap derived different key material")
    return remote, context


async def outgoing_application(arguments, wire, fixture, context, remote, record, generation=None):
    _, message = await wire.receive(remote, "Coaptic-protected-PUT", arguments.timeout)
    require(message.mtype == aiocoap.CON and message.code == aiocoap.POST and options(message) == [(9, message.opt.oscore)], "unexpected outer Coaptic request metadata")
    unprotected, request_id = context.unprotect(message)
    validate_application(unprotected)
    record["coaptic_application_request"] = metadata(unprotected)
    response = aiocoap.Message(code=aiocoap.CHANGED, payload=RESPONSE)
    response.mtype, response.mid, response.token = aiocoap.ACK, message.mid, message.token
    response.opt.content_format = 42
    encrypted, _ = protect(context, response, request_id)
    await wire.send(encrypted, remote, "independent-protected-CHANGED")
    event = await fixture.event(lambda value: value.get("response") is True
                                and (generation is None or value.get("generation") == generation))
    require(event.get("code") == 68 and binary_field(event, "payload") == RESPONSE and event.get("content_format") == 42, "Coaptic authenticated a different response")
    require(event.get("mid") == message.mid and binary_field(event, "token") == message.token, "Coaptic response metadata changed")
    require(event.get("mtype") == 2, "Coaptic response type changed")
    record["coaptic_response_event"] = event


async def incoming_application(arguments, wire, fixture, context, remote, record, mid, count, interleave=False, prepared=None):
    if prepared is None:
        request = plain_request(mid, secrets.token_bytes(8))
        encrypted, request_id = protect(context, request)
    else:
        request, encrypted, request_id = prepared
    cached_seen = not interleave
    if interleave:
        await wire.send(bytes.fromhex(record["cached_m3"]), remote, "duplicate-M3-interleaved-after-App-handoff")
    packet = await wire.send(encrypted, remote, "independent-protected-PUT")
    response_seen = False
    deadline = asyncio.get_running_loop().time() + arguments.timeout
    while not (cached_seen and response_seen):
        reply_packet, reply = await wire.receive(remote, "protected-response-or-cached-M4", deadline - asyncio.get_running_loop().time())
        if reply_packet.hex() == record.get("cached_m4"):
            require(interleave and not cached_seen, "unexpected cached M4")
            cached_seen = True
            continue
        require(reply.mtype == aiocoap.ACK and reply.code == aiocoap.CHANGED and (reply.mid, reply.token) == (request.mid, request.token), "wrong protected response operation metadata")
        require(options(reply) == [(9, reply.opt.oscore)], "application response lacked exact OSCORE outer options")
        unprotected, _ = context.unprotect(reply, request_id)
        validate_application(unprotected, response=True)
        record.setdefault("independent_application_responses", []).append(metadata(unprotected))
        response_seen = True
    handled = await fixture.event(lambda value: value.get("handled") is True and value.get("count") == count)
    require(handled.get("code") == 3 and binary_field(handled, "payload") == REQUEST and handled.get("content_format") == 42 and handled.get("path") == "provisioned", "Coaptic handler received different application data")
    require(handled.get("mtype") == 0 and handled.get("options") == [{"number": 11, "hex": b"provisioned".hex()}, {"number": 12, "hex": "2a"}], "Coaptic handler type or complete options changed")
    require(handled.get("mid") == request.mid and binary_field(handled, "token") == request.token, "Coaptic handler metadata changed")
    require(binary_field(handled, "principal", 32) == bytes.fromhex(record["validated"]["principal"]), "Coaptic handler principal changed")
    record.setdefault("handled_events", []).append(handled)
    return packet


async def refused_corruption_and_interleave(wire, context, remote, record, old_ciphertext=None, stale_bootstrap=None):
    fresh, _ = protect(context, plain_request(60003, b"corrupt"))
    fresh.mtype = aiocoap.NON
    packet = bytearray(fresh.encode())
    packet[-1] ^= 1
    await wire.send(bytes(packet), remote, "corrupted-fresh-ciphertext")
    await wire.quiet(remote, "corrupted-ciphertext-refusal")
    unsupported = bootstrap_request(b"\x40", 3, 60004, b"unrel")
    unsupported.mtype = aiocoap.NON
    await wire.send(unsupported, remote, "unrelated-bootstrap-interleave")
    await wire.quiet(remote, "unrelated-bootstrap-refusal")
    if old_ciphertext is not None:
        old = aiocoap.Message.decode(old_ciphertext)
        old.direction = Direction.OUTGOING
        old.mtype, old.mid, old.token = aiocoap.NON, 60005, b"old-key"
        await wire.send(old, remote, "old-ciphertext-after-fresh-handshake")
        await wire.quiet(remote, "old-key-refusal")
    if stale_bootstrap is not None:
        stale = aiocoap.Message.decode(bytes.fromhex(stale_bootstrap))
        stale.direction = Direction.OUTGOING
        stale.mtype = aiocoap.NON
        await wire.send(stale, remote, "stale-bootstrap-NON-after-coordinated-restart")
        await wire.quiet(remote, "stale-bootstrap-isolation")
        record["stale_bootstrap_original"] = stale_bootstrap
    record["negative_checks"] = ["plaintext", "replay_with_fresh_mid_token", "wrong_endpoint", "corrupted_fresh_ciphertext", "unrelated_bootstrap"]
    if old_ciphertext is not None:
        record["negative_checks"].append("old_ciphertext_after_restart")
    if stale_bootstrap is not None:
        record["negative_checks"].append("old_bootstrap_NON_after_restart_did_not_replace_session")
    for size in (385, 1281, 8192):
        packet = oversized_packet(size, protected=True)
        await wire.send(packet, remote, f"oversized-{size}-after-handoff-wrong-endpoint", wrong_endpoint=True)
        await wire.send(packet, remote, f"oversized-{size}-after-handoff-bound-endpoint")
        await wire.quiet(remote, f"oversized-{size}-refusal")
    record["negative_checks"].append("bounded_adversarial_oversized_datagrams_before_and_after_handoff")
    if "cached_m3" in record:
        await wire.send(bytes.fromhex(record["cached_m3"]), remote, "cached-M3-after-oversized-probes")
        packet, _ = await wire.receive(remote, "cached-M4-preserved-after-oversized-probes", 2)
        require(packet.hex() == record["cached_m4"], "oversized probes evicted or changed completion cache")
        record["negative_checks"].append("cached_m4_preserved_after_oversized_datagrams")


async def phase(arguments, wire, role, fault, record, local=("127.0.0.1", 0), old_ciphertext=None, stale_bootstrap=None):
    independent_role = "initiator" if role == "responder" else "responder"
    independent = Peer(arguments.libedhoc, "libedhoc", independent_role, arguments.timeout)
    fixture = Fixture(arguments.coaptic, role, local, wire.local, arguments.timeout)
    record["processes"] = [fixture.record, independent.record]
    try:
        await independent.start()
        await fixture.start()
        remote, context = await handshake(arguments, wire, fixture, independent, role, fault, record)
        if role == "initiator":
            await outgoing_application(arguments, wire, fixture, context, remote, record)
        original = await incoming_application(arguments, wire, fixture, context, remote, record, 59000, 1, interleave=role == "responder" and fault == "duplicate-M3")
        plaintext = plain_request(60000, b"plain")
        plaintext.mtype = aiocoap.NON
        await wire.send(plaintext, remote, "plaintext-control-adversarial-NON")
        await wire.quiet(remote, "plaintext-refusal")
        replay = aiocoap.Message.decode(original)
        replay.direction = Direction.OUTGOING
        replay.mtype = aiocoap.NON
        replay.mid, replay.token = 60001, b"replay"
        await wire.send(replay, remote, "replay-fresh-MID-token")
        await wire.quiet(remote, "replay-refusal")
        probe_request = plain_request(60002, b"wrong")
        probe, probe_id = protect(context, probe_request)
        await wire.send(probe, remote, "fresh-protected-wrong-endpoint", wrong_endpoint=True)
        await incoming_application(arguments, wire, fixture, context, remote, record, 60002, 2, prepared=(probe_request, probe, probe_id))
        await refused_corruption_and_interleave(wire, context, remote, record, old_ciphertext, stale_bootstrap)
        await incoming_application(arguments, wire, fixture, context, remote, record, 59001, 3)
        record["old_ciphertext"] = original.hex()
        record["status"] = "passed"
    finally:
        await fixture.stop()
        await independent.stop()
    require(fixture.record.get("exit_code") == 0 and not fixture.record.get("stderr"), "Coaptic fixture did not exit cleanly")
    stats = next((value for value in fixture.record["records"] if value.get("stats") is True), None)
    require(stats is not None and stats.get("complete") is True and stats.get("handled_count") == 3 and stats.get("response_count") == (1 if role == "initiator" else 0), "negative probes changed handler/response admission count")
    record["stats"] = stats
    return remote, original


async def case(arguments, role, repetition=None, fault=None):
    record = {"name": fault or "complete-UDP-provisioning-and-protected-App", "coaptic_role": role,
              "repetition": repetition, "datagrams": []}
    wire = Wire(record)
    started = time.perf_counter_ns()
    try:
        if fault == "restart":
            phases = [{}, {}]
            record["phases"] = phases
            remote, old = await phase(arguments, wire, role, None, phases[0])
            stale = phases[0].get("cached_m3") if role == "responder" else phases[0].get("old_bootstrap_reply")
            require(stale is not None, "missing stale bootstrap candidate")
            await phase(arguments, wire, role, None, phases[1], local=remote, old_ciphertext=old, stale_bootstrap=stale)
            require(phases[0]["validated"]["master_secret"] != phases[1]["validated"]["master_secret"] and phases[0]["validated"]["master_salt"] != phases[1]["validated"]["master_salt"], "restart reused key material")
            record["validated"] = phases[1]["validated"]
        else:
            await phase(arguments, wire, role, fault, record)
        record["status"] = "passed"
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = repr(error)
        record["traceback"] = traceback.format_exc()
    finally:
        wire.close()
        record["wall_ns"] = time.perf_counter_ns() - started
    return record


async def wrong_pin_case(arguments, role):
    record = {"name": "wrong-static-pin-same-kid", "coaptic_role": role, "datagrams": [],
              "independent_configuration": "same expected kid, different public test scalar 3"}
    wire = Wire(record)
    independent_role = "initiator" if role == "responder" else "responder"
    independent = Peer(arguments.libedhoc, "libedhoc", independent_role, arguments.timeout, ("wrong-identity",))
    fixture = Fixture(arguments.coaptic, role, ("127.0.0.1", 0), wire.local, arguments.timeout)
    record["processes"] = [fixture.record, independent.record]
    started = time.perf_counter_ns()
    try:
        await independent.start()
        await fixture.start()
        ready = await fixture.event(lambda value: value.get("ready") is True)
        remote = endpoint_parse(ready["local"])
        record["coaptic_endpoint"] = endpoint_text(remote)
        if role == "responder":
            token = secrets.token_bytes(8)
            mid = secrets.randbelow(50000)
            m1 = bootstrap_request(await independent_message(independent, 1), 1, mid, token)
            await wire.send(m1, remote, "wrong-pin-message-1")
            _, m2 = await wire.receive(remote, "wrong-pin-message-2", arguments.timeout)
            await independent.send(validate_bootstrap_response(m2, m1))
            m3 = bootstrap_request(await independent_message(independent, 3), 3, mid + 1, token)
            await wire.send(m3, remote, "wrong-pin-message-3")
        else:
            require(await independent.read() == {"ready": True}, "missing wrong-pin responder readiness")
            _, m1 = await wire.receive(remote, "wrong-pin-message-1", arguments.timeout)
            await independent.send(validate_bootstrap_request(m1, 1))
            m2 = bootstrap_response(await independent_message(independent, 2), m1)
            await wire.send(m2, remote, "wrong-pin-message-2")
        await asyncio.wait_for(fixture.process.wait(), arguments.timeout)
        await fixture.stop()
        require(fixture.record["exit_code"] == 1 and fixture.record["stderr"] and "panicked" not in fixture.record["stderr"].lower(), "wrong pin did not produce a clean fixture rejection")
        require("Authentication" in fixture.record["stderr"], "wrong pin failed for a reason other than authentication")
        require(not any(value.get("complete") or value.get("handled") or value.get("response") or "sender_key" in value for value in fixture.record["records"]), "wrong pin admitted a session or application operation")
        await wire.quiet(remote, "wrong-pin-no-application-response")
        record["status"] = "passed"
    except BaseException as error:
        record["status"], record["error"], record["traceback"] = "failed", repr(error), traceback.format_exc()
    finally:
        await fixture.stop()
        await independent.stop()
        wire.close()
        record["wall_ns"] = time.perf_counter_ns() - started
    return record


async def run(arguments):
    report = {"schema": "coaptic-edhoc-udp-independent/1", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "scope": "real loopback IPv4 UDP, independent libedhoc EDHOC and aiocoap OSCORE; coordinated two-peer process restart with fresh context; fixed public test identities; no transparent one-sided rebootstrap, device, production trust-store, full release qualification or throughput claim",
              "python": sys.version, "platform": platform.platform(), "cases": [],
              "versions": {name: importlib.metadata.version(name) for name in ("aiocoap", "cryptography", "cbor2", "blake3")},
              "coaptic_build_profile": arguments.coaptic_build_profile,
              "resource_profile": {"bootstrap_bytes": 384, "packet_bytes": 1280, "credential_bytes": 82, "app": "profiles::Constrained, block_wise=false", "nstart": 1, "initial_timeout_ms": [2000, 3000], "max_retransmit": 4},
              "adversarial_injections": "plaintext, replay, corruption, unrelated bootstrap, old-key and oversized injections use NON; 150ms observation windows are bounded negative probes, not CoAP retransmission deadlines; correct-endpoint valid CON transactions are sequential",
              "fixtures": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in (("coaptic", arguments.coaptic), ("libedhoc", arguments.libedhoc))},
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "edhoc_oracle_sha256": hashlib.sha256(Path(__file__).with_name("edhoc.py").read_bytes()).hexdigest(),
              "aiocoap_oscore_source": {"path": oscore.__file__, "sha256": hashlib.sha256(Path(oscore.__file__).read_bytes()).hexdigest()},
              "protocol_references": [{"file": name, "sha256": hashlib.sha256((Path(__file__).resolve().parents[2] / "knowledge" / "rfcs" / name).read_bytes()).hexdigest()} for name in ("rfc9668.txt", "rfc8613.txt")]}
    for path in sorted((arguments.libedhoc.parent / "evidence").glob("*/manifest.json"), reverse=True):
        build = json.loads(path.read_text(encoding="utf-8"))
        if build.get("result") == "passed" and build.get("executable", {}).get("sha256") == report["fixtures"]["libedhoc"]["sha256"]:
            report["libedhoc_build"] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "source_revisions": build["source_revisions"], "configuration": build["configuration"], "fixture_sha256": build["fixture_sha256"]}
            break
    arguments.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        report["passed"] = sum(item["status"] == "passed" for item in report["cases"])
        report["failed"] = sum(item["status"] == "failed" for item in report["cases"])
        report["result"] = "passed" if report["cases"] and not report["failed"] else "failed"
        timing = {"definition": "whole case including process startup, UDP handshake, authenticated requests, negative-probe observation windows and cleanup; wall time, not CPU or throughput", "roles": {}}
        for role in ("initiator", "responder"):
            samples = [item["wall_ns"] for item in report["cases"] if item["name"] == "complete-UDP-provisioning-and-protected-App" and item["coaptic_role"] == role]
            if samples:
                timing["roles"][role] = {"all_samples_ns": samples, "mean_ns": statistics.mean(samples), "median_ns": statistics.median(samples), "min_ns": min(samples), "max_ns": max(samples)}
        report["case_wall_timing"] = timing
        arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    secrets_seen = set()
    salts_seen = set()
    for repetition in range(1, arguments.repetitions + 1):
        for role in (("initiator", "responder") if repetition % 2 else ("responder", "initiator")):
            record = await case(arguments, role, repetition)
            if record["status"] == "passed":
                for name, seen in (("master_secret", secrets_seen), ("master_salt", salts_seen)):
                    value = record["validated"][name]
                    if value in seen:
                        record["status"], record["error"] = "failed", f"fresh handshake repeated {name}"
                    seen.add(value)
            report["cases"].append(record)
            save()
    for role, fault in (("initiator", "lost-M4"), ("responder", "lost-M4"), ("responder", "duplicate-M3"), ("initiator", "restart"), ("responder", "restart")):
        report["cases"].append(await case(arguments, role, fault=fault))
        save()
    for role in ("initiator", "responder"):
        report["cases"].append(await wrong_pin_case(arguments, role))
        save()
    print(json.dumps({"passed": report["passed"], "failed": report["failed"], "output": str(arguments.output)}))
    return 1 if report["failed"] else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--libedhoc", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", default=5, type=int)
    parser.add_argument("--timeout", default=10, type=float)
    parser.add_argument("--coaptic-build-profile", default="unspecified")
    arguments = parser.parse_args()
    require(arguments.repetitions >= 1 and arguments.timeout > 0, "positive repetition count and timeout required")
    require(not arguments.output.exists(), "output already exists; preserve previous evidence")
    arguments.coaptic = arguments.coaptic.resolve(strict=True)
    arguments.libedhoc = arguments.libedhoc.resolve(strict=True)
    logging.disable(logging.CRITICAL)
    return asyncio.run(run(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
