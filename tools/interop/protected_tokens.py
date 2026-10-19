"""One independent native OSCORE extended-token boundary; public fixture keys."""
import json
import select
import subprocess
import time

import aiocoap
from aiocoap.message import Direction
from oscore_qblock1 import FixtureContext
from run import Proxy, Server, command, expect, packet_token, request, token_bounds


def require(value, message):
    if not value:
        raise AssertionError(message)


def incoming(wire):
    # aiocoap's UDP Message.decode assumes compact TKL. Its public Message and
    # OSCORE APIs accept the complete token; decode unchanged options/ciphertext
    # after the shared strict RFC8974 prefix reader. No crypto or token rewrite.
    start, end = token_bounds(wire)
    message = aiocoap.Message(code=wire[1])
    message.mtype = aiocoap.Type((wire[0] >> 4) & 3)
    message.mid = int.from_bytes(wire[2:4], "big")
    message.token = wire[start:end]
    message.payload = message.opt.decode(wire[end:])
    message.direction = Direction.INCOMING
    return message


def plain_request(wire):
    return FixtureContext(server=True).unprotect(incoming(wire))


def plain_response(wire, sent):
    _, binding = plain_request(sent)
    return FixtureContext(server=False).unprotect(incoming(wire), binding)[0]


class TokenRelay(Proxy):
    def __init__(self, number, tamper=False):
        self.tamper = tamper
        super().__init__(number, "pass")

    def run(self):
        client = None
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.front, self.back], [], [], .02)
                for sock in ready:
                    wire, source = sock.recvfrom(1473)
                    require(4 <= len(wire) <= 1472 and len(self.trace) < 96, "protected token bounds")
                    if sock is self.front:
                        require(client is None or client == source, "protected client endpoint changed")
                        client = source
                        target, address, direction = self.back, self.dest, "request"
                        changed = wire
                        if self.tamper and wire[1] != 0:
                            plain, _ = plain_request(wire)
                            if int(plain.code) == 2:
                                require(len(packet_token(wire)) == 32, "tamper request lost extended token")
                                changed = wire[:-1] + bytes([wire[-1] ^ 1])
                    else:
                        require(source == self.dest and client is not None, "protected server endpoint changed")
                        target, address, direction, changed = self.front, client, "response", wire
                    require(target.sendto(changed, address) == len(changed), "partial protected relay send")
                    self.trace.append({"direction": direction, "source": list(source),
                                       "destination": list(address), "relay": list(target.getsockname()),
                                       "time_ns": time.perf_counter_ns(), "hex": wire.hex(),
                                       "forwarded_hex": changed.hex(),
                                       "action": "tamper-tag" if changed != wire else "forward"})
        except Exception as error:
            self.error = repr(error)


def native(client, port, length, sequence, *, timeout=6000):
    argv = command(client, "client", "oscore", port, path="counter", method="POST",
                   sequence=sequence, timeout=timeout) + [f"token:{length}"]
    result = subprocess.run(argv, capture_output=True, timeout=12)
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, "native output bound")
    event = json.loads(result.stdout)
    event["exit_code"] = result.returncode
    return {"argv": list(map(str, argv)), "event": event, "stderr": result.stderr.decode(errors="replace")}


def grade(trace, length, *, tamper=False, refusal=False):
    from profiles import validate_trace
    validate_trace([dict(row, action="forward", forwarded_hex=row["hex"]) for row in trace])
    requests = []
    authenticated = []
    altered = []
    for row in trace:
        wire = bytes.fromhex(row["hex"])
        if wire[1] == 0:
            continue
        require(len(packet_token(wire)) == length, "full protected token length changed")
        if row["direction"] == "request":
            plain, _ = plain_request(wire)
            require(int(plain.code) in (1, 2), "unexpected native inner request")
            requests.append(wire)
            if row["action"] == "tamper-tag":
                changed = bytes.fromhex(row["forwarded_hex"])
                require(changed[:-1] == wire[:-1] and changed[-1] == wire[-1] ^ 1,
                        "tamper changed identity/options")
                try:
                    plain_request(changed)
                except Exception:
                    pass
                else:
                    raise AssertionError("altered tag authenticated")
                altered.append(wire)
        else:
            require(row["action"] == "forward", "response changed")
            candidates = [sent for sent in requests if packet_token(sent) == packet_token(wire)
                          and ((wire[0] >> 4) & 3 != 2 or sent[2:4] == wire[2:4])]
            matched = []
            for sent in candidates:
                try:
                    plain = plain_response(wire, sent)
                    matched.append((sent, plain))
                except Exception:
                    continue
            require(matched, "response has no authenticated full-token/MID request")
            authenticated.append(matched[-1])
    require(requests, "no protected native request")
    if refusal:
        require(any(int(reply.code) == 128 and not reply.payload for _, reply in authenticated),
                "missing authenticated full-token capacity refusal")
        require(all(int(plain_request(sent)[0].code) == 1 for sent in requests),
                "refused native bound still sent application POST")
    elif tamper:
        require(altered and not any(int(reply.code) == 68 for _, reply in authenticated),
                "tamper returned application success")
    else:
        require(any(int(reply.code) == 68 for _, reply in authenticated), "missing protected POST success")


def workflow(client, server, captures=None, commands=None):
    events = []
    with Server(server, "oscore") as service:
        for length, sequence, tamper, refusal in ((32, 0, False, False), (64, 100, False, True),
                                                  (32, 200, True, False), (32, 400, False, False)):
            with TokenRelay(service.number, tamper) as relay:
                if captures is not None:
                    captures.append(relay.trace)
                result = native(client, relay.number, length, sequence, timeout=600 if tamper else 6000)
            if commands is not None:
                commands.append(result)
            grade(relay.trace, length, tamper=tamper, refusal=refusal)
            if tamper or refusal:
                require(result["event"]["exit_code"] != 0, "native refusal reported success")
            else:
                expect(result["event"], 68, b"")
            readback = request(client, "oscore", service.number, path="counter", sequence=sequence + 50)
            expect(readback, 69, b"2" if sequence == 400 else b"1")
            events.append({"length": length, "tamper": tamper, "capacity_refusal": refusal,
                           "native": result, "trace": relay.trace, "readback": readback})
    return {"cases": events, "full_token_preserved": True,
            "offline_oracle": "aiocoap OSCORE with RFC8974 Message population"}
