"""Finite independent UDP metadata, token and Observe profile captures."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import time

from aiocoap.util import linkformat
from run import Server, Proxy, command, expect, request, decoded_options, coap_payload, packet_token
from source_identity import source_identity

# One sequential case owns these bounded evidence references; failed cases keep
# their original wire/process evidence too, rather than only an exception string.
ACTIVE_CAPTURES = []
ACTIVE_COMMANDS = []

def require(value, message):
    if not value:
        raise AssertionError(message)


def validate_trace(trace):
    require(0 < len(trace) <= 256, "empty or excessive capture")
    requests = [row for row in trace if row["direction"] == "request"]
    require(requests, "no client datagram")
    client, server = requests[0]["source"], requests[0]["destination"]
    relays = {}
    previous = 0
    for row in trace:
        direction = row["direction"]
        for endpoint in (row["source"], row["destination"], row["relay"]):
            require(isinstance(endpoint, list) and len(endpoint) == 2 and endpoint[0] == "127.0.0.1"
                    and type(endpoint[1]) is int and 0 < endpoint[1] <= 65535, "not an exact IPv4 loopback owner")
        require(row["action"] == "forward" and row["hex"] == row["forwarded_hex"], "changed capture bytes")
        require(row["source"] == (client if direction == "request" else server), "wrong source")
        require(row["destination"] == (server if direction == "request" else client), "wrong destination")
        require(row["time_ns"] >= previous, "clock regression")
        previous = row["time_ns"]
        require(relays.setdefault(direction, row["relay"]) == row["relay"], "changed relay owner")
    require(len(relays) == 2 and len({tuple(client), tuple(server), *(tuple(value) for value in relays.values())}) == 4,
            "capture does not bind four distinct owners")
    return client, server


def exchange_identity(trace, path, code, token_length=8):
    validate_trace(trace)
    candidates = []
    for row in trace:
        packet = bytes.fromhex(row["hex"])
        if row["direction"] == "request" and packet[1] == 1 and decoded_options(packet).get(11, []) == path:
            if len(packet_token(packet)) == token_length:
                candidates.append(packet)
    require(candidates, "missing exact request path/token length")
    first = candidates[0]
    replies = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "response"]
    matching = [packet for packet in replies if packet[1] == code and packet_token(packet) == packet_token(first)]
    require(matching, "missing exact complete token response")
    for packet in matching:
        if (packet[0] >> 4) & 3 == 2:
            require(packet[2:4] == first[2:4], "wrong piggyback MID")
    return first, matching


def execute(exe, port, path, flags=()):
    argv = command(exe, "client", "udp", port, path=path, timeout=6000) + list(flags)
    result = subprocess.run(argv, capture_output=True, timeout=10)
    ACTIVE_COMMANDS.append({"argv": list(map(str, argv)), "exit_code": result.returncode,
                            "stdout": result.stdout.decode(errors="replace"),
                            "stderr": result.stderr.decode(errors="replace")})
    require(len(result.stdout) <= 65536 and len(result.stdout.splitlines()) == 1, "invalid bounded peer output")
    value = json.loads(result.stdout)
    value["exit_code"] = result.returncode
    require(result.returncode == 0, f"peer refused: {value}; {result.stderr[-1000:]!r}")
    return value


def metadata_body(payload):
    parsed = linkformat.parse(payload.decode("utf-8"))
    sensors = [link for link in parsed.links if link.href == "/sensor"]
    require(len(sensors) == 1, "missing or repeated metadata target")
    attributes = dict(sensors[0].attr_pairs)
    require(attributes.get("rt", "").split() == ["temperature-c", "sensor"], "resource types changed")
    require(attributes.get("if") == "sensor", "interface changed")
    require(attributes.get("ct", "").split() == ["0", "50"], "content formats changed")
    require(attributes.get("sz") == "96" and "obs" in attributes, "size/observable metadata changed")
    require(attributes.get("title") == 'Room "one"', "quoted extension changed")
    return sensors[0].href, sensors[0].attr_pairs


def ordinary(client, server, path, flags=(), code=69, body=None, token_length=8):
    with Server(server, "udp") as service:
        with Proxy(service.number, "profiles") as relay:
            ACTIVE_CAPTURES.append(relay.trace)
            result = execute(client, relay.number, path, flags)
            expect(result, code, body)
        trace = relay.trace
        wire_path = [b"escaped", b"a/b"] if path == "escaped" else [part.encode() for part in path.split("/")]
        first, replies = exchange_identity(trace, wire_path, code, token_length)
        if path == "escaped":
            require(decoded_options(first).get(15) == [b"key=a&b"], "URI query split/decoded incorrectly")
        if path == ".well-known/core":
            require(decoded_options(replies[0]).get(12) == [b"("], "discovery format changed")
            metadata_body(bytes.fromhex(result["payload_hex"]))
        # A fresh compact request after every case proves the server is reusable.
        fresh = request(client, "udp", service.number)
        expect(fresh)
        return {"result": result, "trace": trace, "fresh": fresh}


def probe(client, server):
    with Server(server, "udp") as service:
        with Proxy(service.number, "profiles") as relay:
            ACTIVE_CAPTURES.append(relay.trace)
            result = execute(client, relay.number, "test", ["token:32", "token-probe"])
        require(result["event"] == "probe" and result["outcome"].startswith("Supported("), "probe not supported")
        require(result["length"] == 32, "wrong tested length")
        trace = relay.trace
        validate_trace(trace)
        probes = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "request" and len(packet_token(bytes.fromhex(row["hex"]))) == 32]
        require(probes, "missing probe")
        first = probes[0]
        require((first[0] >> 4) & 3 == 0 and first[1] == 1 and decoded_options(first) == {5: [b""]} and coap_payload(first) == b"", "noncanonical support probe")
        replies = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "response"]
        require(any(packet_token(value) == packet_token(first) and value[1] != 0 for value in replies), "probe identity not echoed")
        fresh = request(client, "udp", service.number)
        expect(fresh)
        return {"result": result, "trace": trace, "fresh": fresh}


def observation(client, server, initial=0, valid=False, qblock=False):
    def complete_epoch(trace, epoch):
        for row in trace:
            if row["direction"] != "response":
                continue
            wire = bytes.fromhex(row["hex"])
            if wire[1] not in (67, 69):
                continue
            options = decoded_options(wire)
            if options.get(4) != [bytes([epoch + 1])]:
                continue
            block = options.get(31 if qblock else 23, [b""])[0]
            if wire[1] == 67 or not int.from_bytes(block, "big") & 8:
                return True
        return False

    def wait_epoch(relay, epoch):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if complete_epoch(relay.trace, epoch):
                return
            time.sleep(.01)
        raise AssertionError(f"epoch {epoch} did not finish")

    with Server(server, "udp") as service:
        with Proxy(service.number, "profiles") as relay:
            ACTIVE_CAPTURES.append(relay.trace)
            flags = ["observe", f"block2:{initial}"]
            if qblock:
                flags = ["observe", "qblock2"]
            if valid:
                flags.append("initial-valid")
            proc = subprocess.Popen(command(client, "client", "udp", relay.number, path="obs-large", timeout=15000) + flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for epoch in (0, 1):
                    wait_epoch(relay, epoch)
                    expect(request(client, "udp", service.number, path="obs-large", method="POST"), 68, b"")
                output, error = proc.communicate(timeout=20)
                ACTIVE_COMMANDS.append({"argv": list(map(str, proc.args)), "exit_code": proc.returncode,
                                        "stdout": output.decode(errors="replace"), "stderr": error.decode(errors="replace")})
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            require(proc.returncode == 0 and len(output) <= 65536 and len(output.splitlines()) == 1, f"observation failed: {output[:500]!r} {error[-500:]!r}")
            result = json.loads(output)
            result["exit_code"] = proc.returncode
            first_body = b"" if valid else b"a" * 96
            expect(result, 69, first_body + b"," + b"b" * 96 + b"," + b"c" * 96)
        trace = relay.trace
        first, replies = exchange_identity(trace, [b"obs-large"], 67 if valid else 69)
        require(decoded_options(first).get(6) == [b""], "registration omitted Observe")
        require(decoded_options(first).get(23) == [bytes([(initial << 4) | 1])], "wrong initial Block2 selector")
        wire_replies = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "response"]
        for epoch in range(3):
            packets = [wire for wire in wire_replies if decoded_options(wire).get(4) == [bytes([epoch + 1])]]
            starts = [wire for wire in packets if 6 in decoded_options(wire)]
            require(starts, "missing Observe epoch start")
            require(packet_token(starts[0]) == packet_token(first), "notification token changed")
            if valid and epoch == 0:
                require(starts[0][1] == 67 and not coap_payload(starts[0]), "initial Valid contract changed")
                continue
            chunks = {}
            for wire in packets:
                require(wire[1] == 69, "wrong representation code")
                options = decoded_options(wire)
                block = int.from_bytes(options.get(23, [b""])[0], "big")
                require(block & 7 == 1, "negotiated block size changed")
                num = block >> 4
                payload = coap_payload(wire)
                require(payload == bytes([ord('a') + epoch]) * 32, "representation payload changed")
                require(bool(block & 8) == (num < 2), "wrong final-block marker")
                require(chunks.setdefault(num, payload) == payload, "inconsistent repeated block")
            require(set(chunks) == {0, 1, 2}, "whole Observe representation missing blocks")
            require(int.from_bytes(decoded_options(starts[0]).get(23, [b""])[0], "big") >> 4 == 0,
                    "Observe epoch did not start at block zero")
        require(all(complete_epoch(trace, epoch) for epoch in range(3)), "missing complete epoch")
        fresh = request(client, "udp", service.number)
        expect(fresh)
        return {"result": result, "trace": trace, "fresh": fresh, "initial_block": initial, "initial_valid": valid, "qblock": qblock}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("coaptic", "coap-rs", "libcoap", "build-record", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    identity = source_identity()
    require(not identity["dirty"] and not identity["suite_dirty"], "source must be committed and clean")
    peers = {"coaptic": args.coaptic.resolve(), "coap-rs": args.coap_rs.resolve(), "libcoap": args.libcoap.resolve()}
    builds = json.loads(args.build_record.read_text(encoding="utf-8"))
    require(builds["source"] == identity["source"] and builds["suite_source"] == identity["suite_source"], "build sources do not match")
    binaries = {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in peers.items()}
    require(builds["executables"] == binaries, "binary build identity mismatch")
    report = {"schema": "coaptic-independent-profiles/1", **identity, "platform": platform.platform(), "executables": binaries, "build_record": builds, "aiocoap": importlib.metadata.version("aiocoap"), "security": "unprotected", "capture_limit": 256, "cases": [], "unqualified": ["protected profiles", "routed/scoped IPv6", "independent EDHOC", "physical execution"]}
    cases = []
    for left, right in (("coaptic", "libcoap"), ("libcoap", "coaptic")):
        client, server = peers[left], peers[right]
        cases.extend([
            (f"metadata:{left}->{right}", lambda c=client,s=server: ordinary(c,s,".well-known/core")),
            (f"uri:{left}->{right}", lambda c=client,s=server: ordinary(c,s,"escaped",body=b"uri-identity")),
            (f"token32:{left}->{right}", lambda c=client,s=server: ordinary(c,s,"test",["token:32"],body=b"core-test-payload",token_length=32)),
            (f"observe-large:{left}->{right}", lambda c=client,s=server: observation(c,s)),
            (f"observe-valid:{left}->{right}", lambda c=client,s=server: observation(c,s,valid=True)),
            (f"observe-nonzero:{left}->{right}", lambda c=client,s=server: observation(c,s,initial=1)),
        ])
    cases.extend([
        ("token64-refusal:libcoap->coaptic", lambda: ordinary(peers["libcoap"],peers["coaptic"],"test",["token:64"],code=128,body=b"",token_length=64)),
        ("token-probe:coaptic->libcoap", lambda: probe(peers["coaptic"],peers["libcoap"])),
        ("compact:coap-rs->coaptic", lambda: ordinary(peers["coap-rs"],peers["coaptic"],"test",body=b"core-test-payload")),
        ("compact:coaptic->coap-rs", lambda: ordinary(peers["coaptic"],peers["coap-rs"],"test",body=b"core-test-payload")),
    ])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for name, work in cases:
        ACTIVE_CAPTURES.clear()
        ACTIVE_COMMANDS.clear()
        try:
            detail = work()
            row = {"id": name, "passed": True, "evidence": detail}
        except Exception as error:
            row = {"id": name, "passed": False, "error": repr(error),
                   "captures": list(ACTIVE_CAPTURES), "commands": list(ACTIVE_COMMANDS)}
        report["cases"].append(row)
        report["passed"] = len(report["cases"]) == len(cases) and all(case["passed"] for case in report["cases"])
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(("PASS " if row["passed"] else "FAIL ") + name + ("" if row["passed"] else " " + row["error"]), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
