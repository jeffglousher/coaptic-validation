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

class EvidenceServer(Server):
    """Keep bounded failure diagnostics before Server closes its temporary file."""
    def __exit__(self, kind, value, traceback):
        failure = None
        try:
            if kind is not None:
                self.stderr.seek(0)
                diagnostic = self.stderr.read(65537)
                failure = {"role": "server", "argv": list(map(str, self.proc.args)),
                           "exit_code_before_cleanup": self.proc.poll(),
                           "stderr": diagnostic[:65536].decode(errors="replace"),
                           "stderr_truncated": len(diagnostic) > 65536}
        finally:
            try:
                super().__exit__(kind, value, traceback)
            finally:
                if failure is not None:
                    diagnostic = bytes(self.stdout_after_ready)
                    failure.update(stdout_after_ready=diagnostic.decode(errors="replace"),
                                   stdout_after_ready_hex=diagnostic.hex(),
                                   stdout_after_ready_truncated=self.stdout_after_ready_truncated,
                                   stdout_after_ready_complete=self.stdout_after_ready_complete,
                                   stdout_after_ready_error=self.stdout_after_ready_error)
                    ACTIVE_COMMANDS.append(failure)


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


def exchange_identity(trace, path, code, token_length=None, method_code=1):
    validate_trace(trace)
    candidates = []
    for row in trace:
        packet = bytes.fromhex(row["hex"])
        if row["direction"] == "request" and packet[1] == method_code and decoded_options(packet).get(11, []) == path:
            if (0 <= len(packet_token(packet)) <= 8) if token_length is None else len(packet_token(packet)) == token_length:
                candidates.append(packet)
    require(candidates, "missing exact request path/token length")
    first = candidates[0]
    replies = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "response"]
    matching = [packet for packet in replies if packet[1] == code and packet_token(packet) == packet_token(first)]
    require(matching, "missing exact complete token response")
    for packet in matching:
        if (packet[0] >> 4) & 3 == 2:
            require(any(packet[2:4] == sent[2:4] and packet_token(packet) == packet_token(sent) for sent in candidates), "wrong piggyback MID")
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
    pairs = sensors[0].attr_pairs
    for name in ("rt", "if", "ct", "sz", "obs", "title"):
        require(sum(key == name for key, _ in pairs) == 1, "missing or duplicate named metadata")
    attributes = dict(pairs)
    require(attributes.get("rt", "").split() == ["temperature-c", "sensor"], "resource types changed")
    require(attributes.get("if") == "sensor", "interface changed")
    require(attributes.get("ct", "").split() == ["0", "50"], "content formats changed")
    require(attributes.get("sz") == "96" and "obs" in attributes, "size/observable metadata changed")
    require(attributes.get("title") == 'Room "one"', "quoted extension changed")
    return sensors[0].href, sensors[0].attr_pairs


def ordinary(client, server, path, flags=(), code=69, body=None, token_length=None):
    with Server(server, "udp") as service:
        with Proxy(service.number, "profiles") as relay:
            ACTIVE_CAPTURES.append(relay.trace)
            result = execute(client, relay.number, path, flags)
            expect(result, code, body)
        trace = relay.trace
        wire_path = [b"escaped", b"a/b"] if path == "escaped" else [part.encode() for part in path.split("/")]
        first, replies = exchange_identity(trace, wire_path, code, token_length)
        if "observe" in flags:
            require(decoded_options(first).get(6) == [b""], "refusal request omitted Observe")
            for flag in flags:
                if flag.startswith("block2:"):
                    selector = (int(flag.split(":")[1]) << 4) | 1
                    require(decoded_options(first).get(23) == [bytes([selector])], "refusal request changed initial block")
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


def native_capacity_refusal(client, server):
    # libcoap probes its configured bound before the application request. Its
    # public API then refuses the over-capacity send; grade that exact exchange.
    with Server(server, "udp") as service:
        with Proxy(service.number, "profiles") as relay:
            ACTIVE_CAPTURES.append(relay.trace)
            argv = command(client, "client", "udp", relay.number, timeout=6000) + ["token:64"]
            process = subprocess.run(argv, capture_output=True, timeout=10)
            evidence = {"argv": list(map(str, argv)), "exit_code": process.returncode,
                        "stdout": process.stdout.decode(), "stderr": process.stderr.decode()}
            ACTIVE_COMMANDS.append(evidence)
            require(process.returncode != 0, "native send unexpectedly accepted refused bound")
        first, replies = exchange_identity(relay.trace, [], 128, 64)
        require(decoded_options(first) == {5: [b""]}, "not the native capacity probe")
        require(not coap_payload(replies[0]), "capacity refusal payload changed")
        fresh = request(client, "udp", service.number)
        expect(fresh)
        return {"native_send": evidence, "trace": relay.trace, "fresh": fresh, "refused_length": 64}


def grade_fetch_continuation(wire):
    options = decoded_options(wire)
    require(wire[1] == 5 and options.get(11) == [b"obs-selected"] and
            options.get(12) == [b"*"] and not options.get(15) and
            coap_payload(wire) == b"left", "FETCH continuation changed selection/format/URI")


def grade_q_notification_epoch(packets, requests, token, body_size, blocks):
    notifications = [wire for wire in packets if 6 in decoded_options(wire)]
    require(notifications, "Q notification epoch absent")
    sequence = decoded_options(notifications[0])[6]
    nums = set()
    for wire in packets:
        options = decoded_options(wire)
        require(packet_token(wire) == token, "Q epoch response owner changed")
        require(options.get(28) == [body_size.to_bytes((body_size.bit_length()+7)//8, "big")],
                "Q Size2 changed")
        if 6 in options:
            require((wire[0] >> 4) & 3 == 0 and options[6] == sequence, "Q notification changed CON/epoch")
            require(b"\x60\x00" + wire[2:4] in requests, "Q notification lacks exact ACK")
            nums.add(int.from_bytes(options[31][0], "big") >> 4)
        else:
            # A final native cancellation can return current block0 with the
            # same ETag. It is solicited work, not an unsolicited notification.
            owners = [sent for sent in requests if sent[1] == 1 and packet_token(sent) == token and
                      decoded_options(sent).get(6) == [b"\x01"] and
                      decoded_options(sent).get(11) == [b"obs-q"] and not decoded_options(sent).get(15) and not coap_payload(sent)]
            require(len(options.get(31, [])) == 1 and int.from_bytes(options[31][0], "big") >> 4 == 0,
                    "Q cancellation response changed block")
            require(any((((sent[0] >> 4) & 3 == 1) and ((wire[0] >> 4) & 3 == 1)) or
                        (((sent[0] >> 4) & 3 == 0) and ((wire[0] >> 4) & 3 == 2) and sent[2:4] == wire[2:4])
                        for sent in owners), "unexplained non-Observe Q response")
    require(nums == set(range(blocks)), "Q CON notification omitted blocks")


def observation(client, server, initial=0, valid=False, qblock=False, selected=None, client_kind=None, server_kind=None):
    require(selected in (None, "query", "fetch"), "unknown selected profile")
    require(not (qblock and selected), "fixture profiles are separate")
    path = "obs-q" if qblock else "obs-selected" if selected else "obs-large"
    requested_q_szx = 6 if client_kind == "coaptic" else 1
    body_size = 704 if qblock else 96
    blocks = body_size // 32
    block_option = 31 if qblock else 23
    method = "FETCH" if selected == "fetch" else "GET"
    method_code = 5 if selected == "fetch" else 1
    selection_payload = b"left" if selected == "fetch" else b""
    def expected_etag(epoch):
        return bytes([(epoch + 1) * 2 if selected else epoch + 1])
    def complete_epoch(trace, epoch):
        for row in trace:
            if row["direction"] != "response":
                continue
            wire = bytes.fromhex(row["hex"])
            if wire[1] not in (67, 69):
                continue
            options = decoded_options(wire)
            if options.get(4) != [expected_etag(epoch)]:
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

    with EvidenceServer(server, "udp", path="obs-q" if qblock else "test") as service:
        with Proxy(service.number, "profiles") as relay:
            ACTIVE_CAPTURES.append(relay.trace)
            flags = ["observe", f"block2:{initial}"]
            if qblock:
                flags = ["observe", "qblock2"]
            if valid:
                flags.append("initial-valid")
            proc = subprocess.Popen(command(client, "client", "udp", relay.number, path=path, method=method, payload=selection_payload, timeout=15000) + flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            recorded = False
            try:
                for epoch in (0, 1):
                    wait_epoch(relay, epoch)
                    expect(request(client, "udp", service.number, path=path, method="POST"), 68, b"")
                output, error = proc.communicate(timeout=20)
                ACTIVE_COMMANDS.append({"argv": list(map(str, proc.args)), "exit_code": proc.returncode,
                                        "stdout": output.decode(errors="replace"), "stderr": error.decode(errors="replace")})
                recorded = True
            finally:
                if proc.poll() is None:
                    proc.kill()
                if not recorded:
                    output, error = proc.communicate()
                    ACTIVE_COMMANDS.append({"argv": list(map(str, proc.args)), "exit_code": proc.returncode,
                                            "stdout": output.decode(errors="replace"), "stderr": error.decode(errors="replace")})
            require(proc.returncode == 0 and len(output) <= 65536 and len(output.splitlines()) == 1, f"observation failed: {output[:500]!r} {error[-500:]!r}")
            result = json.loads(output)
            result["exit_code"] = proc.returncode
            first_body = b"" if valid else b"a" * body_size
            expect(result, 69, first_body + b"," + b"b" * body_size + b"," + b"c" * body_size)
        trace = relay.trace
        first, replies = exchange_identity(trace, [path.encode()], 67 if valid else 69, method_code=method_code)
        require(decoded_options(first).get(6) == [b""], "registration omitted Observe")
        require(decoded_options(first).get(block_option) == [bytes([8 | requested_q_szx if qblock else (initial << 4) | 1])], "wrong initial block selector")
        if qblock:
            require(23 not in decoded_options(first), "Q registration also carried classic Block2")
        if selected == "query":
            require(decoded_options(first).get(15) == [b"pick=left"] and not coap_payload(first), "GET selection changed")
        elif selected == "fetch":
            require(decoded_options(first).get(12) == [b"*"] and not decoded_options(first).get(15) and coap_payload(first) == b"left", "FETCH selection changed")
        wire_replies = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "response"]
        wire_requests = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "request"]
        if selected == "fetch":
            followups = [wire for wire in wire_requests if wire[1] == 5 and 23 in decoded_options(wire)
                         and int.from_bytes(decoded_options(wire)[23][0], "big") >> 4 > 0]
            require(followups, "FETCH profile omitted continuations")
            for followup in followups:
                grade_fetch_continuation(followup)
        for reply in wire_replies:
            if reply[1] and (reply[0] >> 4) & 3 == 2:
                require(any(sent[1] == method_code and sent[2:4] == reply[2:4] and packet_token(sent) == packet_token(reply)
                            for sent in wire_requests), "unowned Observe block response")
        previous_observe = None
        for epoch in range(3):
            packets = [wire for wire in wire_replies if decoded_options(wire).get(4) == [expected_etag(epoch)]]
            starts = [wire for wire in packets if 6 in decoded_options(wire)]
            require(starts, "missing Observe epoch start")
            require(packet_token(starts[0]) == packet_token(first), "notification token changed")
            sequence = int.from_bytes(decoded_options(starts[0])[6][0], "big")
            require(sequence <= 0xffffff, "invalid Observe serial")
            if previous_observe is not None:
                require(0 < (sequence - previous_observe) % (1 << 24) < (1 << 23), "Observe serial did not advance")
            previous_observe = sequence
            if valid and epoch == 0:
                require(starts[0][1] == 67 and not coap_payload(starts[0]), "initial Valid contract changed")
                continue
            chunks = {}
            for wire in packets:
                require(wire[1] == 69, "wrong representation code")
                options = decoded_options(wire)
                block = int.from_bytes(options.get(block_option, [b""])[0], "big")
                require(block & 7 == 1, "negotiated block size changed")
                num = block >> 4
                payload = coap_payload(wire)
                require(payload == bytes([ord('a') + epoch]) * 32, "representation payload changed")
                require(bool(block & 8) == (num < blocks - 1), "wrong final-block marker")
                require(chunks.setdefault(num, payload) == payload, "inconsistent repeated block")
            require(set(chunks) == set(range(blocks)), "whole Observe representation missing blocks")
            if qblock and epoch > 0:
                grade_q_notification_epoch(packets, wire_requests, packet_token(first), body_size, blocks)
            require(int.from_bytes(decoded_options(starts[0]).get(block_option, [b""])[0], "big") >> 4 == 0,
                    "Observe epoch did not start at block zero")
        require(all(complete_epoch(trace, epoch) for epoch in range(3)), "missing complete epoch")
        fresh = request(client, "udp", service.number)
        expect(fresh)
        service.stderr.seek(0)
        server_diagnostics = service.stderr.read(65537)
        require(len(server_diagnostics) <= 65536, "server diagnostic bound")
        if qblock:
            require(b"q_max_payloads=10" in server_diagnostics, "missing configured server Q window receipt")
        detail = {"result": result, "trace": trace, "fresh": fresh, "initial_block": initial, "initial_valid": valid, "qblock": qblock, "selection": selected, "body_bytes": body_size, "block_count": blocks, "server_ready": service.ready, "server_stderr": server_diagnostics.decode(errors="replace")}
    if qblock:
        detail.update(requested_szx=requested_q_szx, negotiated_szx=1, max_payloads=10)
    if selected or qblock:
        from observe_controls import selected_lifecycle, q_recovery_lifecycle
        with EvidenceServer(server, "udp", path="obs-q" if qblock else "test") as control_service:
            detail["independent_control"] = selected_lifecycle(control_service.number, selected, ACTIVE_CAPTURES, strict_refusal=server_kind == "coaptic") if selected else q_recovery_lifecycle(control_service.number, ACTIVE_CAPTURES)
    return detail


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("coaptic", "coap-rs", "libcoap", "build-record", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--case", action="append", help="Exact case IDs; omitted runs the finite matrix")
    args = parser.parse_args()
    identity = source_identity()
    require(not identity["dirty"] and not identity["suite_dirty"], "source must be committed and clean")
    peers = {"coaptic": args.coaptic.resolve(), "coap-rs": args.coap_rs.resolve(), "libcoap": args.libcoap.resolve()}
    builds = json.loads(args.build_record.read_text(encoding="utf-8"))
    require(builds["source"] == identity["source"] and builds["suite_source"] == identity["suite_source"], "build sources do not match")
    binaries = {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in peers.items()}
    require(builds["executables"] == binaries, "binary build identity mismatch")
    report = {"schema": "coaptic-independent-profiles/1", **identity, "platform": platform.platform(), "executables": binaries, "build_record": builds, "aiocoap": importlib.metadata.version("aiocoap"), "security": "per-case", "capture_limit": 256, "cases": [], "unqualified": ["protected profiles beyond named token boundary", "physical execution"]}
    cases = []
    for left, right in (("coaptic", "libcoap"), ("libcoap", "coaptic")):
        client, server = peers[left], peers[right]
        cases.extend([
            (f"metadata:{left}->{right}", lambda c=client,s=server: ordinary(c,s,".well-known/core")),
            (f"uri:{left}->{right}", lambda c=client,s=server: ordinary(c,s,"escaped",body=b"uri-identity")),
            (f"token32:{left}->{right}", lambda c=client,s=server: ordinary(c,s,"test",["token:32"],body=b"core-test-payload",token_length=32)),
            (f"observe-large:{left}->{right}", lambda c=client,s=server: observation(c,s)),
            (f"observe-selected-query:{left}->{right}", lambda c=client,s=server,r=right: observation(c,s,selected="query",server_kind=r)),
            (f"observe-selected-fetch:{left}->{right}", lambda c=client,s=server,r=right: observation(c,s,selected="fetch",server_kind=r)),
            (f"observe-con-q:{left}->{right}", lambda c=client,s=server,l=left,r=right: observation(c,s,qblock=True,client_kind=l,server_kind=r)),
            (f"observe-valid:{left}->{right}", lambda c=client,s=server: observation(c,s,valid=True)),
            (f"observe-nonzero:{left}->{right}", lambda c=client,s=server: observation(c,s,initial=1)),
        ])
    from protected_tokens import workflow as protected_token_workflow
    cases.extend([
        ("protected-token-boundary:libcoap->coaptic", lambda: protected_token_workflow(peers["libcoap"],peers["coaptic"],ACTIVE_CAPTURES,ACTIVE_COMMANDS)),
        ("token64-refusal:libcoap->coaptic", lambda: native_capacity_refusal(peers["libcoap"],peers["coaptic"])),
        ("observe-nonzero-refusal:coaptic->libcoap", lambda: ordinary(peers["coaptic"],peers["libcoap"],"obs-large",["observe","block2:1"],code=128,body=b"")),
        ("token-probe:coaptic->libcoap", lambda: probe(peers["coaptic"],peers["libcoap"])),
        ("compact:coap-rs->coaptic", lambda: ordinary(peers["coap-rs"],peers["coaptic"],"test",body=b"core-test-payload")),
        ("compact:coaptic->coap-rs", lambda: ordinary(peers["coaptic"],peers["coap-rs"],"test",body=b"core-test-payload")),
    ])
    if args.case:
        require(set(args.case) <= {name for name, _ in cases}, "unknown selected case")
        cases = [(name, work) for name, work in cases if name in args.case]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for name, work in cases:
        ACTIVE_CAPTURES.clear()
        ACTIVE_COMMANDS.clear()
        try:
            detail = work()
            row = {"id": name, "security": "oscore" if name.startswith("protected-token-") else "unprotected", "passed": True, "evidence": detail}
        except Exception as error:
            row = {"id": name, "security": "oscore" if name.startswith("protected-token-") else "unprotected", "passed": False, "error": repr(error),
                   "captures": list(ACTIVE_CAPTURES), "commands": list(ACTIVE_COMMANDS)}
        report["cases"].append(row)
        report["passed"] = len(report["cases"]) == len(cases) and all(case["passed"] for case in report["cases"])
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(("PASS " if row["passed"] else "FAIL ") + name + ("" if row["passed"] else " " + row["error"]), flush=True)
    report["source_after"] = source_identity()
    report["source_unchanged"] = report["source_after"] == identity
    report["passed"] = report["passed"] and report["source_unchanged"]
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
