"""Finite protected explicit cancellation and fresh-registration qualification."""
import json
import subprocess
import time

from oscore_observe import (ObserveRelay, authenticated_notifications, observer_grade,
                            exchange_grade, opts)
from oscore_qblock1 import require, request_plain, response_plain, FixtureContext, incoming
from oscore_qblock2 import loopback_endpoint, relay_endpoints
from run import Proxy, Server, command, decode, expect, packet_token, decoded_options, request


def cancellation_plain(wire):
    """Retain authenticated Inner Observe before aiocoap normalizes cancellation.

    aiocoap 0.4.16 removes Observe from a returned cancellation request. Its
    post-decrypt hook exposes the verified plaintext before that normalization;
    its own message decoder parses the Inner Code/options/payload here.
    """
    import aiocoap

    class Context(FixtureContext):
        def _post_decrypt_checks(self, aad, plaintext, protected_message, request_id):
            super()._post_decrypt_checks(aad, plaintext, protected_message, request_id)
            self.inner = aiocoap.Message.decode(b"\x40" + plaintext[:1] + b"\x00\x00" + plaintext[1:])

    try:
        context = Context(server=True)
        _, binding = context.unprotect(incoming(wire))
        return context.inner, binding
    except Exception as error:
        raise AssertionError("cancellation request authentication failed") from error


def requests(trace):
    return [(index, bytes.fromhex(row["hex"])) for index, row in enumerate(trace)
            if row["direction"] == "request" and bytes.fromhex(row["hex"])[1] == 5]


def cancellation_grade(trace, endpoints, original):
    """Authenticate a complete ordinary GET after matching-token Observe=1."""
    require(2 <= len(trace) <= 4, "incomplete/unbounded cancellation exchange")
    front, back, server = (loopback_endpoint(endpoints[k], "ipv4")
                           for k in ("front", "back", "server"))
    client = loopback_endpoint(trace[0]["source"], "ipv4")
    require(len({front, back, server, client}) == 4, "overlapping cancellation owners")
    req = bytes.fromhex(trace[0]["hex"])
    plain, binding = cancellation_plain(req)
    registered, old_binding = request_plain(original)
    require(req[0] >> 4 & 3 == 0 and req[1] == 5 and packet_token(req) == packet_token(original)
            and req[2:4] != original[2:4] and binding.partial_iv != old_binding.partial_iv,
            "cancellation token/MID/request binding mismatch")
    require(int(plain.code) == 1 and not plain.payload and opts(plain) == {6: [b"\x01"], 11: [b"counter"]}
            and opts(registered) == {6: [b""], 11: [b"counter"]}, "wrong authenticated cancellation target")
    require(set(decoded_options(req)) == {6, 9} and decoded_options(req)[6] == [b"\x01"], "wrong cancellation outer options")
    waiting = True
    pending = None
    response = None
    previous = -1
    for index, row in enumerate(trace):
        direction = row["direction"]
        require(direction in ("request", "response") and row["action"] == "forward"
                and row["hex"] == row["forwarded_hex"], "cancellation relay fault")
        require(tuple(loopback_endpoint(row[k], "ipv4") for k in ("source", "destination", "relay")) ==
                ((client, server, back) if direction == "request" else (server, client, front)), "cancellation owner mismatch")
        at = row["time_ns"]
        require(type(at) is int and at > previous and at >= 0, "cancellation clock mismatch")
        previous = at
        wire = bytes.fromhex(row["hex"])
        require(4 <= len(wire) <= 4096 and wire[0] >> 6 == 1, "invalid cancellation datagram")
        if index == 0:
            require(direction == "request", "cancellation must begin with request")
            continue
        if direction == "request":
            require(pending is not None and wire == b"\x60\x00" + pending, "wrong cancellation client ACK")
            pending = None
        elif wire[1] == 0:
            require(waiting and wire == b"\x60\x00" + req[2:4], "wrong cancellation server ACK")
            waiting = False
        else:
            require(response is None and wire[1] == 69 and packet_token(wire) == packet_token(req)
                    and set(decoded_options(wire)) == {9}, "wrong cancellation response owner/options")
            ty = wire[0] >> 4 & 3
            if ty == 2:
                require(waiting and wire[2:4] == req[2:4], "wrong cancellation piggyback MID")
                waiting = False
            else:
                require(ty == 0 and not waiting, "wrong cancellation separate response")
                pending = wire[2:4]
            response = response_plain(wire, req)
            require(int(response.code) == 69 and response.payload == b"1" and 6 not in opts(response)
                    and set(opts(response)) <= {4, 12, 14}, "cancellation did not return ordinary current representation")
    require(response is not None and not waiting and pending is None, "unsettled cancellation")
    return bytes(binding.partial_iv).hex()


def review(record, patch):
    expect(record["setup"], 69, b"0")
    ready = record["server_ready"]
    require(ready.get("transport") == "oscore" and ready.get("libcoap_patch_sha256") == patch["patch_sha256"], "peer provenance changed")
    trace, endpoints = record["trace"], record["endpoints"]
    require(10 <= len(trace) <= 128, "lifecycle trace outside bound")
    server = loopback_endpoint(("127.0.0.1", ready["port"]), "ipv4")
    require(tuple(endpoints["server"]) == server, "server changed")
    client = loopback_endpoint(trace[0]["source"], "ipv4")
    for row in trace:
        require(row["direction"] in ("request", "response")
                and loopback_endpoint(row["source"] if row["direction"] == "request" else row["destination"], "ipv4") == client,
                "lifecycle client endpoint changed")
    expect(record["result"], 69, b"0,1,1,2,3,4")
    reqs = requests(trace)
    require(len(reqs) == 3 and reqs[0][0] == 0, "missing/extra lifecycle request")
    require(len({wire[2:4] for _, wire in reqs}) == 3, "lifecycle client request MID reused")
    server_mids = set()
    for row in trace:
        wire = bytes.fromhex(row["hex"])
        if row["direction"] == "response" and wire[1] != 0 and wire[0] >> 4 & 3 in (0, 1):
            require(wire[2:4] not in server_mids, "lifecycle server MID reused")
            server_mids.add(wire[2:4])
    cancel_at, cancel = reqs[1]
    fresh_at, fresh = reqs[2]
    before, cancelled, after = trace[:cancel_at], trace[cancel_at:fresh_at], trace[fresh_at:]
    result = lambda body: dict(event="response", exit_code=0, code=69, payload_hex=body.hex())
    initial = observer_grade(before, result(b"0,1"), endpoints, 0, False, count=2)
    cancellation_piv = cancellation_grade(cancelled, endpoints, reqs[0][1])
    fresh_proof = observer_grade(after, result(b"2,3,4"), endpoints, 2, False)
    require(packet_token(fresh) != packet_token(cancel), "fresh registration reused cancelled token")
    previous = -1
    for row in trace:
        require(row["time_ns"] > previous, "lifecycle phases overlap/reorder")
        previous = row["time_ns"]
    require(trace[-1]["time_ns"] - trace[0]["time_ns"] < 20_000_000_000, "lifecycle duration exceeds bound")
    require(after[0]["time_ns"] - cancelled[-1]["time_ns"] >= 2_500_000_000, "missing bounded cancellation hold")
    writes = record["writes"]
    require(len(writes) == 4, "missing resource updates")
    pivs = [initial["request_piv"], cancellation_piv, fresh_proof["request_piv"]]
    for write in writes:
        pivs.append(exchange_grade(write, 2, b"", server))
    pivs.append(exchange_grade(record["quiet_readback"], 1, b"2", server))
    require(len(set(pivs)) == len(pivs), "reused protected request binding")
    require(not set(initial["response_pivs"]).intersection(fresh_proof["response_pivs"]), "notification nonce reused")
    from aiocoap import oscore
    server_pivs = set()
    for part in [trace, *(write["trace"] for write in writes), record["quiet_readback"]["trace"]]:
        for row in part:
            wire = bytes.fromhex(row["hex"])
            if row["direction"] == "response" and wire[1] != 0:
                _, _, cose, _ = oscore.CanUnprotect._extract_encrypted0(incoming(wire))
                piv = cose.get(oscore.COSE_PIV)
                if piv is not None:
                    require(isinstance(piv, bytes) and 1 <= len(piv) <= 5 and piv not in server_pivs,
                            "server response PIV reused across lifecycle/exchanges")
                    server_pivs.add(piv)
    intervals = [(initial["notification_times_ns"][0], initial["notification_times_ns"][1]),
                 (cancelled[-1]["time_ns"], after[0]["time_ns"]),
                 (fresh_proof["notification_times_ns"][0], fresh_proof["notification_times_ns"][1]),
                 (fresh_proof["notification_times_ns"][1], fresh_proof["notification_times_ns"][2])]
    for write, (left, right) in zip(writes, intervals):
        require(left < write["trace"][0]["time_ns"] and write["trace"][-1]["time_ns"] < right,
                "resource update outside required lifecycle interval")
    readback = record["quiet_readback"]["trace"]
    require(writes[1]["trace"][-1]["time_ns"] < readback[0]["time_ns"]
            and readback[-1]["time_ns"] < after[0]["time_ns"], "missing authenticated quiet-interval effect")
    return {"same_server": list(server), "complete_bodies": ["0", "1", "1", "2", "3", "4"],
            "quiet_interval_ns": after[0]["time_ns"] - cancelled[-1]["time_ns"],
            "request_pivs": pivs, "scope": "finite IPv4 loopback explicit cancellation; no enrollment, power-loss, routed-network or sustained-availability qualification"}


def campaign(client, server, record, patch):
    record["writes"] = []
    with Server(server, "oscore") as service:
        record["server_ready"] = service.ready
        require(service.ready.get("libcoap_patch_sha256") == patch["patch_sha256"], "peer patch mismatch")
        # Establish the fixture's replay window before the measured Observe
        # exchange, including any authenticated Echo recovery challenge.
        record["setup"] = request(client, "oscore", service.number, sequence=0, path="counter")
        expect(record["setup"], 69, b"0")
        relay = ObserveRelay(service.number)
        proc = None

        def wait_until(predicate):
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                if predicate(relay.snapshot()):
                    return
                require(proc.poll() is None, "lifecycle client exited before required step")
                time.sleep(.01)
            raise AssertionError("lifecycle wait exceeded finite deadline")

        def ordinary(record, method, sequence):
            r = Proxy(service.number, "pass")
            try:
                with r:
                    record["endpoints"] = relay_endpoints(r, "ipv4")
                    record["result"] = request(client, "oscore", r.number, path="counter", method=method, sequence=sequence)
            finally:
                record["trace"] = r.trace

        def write(sequence):
            entry = {}
            record["writes"].append(entry)
            ordinary(entry, "POST", sequence)

        try:
            with relay:
                record["endpoints"] = relay_endpoints(relay, "ipv4")
                args = command(client, "client", "oscore", relay.number, path="counter", sequence=100, timeout=15000)
                proc = subprocess.Popen(args + ["observe-cancel"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                wait_until(lambda t: len(authenticated_notifications(t)) >= 1)
                # Fixture processes share one sender identity. Allocate distinct
                # nearby sequences (100..102 lifecycle, 110..114 writers) so
                # interleaving stays inside libcoap's 32-entry replay window.
                write(110)
                # A settled authenticated cancellation includes its response and
                # any required ACK before the independent writer changes state.
                def settled(t):
                    rs = requests(t)
                    if len(rs) != 2:
                        return False
                    try:
                        cancellation_grade(t[rs[1][0]:], record["endpoints"], rs[0][1])
                        return True
                    except AssertionError:
                        return False
                wait_until(settled)
                write(111)
                record["quiet_readback"] = {}
                ordinary(record["quiet_readback"], "GET", 112)
                wait_until(lambda t: len(requests(t)) == 3 and len(authenticated_notifications(t[requests(t)[2][0]:])) >= 1)
                write(113)
                wait_until(lambda t: len(authenticated_notifications(t[requests(t)[2][0]:])) >= 2)
                write(114)
                out, err = proc.communicate(timeout=17)
                require(len(out.splitlines()) == 1, "lifecycle client must report exactly one outcome")
                record["result"] = decode(out.splitlines()[0])
                record["result"]["exit_code"] = proc.returncode
                record["stderr_tail"] = err[-2000:].decode(errors="replace")
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.communicate()
            record["trace"] = relay.snapshot()
    record["proof"] = review(record, patch)
    record["complete"] = True


def main():
    import argparse
    import hashlib
    import platform
    from pathlib import Path
    from run import source_identity
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("coaptic", "libcoap", "libcoap-patch-manifest", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    patch = json.loads(args.libcoap_patch_manifest.read_text())
    report = {"schema": "coaptic-protected-observe-cancellation/1", **source_identity(),
              "platform": platform.platform(), "libcoap_patch": patch,
              "libcoap_source": "851533c3cf63d16984d370ce39d586ecb3694971",
              "executables": {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for name, path in (("coaptic", args.coaptic), ("libcoap", args.libcoap))},
              "qualification_complete": False, "campaign": {}}
    try:
        campaign(args.coaptic.resolve(), args.libcoap.resolve(), report["campaign"], patch)
        report["qualification_complete"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps({"qualification_complete": report["qualification_complete"], "report": str(args.output)}))
    return 0 if report["qualification_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
