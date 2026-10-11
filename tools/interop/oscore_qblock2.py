"""Authenticated independent Q-Block2 baseline; loss qualification is separate."""
from oscore_qblock1 import request_plain, response_plain, require, incoming
from aiocoap import oscore


def baseline_grade(trace, result, endpoints, *, partial=False):
    from run import LARGE, decoded_options, block1_fields, packet_token, expect
    if partial:
        from run import expect_refusal
        expect_refusal(result)
        require(not result.get("payload_hex") and "code" not in result, "timeout claimed a response")
    else:
        expect(result, 69, LARGE)
    require(1 <= len(trace) <= 256, "baseline trace outside bound")
    def endpoint(value):
        require(isinstance(value, (list, tuple)) and len(value) == 2
                and value[0] == "127.0.0.1" and type(value[1]) is int
                and 0 < value[1] < 65536, "not exact IPv4 loopback endpoint")
        return tuple(value)
    front, back, server = (endpoint(endpoints[k]) for k in ("front", "back", "server"))
    client = endpoint(trace[0]["source"])
    require(len({front, back, server, client}) == 4, "overlapping endpoint owners")
    latest = None
    request_pending = False
    server_pending = None
    token = etag = None
    request_mids, response_mids, pivs, response_pivs = set(), set(), set(), set()
    body = bytearray()
    forms = []
    previous = -1
    for row in trace:
        direction = row["direction"]
        require(direction in ("request", "response") and row["action"] == "forward",
                "baseline requires forwarded packets")
        actual = tuple(endpoint(row[k]) for k in ("source", "destination", "relay"))
        require(actual == ((client, server, back) if direction == "request" else (server, client, front)),
                "endpoint ownership mismatch")
        at = row["time_ns"]
        require(type(at) is int and at >= 0 and at >= previous
                and at - trace[0]["time_ns"] <= 8_000_000_000, "invalid baseline time")
        previous = at
        require(row["hex"] == row["forwarded_hex"], "relay changed protected bytes")
        wire = bytes.fromhex(row["hex"])
        require(4 <= len(wire) <= 4096 and wire[0] >> 6 == 1
                and wire[0] & 15 <= 8, "invalid bounded packet")
        mid, ty = wire[2:4], (wire[0] >> 4) & 3
        if direction == "request":
            if wire[1] == 0:
                require(server_pending is not None and wire == b"\x60\x00" + server_pending,
                        "client ACK does not own outstanding server CON")
                server_pending = None
                continue
            require(not request_pending and server_pending is None and ty == 0 and wire[1] == 2
                    and mid not in request_mids and set(decoded_options(wire)) == {9},
                    "unexpected protected request ownership")
            plain, binding = request_plain(wire)
            options = {}
            for option in plain.opt.option_list():
                options.setdefault(int(option.number), []).append(option.encode())
            require(int(plain.code) == 1 and plain.payload == b"" and set(options) == {11, 31}
                    and options[11] == [b"large"] and len(options[31]) == 1,
                    "authenticated request is not Q-Block2 GET")
            num, more, szx = block1_fields(options[31][0])
            require(szx == 6 and num * 1024 == len(body) and (latest is not None or more),
                    "request does not select current SZX1024 body range")
            require(token is None or token == packet_token(wire), "request token changed")
            require(packet_token(wire) and bytes(binding.partial_iv) not in pivs, "missing token or reused PIV")
            token = packet_token(wire)
            pivs.add(bytes(binding.partial_iv))
            request_mids.add(mid)
            latest, request_pending = wire, True
            continue
        require(latest is not None, "response without active request")
        if wire[1] == 0:
            require(request_pending and wire == b"\x60\x00" + latest[2:4],
                    "empty ACK owner mismatch")
            request_pending = False
            forms.append("empty request ACK")
            continue
        require(wire[1] == 68 and packet_token(wire) == token and set(decoded_options(wire)) == {9},
                "response token/protection mismatch")
        if ty == 2:
            require(request_pending and mid == latest[2:4], "piggybacked response owner mismatch")
            request_pending = False
            forms.append("piggybacked content")
        else:
            require(ty == 0 and not request_pending and server_pending is None
                    and mid not in response_mids and mid not in request_mids,
                    "separate CON violates owner/NSTART")
            server_pending = mid
            response_mids.add(mid)
            forms.append("separate CON content")
        plain = response_plain(wire, latest)
        # Authentication first; parse the explicit sender PIV with the pinned decoder.
        _, _, cose, _ = oscore.CanUnprotect._extract_encrypted0(incoming(wire))
        piv = cose.get(oscore.COSE_PIV)
        require(isinstance(piv, bytes) and 1 <= len(piv) <= 5 and piv not in response_pivs,
                "distinct Q responses require distinct explicit server PIVs")
        response_pivs.add(piv)
        options = {}
        for option in plain.opt.option_list():
            options.setdefault(int(option.number), []).append(option.encode())
        require(int(plain.code) == 69 and set(options) <= {4, 12, 14, 28, 31}
                and len(options.get(31, [])) == 1 and options.get(12) == [b"*"]
                and options.get(28) == [b"\x07\xd0"] and len(options.get(4, [])) == 1,
                "authenticated representation options mismatch")
        tag = options[4][0]
        require(1 <= len(tag) <= 8 and (etag is None or tag == etag), "missing or changed ETag")
        etag = tag
        num, more, szx = block1_fields(options[31][0])
        require(szx == 6 and num * 1024 == len(body) and num in (0, 1)
                and more == (num == 0) and plain.payload == LARGE[num * 1024:(num + 1) * 1024],
                "authenticated Q-Block2 body mismatch")
        body.extend(plain.payload)
    require(bytes(body) == (LARGE[:1024] if partial else LARGE) and not request_pending and server_pending is None,
            "incomplete body or unsettled CON")
    return {"body_bytes": len(body), "etag_hex": etag.hex(), "response_forms": forms,
            "request_count": len(request_mids), "server_pivs": sorted(p.hex() for p in response_pivs), "scope": "baseline only; loss/refusal/recovery not yet qualified"}



def later_response(wire, trace):
    """Authenticate the intact later block; the relay never rewrites ciphertext."""
    from run import block1_fields
    requests = [bytes.fromhex(r["hex"]) for r in trace
                if r["direction"] == "request" and r["action"] == "forward"
                and bytes.fromhex(r["hex"])[1] == 2]
    require(requests, "response without forwarded protected request")
    plain = response_plain(wire, requests[-1])
    q = [o.encode() for o in plain.opt.option_list() if int(o.number) == 31]
    return int(plain.code) == 69 and len(q) == 1 and block1_fields(q[0])[0] == 1


def campaign_grade(trace, result, endpoints, mode):
    """Finite pinned CON form: intact later-response loss, never synthetic recovery."""
    from run import LARGE, decoded_options, packet_token, coap_payload, expect_refusal
    require(mode in ("baseline", "drop-once", "drop-permanent", "wrong-key"), "unknown campaign mode")
    require(1 <= len(trace) <= 256, "campaign trace outside bound")
    def endpoint(value):
        require(isinstance(value, (list, tuple)) and len(value) == 2
                and value[0] == "127.0.0.1" and type(value[1]) is int
                and 0 < value[1] < 65536, "not exact IPv4 endpoint")
        return tuple(value)
    front, back, server = (endpoint(endpoints[k]) for k in ("front", "back", "server"))
    client = endpoint(trace[0]["source"])
    require(len({front, back, server, client}) == 4, "overlapping owners")
    previous = -1
    for row in trace:
        direction = row["direction"]
        require(direction in ("request", "response") and row["action"] in ("forward", "drop"), "invalid action")
        require(tuple(endpoint(row[k]) for k in ("source", "destination", "relay")) ==
                ((client, server, back) if direction == "request" else (server, client, front)), "wrong endpoint owner")
        at = row["time_ns"]
        require(type(at) is int and at >= 0 and at >= previous
                and at - trace[0]["time_ns"] <= 8_000_000_000, "invalid bounded timestamp")
        previous = at
        require(row["hex"] == row["forwarded_hex"], "relay changed bytes")
        wire = bytes.fromhex(row["hex"])
        require(4 <= len(wire) <= 4096 and wire[0] >> 6 == 1 and wire[0] & 15 <= 8, "invalid packet")
    timeout = mode in ("drop-permanent", "wrong-key")
    host_ns = result.get("host_total_ns")
    require(type(host_ns) is int and 0 <= host_ns <= 10_500_000_000, "missing bounded host duration")
    require(trace[-1]["time_ns"] - trace[0]["time_ns"] <= host_ns, "trace exceeds observed process lifetime")
    if timeout:
        expect_refusal(result)
        require(not result.get("payload_hex") and "code" not in result, "partial data claimed complete")
        require(host_ns >= (650_000_000 if mode == "wrong-key" else 6_450_000_000), "premature timeout")
    if mode == "wrong-key":
        require(len(trace) == 2 and all(r["action"] == "forward" for r in trace)
                and [r["direction"] for r in trace] == ["request", "response"], "wrong-key unexpected progress")
        req, reply = (bytes.fromhex(r["hex"]) for r in trace)
        require((req[0] >> 4) & 3 == 0 and req[1] == 2 and set(decoded_options(req)) == {9}
                and packet_token(req), "wrong-key request shape")
        try:
            request_plain(req)
        except AssertionError:
            pass
        else:
            raise AssertionError("wrong-key request authenticated with configured key")
        plain, _ = request_plain(req, wrong_key=True)
        opts = {}
        for option in plain.opt.option_list():
            opts.setdefault(int(option.number), []).append(option.encode())
        require(int(plain.code) == 1 and not plain.payload and opts == {11: [b"large"], 31: [b"\x0e"]},
                "wrong-key inner request not exact Q2")
        require((reply[0] >> 4) & 3 == 2 and reply[1] == 128 and reply[2:4] == req[2:4]
                and packet_token(reply) == packet_token(req) and decoded_options(reply) == {14: [b""]}
                and coap_payload(reply) == b"Decryption failed", "unexpected unprotected refusal")
        return {"mode": mode, "delivered_body_bytes": 0, "unprotected_decryption_refusals": 1,
                "outcome": "protocol timeout; no authenticated response"}
    if mode == "baseline":
        proof = baseline_grade(trace, result, endpoints)
        require(proof["response_forms"] == ["empty request ACK", "separate CON content", "separate CON content"]
                and proof["request_count"] == 1, "not observed pinned CON form")
        return {"mode": mode, **proof, "delivered_body_bytes": 2000}
    # Keep only actually forwarded unique datagrams for the ordinary complete/
    # partial receiver oracle. Dropped bytes are separately authenticated below.
    delivered = []
    lost = None
    last_at = None
    retries = drops = forwards = 0
    intervals = []
    for row in trace:
        wire = bytes.fromhex(row["hex"])
        if row["direction"] == "response" and wire[1] == 68 and later_response(wire, delivered):
            require(len(delivered) == 4, "later CON before settled first block or after completion")
            if lost is None:
                require(row["action"] == "drop", "later response loss not exercised")
                # Authenticate content, representation metadata and fresh explicit PIV
                # even when no client receives this datagram.
                req = bytes.fromhex(delivered[0]["hex"])
                first = bytes.fromhex(delivered[2]["hex"])
                plain, prior = response_plain(wire, req), response_plain(first, req)
                options = {}
                for option in plain.opt.option_list():
                    options.setdefault(int(option.number), []).append(option.encode())
                old_tag = [o.encode() for o in prior.opt.option_list() if int(o.number) == 4]
                require((wire[0] >> 4) & 3 == 0 and wire[2:4] not in (req[2:4], first[2:4])
                        and packet_token(wire) == packet_token(req) and set(decoded_options(wire)) == {9}, "lost CON ownership")
                require(int(plain.code) == 69 and plain.payload == LARGE[1024:]
                        and set(options) <= {4, 12, 14, 28, 31} and options.get(4) == old_tag
                        and len(old_tag) == 1 and 1 <= len(old_tag[0]) <= 8
                        and options.get(12) == [b"*"] and options.get(28) == [b"\x07\xd0"]
                        and options.get(31) == [b"\x16"], "lost representation mismatch")
                _, _, cose, _ = oscore.CanUnprotect._extract_encrypted0(incoming(wire))
                _, _, old, _ = oscore.CanUnprotect._extract_encrypted0(incoming(first))
                piv = cose.get(oscore.COSE_PIV)
                require(isinstance(piv, bytes) and 1 <= len(piv) <= 5 and piv != old.get(oscore.COSE_PIV), "lost block PIV reused/missing")
                lost = wire
            else:
                require(wire == lost and forwards == 0, "retry changed ciphertext or followed settlement")
                gap = row["time_ns"] - last_at
                require(1_950_000_000 * (2 ** retries) <= gap <= 3_250_000_000 * (2 ** retries),
                        "retry outside original exponential RTO")
                if intervals:
                    # Bind later backoff to the first observed retry, not merely
                    # to independent 2..3 second randomization windows.
                    scale = 2 ** retries
                    require(abs(gap - intervals[0] * scale) <= 25_000_000 * scale + 100_000_000,
                            "retry reset or shortened the observed exponential backoff")
                intervals.append(gap)
                retries += 1
            last_at = row["time_ns"]
            if row["action"] == "drop":
                drops += 1
            else:
                require(mode == "drop-once" and drops == 1 and retries == 1, "unexpected later forward")
                forwards += 1
                delivered.append(row)
        else:
            require(row["action"] == "forward", "unrelated packet loss")
            delivered.append(row)
    require(lost is not None and retries >= 1, "no actual retransmission")
    require((drops == 1 and forwards == 1) if mode == "drop-once" else (drops >= 2 and forwards == 0), "loss schedule mismatch")
    proof = baseline_grade(delivered, result, endpoints, partial=timeout)
    require(proof["request_count"] == 1 and proof["response_forms"] ==
            (["empty request ACK", "separate CON content"] if timeout else
             ["empty request ACK", "separate CON content", "separate CON content"]), "changed CON form")
    return {"mode": mode, "delivered_body_bytes": proof["body_bytes"], "etag_hex": proof["etag_hex"],
            "dropped_later_responses": drops, "exact_ciphertext_retries": retries,
            "retry_intervals_ns": intervals, "outcome": "protocol timeout after authenticated partial body" if timeout else "complete 2000-byte response"}


def campaign(client, server, record, patch):
    from run import Proxy, Server, request, expect
    record["schedules"] = []
    with Server(server, "oscore") as service:
        record["server_ready"] = service.ready
        require(service.ready.get("libcoap_patch_sha256") == patch["patch_sha256"], "peer patch identity mismatch")
        record["setup"] = request(client, "oscore", service.number, sequence=0)
        expect(record["setup"])
        for index, (mode, fault) in enumerate((("baseline", "pass"), ("drop-once", "drop-oscore-q2-once"),
                ("drop-permanent", "drop-oscore-q2-permanent"), ("wrong-key", "pass"), ("baseline", "pass")), 1):
            current = {"mode": mode, "sequence_start": index * 100}
            record["schedules"].append(current)
            relay = Proxy(service.number, fault)
            try:
                with relay:
                    current["endpoints"] = {"front": relay.front.getsockname(), "back": relay.back.getsockname(), "server": relay.dest}
                    current["result"] = request(client, "oscore", relay.number, path="large", sequence=index * 100,
                                                timeout=700 if mode == "wrong-key" else 6500, qblock2=True,
                                                key="incorrect" if mode == "wrong-key" else "sesame")
            finally:
                current["trace"] = relay.trace
            current["proof"] = campaign_grade(current["trace"], current["result"], current["endpoints"], mode)
    record["proof"] = campaign_review(record)
    record["complete"] = True


def campaign_review(record):
    """Regrade every retained case and require fresh bindings on one server."""
    from run import expect
    expect(record["setup"])
    schedules = record["schedules"]
    modes = ["baseline", "drop-once", "drop-permanent", "wrong-key", "baseline"]
    require(len(schedules) == len(modes), "incomplete five-schedule campaign")
    require(record["server_ready"].get("transport") == "oscore", "server not protected")
    server_port = record["server_ready"]["port"]
    proofs, requests, response_pivs = [], set(), set()
    for index, (case, mode) in enumerate(zip(schedules, modes), 1):
        require(case["mode"] == mode and case["sequence_start"] == index * 100, "changed campaign order/sequence")
        require(case["endpoints"]["server"] == ("127.0.0.1", server_port)
                or case["endpoints"]["server"] == ["127.0.0.1", server_port], "server changed during recovery")
        proof = campaign_grade(case["trace"], case["result"], case["endpoints"], mode)
        require(proof == case["proof"], "retained proof differs from actual trace")
        wire = bytes.fromhex(case["trace"][0]["hex"])
        _, binding = request_plain(wire, wrong_key=mode == "wrong-key")
        piv = bytes(binding.partial_iv)
        require(int.from_bytes(piv, "big") == index * 100 and piv not in requests, "fresh request binding not proven")
        requests.add(piv)
        seen = set()
        for row in case["trace"]:
            wire = bytes.fromhex(row["hex"])
            if row["direction"] == "response" and wire[1] == 68 and wire not in seen:
                _, _, cose, _ = oscore.CanUnprotect._extract_encrypted0(incoming(wire))
                piv = cose[oscore.COSE_PIV]
                require(piv not in response_pivs, "server response PIV reused between schedules")
                response_pivs.add(piv)
                seen.add(wire)
        proofs.append(proof)
    return {"same_server": ["127.0.0.1", server_port], "schedules": modes,
            "fresh_request_bindings": len(requests), "distinct_server_pivs": len(response_pivs),
            "final_recovery_bytes": proofs[-1]["delivered_body_bytes"],
            "scope": "finite IPv4 CON Q2 run; no sustained, routed, NON or multi-peer qualification"}


def baseline(client, server, record, patch=None):
    from run import Proxy, Server, request, expect
    with Server(server, "oscore") as service:
        if patch is not None:
            record["server_ready"] = service.ready
            require(service.ready.get("libcoap_patch_sha256") == patch["patch_sha256"],
                    "server binary does not identify the expected dependency patch")
        record["setup"] = request(client, "oscore", service.number, sequence=0)
        expect(record["setup"])
        relay = Proxy(service.number, "pass")
        try:
            with relay:
                record["endpoints"] = {"front": relay.front.getsockname(), "back": relay.back.getsockname(), "server": relay.dest}
                record["result"] = request(client, "oscore", relay.number, path="large", sequence=100, timeout=6500, qblock2=True)
        finally:
            record["trace"] = relay.trace
        record["proof"] = baseline_grade(record["trace"], record["result"], record["endpoints"])


def main():
    import argparse
    import hashlib
    import json
    import platform
    from pathlib import Path
    # Importing run makes the common tools identity module available.
    from run import source_identity
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--libcoap", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--libcoap-patch-manifest", type=Path)
    parser.add_argument("--campaign", action="store_true", help="run reviewed finite loss/refusal/recovery schedules")
    args = parser.parse_args()
    peers = {"coaptic": args.coaptic.resolve(), "libcoap": args.libcoap.resolve()}
    patch = (json.loads(args.libcoap_patch_manifest.read_text(encoding="utf-8"))
             if args.libcoap_patch_manifest else None)
    report = {"libcoap_patch": patch, "schema": "coaptic-protected-qblock2-campaign/1" if args.campaign else "coaptic-protected-qblock2-baseline/1", **source_identity(),
              "platform": platform.platform(), "qualification_complete": False,
              "scope": "baseline observation only; loss/refusal/recovery remain unqualified",
              "libcoap_source": "851533c3cf63d16984d370ce39d586ecb3694971",
              "executables": {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for name, path in peers.items()}, "baseline": {}}
    report["baseline_passed"] = False
    report["campaign_passed"] = False if args.campaign else None
    try:
        baseline(peers["coaptic"], peers["libcoap"], report["baseline"], patch)
        report["baseline_passed"] = True
        if args.campaign:
            require(patch is not None, "campaign requires patched-peer provenance")
            report["campaign"] = {}
            campaign(peers["coaptic"], peers["libcoap"], report["campaign"], patch)
            report["campaign_passed"] = True
            report["qualification_complete"] = True
            report["scope"] = "finite IPv4 CON protected Q2 later-response loss/refusal/recovery only"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({"baseline_passed": report["baseline_passed"],
                      "qualification_complete": report["qualification_complete"], "report": str(args.output)}))
    return 0 if (report["campaign_passed"] if args.campaign else report["baseline_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
