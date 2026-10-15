"""Finite authenticated classic Block2 datagram-cap qualification (IPv4/IPv6 loopback)."""
from oscore_qblock1 import request_plain, response_plain, require, incoming
from oscore_qblock2 import loopback_endpoint, relay_endpoints, require_relay_family
from aiocoap import oscore


def options(message):
    result = {}
    for option in message.opt.option_list():
        result.setdefault(int(option.number), []).append(option.encode())
    return result


def grade(trace, result, endpoints, *, path, capped, family="ipv4"):
    from run import BODY, LARGE, expect, decoded_options, packet_token, block1_fields
    require(path in ("test", "large") and type(capped) is bool, "unknown schedule")
    refused = path == "large" and capped
    elapsed = result.get("host_total_ns")
    require(type(elapsed) is int and 0 <= elapsed < 10_500_000_000, "missing bounded host duration")
    if refused:
        require(result.get("event") == "error" and result.get("exit_code") == 1
                and result.get("message") == "request timed out" and "code" not in result
                and not result.get("payload_hex") and elapsed >= 6_500_000_000,
                "not exact pinned peer protocol timeout")
    else:
        expect(result, 69, LARGE if path == "large" else BODY)
        require(result.get("exit_code") == 0, "unsuccessful client exit")
    require(2 <= len(trace) <= 64, "trace outside finite report bound")
    require_relay_family(endpoints, family)
    endpoint = lambda value: loopback_endpoint(value, family)
    front, back, server = (endpoint(endpoints[k]) for k in ("front", "back", "server"))
    client = endpoint(trace[0]["source"])
    require(len({front, back, server, client}) == 4, "overlapping owners")
    latest = pending_response = None
    waiting_ack = False
    body = bytearray()
    request_mids, request_pivs, response_mids, response_pivs = set(), set(), set(), set()
    tag = token = None
    response_times, dropped_lengths = [], []
    previous = -1
    request_count = response_count = client_acks = 0
    for row in trace:
        direction = row.get("direction")
        require(direction in ("request", "response"), "unknown direction")
        require(tuple(endpoint(row[k]) for k in ("source", "destination", "relay")) ==
                ((client, server, back) if direction == "request" else (server, client, front)),
                "endpoint ownership mismatch")
        at = row.get("time_ns")
        require(type(at) is int and at >= 0 and at > previous, "capture time not increasing")
        previous = at
        require(at - trace[0]["time_ns"] <= elapsed, "trace exceeds client duration")
        require(row.get("hex") == row.get("forwarded_hex"), "relay changed bytes")
        wire = bytes.fromhex(row["hex"])
        require(4 <= len(wire) <= 4096 and wire[0] >> 6 == 1 and wire[0] & 15 <= 8,
                "invalid bounded datagram")
        action = "drop" if capped and len(wire) > 256 else "forward"
        require(row.get("action") == action, "action contradicts exact datagram cap")
        mid, ty = wire[2:4], wire[0] >> 4 & 3
        if direction == "request":
            require(action == "forward", "unexpected oversized request")
            if wire[1] == 0:
                require(pending_response is not None and not refused
                        and wire == b"\x60\x00" + pending_response[2:4], "client ACK ownership mismatch")
                pending_response = None
                client_acks += 1
                continue
            require(not waiting_ack and pending_response is None and ty == 0 and wire[1] == 2
                    and mid not in request_mids and set(decoded_options(wire)) == {9},
                    "request overlaps unsettled exchange")
            plain, binding = request_plain(wire)
            opts = options(plain)
            expected = {11: [path.encode()]}
            if body:
                expected[23] = [b"\x16"]
            require(int(plain.code) == 1 and not plain.payload and opts == expected
                    and (not body or bytes(body) == LARGE[:1024]), "wrong authenticated block selection")
            piv = bytes(binding.partial_iv)
            require(piv and piv not in request_pivs and packet_token(wire)
                    and (token is None or token == packet_token(wire)), "request binding/token reuse")
            request_pivs.add(piv)
            request_mids.add(mid)
            token, latest, waiting_ack = packet_token(wire), wire, True
            request_count += 1
            continue
        require(latest is not None, "response without request")
        if wire[1] == 0:
            require(action == "forward" and waiting_ack and wire == b"\x60\x00" + latest[2:4],
                    "empty ACK does not settle exact request")
            waiting_ack = False
            continue
        require(not waiting_ack and ty == 0 and wire[1] == 68 and packet_token(wire) == token
                and set(decoded_options(wire)) == {9}, "not expected protected separate CON")
        if pending_response is not None:
            require(refused and wire == pending_response and action == "drop", "retry changed ciphertext/owner")
            response_times.append(at)
            dropped_lengths.append(len(wire))
            continue
        # RFC7252 4.4: each sender owns its MID namespace.
        require(mid not in response_mids, "response sender reused MID")
        plain = response_plain(wire, latest)
        opts = options(plain)
        require(int(plain.code) == 69, "not authenticated Content")
        _, _, cose, _ = oscore.CanUnprotect._extract_encrypted0(incoming(wire))
        piv = cose.get(oscore.COSE_PIV)
        # Classic responses may reuse their distinct request nonce (RFC8613 8.3).
        if piv is not None:
            require(isinstance(piv, bytes) and 1 <= len(piv) <= 5 and piv not in response_pivs,
                    "explicit response PIV reused")
            response_pivs.add(piv)
        if path == "test":
            require(plain.payload == BODY and opts == {12: [b"*"], 14: [b"<"]}, "wrong complete small response")
        else:
            require(set(opts) == {4, 12, 14, 23, 28} and opts[12] == [b"*"]
                    and opts[14] == [b"<"] and opts[28] == [b"\x07\xd0"]
                    and len(opts[4]) == len(opts[23]) == 1, "wrong representation metadata")
            current_tag = opts[4][0]
            require(1 <= len(current_tag) <= 8 and (tag is None or tag == current_tag), "ETag changed")
            tag = current_tag
            num = len(body) // 1024
            require(num in (0, 1) and block1_fields(opts[23][0]) == (num, num == 0, 6)
                    and plain.payload == LARGE[num*1024:(num+1)*1024], "wrong exact Block2 body")
        response_mids.add(mid)
        response_count += 1
        pending_response = wire
        if action == "forward":
            body.extend(plain.payload)
        else:
            response_times.append(at)
            dropped_lengths.append(len(wire))
    if refused:
        require(request_count == response_count == 1 and client_acks == 0 and not body
                and not waiting_ack and pending_response is not None and 2 <= len(response_times) <= 3,
                "missing first-block loss and exact retransmission")
        intervals = [b-a for a,b in zip(response_times, response_times[1:])]
        require(1_975_000_000 <= intervals[0] <= 3_100_000_000, "retry outside initial RTO")
        for i, gap in enumerate(intervals[1:], 1):
            require(abs(gap - intervals[0] * 2**i) <= 100_000_000 + 25_000_000 * 2**i,
                    "retry did not preserve exponential backoff")
    else:
        require(not waiting_ack and pending_response is None and bytes(body) == (LARGE if path == "large" else BODY)
                and request_count == response_count == client_acks == (2 if path == "large" else 1),
                "incomplete response or unsettled ownership")
        intervals = []
    return {"delivered_authenticated_bytes": len(body), "dropped_datagram_lengths": dropped_lengths,
            "exact_server_retry_intervals_ns": intervals, "client_acks": client_acks,
            "request_pivs": sorted(p.hex() for p in request_pivs),
            "explicit_response_pivs": sorted(p.hex() for p in response_pivs),
            "outcome": "protocol timeout; no authenticated response delivered" if refused else "complete response"}


SCHEDULES = (("baseline", "large", False), ("small-control", "test", True),
             ("capped-refusal", "large", True), ("fresh-recovery", "large", False))


def review(record, patch, *, family="ipv4"):
    from run import expect
    require(family in ("ipv4", "ipv6") and record.get("family", "ipv4") == family, "campaign family mismatch")
    require(record["server_ready"].get("transport") == "oscore" and
            record["server_ready"].get("libcoap_patch_sha256") == patch["patch_sha256"], "server provenance mismatch")
    expect(record["setup"])
    server_endpoint = loopback_endpoint(("::1", record["server_ready"]["port"], 0, 0) if family == "ipv6"
                                        else ("127.0.0.1", record["server_ready"]["port"]), family)
    require(len(record["schedules"]) == 4, "incomplete campaign")
    requests, explicit = set(), set()
    proofs = []
    for index, (case, (name, path, capped)) in enumerate(zip(record["schedules"], SCHEDULES), 1):
        require(case["name"] == name and case["sequence_start"] == index*100, "wrong schedule/order")
        require(loopback_endpoint(case["endpoints"]["server"], family) == server_endpoint, "server changed")
        proof = grade(case["trace"], case["result"], case["endpoints"], path=path, capped=capped, family=family)
        require(proof == case["proof"], "retained proof does not match trace")
        _, binding = request_plain(bytes.fromhex(case["trace"][0]["hex"]))
        require(int.from_bytes(binding.partial_iv, "big") == index*100, "wrong starting binding")
        for values, seen in ((proof["request_pivs"], requests), (proof["explicit_response_pivs"], explicit)):
            require(not seen.intersection(values), "cross-schedule nonce reuse")
            seen.update(values)
        proofs.append(proof)
    return {"schedules": 4, "same_server_port": record["server_ready"]["port"], "cap_bytes": 256,
            "fresh_recovery_bytes": proofs[-1]["delivered_authenticated_bytes"],
            "scope": f"finite {'IPv6' if family == 'ipv6' else 'IPv4'} loopback silent datagram cap; no adaptive PMTU, ICMP or sustained availability; fresh client/relay for recovery"}


def campaign(client, server, record, patch, *, family="ipv4"):
    from run import Server, Proxy, request, expect
    require(family in ("ipv4", "ipv6"), "unsupported protected address family")
    record.update(family=family, schedules=[])
    with Server(server, "oscore", family=family) as service:
        record["server_ready"] = service.ready
        require(service.ready.get("libcoap_patch_sha256") == patch["patch_sha256"], "peer patch mismatch")
        record["setup"] = request(client, "oscore", service.number, sequence=0, family=family)
        expect(record["setup"])
        for index, (name, path, capped) in enumerate(SCHEDULES, 1):
            case = {"name": name, "sequence_start": index*100}
            record["schedules"].append(case)
            relay = Proxy(service.number, "cap-256" if capped else "pass", family=family)
            try:
                with relay:
                    case["endpoints"] = relay_endpoints(relay, family)
                    case["result"] = request(client, "oscore", relay.number, path=path, sequence=index*100, timeout=6500, family=family)
            finally:
                case["trace"] = relay.trace
            case["proof"] = grade(case["trace"], case["result"], case["endpoints"], path=path, capped=capped, family=family)
    record["proof"] = review(record, patch, family=family)
    record["complete"] = True


def main():
    import argparse, hashlib, json, platform
    from pathlib import Path
    from run import source_identity
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coaptic", type=Path, required=True)
    parser.add_argument("--libcoap", type=Path, required=True)
    parser.add_argument("--libcoap-patch-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    args = parser.parse_args()
    patch = json.loads(args.libcoap_patch_manifest.read_text(encoding="utf-8"))
    report = {"schema": "coaptic-protected-relay-cap/1", **source_identity(), "platform": platform.platform(),
              "libcoap_source": "851533c3cf63d16984d370ce39d586ecb3694971", "libcoap_patch": patch,
              "executables": {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for name,path in (("coaptic",args.coaptic), ("libcoap",args.libcoap))},
              "family": args.family, "qualification_complete": False, "campaign": {}}
    try:
        campaign(args.coaptic.resolve(), args.libcoap.resolve(), report["campaign"], patch, family=args.family)
        report["qualification_complete"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps({"qualification_complete": report["qualification_complete"], "report": str(args.output)}))
    return 0 if report["qualification_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
