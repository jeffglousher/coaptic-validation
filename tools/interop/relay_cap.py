"""Finite silent datagram-cap evidence; not ICMP or adaptive PMTU qualification."""


def grade(trace, result, endpoints, *, path, capped, deadline_ms=6500):
    from run import BODY, LARGE, block1_fields, coap_payload, decoded_options, expect, expect_refusal, packet_token

    refusal = capped and path == "large"
    expected_body = LARGE if path == "large" else BODY
    if path not in ("test", "large") or type(capped) is not bool or deadline_ms != 6500:
        raise AssertionError("unsupported finite cap schedule")
    if refusal:
        expect_refusal(result)
        if "code" in result or result.get("payload_hex"):
            raise AssertionError("timeout returned an application response")
        elapsed = result.get("host_total_ns")
        if type(elapsed) is not int or not deadline_ms * 1_000_000 <= elapsed < (deadline_ms + 4000) * 1_000_000:
            raise AssertionError("not the bounded peer timeout")
    else:
        expect(result, 69, expected_body)

    def endpoint(value):
        if (not isinstance(value, (tuple, list)) or len(value) != 2 or value[0] != "127.0.0.1"
                or type(value[1]) is not int or not 0 < value[1] < 65536):
            raise AssertionError("not an exact IPv4 loopback endpoint")
        return tuple(value)

    if not 2 <= len(trace) <= 256:
        raise AssertionError("trace outside finite bound")
    front, back, server = (endpoint(endpoints.get(key)) for key in ("front", "back", "server"))
    client = endpoint(trace[0].get("source"))
    if len({front, back, server, client}) != 4:
        raise AssertionError("overlapping relay endpoints")
    pending = initial = None
    previous = -1
    requests, drops, parts, request_times = [], [], [], []
    etag = None
    for row in trace:
        direction, action = row.get("direction"), row.get("action")
        if direction not in ("request", "response"):
            raise AssertionError("invalid trace direction")
        actual = tuple(endpoint(row.get(key)) for key in ("source", "destination", "relay"))
        if actual != ((client, server, back) if direction == "request" else (server, client, front)):
            raise AssertionError("relay ownership mismatch")
        stamp = row.get("time_ns")
        if type(stamp) is not int or stamp <= previous:
            raise AssertionError("missing or non-increasing capture time")
        previous = stamp
        wire = bytes.fromhex(row["hex"])
        if row.get("forwarded_hex") != row["hex"]:
            raise AssertionError("relay altered bytes")
        if action != ("drop" if capped and len(wire) > 256 else "forward"):
            raise AssertionError("action contradicts exact wire-length cap")
        if len(wire) < 4 or wire[0] >> 6 != 1 or not 0 < wire[0] & 15 <= 8 or len(wire) < 4 + (wire[0] & 15):
            raise AssertionError("invalid datagram header")
        options = decoded_options(wire)
        token, mid, ty = packet_token(wire), wire[2:4], (wire[0] >> 4) & 3
        if direction == "request":
            if pending is not None or ty != 0 or wire[1] != 1 or options.get(11) != [path.encode()] or coap_payload(wire):
                raise AssertionError("not the expected CON GET")
            if initial is None:
                initial = wire
            if token != packet_token(initial) or 31 in options:
                raise AssertionError("request changed token or used Q-Block")
            if refusal or path == "test" or not parts:
                if wire != initial or 23 in options:
                    raise AssertionError("initial request retry changed bytes")
            elif (len(parts) != 1 or len(options.get(23, [])) != 1
                  or block1_fields(options[23][0]) != (1, False, 6) or mid == initial[2:4]):
                raise AssertionError("continuation does not own next block")
            pending = wire
            requests.append(wire)
            request_times.append(stamp)
            continue
        if pending is None or ty != 2 or wire[1] != 69 or token != packet_token(pending) or mid != pending[2:4]:
            raise AssertionError("response does not acknowledge its exact request")
        pending = None
        payload = coap_payload(wire)
        if path == "test":
            if payload != BODY or 23 in options or len(trace) != 2:
                raise AssertionError("small control was not complete")
        else:
            values, sizes, tags = (options.get(number, []) for number in (23, 28, 4))
            num = 0 if refusal else len(parts)
            if (len(values) != 1 or block1_fields(values[0]) != (num, num == 0, 6)
                    or num > 1 or payload != LARGE[num * 1024:(num + 1) * 1024]
                    or len(sizes) != 1 or int.from_bytes(sizes[0], "big") != 2000
                    or len(tags) != 1 or not 1 <= len(tags[0]) <= 8 or 31 in options):
                raise AssertionError("response lost exact Block2 representation")
            # A rejected first-block retry can create a fresh server snapshot.
            # Only a delivered representation must retain the same ETag.
            if not refusal:
                if etag is not None and etag != tags[0]:
                    raise AssertionError("delivered representation changed ETag")
                etag = tags[0]
        if action == "drop":
            drops.append(wire)
        else:
            parts.append(payload)
    if pending is not None:
        raise AssertionError("request has no captured response")
    if refusal:
        if len(requests) < 2 or len(drops) != len(requests) or parts:
            raise AssertionError("missing actual oversize loss and retry")
        if not 1_950_000_000 <= request_times[1] - request_times[0] <= 4_000_000_000:
            raise AssertionError("first CON retry outside default RTO")
    elif drops or b"".join(parts) != expected_body:
        raise AssertionError("trace does not prove complete delivered bytes")
    return {"cap_bytes": 256 if capped else None, "complete": not refusal,
            "delivered_bytes": sum(map(len, parts)), "drops": len(drops),
            "requests": len(requests), "response_wire_lengths": [len(w) for w in drops],
            "first_retry_interval_ns": request_times[1] - request_times[0] if refusal else None}


def grade_campaign(schedules):
    expected = {"baseline": ("large", False), "control": ("test", True),
                "refusal": ("large", True), "recovery": ("large", False)}
    if set(schedules) != set(expected):
        raise AssertionError("missing complete cap campaign")
    server = None
    prior_end = -1
    for label, (path, capped) in expected.items():
        row = schedules[label]
        current = tuple(row["endpoints"]["server"])
        if server is not None and current != server:
            raise AssertionError("campaign changed server endpoint")
        server = current
        grade(row["trace"], row["result"], row["endpoints"], path=path, capped=capped,
              deadline_ms=row["deadline_ms"])
        if row["trace"][0]["time_ns"] <= prior_end:
            raise AssertionError("campaign schedules are not in execution order")
        prior_end = row["trace"][-1]["time_ns"]
    return True


def workflow(client, server):
    from run import Proxy, Server, request

    schedules = {}
    with Server(server, "udp") as service:
        for label, path, capped in (("baseline", "large", False), ("control", "test", True),
                                    ("refusal", "large", True), ("recovery", "large", False)):
            with Proxy(service.number, "cap-256" if capped else "dtls-reconnect") as relay:
                endpoints = {"front": relay.front.getsockname(), "back": relay.back.getsockname(), "server": relay.dest}
                result = request(client, "udp", relay.number, path=path, timeout=6500)
            proof = grade(relay.trace, result, endpoints, path=path, capped=capped)
            schedules[label] = {"proof": proof, "result": result, "trace": relay.trace,
                                "endpoints": endpoints, "deadline_ms": 6500}
    grade_campaign(schedules)
    return {"family": "ipv4", "transport": "udp", "schedules": schedules,
            "limitation": "Silent relay datagram cap, not IP MTU discovery or adaptive shrinking; recovery uses a fresh client/relay and the same server with the cap removed."}
