"""Authenticated independent Q-Block2 baseline; loss qualification is separate."""
from oscore_qblock1 import request_plain, response_plain, require


def baseline_grade(trace, result, endpoints):
    from run import LARGE, decoded_options, block1_fields, packet_token, expect
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
    request_mids, response_mids, pivs = set(), set(), set()
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
        require(packet_token(wire) == token and set(decoded_options(wire)) == {9},
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
    require(bytes(body) == LARGE and not request_pending and server_pending is None,
            "incomplete body or unsettled CON")
    return {"body_bytes": len(body), "etag_hex": etag.hex(), "response_forms": forms,
            "request_count": len(request_mids), "scope": "baseline only; loss/refusal/recovery not yet qualified"}


def baseline(client, server):
    import json
    from run import Proxy, Server, request, expect
    with Server(server, "oscore") as service:
        expect(request(client, "oscore", service.number, sequence=0))
        with Proxy(service.number, "pass") as relay:
            endpoints = {"front": relay.front.getsockname(), "back": relay.back.getsockname(), "server": relay.dest}
            result = request(client, "oscore", relay.number, path="large", sequence=100, timeout=6500, qblock2=True)
        record = {"trace": relay.trace, "result": result, "endpoints": endpoints}
        try:
            record["proof"] = baseline_grade(relay.trace, result, endpoints)
        except AssertionError as error:
            raise AssertionError(json.dumps({"error": str(error), "baseline": record})) from error
        return record
