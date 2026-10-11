"""Strict evidence oracle for RFC9177 CON reliability at NSTART=1."""


def grade(trace, result, endpoints, *, complete, family="ipv4"):
    # Runtime import avoids a cycle with the executable runner.
    from run import LARGE, block1_fields, coap_payload, decoded_options, expect, expect_refusal, packet_token

    if complete:
        expect(result, 69, LARGE)
    else:
        expect_refusal(result)
        if result.get("payload_hex") or "code" in result:
            raise AssertionError("partial timeout reported an application response")

    if family not in ("ipv4", "ipv6"):
        raise AssertionError("unsupported CON address family")
    ipv6 = family == "ipv6"
    if ipv6 and (endpoints.get("family") != "AF_INET6" or endpoints.get("v6only") != [1, 1]):
        raise AssertionError("CON relay did not use IPv6-only sockets")

    def endpoint(value):
        if (not isinstance(value, (list, tuple)) or len(value) != (4 if ipv6 else 2)
                or value[0] != ("::1" if ipv6 else "127.0.0.1")
                or type(value[1]) is not int or not 0 < value[1] < 65536
                or (ipv6 and value[2:] not in ([0, 0], (0, 0)))):
            raise AssertionError("not an exact CON loopback endpoint")
        return tuple(value)

    if not 4 <= len(trace) <= 256:
        raise AssertionError("CON trace outside finite capture bound")
    front, back, server = (endpoint(endpoints.get(key)) for key in ("front", "back", "server"))
    client = endpoint(trace[0].get("source"))
    if len({client, server, front, back}) != 4:
        raise AssertionError("overlapping relay endpoints")
    initial = None
    pending = None
    delivered = set()
    mids = set()
    etag = None
    dropped = []
    retransmissions = 0
    previous_time = -1
    for index, row in enumerate(trace):
        direction, action = row["direction"], row["action"]
        if direction not in ("request", "response") or action not in ("forward", "drop"):
            raise AssertionError("unsupported trace direction/action")
        actual = tuple(endpoint(row.get(key)) for key in ("source", "destination", "relay"))
        expected = (client, server, back) if direction == "request" else (server, client, front)
        if actual != expected:
            raise AssertionError("CON endpoint ownership mismatch")
        timestamp = row.get("time_ns")
        if type(timestamp) is not int or timestamp < previous_time:
            raise AssertionError("missing or unordered capture time")
        previous_time = timestamp
        if index > 0 and action == "forward" and row.get("forwarded_hex", row["hex"]) != row["hex"]:
            raise AssertionError("response or ACK bytes changed in relay")
        wire = bytes.fromhex(row.get("forwarded_hex", row["hex"]) if action == "forward" else row["hex"])
        if len(wire) < 4 or wire[0] >> 6 != 1 or wire[0] & 15 > 8 or len(wire) < 4 + (wire[0] & 15):
            raise AssertionError("malformed CON trace packet")
        mid = int.from_bytes(wire[2:4], "big")
        ty = (wire[0] >> 4) & 3
        options = decoded_options(wire)
        if index == 0:
            if (direction != "request" or action != "forward" or ty != 0 or wire[1] != 1
                    or options.get(11) != [b"large"] or not packet_token(wire)
                    or len(options.get(31, [])) != 1 or 23 in options
                    or block1_fields(options[31][0]) != (0, True, 4)):
                raise AssertionError("initial forwarded CON Q-Block2 request missing")
            initial = wire
            continue
        if direction == "request":
            if (action != "forward" or wire != b"\x60\x00" + wire[2:4]
                    or pending is None or pending[0] != mid or not pending[2]):
                raise AssertionError("ACK does not own a forwarded outstanding CON")
            pending = None
            continue
        num_values = options.get(31, [])
        if len(num_values) != 1 or 23 in options:
            raise AssertionError("response lacks exactly one Q-Block2")
        num, more, szx = block1_fields(num_values[0])
        tags, sizes = options.get(4, []), options.get(28, [])
        if (wire[1] != 69 or packet_token(wire) != packet_token(initial) or szx != 4
                or num > 7 or more != (num < 7) or coap_payload(wire) != LARGE[num * 256:(num + 1) * 256]
                or len(sizes) != 1 or int.from_bytes(sizes[0], "big") != len(LARGE)
                or len(tags) != 1 or not tags[0] or (etag is not None and tags[0] != etag)):
            raise AssertionError("response does not match the complete representation")
        etag = tags[0]
        if num == 0:
            if index != 1 or action != "forward" or ty != 2 or mid != int.from_bytes(initial[2:4], "big"):
                raise AssertionError("initial piggybacked block identity")
            mids.add(mid)
        else:
            if ty != 0:
                raise AssertionError("later block is not CON")
            if pending is not None:
                if pending[:2] != (mid, wire):
                    raise AssertionError("NSTART1 bypass or changed retransmission")
                retransmissions += 1
            elif mid in mids or num != len(delivered):
                raise AssertionError("reused MID or out-of-order CON")
            else:
                if num == 1 and action != "drop":
                    raise AssertionError("first block1 was not lost")
                mids.add(mid)
            pending = (mid, wire, action == "forward")
        if action == "drop":
            if num != 1:
                raise AssertionError("loss is not later block1")
            dropped.append((wire, timestamp))
        else:
            delivered.add(num)
    if not dropped or retransmissions < 1 or any(wire != dropped[0][0] for wire, _ in dropped):
        raise AssertionError("no identical lost CON retransmission")
    if complete:
        if len(dropped) != 1 or pending is not None or delivered != set(range(8)):
            raise AssertionError("incomplete delivery/ACK or wrong loss schedule")
    elif len(dropped) < 2 or delivered != {0} or pending is None or pending[2]:
        raise AssertionError("missing permanent-loss partial refusal evidence")
    return dict(complete=complete, delivered_bytes=sum(len(LARGE[n * 256:(n + 1) * 256]) for n in delivered),
                blocks=len(delivered), drops=len(dropped), retransmissions=retransmissions,
                nstart=1, family=family, trace=trace, endpoints=endpoints)
