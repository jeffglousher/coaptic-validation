"""Finite IPv6 loss qualification for the standalone coap-rs UDP fixture."""


def grade(trace, result, endpoints, *, mode):
    from run import coap_payload, decoded_options, expect, expect_refusal, grade_ipv6_relay, packet_token

    if mode not in ("loss", "permanent", "fresh"):
        raise AssertionError("unsupported separate-response schedule")
    if mode == "permanent":
        expect_refusal(result)
        if result.get("payload_hex") or "code" in result:
            raise AssertionError("timeout reported an application response")
    else:
        expect(result, 69, b"separate-payload")
    ownership = grade_ipv6_relay(trace, endpoints)
    if len(set(ownership.values())) != 4:
        raise AssertionError("overlapping IPv6 endpoints")
    if len(trace) < 4:
        raise AssertionError("missing separate-response evidence")
    request = reply = None
    drops = replies = forwarded = acknowledgements = 0
    previous_time = -1
    for index, row in enumerate(trace):
        direction, action = row["direction"], row["action"]
        if action not in ("forward", "drop") or row.get("forwarded_hex", row["hex"]) != row["hex"]:
            raise AssertionError("separate-response relay changed or held bytes")
        timestamp = row.get("time_ns")
        if type(timestamp) is not int or timestamp < previous_time:
            raise AssertionError("missing or unordered capture time")
        previous_time = timestamp
        wire = bytes.fromhex(row["hex"])
        if len(wire) < 4 or wire[0] >> 6 != 1 or wire[0] & 15 > 8 or len(wire) < 4 + (wire[0] & 15):
            raise AssertionError("malformed separate-response datagram")
        if index == 0:
            options = decoded_options(wire)
            if (direction != "request" or action != "forward" or wire[0] >> 4 != 4
                    or wire[1] != 1 or not packet_token(wire) or options.get(11) != [b"separate"]):
                raise AssertionError("initial forwarded separate GET missing")
            request = wire
        elif index == 1:
            if direction != "response" or action != "forward" or wire != b"\x60\x00" + request[2:4]:
                raise AssertionError("empty ACK does not own initial request")
        elif direction == "response":
            options = decoded_options(wire)
            formats = options.get(12, [])
            if (acknowledgements or wire[0] >> 4 != 4 or wire[1] != 69
                    or packet_token(wire) != packet_token(request) or wire[2:4] == request[2:4]
                    or coap_payload(wire) != b"separate-payload"
                    or len(formats) != 1 or int.from_bytes(formats[0], "big") != 0
                    or (reply is not None and wire != reply)):
                raise AssertionError("separate response ownership/body/retransmission changed")
            if reply is None and mode != "fresh" and action != "drop":
                raise AssertionError("first separate response was not lost")
            reply = wire
            replies += 1
            drops += action == "drop"
            forwarded += action == "forward"
        else:
            if (action != "forward" or reply is None or not forwarded or acknowledgements
                    or index != len(trace) - 1 or wire != b"\x60\x00" + reply[2:4]):
                raise AssertionError("response ACK precedes delivery or has wrong ownership")
            acknowledgements += 1
    if mode == "permanent":
        if drops < 2 or forwarded or acknowledgements or replies != drops:
            raise AssertionError("permanent refusal lacks repeated lost CON evidence")
    elif acknowledgements != 1 or forwarded < 1 or drops != (1 if mode == "loss" else 0):
        raise AssertionError("complete delivery/loss/ACK evidence missing")
    return dict(complete=mode != "permanent", drops=drops, retransmissions=max(0, replies - 1),
                delivered_bytes=0 if mode == "permanent" else len(b"separate-payload"),
                ownership=ownership, endpoints=endpoints, trace=trace)
