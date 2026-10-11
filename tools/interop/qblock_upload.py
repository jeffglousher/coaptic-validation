"""Exact two-block CON upload evidence for the existing independent libcoap fixture."""
import re

# peer-coaptic uses App's unchanged Transmission defaults: ACK_TIMEOUT 2000 ms,
# ACK_RANDOM_FACTOR 1.5 (core src/message/mod.rs). Relay capture may lag socket
# arrival: allow 50 ms early capture skew and 1000 ms late host scheduling.
INITIAL_RTO_NS = (2_000_000_000, 3_000_000_000)
CAPTURE_TOLERANCE_NS = (50_000_000, 1_000_000_000)


def later_upload(packet):
    from run import block1_fields, decoded_options
    try:
        options = decoded_options(packet)
        values = options.get(19, [])
        return (len(packet) >= 4 and packet[0] >> 6 == 1 and (packet[0] >> 4) & 3 == 0
                and packet[1] == 2 and options.get(11) == [b"upload"] and len(values) == 1
                and block1_fields(values[0])[0] == 1)
    except (AssertionError, IndexError, ValueError):
        return False


def grade(trace, result, endpoints, before, after, *, complete):
    from run import LARGE, coap_payload, decoded_options, expect, expect_refusal, packet_token
    if complete:
        expect(result, 65, b"")
    else:
        expect_refusal(result)
        if "code" in result or result.get("payload_hex"):
            raise AssertionError("partial upload reported an application response")
    expect(before, 69, None)
    counts = bytes.fromhex(before["payload_hex"])
    if not re.fullmatch(rb"[0-9]{1,3}:[0-9]{1,3}", counts):
        raise AssertionError("unbounded or missing upload readback")
    accepted, calls = (int(n) for n in counts.split(b":"))
    if accepted != calls:
        raise AssertionError("unexpected prior upload handler effect")
    expected = accepted + int(complete)
    expect(after, 69, f"{expected}:{expected}".encode())

    def endpoint(value):
        if (not isinstance(value, (list, tuple)) or len(value) != 2 or value[0] != "127.0.0.1"
                or type(value[1]) is not int or not 0 < value[1] < 65536):
            raise AssertionError("not an exact IPv4 loopback endpoint")
        return tuple(value)

    if not 4 <= len(trace) <= 256:
        raise AssertionError("upload trace outside finite capture bound")
    front, back, server = (endpoint(endpoints.get(key)) for key in ("front", "back", "server"))
    client = endpoint(trace[0].get("source"))
    if len({client, front, back, server}) != 4:
        raise AssertionError("overlapping upload endpoints")
    initial = later = None
    initial_acked = later_forwarded = final_acked = False
    drops = retries = 0
    first_drop_time = first_retry_interval = None
    previous_time = -1
    for index, row in enumerate(trace):
        direction, action = row["direction"], row["action"]
        if direction not in ("request", "response") or action not in ("forward", "drop"):
            raise AssertionError("unsupported upload trace action/direction")
        actual = tuple(endpoint(row.get(key)) for key in ("source", "destination", "relay"))
        owned = (client, server, back) if direction == "request" else (server, client, front)
        if actual != owned:
            raise AssertionError("upload endpoint ownership mismatch")
        timestamp = row.get("time_ns")
        if type(timestamp) is not int or timestamp < previous_time:
            raise AssertionError("missing or unordered upload capture time")
        previous_time = timestamp
        if row.get("forwarded_hex", row["hex"]) != row["hex"]:
            raise AssertionError("upload relay changed packet bytes")
        wire = bytes.fromhex(row["hex"])
        if (len(wire) < 4 or wire[0] >> 6 != 1 or not 0 <= wire[0] & 15 <= 8
                or len(wire) < 4 + (wire[0] & 15) or final_acked):
            raise AssertionError("malformed or late upload packet")
        if direction == "request":
            if (wire[0] >> 4) & 3 != 0 or wire[1] != 2 or not packet_token(wire):
                raise AssertionError("upload request is not a token-bound CON POST")
            options = decoded_options(wire)
            num = 0 if index == 0 else 1
            expected_options = {11: [b"upload"], 12: [b"*"], 19: [b"\x0e" if num == 0 else b"\x16"],
                                60: [b"\x07\xd0"], 292: [b"upload-1"]}
            if options != expected_options or coap_payload(wire) != LARGE[num * 1024:(num + 1) * 1024]:
                raise AssertionError("upload block does not match the complete representation")
            if num == 0:
                if action != "forward":
                    raise AssertionError("initial upload block not delivered")
                initial = wire
            else:
                if (not initial_acked or later_forwarded or packet_token(wire) != packet_token(initial)
                        or wire[2:4] == initial[2:4]):
                    raise AssertionError("later upload bypassed ACK ownership")
                if later is None:
                    if action != "drop":
                        raise AssertionError("first later upload block was not lost")
                    later = wire
                    first_drop_time = timestamp
                elif wire != later:
                    raise AssertionError("upload retry changed bytes or identity")
                else:
                    if retries == 0:
                        first_retry_interval = timestamp - first_drop_time
                        if not (INITIAL_RTO_NS[0] - CAPTURE_TOLERANCE_NS[0] <= first_retry_interval
                                <= INITIAL_RTO_NS[1] + CAPTURE_TOLERANCE_NS[1]):
                            raise AssertionError("first retry outside fixture RTO capture window")
                    retries += 1
                if action == "drop":
                    drops += 1
                else:
                    later_forwarded = True
        else:
            if action != "forward" or initial is None:
                raise AssertionError("unowned upload response")
            if not initial_acked:
                if wire != b"\x60\x00" + initial[2:4]:
                    raise AssertionError("initial upload ACK mismatch")
                initial_acked = True
            else:
                if (not later_forwarded or wire != bytes([0x60 | len(packet_token(later)), 65])
                        + later[2:4] + packet_token(later)):
                    raise AssertionError("final upload response mismatch")
                final_acked = True
    if retries < 1 or (complete and (drops != 1 or not final_acked)):
        raise AssertionError("missing successful upload loss/retry proof")
    if not complete and (drops < 2 or later_forwarded or final_acked or not initial_acked):
        raise AssertionError("missing permanent upload loss/refusal proof")
    return dict(complete=complete, delivered_bytes=2000 if complete else 1024, drops=drops,
                retransmissions=retries, accepted_before=accepted, accepted_after=expected,
                handler_calls_after=expected, first_retry_interval_ns=first_retry_interval,
                initial_rto_ns=INITIAL_RTO_NS, capture_tolerance_ns=CAPTURE_TOLERANCE_NS,
                trace=trace, endpoints=endpoints)
