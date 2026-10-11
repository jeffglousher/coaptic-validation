"""IPv6 fixture evidence must prove delivery, retry, refusal and exact ownership."""
import copy
import unittest

from run import coap_message
from separate_ipv6 import grade

ENDPOINTS = dict(family="AF_INET6", v6only=[1, 1], front=["::1", 1001, 0, 0],
                 back=["::1", 1002, 0, 0], server=["::1", 1003, 0, 0])
CLIENT = ["::1", 1004, 0, 0]
SUCCESS = dict(event="response", code=69, payload_hex=b"separate-payload".hex(), exit_code=0)
REFUSAL = dict(event="error", message="request timed out", exit_code=1)


def evidence(mode):
    request = coap_message(1, 10, b"t", [(11, b"separate")])
    reply = coap_message(69, 11, b"t", [(12, b"")], b"separate-payload")
    rows = [("request", "forward", request), ("response", "forward", b"\x60\x00\x00\x0a")]
    if mode == "fresh":
        rows += [("response", "forward", reply)]
    else:
        rows += [("response", "drop", reply), ("response", "drop" if mode == "permanent" else "forward", reply)]
    if mode != "permanent":
        rows += [("request", "forward", b"\x60\x00\x00\x0b")]
    return [dict(direction=direction, action=action, hex=wire.hex(), time_ns=index * 3_000_000_000,
                 source=CLIENT if direction == "request" else ENDPOINTS["server"],
                 destination=ENDPOINTS["server"] if direction == "request" else CLIENT,
                 relay=ENDPOINTS["back"] if direction == "request" else ENDPOINTS["front"])
            for index, (direction, action, wire) in enumerate(rows)]


class SeparateIpv6Tests(unittest.TestCase):
    def test_loss_refusal_and_fresh_are_distinct(self):
        for mode, delivered, retries in [("loss", 16, 1), ("permanent", 0, 1), ("fresh", 16, 0)]:
            proof = grade(evidence(mode), REFUSAL if mode == "permanent" else SUCCESS, ENDPOINTS, mode=mode)
            self.assertEqual(proof["delivered_bytes"], delivered)
            self.assertEqual(proof["retransmissions"], retries)
            self.assertEqual(proof["complete"], mode != "permanent")

    def test_missing_packets_wrong_endpoints_or_family_refuse(self):
        for mode in ("loss", "permanent", "fresh"):
            trace = evidence(mode)
            result = REFUSAL if mode == "permanent" else SUCCESS
            for index in range(len(trace)):
                with self.subTest(mode=mode, missing=index), self.assertRaises(AssertionError):
                    grade(trace[:index] + trace[index + 1:], result, ENDPOINTS, mode=mode)
                for key in ("source", "destination", "relay"):
                    changed = copy.deepcopy(trace)
                    changed[index][key] = ["::1", 9999, 0, 0]
                    with self.subTest(mode=mode, index=index, key=key), self.assertRaises(AssertionError):
                        grade(changed, result, ENDPOINTS, mode=mode)
            for key, value in [("family", "AF_INET"), ("v6only", [0, 1]), ("server", ["127.0.0.1", 1003])]:
                with self.subTest(mode=mode, key=key), self.assertRaises(AssertionError):
                    grade(trace, result, dict(ENDPOINTS, **{key: value}), mode=mode)

    def test_changed_wire_and_hidden_relay_rewrite_refuse(self):
        for index in range(len(evidence("loss"))):
            wire_length = len(bytes.fromhex(evidence("loss")[index]["hex"]))
            for offset in (0, 1, 2, -1) + ((4,) if wire_length > 4 else ()):
                changed = evidence("loss")
                packet = bytearray.fromhex(changed[index]["hex"])
                packet[offset] ^= 1
                changed[index]["hex"] = packet.hex()
                with self.subTest(index=index, offset=offset), self.assertRaises(AssertionError):
                    grade(changed, SUCCESS, ENDPOINTS, mode="loss")
            changed = evidence("loss")
            changed[index]["forwarded_hex"] = "00"
            with self.subTest(rewrite=index), self.assertRaises(AssertionError):
                grade(changed, SUCCESS, ENDPOINTS, mode="loss")
        changed = evidence("loss")
        changed[3]["forwarded_hex"] = changed[3]["hex"]
        changed[3]["hex"] += "00"
        with self.assertRaises(AssertionError):
            grade(changed, SUCCESS, ENDPOINTS, mode="loss")

    def test_actions_loss_and_ack_order_are_required(self):
        for index in range(len(evidence("loss"))):
            for action in ("hold", "corrupt"):
                changed = evidence("loss")
                changed[index]["action"] = action
                with self.subTest(index=index, action=action), self.assertRaises(AssertionError):
                    grade(changed, SUCCESS, ENDPOINTS, mode="loss")
        for left, right in [(1, 2), (2, 3), (3, 4)]:
            changed = evidence("loss")
            changed[left], changed[right] = changed[right], changed[left]
            for index, item in enumerate(changed):
                item["time_ns"] = index
            with self.subTest(order=(left, right)), self.assertRaises(AssertionError):
                grade(changed, SUCCESS, ENDPOINTS, mode="loss")
        changed = evidence("loss")
        changed[2]["action"] = "forward"
        with self.assertRaises(AssertionError):
            grade(changed, SUCCESS, ENDPOINTS, mode="loss")

    def test_refusal_requires_protocol_timeout_and_repeated_lost_reply(self):
        for change in [dict(exit_code=0), dict(event="response"), dict(message="socket unavailable"),
                       dict(code=69), dict(payload_hex="00")]:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                grade(evidence("permanent"), dict(REFUSAL, **change), ENDPOINTS, mode="permanent")
        with self.assertRaises(AssertionError):
            grade(evidence("fresh"), REFUSAL, ENDPOINTS, mode="permanent")


if __name__ == "__main__":
    unittest.main()
