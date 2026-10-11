"""CON reliability qualification refuses missing or incorrectly owned evidence."""
import copy
import unittest

from qblock_con import grade
from run import LARGE
from test_qblock_recovery import content, get, row

ENDPOINTS = dict(front=["127.0.0.1", 1001], back=["127.0.0.1", 1002], server=["127.0.0.1", 1003])
CLIENT = ["127.0.0.1", 1004]
SUCCESS = dict(event="response", code=69, payload_hex=LARGE.hex(), exit_code=0)
REFUSAL = dict(event="error", message="request timed out", exit_code=1)


def wire(num):
    packet = bytearray(content(num))
    packet[0] = (packet[0] & 15) | (0x60 if num == 0 else 0x40)
    if num == 0:
        packet[2:4] = get()[2:4]
    return bytes(packet)


def evidence(complete=True):
    trace = [row("request", get()), row("response", wire(0)), row("response", wire(1), "drop")]
    if complete:
        for num in range(1, 8):
            packet = wire(num)
            trace += [row("response", packet), row("request", b"\x60\x00" + packet[2:4])]
    else:
        trace.append(row("response", wire(1), "drop"))
    for index, item in enumerate(trace):
        incoming = item["direction"] == "request"
        item.update(time_ns=index * 3_000_000_000,
                    source=CLIENT if incoming else ENDPOINTS["server"],
                    destination=ENDPOINTS["server"] if incoming else CLIENT,
                    relay=ENDPOINTS["back"] if incoming else ENDPOINTS["front"])
    return trace


class ConRecoveryTests(unittest.TestCase):
    def test_complete_and_partial_evidence_are_distinct(self):
        passed = grade(evidence(), SUCCESS, ENDPOINTS, complete=True)
        self.assertEqual((passed["delivered_bytes"], passed["retransmissions"], passed["nstart"]), (2000, 1, 1))
        partial = grade(evidence(False), REFUSAL, ENDPOINTS, complete=False)
        self.assertEqual((partial["complete"], partial["delivered_bytes"], partial["drops"]), (False, 256, 2))
        for trace, result, complete in [(evidence(False), SUCCESS, True), (evidence(), REFUSAL, False)]:
            with self.assertRaises(AssertionError):
                grade(trace, result, ENDPOINTS, complete=complete)

    def test_every_datagram_and_owned_endpoint_is_required(self):
        original = evidence()
        for index in range(len(original)):
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                grade(original[:index] + original[index + 1:], SUCCESS, ENDPOINTS, complete=True)
            for key in ("source", "destination", "relay"):
                changed = copy.deepcopy(original)
                changed[index][key] = ["127.0.0.1", 9999]
                with self.subTest(index=index, endpoint=key), self.assertRaises(AssertionError):
                    grade(changed, SUCCESS, ENDPOINTS, complete=True)

    def test_changed_wire_or_action_refuses(self):
        for index in range(len(evidence())):
            for action in ("hold", "corrupt"):
                changed = evidence()
                changed[index]["action"] = action
                with self.subTest(index=index, action=action), self.assertRaises(AssertionError):
                    grade(changed, SUCCESS, ENDPOINTS, complete=True)
            for offset in (0, 1, 2, -1):
                changed = evidence()
                packet = bytearray.fromhex(changed[index]["hex"])
                packet[offset] ^= 1
                changed[index]["hex"] = packet.hex()
                with self.subTest(index=index, offset=offset), self.assertRaises(AssertionError):
                    grade(changed, SUCCESS, ENDPOINTS, complete=True)
        changed = evidence()
        changed[2]["action"] = "forward"
        with self.assertRaises(AssertionError):
            grade(changed, SUCCESS, ENDPOINTS, complete=True)
        changed = evidence()
        changed[3]["forwarded_hex"] = wire(2).hex()
        with self.assertRaises(AssertionError):
            grade(changed, SUCCESS, ENDPOINTS, complete=True)
        changed = evidence()
        changed[3]["forwarded_hex"] = changed[3]["hex"]
        changed[3]["hex"] = wire(2).hex()
        with self.assertRaises(AssertionError):
            grade(changed, SUCCESS, ENDPOINTS, complete=True)

    def test_nstart_bypass_and_wrong_ack_order_refuse(self):
        for left, right in [(2, 3), (3, 4), (4, 5), (5, 6)]:
            changed = evidence()
            changed[left], changed[right] = changed[right], changed[left]
            # Keep timestamps ordered, so packet ownership/state is the refusal.
            for index, item in enumerate(changed):
                item["time_ns"] = index
            with self.subTest(order=(left, right)), self.assertRaises(AssertionError):
                grade(changed, SUCCESS, ENDPOINTS, complete=True)
        for timestamp in (None, -1, "time"):
            changed = evidence()
            changed[3]["time_ns"] = timestamp
            with self.subTest(timestamp=timestamp), self.assertRaises(AssertionError):
                grade(changed, SUCCESS, ENDPOINTS, complete=True)

    def test_partial_refusal_requires_real_data_retry_and_protocol_timeout(self):
        trace = evidence(False)
        for index in range(len(trace)):
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                grade(trace[:index] + trace[index + 1:], REFUSAL, ENDPOINTS, complete=False)
        for change in [dict(exit_code=0), dict(event="response"), dict(message="socket unavailable"),
                       dict(code=69), dict(payload_hex="00")]:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                grade(trace, dict(REFUSAL, **change), ENDPOINTS, complete=False)


class Ipv6ConRecoveryTests(unittest.TestCase):
    def evidence(self, complete=True):
        trace = evidence(complete)
        for item in trace:
            for key in ("source", "destination", "relay"):
                item[key] = ["::1", item[key][1], 0, 0]
        endpoints = {key: ["::1", value[1], 0, 0] for key, value in ENDPOINTS.items()}
        endpoints.update(family="AF_INET6", v6only=[1, 1])
        return trace, endpoints

    def grade(self, trace, endpoints, complete=True, result=None):
        return grade(trace, (SUCCESS if complete else REFUSAL) if result is None else result,
                     endpoints, complete=complete, family="ipv6")

    def test_exact_complete_and_partial_ipv6_evidence(self):
        for complete, size in [(True, 2000), (False, 256)]:
            trace, endpoints = self.evidence(complete)
            proof = self.grade(trace, endpoints, complete)
            self.assertEqual((proof["family"], proof["delivered_bytes"], proof["complete"]),
                             ("ipv6", size, complete))
            with self.assertRaises(AssertionError):
                self.grade(trace, endpoints, not complete)
            with self.assertRaises(AssertionError):
                grade(trace, SUCCESS if complete else REFUSAL, endpoints, complete=complete)
        with self.assertRaises(AssertionError):
            grade(evidence(), SUCCESS, ENDPOINTS, complete=True, family="ipv6")
        with self.assertRaises(AssertionError):
            grade(evidence(), SUCCESS, ENDPOINTS, complete=True, family="unknown")

    def test_socket_family_and_every_endpoint_are_required(self):
        for complete in (True, False):
            trace, endpoints = self.evidence(complete)
            for key, values in [("family", [None, "AF_INET"]), ("v6only", [None, [0, 1], [1, 0]])]:
                for value in values:
                    with self.subTest(complete=complete, key=key, value=value), self.assertRaises(AssertionError):
                        self.grade(trace, dict(endpoints, **{key: value}), complete)
            for index in range(len(trace)):
                for key in ("source", "destination", "relay"):
                    for value in (["127.0.0.1", 9999], ["::ffff:127.0.0.1", 9999, 0, 0],
                                  ["::1", 9999, 0, 0], ["::1", 1001, 1, 0], ["::1", 1001, 0, 1]):
                        changed = copy.deepcopy(trace)
                        changed[index][key] = value
                        with self.subTest(index=index, key=key, value=value), self.assertRaises(AssertionError):
                            self.grade(changed, endpoints, complete)
            for key in ("front", "back", "server"):
                with self.subTest(endpoint=key), self.assertRaises(AssertionError):
                    self.grade(trace, dict(endpoints, **{key: ["::1", 9999, 0, 0]}), complete)

    def test_missing_changed_or_reordered_packets_refuse(self):
        for complete in (True, False):
            trace, endpoints = self.evidence(complete)
            for index in range(len(trace)):
                with self.subTest(missing=index), self.assertRaises(AssertionError):
                    self.grade(trace[:index] + trace[index + 1:], endpoints, complete)
                for offset in (0, 1, 2, -1):
                    changed = copy.deepcopy(trace)
                    wire = bytearray.fromhex(changed[index]["hex"])
                    wire[offset] ^= 1
                    changed[index]["hex"] = wire.hex()
                    with self.subTest(index=index, offset=offset), self.assertRaises(AssertionError):
                        self.grade(changed, endpoints, complete)
            changed = copy.deepcopy(trace)
            changed[2]["action"] = "forward"
            with self.assertRaises(AssertionError):
                self.grade(changed, endpoints, complete)
            changed = copy.deepcopy(trace)
            left, right = (2, 3) if complete else (1, 2)
            changed[left], changed[right] = changed[right], changed[left]
            for index, row in enumerate(changed):
                row["time_ns"] = index
            with self.assertRaises(AssertionError):
                self.grade(changed, endpoints, complete)
            with self.assertRaises(AssertionError):
                self.grade(trace * 256, endpoints, complete)

    def test_partial_result_cannot_be_an_application_response_or_non_timeout_error(self):
        trace, endpoints = self.evidence(False)
        for change in [dict(exit_code=0), dict(event="response"), dict(message="socket unavailable"),
                       dict(code=69), dict(payload_hex="00")]:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                self.grade(trace, endpoints, False, dict(REFUSAL, **change))


if __name__ == "__main__":
    unittest.main()
