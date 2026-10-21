"""Selective Q-Block2 recovery evidence must survive independent mutation checks."""
import copy
import unittest
from unittest.mock import patch

from run import (LARGE, block1_value, coap_message, command, grade_qblock2_missing,
                 grade_qblock2_timeout, grade_ipv6_relay, grade_qblock2_window, qblock2_window)


def row(direction, wire, action="forward"):
    return {"direction": direction, "action": action, "hex": wire.hex()}


def get(num=0, more=True, token=b"q", szx=4):
    return coap_message(1, 10 + num, token,
                        [(11, b"large"), (31, block1_value(num, more, szx))])


def content(num, *, more=None, szx=4, etag=b"v", token=b"q", payload=None, size=2000):
    return coap_message(69, 20 + num, token,
                        [(4, etag), (28, size.to_bytes(2, "big")),
                         (31, block1_value(num, num < 7 if more is None else more, szx))],
                        LARGE[num * 256:(num + 1) * 256] if payload is None else payload, non=True)


def evidence():
    return ([row("request", get()), row("response", content(0)),
             row("response", content(1), "drop")]
            + [row("response", content(num)) for num in range(2, 8)]
            + [row("request", get(1, False)), row("response", content(1))])


def window_evidence(*, non=True, ack=False):
    initial = coap_message(1, 90, b"w", [(11, b"large"), (31, block1_value(0, True, 6))], non=non)
    trace = [row("request", initial)]
    if ack:
        trace.append(row("response", b"\x60\x00" + initial[2:4]))
    for num in range(16):
        if num == 10:
            trace.append(row("request", coap_message(
                1, 91, b"w", [(11, b"large"), (31, block1_value(10, True, 3))], non=non)))
        packet = coap_message(69, 100 + num, b"w",
                              [(4, b"v"), (28, len(LARGE).to_bytes(2, "big")),
                               (31, block1_value(num, num < 15, 3))],
                              LARGE[num * 128:(num + 1) * 128], non=True)
        trace.append(row("response", packet))
    return trace


class WindowTests(unittest.TestCase):
    result = dict(event="response", code=69, payload_hex=LARGE.hex(), exit_code=0)

    def test_explicit_non_window_selection_does_not_require_an_empty_ack(self):
        trace = window_evidence()
        self.assertEqual(grade_qblock2_window(trace, self.result, require_non=True, require_ack=True),
                         dict(continue_num=10, blocks=16, length=2000))
        with patch("run.Server") as server, patch("run.Proxy") as proxy, patch("run.request") as request:
            server.return_value.__enter__.return_value.number = 1234
            relay = proxy.return_value.__enter__.return_value
            relay.number, relay.trace = 5678, trace
            request.return_value = self.result
            qblock2_window("peer-coaptic", "peer-coaptic", non=True)
            request.assert_called_once_with("peer-coaptic", "udp", 5678, path="large", timeout=20000,
                                            qblock2=False, qblock2_non=True)

    def test_con_negotiation_of_non_payloads_requires_its_own_empty_ack(self):
        trace = window_evidence(non=False, ack=True)
        self.assertEqual(grade_qblock2_window(trace, self.result, require_ack=True)["blocks"], 16)
        for replacement in (None, row("response", b"\x60\x00\x00\x5b")):
            changed = trace[:1] + ([] if replacement is None else [replacement]) + trace[2:]
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "empty ACK"):
                grade_qblock2_window(changed, self.result, require_ack=True)

    def test_confirmable_payload_train_cannot_satisfy_a_non_window(self):
        trace = window_evidence()
        wire = bytearray.fromhex(trace[1]["hex"])
        wire[0] &= ~0x10
        trace[1]["hex"] = wire.hex()
        with self.assertRaisesRegex(AssertionError, "payloads must be NON"):
            grade_qblock2_window(trace, self.result, require_non=True)
        with self.assertRaisesRegex(AssertionError, "explicit NON"):
            grade_qblock2_window(window_evidence(non=False, ack=True), self.result, require_non=True)

    def test_window_still_requires_continue_block_identity_and_complete_body(self):
        original = window_evidence()
        mutations = []
        mutations.append(original[:11] + original[12:])  # Missing NUM 10 Continue.
        changed = copy.deepcopy(original)
        changed[11] = row("request", get(10, True, token=b"w", szx=4))
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed[12] = row("response", coap_message(69, 110, b"w",
                           [(4, b"other"), (31, block1_value(10, True, 3))], LARGE[1280:1408], non=True))
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed[11] = row("request", coap_message(1, 91, b"w",
                           [(11, b"large"), (23, block1_value(10, True, 3)),
                            (31, block1_value(10, True, 3))], non=True))
        mutations.extend([changed, original[:-1]])
        changed = copy.deepcopy(original)
        packet = bytearray.fromhex(changed[-1]["hex"])
        packet[-1] ^= 1
        changed[-1]["hex"] = packet.hex()
        mutations.append(changed)
        for index, trace in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(AssertionError):
                grade_qblock2_window(trace, self.result, require_non=True)


class RecoveryTests(unittest.TestCase):
    def test_requests_must_be_forwarded_and_recovery_size_must_match(self):
        for index in (0, 9):
            for action in ("hold", "drop", "corrupt"):
                changed = copy.deepcopy(evidence())
                changed[index]["action"] = action
                with self.subTest(index=index, action=action), self.assertRaises(AssertionError):
                    grade_qblock2_missing(changed)
        changed = evidence()
        changed[9] = row("request", get(1, False, szx=3))
        with self.assertRaisesRegex(AssertionError, "recovery SZX"):
            grade_qblock2_missing(changed)

    def test_held_higher_blocks_do_not_prove_delivery_before_recovery(self):
        trace = evidence()
        # The complete body still arrives, but higher blocks arrive only after recovery.
        # Their earlier held copies must not satisfy the higher-block prerequisite.
        held = [dict(item, action="hold") for item in trace[3:9]]
        changed = trace[:3] + held + trace[9:] + trace[3:9]
        with self.assertRaisesRegex(AssertionError, "no higher Q-Block2"):
            grade_qblock2_missing(changed)

    def test_non_flag_is_explicit_and_preserves_the_existing_con_option(self):
        self.assertEqual(command("peer", "client", "udp", 5683, qblock2=True)[-1], "qblock2")
        args = command("peer", "client", "udp", 5683, qblock2_non=True)
        self.assertEqual(args[-2:], ["0", "qblock2-non"])
        self.assertNotIn("qblock2", args)

    def test_non_scenario_rejects_confirmable_requests_and_responses(self):
        trace = evidence()
        for index in (0, 9):
            wire = bytearray.fromhex(trace[index]["hex"])
            wire[0] |= 0x10
            trace[index]["hex"] = wire.hex()
        self.assertEqual(grade_qblock2_missing(trace, require_non=True)["length"], 2000)
        for index in (0, 2, 9, 10):
            changed = copy.deepcopy(trace)
            wire = bytearray.fromhex(changed[index]["hex"])
            wire[0] &= ~0x10
            changed[index]["hex"] = wire.hex()
            with self.subTest(index=index), self.assertRaises(AssertionError):
                grade_qblock2_missing(changed, require_non=True)

    def test_complete_selective_recovery(self):
        result = grade_qblock2_missing(evidence())
        self.assertEqual((result["missing"], result["blocks"], result["length"]), (1, 8, 2000))

    def test_missing_evidence_and_reordered_recovery_are_refused(self):
        trace = evidence()
        for index in range(len(trace)):
            with self.subTest(missing=index), self.assertRaises(AssertionError):
                grade_qblock2_missing(trace[:index] + trace[index + 1:])
        for left, right in ((2, 9), (9, 10)):
            changed = copy.deepcopy(trace)
            changed[left], changed[right] = changed[right], changed[left]
            with self.subTest(order=(left, right)), self.assertRaises(AssertionError):
                grade_qblock2_missing(changed)

    def test_changed_protocol_evidence_is_refused(self):
        mutations = [(2, row("response", content(1), "forward")),
                     (2, row("response", content(1, token=b"x"), "drop")),
                     (2, row("response", content(1, etag=b"x"), "drop")),
                     (9, row("request", get(2, False))),
                     (9, row("request", get(1, True))),
                     (10, row("response", content(1, etag=b"x"))),
                     (10, row("response", content(1, token=b"x"))),
                     (10, row("response", content(1, szx=3))),
                     (10, row("response", content(1, size=1999))),
                     (10, row("response", content(1, payload=b"x" * 256))),
                     (10, row("response", content(1, payload=b"x"))),
                     (8, row("response", content(7, more=True))),
                     (3, row("response", content(2, more=False)))]
        for index, replacement in mutations:
            changed = copy.deepcopy(evidence())
            changed[index] = replacement
            with self.subTest(index=index, replacement=replacement), self.assertRaises(AssertionError):
                grade_qblock2_missing(changed)

    def test_forwarded_bytes_are_the_delivery_evidence(self):
        trace = evidence()
        trace[-1]["forwarded_hex"] = content(1, payload=b"x" * 256).hex()
        with self.assertRaises(AssertionError):
            grade_qblock2_missing(trace)


class Ipv6RecoveryTests(unittest.TestCase):
    def trace(self):
        trace = evidence()
        for index in (0, 9):
            wire = bytearray.fromhex(trace[index]["hex"])
            wire[0] |= 0x10
            trace[index]["hex"] = wire.hex()
        return trace

    def test_exact_ipv6_endpoint_evidence_refuses_fallback_and_wrong_owner(self):
        endpoints = dict(family="AF_INET6", v6only=[1, 1], front=["::1", 1001, 0, 0],
                         back=["::1", 1002, 0, 0], server=["::1", 1003, 0, 0])
        client = ["::1", 1004, 0, 0]
        trace = self.trace()
        for row in trace:
            incoming = row["direction"] == "request"
            row.update(source=client if incoming else endpoints["server"],
                       destination=endpoints["server"] if incoming else client,
                       relay=endpoints["back"] if incoming else endpoints["front"])
        self.assertEqual(grade_ipv6_relay(trace, endpoints)["client"], tuple(client))
        for key, value in [("family", "AF_INET"), ("v6only", [0, 1]),
                           ("server", ["127.0.0.1", 1003]), ("front", endpoints["back"])]:
            changed = copy.deepcopy(endpoints)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                grade_ipv6_relay(trace, changed)
        for index in (0, 1, 2, 9, 10):
            for key in ("source", "destination", "relay"):
                for wrong in (["::1", 9999, 0, 0], ["::ffff:127.0.0.1", 1004, 0, 0], None):
                    changed = copy.deepcopy(trace)
                    changed[index][key] = wrong
                    with self.subTest(index=index, key=key, wrong=wrong), self.assertRaises(AssertionError):
                        grade_ipv6_relay(changed, endpoints)

    def test_partial_timeout_requires_real_incomplete_data_and_selective_attempt(self):
        trace = self.trace()[:-1]
        refusal = dict(event="error", message="request timed out", exit_code=1)
        proof = grade_qblock2_timeout(trace, refusal)
        self.assertFalse(proof["complete"])
        self.assertEqual(proof["partial_bytes"], 1744)
        self.assertEqual(proof["blocks"], 7)
        self.assertNotIn("length", proof)
        for invalid in [[], trace[:-1], trace[:3], self.trace()]:
            with self.subTest(trace=invalid), self.assertRaises(AssertionError):
                grade_qblock2_timeout(invalid, refusal)
        for change in [dict(exit_code=0), dict(event="response"), dict(message="socket unavailable"),
                       dict(code=69), dict(payload_hex="00")]:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                grade_qblock2_timeout(trace, dict(refusal, **change))
        for index in range(1, 9):
            changed = copy.deepcopy(trace)
            wire = bytearray.fromhex(changed[index]["hex"])
            wire[-1] ^= 1
            changed[index]["hex"] = wire.hex()
            with self.subTest(index=index), self.assertRaises(AssertionError):
                grade_qblock2_timeout(changed, refusal)
        with self.assertRaises(AssertionError):
            grade_qblock2_missing(trace, require_non=True)


if __name__ == "__main__":
    unittest.main()
