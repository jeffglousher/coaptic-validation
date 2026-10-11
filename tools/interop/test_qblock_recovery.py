"""Selective Q-Block2 recovery evidence must survive independent mutation checks."""
import copy
import unittest

from run import LARGE, block1_value, coap_message, command, grade_qblock2_missing


def row(direction, wire, action="forward"):
    return {"direction": direction, "action": action, "hex": wire.hex()}


def get(num=0, more=True, token=b"q"):
    return coap_message(1, 10 + num, token,
                        [(11, b"large"), (31, block1_value(num, more, 4))])


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


class RecoveryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
