"""Missing or altered independent upload evidence must never grade as completion."""
import copy
import unittest

from qblock_upload import grade, later_upload
from run import LARGE, coap_message

ENDPOINTS = dict(front=["127.0.0.1", 1001], back=["127.0.0.1", 1002], server=["127.0.0.1", 1003])
CLIENT = ["127.0.0.1", 1004]
SUCCESS = dict(event="response", code=65, payload_hex="", exit_code=0)
REFUSAL = dict(event="error", message="request timed out", exit_code=1)


def counts(value):
    return dict(event="response", code=69, payload_hex=value.encode().hex(), exit_code=0)


def upload(num):
    return coap_message(2, 10 + num, b"q", [(11, b"upload"), (12, b"*"),
                        (19, b"\x0e" if num == 0 else b"\x16"), (60, b"\x07\xd0"),
                        (292, b"upload-1")], LARGE[num * 1024:(num + 1) * 1024])


def evidence(complete=True):
    packets = [("request", "forward", upload(0)), ("response", "forward", b"\x60\x00\x00\x0a"),
               ("request", "drop", upload(1)), ("request", "forward" if complete else "drop", upload(1))]
    if complete:
        packets.append(("response", "forward", b"\x61\x41\x00\x0bq"))
    return [dict(direction=direction, action=action, hex=wire.hex(), forwarded_hex=wire.hex(),
                 time_ns=index * 3_000_000_000,
                 source=CLIENT if direction == "request" else ENDPOINTS["server"],
                 destination=ENDPOINTS["server"] if direction == "request" else CLIENT,
                 relay=ENDPOINTS["back"] if direction == "request" else ENDPOINTS["front"])
            for index, (direction, action, wire) in enumerate(packets)]


class UploadLossTests(unittest.TestCase):
    def grade(self, trace, complete=True, *, result=None, before=None, after=None, endpoints=None):
        return grade(trace, (SUCCESS if complete else REFUSAL) if result is None else result,
                     ENDPOINTS if endpoints is None else endpoints,
                     counts("1:1") if before is None else before,
                     counts("2:2" if complete else "1:1") if after is None else after, complete=complete)

    def test_exact_complete_partial_and_fresh_success(self):
        for complete, size, accepted in [(True, 2000, 2), (False, 1024, 1), (True, 2000, 2)]:
            proof = self.grade(evidence(complete), complete)
            self.assertEqual((proof["delivered_bytes"], proof["accepted_after"], proof["handler_calls_after"]),
                             (size, accepted, accepted))
            self.assertEqual(proof["retransmissions"], 1)

    def test_missing_or_reordered_evidence_refuses(self):
        for complete in (True, False):
            trace = evidence(complete)
            for index in range(len(trace)):
                with self.subTest(complete=complete, missing=index), self.assertRaises(AssertionError):
                    self.grade(trace[:index] + trace[index + 1:], complete)
            changed = copy.deepcopy(trace)
            changed[1], changed[2] = changed[2], changed[1]
            for index, row in enumerate(changed):
                row["time_ns"] = index
            with self.assertRaises(AssertionError):
                self.grade(changed, complete)
            with self.assertRaises(AssertionError):
                self.grade(trace * 256, complete)

    def test_changed_packet_or_forwarded_bytes_refuse(self):
        for complete in (True, False):
            trace = evidence(complete)
            for index in range(len(trace)):
                for offset in (0, 1, 2, 3, -1):
                    changed = copy.deepcopy(trace)
                    wire = bytearray.fromhex(changed[index]["hex"])
                    wire[offset] ^= 1
                    changed[index]["hex"] = changed[index]["forwarded_hex"] = wire.hex()
                    with self.subTest(index=index, offset=offset), self.assertRaises(AssertionError):
                        self.grade(changed, complete)
                changed = copy.deepcopy(trace)
                changed[index]["forwarded_hex"] = "00"
                with self.assertRaises(AssertionError):
                    self.grade(changed, complete)
            # A stable wrong tag/body across both later copies must still refuse.
            for old, new in [(b"upload-1", b"upload-2"), (LARGE[-8:], b"changed!")]:
                changed = copy.deepcopy(trace)
                for index in (2, 3):
                    wire = bytes.fromhex(changed[index]["hex"]).replace(old, new)
                    changed[index]["hex"] = changed[index]["forwarded_hex"] = wire.hex()
                with self.assertRaises(AssertionError):
                    self.grade(changed, complete)

    def test_all_endpoint_and_loss_ownership_is_required(self):
        for complete in (True, False):
            trace = evidence(complete)
            for index in range(len(trace)):
                for key in ("source", "destination", "relay"):
                    changed = copy.deepcopy(trace)
                    changed[index][key] = ["127.0.0.1", 9999]
                    with self.subTest(index=index, endpoint=key), self.assertRaises(AssertionError):
                        self.grade(changed, complete)
                for action in ("hold", "corrupt", "duplicate"):
                    changed = copy.deepcopy(trace)
                    changed[index]["action"] = action
                    with self.assertRaises(AssertionError):
                        self.grade(changed, complete)
            for key in ENDPOINTS:
                with self.assertRaises(AssertionError):
                    self.grade(trace, complete, endpoints=dict(ENDPOINTS, **{key: CLIENT}))
            changed = copy.deepcopy(trace)
            changed[2]["action"] = "forward"
            with self.assertRaises(AssertionError):
                self.grade(changed, complete)
            for timestamp in (None, -1, "time"):
                changed = copy.deepcopy(trace)
                changed[2]["time_ns"] = timestamp
                with self.assertRaises(AssertionError):
                    self.grade(changed, complete)

    def test_timeout_and_handler_effect_are_independent_requirements(self):
        for change in [dict(exit_code=0), dict(event="response"), dict(message="socket unavailable"),
                       dict(code=65), dict(payload_hex="00")]:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                self.grade(evidence(False), False, result=dict(REFUSAL, **change))
        for complete in (True, False):
            for bad in ("0:0", "2:3", "0:1", "9999:9999", "bad"):
                with self.subTest(complete=complete, counts=bad), self.assertRaises(AssertionError):
                    self.grade(evidence(complete), complete, after=counts(bad))
            with self.assertRaises(AssertionError):
                self.grade(evidence(complete), complete, before=counts("1:2"))
            with self.assertRaises(AssertionError):
                self.grade(evidence(complete), not complete)

    def test_retry_capture_must_match_declared_fixture_rto(self):
        for complete in (True, False):
            for interval in (0, 1, 1_000_000, 1_949_999_999, 4_000_000_001):
                changed = evidence(complete)
                changed[3]["time_ns"] = changed[2]["time_ns"] + interval
                if complete:
                    changed[4]["time_ns"] = changed[3]["time_ns"] + 1
                with self.subTest(complete=complete, interval=interval), self.assertRaises(AssertionError):
                    self.grade(changed, complete)
            for interval in (1_950_000_000, 2_000_000_000, 3_000_000_000, 4_000_000_000):
                changed = evidence(complete)
                changed[3]["time_ns"] = changed[2]["time_ns"] + interval
                if complete:
                    changed[4]["time_ns"] = changed[3]["time_ns"] + 1
                self.assertEqual(self.grade(changed, complete)["first_retry_interval_ns"], interval)

    def test_fault_selector_is_confined_to_later_con_upload(self):
        self.assertTrue(later_upload(upload(1)))
        self.assertFalse(later_upload(upload(0)))
        for packet in (b"", b"\x40", b"\x60\x00\x00\x01", upload(1).replace(b"upload", b"other!")):
            self.assertFalse(later_upload(packet))
        for offset, value in ((0, 0x51), (1, 1)):
            packet = bytearray(upload(1))
            packet[offset] = value
            self.assertFalse(later_upload(packet))


if __name__ == "__main__":
    unittest.main()
