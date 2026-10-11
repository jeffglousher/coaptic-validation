"""Mutations must not turn a cap outage, wrong owner or partial body into success."""
import copy
import unittest

from relay_cap import grade, grade_campaign
from run import BODY, LARGE, coap_message


def fixture(path="large", capped=False):
    endpoints = {"front": ["127.0.0.1", 10001], "back": ["127.0.0.1", 10002],
                 "server": ["127.0.0.1", 10003]}
    client = ["127.0.0.1", 10004]
    refusal = capped and path == "large"
    trace = []

    def add(direction, wire, stamp):
        incoming = direction == "request"
        trace.append({"direction": direction, "action": "drop" if capped and len(wire) > 256 else "forward",
                      "hex": wire.hex(), "forwarded_hex": wire.hex(), "time_ns": stamp,
                      "source": client if incoming else endpoints["server"],
                      "destination": endpoints["server"] if incoming else client,
                      "relay": endpoints["back"] if incoming else endpoints["front"]})

    for i in range(1 if path == "test" else 2):
        num = 0 if refusal else i
        mid = 42 + num
        options = [(11, path.encode())] + ([(23, b"\x16")] if num else [])
        add("request", coap_message(1, mid, b"cap", options), 1_000_000_000 + i * 2_500_000_000)
        body = BODY if path == "test" else LARGE[num * 1024:(num + 1) * 1024]
        opts = [] if path == "test" else [(4, b"tag"), (23, bytes([14 if num == 0 else 22])), (28, b"\x07\xd0")]
        wire = coap_message(69, mid, b"cap", opts, body)
        wire = bytes([wire[0] | 0x20]) + wire[1:]
        add("response", wire, 1_001_000_000 + i * 2_500_000_000)
    result = ({"event": "error", "exit_code": 1, "message": "request timed out", "host_total_ns": 6_510_000_000}
              if refusal else {"event": "response", "exit_code": 0, "code": 69,
                               "payload_hex": (BODY if path == "test" else LARGE).hex()})
    return {"trace": trace, "result": result, "endpoints": endpoints, "deadline_ms": 6500}


class RelayCapTests(unittest.TestCase):
    def check(self, evidence, path="large", capped=True):
        return grade(**evidence, path=path, capped=capped)

    def test_full_small_refusal_and_recovery_campaign(self):
        schedules = {"baseline": fixture(), "control": fixture("test", True),
                     "refusal": fixture(capped=True), "recovery": fixture()}
        for i, row in enumerate(schedules.values()):
            for packet in row["trace"]:
                packet["time_ns"] += i * 10_000_000_000
        self.assertTrue(grade_campaign(schedules))
        for label in schedules:
            missing = copy.deepcopy(schedules)
            del missing[label]
            with self.assertRaises(AssertionError):
                grade_campaign(missing)
        wrong_server = copy.deepcopy(schedules)
        wrong_server["recovery"]["endpoints"]["server"][1] += 1
        with self.assertRaises(AssertionError):
            grade_campaign(wrong_server)
        earlier_recovery = copy.deepcopy(schedules)
        earlier_recovery["recovery"] = fixture()
        with self.assertRaises(AssertionError):
            grade_campaign(earlier_recovery)

    def test_cap_loss_and_retry_are_required(self):
        mutations = [lambda e: e["trace"][1].update(action="forward"),
                     lambda e: e["trace"][0].update(action="drop"),
                     lambda e: e["trace"].__delitem__(slice(2, None)),
                     lambda e: e["trace"][2].update(time_ns=1_002_000_000),
                     lambda e: e["trace"][1].update(action="hold"),
                     lambda e: e["trace"][2].update(hex=e["trace"][2]["hex"] + "00", forwarded_hex=e["trace"][2]["hex"] + "00")]
        for mutate in mutations:
            e = fixture(capped=True)
            mutate(e)
            with self.subTest(mutation=mutate), self.assertRaises(AssertionError):
                self.check(e)

    def test_owner_bytes_block_metadata_and_body_refuse_mutations(self):
        for row in range(4):
            for field in ("source", "destination", "relay"):
                e = fixture(capped=True)
                e["trace"][row][field] = ["127.0.0.2", 10001]
                with self.assertRaises(AssertionError):
                    self.check(e)
        for byte in (0, 1, 2, 4, -1):
            e = fixture(capped=True)
            wire = bytearray.fromhex(e["trace"][1]["hex"])
            wire[byte] ^= 1
            e["trace"][1].update(hex=wire.hex(), forwarded_hex=wire.hex())
            with self.assertRaises(AssertionError):
                self.check(e)
        e = fixture(capped=True)
        e["trace"][1]["forwarded_hex"] += "00"
        with self.assertRaises(AssertionError):
            self.check(e)

    def test_timeout_is_not_crash_success_or_process_deadline(self):
        for changed in ({"exit_code": -9}, {"event": "response"}, {"code": 69},
                        {"payload_hex": "00"}, {"message": "process killed"},
                        {"host_total_ns": 100}, {"host_total_ns": 11_000_000_000}):
            e = fixture(capped=True)
            e["result"].update(changed)
            with self.assertRaises(AssertionError):
                self.check(e)

    def test_success_requires_entire_trace_and_report_body(self):
        for mutate in (lambda e: e["trace"].__delitem__(slice(2, None)),
                       lambda e: e["result"].update(payload_hex=LARGE[:1024].hex()),
                       lambda e: e["trace"][3].update(action="drop")):
            e = fixture()
            mutate(e)
            with self.assertRaises(AssertionError):
                self.check(e, capped=False)
        e = fixture("test", True)
        e["trace"][1].update(action="drop")
        with self.assertRaises(AssertionError):
            self.check(e, path="test")

    def test_block_size_size2_and_delivered_etag_are_bound(self):
        for tags in ([], [(4, b"")], [(4, b"123456789")], [(4, b"a"), (4, b"b")]):
            for capped in (True, False):
                e = fixture(capped=capped)
                wire = coap_message(69, 42, b"cap", tags + [(23, b"\x0e"), (28, b"\x07\xd0")], LARGE[:1024])
                wire = bytes([wire[0] | 0x20]) + wire[1:]
                e["trace"][1].update(hex=wire.hex(), forwarded_hex=wire.hex())
                with self.subTest(tags=tags, capped=capped), self.assertRaises(AssertionError):
                    self.check(e, capped=capped)
        for replacement in (bytes([15]), bytes([6])):
            e = fixture(capped=True)
            wire = coap_message(69, 42, b"cap", [(4, b"tag"), (23, replacement), (28, b"\x07\xd0")], LARGE[:1024])
            wire = bytes([wire[0] | 0x20]) + wire[1:]
            e["trace"][1].update(hex=wire.hex(), forwarded_hex=wire.hex())
            with self.assertRaises(AssertionError):
                self.check(e)
        for sizes in ([], [(28, b"\x07\xcf")]):
            e = fixture(capped=True)
            wire = coap_message(69, 42, b"cap", [(4, b"tag"), (23, b"\x0e")] + sizes, LARGE[:1024])
            wire = bytes([wire[0] | 0x20]) + wire[1:]
            e["trace"][1].update(hex=wire.hex(), forwarded_hex=wire.hex())
            with self.assertRaises(AssertionError):
                self.check(e)
        for capped in (True, False):
            e = fixture(capped=capped)
            wire = bytes.fromhex(e["trace"][3]["hex"]).replace(b"tag", b"new")
            e["trace"][3].update(hex=wire.hex(), forwarded_hex=wire.hex())
            if capped:
                self.check(e)
            else:
                with self.assertRaises(AssertionError):
                    self.check(e, capped=False)


if __name__ == "__main__":
    unittest.main()
