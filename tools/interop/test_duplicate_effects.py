import copy
import unittest

from run import BODY, coap_message
from duplicate_effects import grade


def fixture():
    record = {"exchanges": []}
    specs = ((1, b"counter", 69, b"0", False), (2, b"counter", 68, b"", True),
             (1, b"counter", 69, b"2", False), (2, b"counter", 68, b"", False),
             (1, b"counter", 69, b"3", False), (1, b"test", 69, BODY, False))
    for index, (method, path, code, body, duplicate) in enumerate(specs):
        client, server = ["127.0.0.1", 10000 + index], ["127.0.0.1", 20000]
        back, front = ["127.0.0.1", 30000 + index], ["127.0.0.1", 40000 + index]
        request = coap_message(method, 50 + index, bytes([index]), [(11, path)])
        response = bytearray(coap_message(code, 50 + index, bytes([index]), [], body))
        response[0] = 0x60 | len(bytes([index]))
        row = {"direction": "request", "action": "duplicate" if duplicate else "forward",
               "hex": request.hex(), "forwarded_hex": request.hex(), "source": client,
               "destination": server, "relay": back, "time_ns": 1}
        replies = [{"direction": "response", "action": "forward", "hex": response.hex(),
                    "forwarded_hex": response.hex(), "source": server, "destination": client,
                    "relay": front, "time_ns": 2 + offset} for offset in range(2 if duplicate else 1)]
        record["exchanges"].append({"trace": [row, *replies],
                                    "result": {"exit_code": 0, "code": code, "payload_hex": body.hex()}})
    return record


class DuplicateOracle(unittest.TestCase):
    def test_characterization_is_not_dedup_pass(self):
        result = grade(fixture())
        self.assertEqual(result["duplicate_effects"], 2)
        self.assertIn("not present", result["duplicate_suppression"])

    def test_missing_duplicate_or_changed_wire_rejected(self):
        for mutation in ("missing-reply", "changed-wire", "not-duplicated", "wrong-owner", "wrong-mid"):
            record = fixture()
            trace = record["exchanges"][1]["trace"]
            if mutation == "missing-reply":
                trace.pop()
            elif mutation == "changed-wire":
                trace[0]["forwarded_hex"] += "00"
            elif mutation == "not-duplicated":
                trace[0]["action"] = "forward"
            elif mutation == "wrong-owner":
                trace[1]["source"][1] += 1
            else:
                packet = bytearray.fromhex(trace[1]["hex"])
                packet[3] ^= 1
                trace[1]["hex"] = trace[1]["forwarded_hex"] = packet.hex()
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                grade(record)

    def test_single_effect_and_missing_recovery_rejected(self):
        for index, body in ((2, b"1"), (4, b"2"), (5, b"wrong")):
            record = fixture()
            exchange = record["exchanges"][index]
            exchange["result"]["payload_hex"] = body.hex()
            with self.subTest(index=index), self.assertRaises(AssertionError):
                grade(record)
        record = fixture()
        record["exchanges"][3] = copy.deepcopy(record["exchanges"][1])
        record["exchanges"][3]["trace"][0]["action"] = "forward"
        record["exchanges"][3]["trace"].pop()
        with self.assertRaises(AssertionError):
            grade(record)


if __name__ == "__main__":
    unittest.main()
