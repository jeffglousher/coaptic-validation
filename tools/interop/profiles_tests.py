import copy
import unittest

from profiles import exchange_identity, metadata_body, validate_trace
from run import coap_payload, decoded_options, packet_token, token_bounds


class ProfileOracleTests(unittest.TestCase):
    def fixture(self):
        token = bytes(range(32))
        request = bytes.fromhex("4d01123413") + token + b"\xb4test"
        reply = bytes.fromhex("6d45123413") + token + b"\xffready"
        return [
            {"direction": "request", "action": "forward", "hex": request.hex(), "forwarded_hex": request.hex(),
             "time_ns": 1, "source": ["127.0.0.1", 1100], "destination": ["127.0.0.1", 2200], "relay": ["127.0.0.1", 3300]},
            {"direction": "response", "action": "forward", "hex": reply.hex(), "forwarded_hex": reply.hex(),
             "time_ns": 2, "source": ["127.0.0.1", 2200], "destination": ["127.0.0.1", 1100], "relay": ["127.0.0.1", 4400]},
        ]

    def test_complete_extended_identity_and_shared_option_payload_decoder(self):
        trace = self.fixture()
        request, replies = exchange_identity(trace, [b"test"], 69, 32)
        self.assertEqual(packet_token(request), bytes(range(32)))
        self.assertEqual(decoded_options(request), {11: [b"test"]})
        self.assertEqual(coap_payload(replies[0]), b"ready")
        for wire in (b"", b"\x4f\x01\0\0", b"\x4d\x01\0\0", b"\x4e\x01\0\0\0", b"\x49\x01\0\0"):
            with self.assertRaises(AssertionError):
                token_bounds(wire)

    def test_missing_mutated_token_mid_endpoint_or_delivery_refuses(self):
        baseline = self.fixture()
        for kind in ("missing", "token", "mid", "source", "forward", "same-owner", "clock"):
            trace = copy.deepcopy(baseline)
            if kind == "missing":
                trace.pop()
            elif kind in ("token", "mid"):
                wire = bytearray.fromhex(trace[1]["hex"])
                wire[36 if kind == "token" else 3] ^= 1
                trace[1]["hex"] = trace[1]["forwarded_hex"] = wire.hex()
            elif kind == "source":
                trace[1]["source"][1] += 1
            elif kind == "forward":
                trace[1]["forwarded_hex"] += "00"
            elif kind == "same-owner":
                trace[1]["relay"] = trace[0]["relay"]
            else:
                trace[1]["time_ns"] = 0
            with self.assertRaises(AssertionError, msg=kind):
                exchange_identity(trace, [b"test"], 69, 32)

    def test_independent_metadata_parser_requires_exact_named_attributes(self):
        valid = b'</sensor>;rt="temperature-c sensor";if="sensor";ct="0 50";sz=96;obs;title="Room \\"one\\""'
        metadata_body(valid)
        for mutation in (valid.replace(b"96", b"97"), valid.replace(b";obs", b""), valid + b"," + valid,
                         valid.replace(b"0 50", b"0"), valid.replace(b"sensor\";ct", b"other\";ct")):
            with self.assertRaises(AssertionError):
                metadata_body(mutation)


if __name__ == "__main__":
    unittest.main()
