"""Focused authenticated oracle tests; run explicitly in the pinned OSCORE venv."""
import copy
import unittest

import aiocoap
from aiocoap.message import Direction

from oscore_qblock1 import FixtureContext, grade, request_plain, response_plain, final_response
from run import LARGE, coap_message


ENDPOINTS = dict(front=["127.0.0.1", 1001], back=["127.0.0.1", 1002], server=["127.0.0.1", 1003])
CLIENT = ["127.0.0.1", 1004]
SUCCESS = dict(event="response", code=65, payload_hex="", exit_code=0)
REFUSAL = dict(event="error", message="request timed out", exit_code=1)


def counts(n):
    return dict(event="response", code=69, payload_hex=f"{n}:{n}".encode().hex(), exit_code=0)


def protect(context, wire, request_id=None):
    plain = aiocoap.Message.decode(wire)
    plain.direction = Direction.OUTGOING
    protected, binding = context.protect(plain, request_id=request_id)
    protected.mtype, protected.mid, protected.token = plain.mtype, plain.mid, plain.token
    return protected.encode(), binding


def evidence(mode="baseline", option=19, body=LARGE):
    client = FixtureContext(server=False, wrong_key=mode == "wrong-key")
    server = FixtureContext(server=True)
    packets = []
    for num in range(1 if mode == "wrong-key" else 2):
        plain = coap_message(2, 10 + num, b"q", [(11, b"upload"), (12, b"*"),
                    (option, b"\x0e" if num == 0 else b"\x16"), (60, b"\x07\xd0"),
                    (292, b"upload-1")], body[num * 1024:(num + 1) * 1024])
        request, binding = protect(client, plain)
        packets.append(("request", "forward", request))
        if mode == "wrong-key":
            break
        if num == 0:
            packets.append(("response", "forward", b"\x60\x00\x00\x0a"))
        else:
            _, received_binding = request_plain(request)
            response, _ = protect(server, b"\x61\x41\x00\x0bq", received_binding)
            packets.append(("response", "forward" if mode == "baseline" else "drop", response))
            if mode != "baseline":
                packets += [("request", "forward", request),
                            ("response", "forward" if mode == "drop-once" else "drop", response)]
    trace = [dict(direction=d, action=a, hex=w.hex(), forwarded_hex=w.hex(), time_ns=i * 10_000_000 + (2_500_000_000 if i >= 4 else 0),
                  source=CLIENT if d == "request" else ENDPOINTS["server"],
                  destination=ENDPOINTS["server"] if d == "request" else CLIENT,
                  relay=ENDPOINTS["back"] if d == "request" else ENDPOINTS["front"])
             for i, (d, a, w) in enumerate(packets)]
    return [trace, REFUSAL.copy() if mode in ("wrong-key", "drop-permanent") else SUCCESS.copy(),
            copy.deepcopy(ENDPOINTS), counts(0), counts(0 if mode == "wrong-key" else 1), mode]


class ProtectedQBlockTests(unittest.TestCase):
    def test_original_rfc8613_c1_c4_authentication(self):
        context = FixtureContext(server=True)
        self.assertEqual(context.recipient_key.hex(), "f0910ed7295e6ad4b54fc793154302ff")
        self.assertEqual(context.sender_key.hex(), "ffb14e093c94c9cac9471648b4f98710")
        self.assertEqual(context.common_iv.hex(), "4622d4dd6d944168eefb54987c")
        plain, _ = request_plain(bytes.fromhex(
            "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"))
        self.assertEqual((int(plain.code), plain.opt.uri_path, plain.payload), (1, ("tv1",), b""))

    def test_original_rfc8613_c7_c8_response_binding(self):
        request = bytes.fromhex("44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e")
        for value in ("64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106",
                      "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e"):
            plain = response_plain(bytes.fromhex(value), request)
            self.assertEqual((int(plain.code), plain.payload), (69, b"Hello World!"))
        different_request = bytes.fromhex(evidence()[0][0]["hex"])
        with self.assertRaises(AssertionError):
            response_plain(bytes.fromhex(value), different_request)

    def test_success_loss_wrong_key_and_unknown_outcome(self):
        for mode in ("baseline", "drop-once", "drop-permanent", "wrong-key"):
            with self.subTest(mode=mode):
                proof = grade(*evidence(mode))
                self.assertEqual(proof["body_bytes_observed"], 1024 if mode == "wrong-key" else 2000)
        self.assertIn("one application effect", grade(*evidence("drop-permanent"))["client_outcome"])

    def test_classifier_requires_authenticated_final_response(self):
        trace = evidence()[0]
        self.assertFalse(final_response(bytes.fromhex(trace[1]["hex"]), trace[:1]))
        self.assertTrue(final_response(bytes.fromhex(trace[-1]["hex"]), trace[:-1]))
        with self.assertRaises(AssertionError):
            final_response(bytes.fromhex(trace[-1]["hex"][:-2] + "00"), trace[:-1])

    def test_validly_protected_classic_or_changed_body_refuse(self):
        for data in (evidence(option=27), evidence(body=LARGE[:-1] + b"\xff")):
            with self.assertRaises(AssertionError):
                grade(*data)

    def test_trace_mutations_refuse(self):
        mutations = [
            lambda x: x[0][0].update(action="drop"),
            lambda x: x[0][0].update(source=["127.0.0.2", 1004]),
            lambda x: x[0][1].update(destination=["127.0.0.1", 9999]),
            lambda x: x[0][0].update(forwarded_hex="00"),
            lambda x: x[0][0].update(hex=x[0][0]["hex"][:-2] + "00", forwarded_hex=x[0][0]["hex"][:-2] + "00"),
            lambda x: x[0][1].update(hex="600000ff", forwarded_hex="600000ff"),
            lambda x: x[0][-1].update(action="drop"),
            lambda x: x[0].pop(2),
            lambda x: x[0][-1].update(time_ns=-1),
            lambda x: x[0][-1].update(time_ns=9_000_000_000),
            lambda x: x[4].update(payload_hex=b"2:2".hex()),
            lambda x: x[1].update(payload_hex="01"),
        ]
        for change in mutations:
            data = evidence()
            change(data)
            with self.subTest(mutation=mutations.index(change)), self.assertRaises(AssertionError):
                grade(*data)

    def test_loss_and_timeout_mutations_refuse(self):
        for mode, mutate in [
            ("drop-once", lambda x: x[0][3].update(action="forward")),
            ("drop-once", lambda x: x[0][4].update(time_ns=x[0][2]["time_ns"] + 100_000_000)),
            ("drop-permanent", lambda x: x[0][-1].update(action="forward")),
            ("drop-permanent", lambda x: x[1].update(message="process killed")),
            ("drop-permanent", lambda x: x[1].update(exit_code=-9)),
            ("drop-permanent", lambda x: x[4].update(payload_hex=b"0:0".hex())),
            ("wrong-key", lambda x: x[4].update(payload_hex=b"1:1".hex())),
        ]:
            data = evidence(mode)
            mutate(data)
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                grade(*data)


if __name__ == "__main__":
    unittest.main()
