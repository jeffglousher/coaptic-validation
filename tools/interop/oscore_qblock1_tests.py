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
    at = 0
    def append(direction, action, wire, *, retry=False):
        nonlocal at
        at += 2_500_000_000 if retry else 10_000_000
        packets.append((direction, action, wire, at))
    for num in range(1 if mode == "wrong-key" else 2):
        plain = coap_message(2, 10 + num, b"q", [(11, b"upload"), (12, b"*"),
                    (option, b"\x0e" if num == 0 else b"\x16"), (60, b"\x07\xd0"),
                    (292, b"upload-1")], body[num * 1024:(num + 1) * 1024])
        request, binding = protect(client, plain)
        if mode == "drop-request" and num == 0:
            append("request", "drop", request)
            append("request", "forward", request, retry=True)
        else:
            append("request", "forward", request)
        if mode == "wrong-key":
            error = coap_message(128, 10, b"q", [(14, b"")], b"Decryption failed")
            error = bytes([error[0] | 0x20]) + error[1:]
            append("response", "forward", error)
            break
        append("response", "forward", b"\x60\x00\x00" + bytes([10 + num]))
        if num == 1:
            _, received_binding = request_plain(request)
            response, _ = protect(server, b"\x41\x41\x00\x32q", received_binding)
            loss = mode in ("drop-once", "drop-permanent")
            append("response", "drop" if loss else "forward", response)
            if loss:
                append("response", "drop" if mode == "drop-permanent" else "forward", response, retry=True)
            if mode != "drop-permanent":
                append("request", "forward", b"\x60\x00\x00\x32")
    trace = [dict(direction=d, action=a, hex=w.hex(), forwarded_hex=w.hex(), time_ns=t,
                  source=CLIENT if d == "request" else ENDPOINTS["server"],
                  destination=ENDPOINTS["server"] if d == "request" else CLIENT,
                  relay=ENDPOINTS["back"] if d == "request" else ENDPOINTS["front"])
             for d, a, w, t in packets]
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
        for mode in ("baseline", "drop-request", "drop-once", "drop-permanent", "wrong-key"):
            with self.subTest(mode=mode):
                proof = grade(*evidence(mode))
                self.assertEqual(proof["body_bytes_observed"], 1024 if mode == "wrong-key" else 2000)
        self.assertIn("one application effect", grade(*evidence("drop-permanent"))["client_outcome"])

    def test_classifier_requires_authenticated_final_response(self):
        trace = evidence()[0]
        self.assertFalse(final_response(bytes.fromhex(trace[1]["hex"]), trace[:1]))
        self.assertTrue(final_response(bytes.fromhex(trace[4]["hex"]), trace[:4]))
        with self.assertRaises(AssertionError):
            final_response(bytes.fromhex(trace[4]["hex"][:-2] + "00"), trace[:4])

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

    def test_pending_con_requires_exact_owner_settlement(self):
        missing = evidence()
        missing[0].pop(1)
        delayed = evidence()
        delayed[0][1], delayed[0][2] = delayed[0][2], delayed[0][1]
        for i, row in enumerate(delayed[0]):
            row["time_ns"] = i * 10_000_000
        settled_retry = evidence()
        retry = copy.deepcopy(settled_retry[0][0])
        retry["time_ns"] = 2_500_000_000
        settled_retry[0].insert(2, retry)
        for row in settled_retry[0][3:]:
            row["time_ns"] += 2_500_000_000
        for name, data in (("missing ACK", missing), ("delayed ACK", delayed),
                           ("settled retry", settled_retry)):
            with self.subTest(case=name), self.assertRaises(AssertionError):
                grade(*data)

    def test_unrelated_retry_does_not_prove_final_reply_recovery(self):
        for mode in ("drop-once", "drop-permanent"):
            data = evidence(mode)
            data[0].insert(1, copy.deepcopy(data[0][0]))
            data[0].pop(6)  # Remove actual separate-response retry.
            for i, row in enumerate(data[0]):
                row["time_ns"] = 0 if i == 0 else 2_000_000_000 + i * 10_000_000
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                grade(*data)

    def test_separate_ack_and_retry_mutations_refuse(self):
        for mode, mutate in [
            ("baseline", lambda x: x[0].pop()),
            ("baseline", lambda x: x[0][-1].update(hex="60000033", forwarded_hex="60000033")),
            ("baseline", lambda x: x[0][-1].update(source=["127.0.0.1", 9999])),
            ("baseline", lambda x: x[0][-1].update(action="drop")),
            ("drop-once", lambda x: x[0][5].update(hex=x[0][5]["hex"][:-2] + "00", forwarded_hex=x[0][5]["hex"][:-2] + "00")),
            ("drop-once", lambda x: x[0][5].update(time_ns=x[0][4]["time_ns"] + 100_000_000)),
            ("drop-request", lambda x: x[0][0].update(action="forward")),
            ("drop-request", lambda x: x[0].pop(1)),
            ("drop-request", lambda x: x[0][1].update(time_ns=100_000_000)),
        ]:
            data = evidence(mode)
            mutate(data)
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                grade(*data)

    def test_wrong_key_diagnostic_is_not_authenticated_progress(self):
        originals = evidence("wrong-key")
        invalid = [
            coap_message(65, 10, b"q", [(14, b"")], b"Decryption failed"),
            coap_message(128, 11, b"q", [(14, b"")], b"Decryption failed"),
            coap_message(128, 10, b"r", [(14, b"")], b"Decryption failed"),
            coap_message(128, 10, b"q", [(9, b"")], b"Decryption failed"),
            coap_message(128, 10, b"q", [(14, b"\x01")], b"Decryption failed"),
            coap_message(128, 10, b"q", [(14, b"")], b"changed diagnostic"),
        ]
        for wire in invalid:
            data = copy.deepcopy(originals)
            wire = bytes([wire[0] | 0x20]) + wire[1:]
            data[0][-1].update(hex=wire.hex(), forwarded_hex=wire.hex())
            with self.subTest(wire=wire.hex()), self.assertRaises(AssertionError):
                grade(*data)
        missing = copy.deepcopy(originals)
        missing[0].pop()
        with self.assertRaises(AssertionError):
            grade(*missing)
        advanced = copy.deepcopy(originals)
        advanced[1] = SUCCESS.copy()
        with self.assertRaises(AssertionError):
            grade(*advanced)

    def test_loss_and_timeout_mutations_refuse(self):
        for mode, mutate in [
            ("drop-once", lambda x: x[0][4].update(action="forward")),
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
