"""Synthetic baseline shapes only; actual protected peer qualification is hosted."""
import copy
import unittest
import aiocoap
from aiocoap.message import Direction
from oscore_qblock1 import FixtureContext, request_plain
from oscore_qblock2 import baseline, baseline_grade
from run import LARGE, coap_message

ENDPOINTS = {"front": ["127.0.0.1", 1001], "back": ["127.0.0.1", 1002], "server": ["127.0.0.1", 1003]}
CLIENT = ["127.0.0.1", 1004]

def protected(context, wire, binding=None):
    plain = aiocoap.Message.decode(wire)
    plain.direction = Direction.OUTGOING
    value, _ = context.protect(plain, request_id=binding)
    value.mtype, value.mid, value.token = plain.mtype, plain.mid, plain.token
    return value.encode()

def evidence(separate=False, *, tag=b"tag", size=b"\x07\xd0", q_option=31, body=LARGE, wrong_binding=False):
    client, server = FixtureContext(server=False), FixtureContext(server=True)
    wire = protected(client, coap_message(1, 10, b"q", [(11, b"large"), (31, b"\x0e")], b""))
    _, binding = request_plain(wire)
    packets = [("request", wire)]
    if wrong_binding:
        other = protected(client, coap_message(1, 11, b"q", [(11, b"large"), (31, b"\x0e")], b""))
        _, binding = request_plain(other)
    if separate:
        packets.append(("response", b"\x60\x00\x00\x0a"))
    for num in (0, 1):
        mid = 20 + num if separate or num else 10
        plain = coap_message(69, mid, b"q", sorted([(4, b"tag" if num == 0 else tag), (12, b"*"), (28, size),
                                          (q_option, b"\x0e" if num == 0 else b"\x16")]), body[num*1024:(num+1)*1024])
        if not separate and num == 0:
            plain = bytes([plain[0] | 0x20]) + plain[1:]
        packets.append(("response", protected(server, plain, binding)))
        if separate or num:
            packets.append(("request", b"\x60\x00" + mid.to_bytes(2, "big")))
    trace = [dict(direction=d, action="forward", hex=w.hex(), forwarded_hex=w.hex(), time_ns=i*1000000,
                  source=CLIENT if d == "request" else ENDPOINTS["server"],
                  destination=ENDPOINTS["server"] if d == "request" else CLIENT,
                  relay=ENDPOINTS["back"] if d == "request" else ENDPOINTS["front"])
             for i,(d,w) in enumerate(packets)]
    return [trace, dict(event="response", code=69, payload_hex=LARGE.hex(), exit_code=0), copy.deepcopy(ENDPOINTS)]

class BaselineTests(unittest.TestCase):
    def test_subprocess_failure_retains_joined_relay_trace(self):
        from unittest.mock import MagicMock, patch
        service, relay = MagicMock(), MagicMock()
        service.__enter__.return_value = service
        relay.__enter__.return_value = relay
        service.number = 1003
        relay.front.getsockname.return_value = ENDPOINTS["front"]
        relay.back.getsockname.return_value = ENDPOINTS["back"]
        relay.dest = ENDPOINTS["server"]
        # The trace becomes final only when the context joins its worker.
        relay.trace = []
        def joined(*_):
            relay.trace = [{"action": "forward", "partial": True}]
            return False
        relay.__exit__.side_effect = joined
        record = {}
        with patch("run.Server", return_value=service), patch("run.Proxy", return_value=relay), \
             patch("run.expect"), patch("run.request", side_effect=[{}, RuntimeError("subprocess deadline")]):
            with self.assertRaisesRegex(RuntimeError, "subprocess deadline"):
                baseline(None, None, record)
        self.assertEqual(record["trace"], [{"action": "forward", "partial": True}])
        self.assertEqual(record["endpoints"]["server"], ENDPOINTS["server"])
        self.assertNotIn("proof", record)
        self.assertNotIn("result", record)

    def test_authenticated_baseline_shapes(self):
        for separate in (False, True):
            proof=baseline_grade(*evidence(separate))
            self.assertEqual(proof["body_bytes"], 2000)
            self.assertIn("baseline only", proof["scope"])
    def test_missing_or_wrong_owners_and_body_refuse(self):
        for mutate in (
            lambda x: x[0].pop(),
            lambda x: x[0][0].update(action="drop"),
            lambda x: x[0][-1].update(source=["127.0.0.1", 9999]),
            lambda x: x[0][-1].update(hex="600000ff", forwarded_hex="600000ff"),
            lambda x: x[1].update(payload_hex=LARGE[:-1].hex()),
            lambda x: x[0][1].update(hex=x[0][1]["hex"][:-2]+"00", forwarded_hex=x[0][1]["hex"][:-2]+"00"),
        ):
            data=evidence();mutate(data)
            with self.assertRaises(AssertionError):baseline_grade(*data)
    def test_authenticated_representation_and_binding_mutations_refuse(self):
        for changes in ({"tag": b"changed"}, {"tag": b""}, {"tag": b"123456789"},
                        {"size": b"\x07\xd1"}, {"q_option": 23},
                        {"body": LARGE[:-1]+b"\xff"}, {"wrong_binding": True}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                baseline_grade(*evidence(**changes))

    def test_separate_response_requires_initial_settlement(self):
        data=evidence(True);data[0].pop(1)
        with self.assertRaises(AssertionError):baseline_grade(*data)

if __name__ == "__main__": unittest.main()
