"""Authenticated synthetic oracle proofs; actual peer execution is separate."""
import copy
import unittest
from unittest.mock import MagicMock, patch

from oscore_qblock1 import FixtureContext, request_plain
from oscore_qblock2_tests import protected, ENDPOINTS
from oscore_observe_tests import observer, exchange, rows
from oscore_observe_cancel import review, campaign
from run import coap_message


def evidence(*, cancel_token=b"o", cancel_observe=b"\x01", wrong_binding=False,
             response_observe=False, fresh_token=b"o", reused_piv=False):
    before, _, endpoints = observer()
    before = before[:6]  # Registration plus one later observation and both ACKs.
    client = FixtureContext(server=False, sequence=101 if not reused_piv else 100)
    server = FixtureContext(server=True, sequence=1100)
    req = protected(client, coap_message(1, 30, cancel_token, [(6, cancel_observe), (11, b"counter")]))
    _, binding = request_plain(req if not wrong_binding else bytes.fromhex(before[0]["hex"]))
    response = protected(server, coap_message(69, 31, cancel_token, [(6, b"\x03")] if response_observe else [], b"1"), binding)
    cancel = rows([("request", "forward", req), ("response", "forward", b"\x60\x00\x00\x1e"),
                   ("response", "forward", response), ("request", "forward", b"\x60\x00\x00\x1f")], 10_000_000)
    after, _, _ = observer(2, sequence=102, server_sequence=1200)
    # Tokens are outer fields: use a fresh value without changing authentication.
    for row in after:
        wire = bytes.fromhex(row["hex"])
        old_mid = int.from_bytes(wire[2:4], "big")
        wire = wire[:2] + (40 if old_mid == 10 else old_mid + 40).to_bytes(2, "big") + wire[4:]
        if wire[0] & 15:
            wire = wire[:4] + fresh_token + wire[5:]
        row.update(hex=wire.hex(), forwarded_hex=wire.hex())
        row["time_ns"] += 3_100_000_000
    def ordinary(method, body, sequence, offset):
        record = exchange(method, body, sequence, offset)
        for index, row in enumerate(record["trace"]):
            row["time_ns"] = offset + index * 100_000
        return record

    return dict(server_ready=dict(transport="oscore", port=1003, libcoap_patch_sha256="patch"),
                setup=dict(event="response", exit_code=0, code=69, payload_hex=b"0".hex()),
                trace=before + cancel + after, endpoints=endpoints,
                result=dict(event="response", exit_code=0, code=69, payload_hex=b"0,1,1,2,3,4".hex()),
                writes=[ordinary(2, b"", 200, 3_100_000), ordinary(2, b"", 300, 100_000_000),
                        ordinary(2, b"", 500, 3_103_100_000), ordinary(2, b"", 600, 3_105_100_000)],
                quiet_readback=ordinary(1, b"2", 400, 200_000_000))


class CancellationTests(unittest.TestCase):
    def test_complete_authenticated_lifecycle(self):
        proof = review(evidence(fresh_token=b"n"), {"patch_sha256": "patch"})
        self.assertEqual(proof["complete_bodies"], ["0", "1", "1", "2", "3", "4"])
        self.assertGreaterEqual(proof["quiet_interval_ns"], 2_500_000_000)

    def test_authenticated_cancellation_identity_and_binding_refusal(self):
        for kw in ({"cancel_token": b"x"}, {"cancel_observe": b""},
                   {"wrong_binding": True}, {"response_observe": True}, {"reused_piv": True}):
            with self.subTest(kw=kw), self.assertRaises(AssertionError):
                review(evidence(fresh_token=b"n", **kw), {"patch_sha256": "patch"})

    def test_fresh_registration_must_use_new_token(self):
        with self.assertRaisesRegex(AssertionError, "cancelled token"):
            review(evidence(), {"patch_sha256": "patch"})

    def test_missing_cancel_ack_wrong_owner_and_packet_mutations_refuse(self):
        mutations = [lambda r: r["trace"].pop(9),
                     lambda r: r["trace"][8].update(source=["127.0.0.1", 9000]),
                     lambda r: r["trace"][7].update(hex="60000099", forwarded_hex="60000099"),
                     lambda r: r["trace"][8].update(action="drop"),
                     lambda r: r["trace"][8].update(forwarded_hex="00"),
                     lambda r: r["trace"][8].update(time_ns=0)]
        for i, mutate in enumerate(mutations):
            r = evidence(fresh_token=b"n")
            mutate(r)
            with self.subTest(i=i), self.assertRaises(AssertionError):
                review(r, {"patch_sha256": "patch"})

    def test_notification_during_quiet_interval_refuses(self):
        r = evidence(fresh_token=b"n")
        row = copy.deepcopy(r["trace"][4])
        row["time_ns"] = 500_000_000
        r["trace"].insert(10, row)
        with self.assertRaises(AssertionError):
            review(r, {"patch_sha256": "patch"})

    def test_each_phase_remains_at_original_client_endpoint(self):
        for begin, end in ((6, 10), (10, 18)):
            r = evidence(fresh_token=b"n")
            for row in r["trace"][begin:end]:
                row["source" if row["direction"] == "request" else "destination"] = ["127.0.0.1", 9009]
            with self.subTest(begin=begin), self.assertRaisesRegex(AssertionError, "client endpoint changed"):
                review(r, {"patch_sha256": "patch"})

    def test_client_request_mid_reuse_across_phases_refuses(self):
        r = evidence(fresh_token=b"n")
        for index in (10, 11):
            wire = bytes.fromhex(r["trace"][index]["hex"])
            wire = wire[:2] + b"\x00\x0a" + wire[4:]
            r["trace"][index].update(hex=wire.hex(), forwarded_hex=wire.hex())
        with self.assertRaisesRegex(AssertionError, "client request MID reused"):
            review(r, {"patch_sha256": "patch"})

    def test_server_mid_reuse_across_phases_refuses(self):
        r = evidence(fresh_token=b"n")
        for index in (12, 13):
            wire = bytes.fromhex(r["trace"][index]["hex"])
            wire = wire[:2] + b"\x00\x14" + wire[4:]
            r["trace"][index].update(hex=wire.hex(), forwarded_hex=wire.hex())
        with self.assertRaisesRegex(AssertionError, "server MID reused"):
            review(r, {"patch_sha256": "patch"})

    def test_silence_before_resource_change_does_not_replace_post_change_hold(self):
        r = evidence(fresh_token=b"n")
        shift = r["trace"][10]["time_ns"] - 5_000 - r["quiet_readback"]["trace"][-1]["time_ns"]
        for row in r["quiet_readback"]["trace"]:
            row["time_ns"] += shift
        with self.assertRaisesRegex(AssertionError, "after confirmed resource change"):
            review(r, {"patch_sha256": "patch"})

    def test_hold_update_readback_and_fresh_recovery_are_required(self):
        mutations = [lambda r: r["writes"].pop(),
                     lambda r: r["quiet_readback"]["result"].update(payload_hex=b"1".hex()),
                     lambda r: r["quiet_readback"]["trace"][-1].update(time_ns=4_000_000_000),
                     lambda r: r["writes"][1]["trace"][0].update(time_ns=1),
                     lambda r: r["trace"].pop(),
                     lambda r: r["result"].update(exit_code=1),
                     lambda r: r["server_ready"].update(libcoap_patch_sha256="other"),
                     lambda r: r["endpoints"].update(server=["::1", 1003, 0, 0])]
        for i, mutate in enumerate(mutations):
            r = evidence(fresh_token=b"n")
            mutate(r)
            with self.subTest(i=i), self.assertRaises(AssertionError):
                review(r, {"patch_sha256": "patch"})
        r = evidence(fresh_token=b"n")
        for row in r["trace"][10:]:
            row["time_ns"] -= 2_000_000_000
        with self.assertRaisesRegex(AssertionError, "cancellation hold"):
            review(r, {"patch_sha256": "patch"})

    def test_failure_retains_partial_trace_and_stops_only_owned_client(self):
        service, relay, writer, proc = (MagicMock() for _ in range(4))
        service.__enter__.return_value = service
        service.ready = dict(libcoap_patch_sha256="patch")
        service.number = 1003
        relay.__enter__.return_value = relay
        relay.snapshot.return_value = [{"retained": "partial lifecycle trace"}]
        proc.poll.return_value = None
        writer.__enter__.side_effect = RuntimeError("injected writer supervisor failure")
        writer.trace = [{"retained": "partial writer trace"}]
        r = {}
        with patch("oscore_observe_cancel.Server", return_value=service), \
             patch("oscore_observe_cancel.ObserveRelay", return_value=relay), \
             patch("oscore_observe_cancel.Proxy", return_value=writer), \
             patch("oscore_observe_cancel.subprocess.Popen", return_value=proc), \
             patch("oscore_observe_cancel.command", return_value=[]), \
             patch("oscore_observe_cancel.request", return_value=dict(exit_code=0, code=69, payload_hex=b"0".hex())), \
             patch("oscore_observe_cancel.authenticated_notifications", return_value=[(b"wire", b"0")]):
            with self.assertRaisesRegex(RuntimeError, "supervisor failure"):
                campaign(None, None, r, {"patch_sha256": "patch"})
        self.assertEqual(r["trace"], [{"retained": "partial lifecycle trace"}])
        self.assertEqual(r["writes"][0]["trace"], [{"retained": "partial writer trace"}])
        self.assertNotIn("complete", r)
        proc.kill.assert_called_once()
        proc.communicate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
