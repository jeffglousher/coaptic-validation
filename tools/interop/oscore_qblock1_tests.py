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


def evidence(mode="baseline", option=19, body=LARGE, sequence=0, response_mid=50):
    client = FixtureContext(server=False, wrong_key=mode == "wrong-key", sequence=sequence)
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
            response, _ = protect(server, b"\x41\x41" + response_mid.to_bytes(2, "big") + b"q", received_binding)
            loss = mode in ("drop-once", "drop-permanent")
            append("response", "drop" if loss else "forward", response)
            if loss:
                append("response", "drop" if mode == "drop-permanent" else "forward", response, retry=True)
            if mode != "drop-permanent":
                append("request", "forward", b"\x60\x00" + response_mid.to_bytes(2, "big"))
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



def ipv6_evidence(data):
    data = copy.deepcopy(data)
    for row in data[0]:
        for key in ("source", "destination", "relay"):
            row[key] = ["::1", row[key][1], 0, 0]
    for key in ("front", "back", "server"):
        data[2][key] = ["::1", data[2][key][1], 0, 0]
    data[2].update(family="AF_INET6", v6only=[1, 1])
    return data


def campaign_evidence(family="ipv6"):
    from oscore_qblock1 import MODES
    record = {"family": family, "server_ready": {"port": 1003, "transport": "oscore"},
              "schedules": [], "final_readback": counts(5)}
    for index, mode in enumerate(MODES):
        data = evidence(mode, sequence=201+index*300)
        if family == "ipv6": data = ipv6_evidence(data)
        data[3], data[4] = counts(min(index, 4)), counts(min(index, 4)+int(mode != "wrong-key"))
        data[1]["host_total_ns"] = (6_600_000_000 if mode == "drop-permanent" else
                                     710_000_000 if mode == "wrong-key" else 2_700_000_000)
        record["schedules"].append(dict(mode=mode, sequence_start=200+index*300,
            trace=data[0], result=data[1], endpoints=data[2], before=data[3], after=data[4],
            proof=grade(*data, family=family)))
    return record


class IPv6CampaignTests(unittest.TestCase):
    def test_authenticated_six_schedules_and_same_server_fresh_effect_recovery(self):
        import json
        from oscore_qblock1 import campaign_review
        for family in ("ipv4", "ipv6"):
            record = campaign_evidence(family)
            proof = campaign_review(record, family=family)
            self.assertEqual(proof["final_effect"], [5, 5])
            self.assertEqual(proof["fresh_upload_bindings"], [201, 501, 801, 1101, 1401, 1701])
            self.assertEqual(proof["distinct_request_pivs"], 11)
            self.assertEqual(proof["fresh_recovery_body_bytes"], 2000)
            self.assertEqual(campaign_review(json.loads(json.dumps(record)), family=family), proof)

    def test_separate_response_mid_is_sender_scoped_but_ack_owner_is_exact(self):
        for family in ("ipv4", "ipv6"):
            for mid in (10, 11):
                data = evidence("drop-once", response_mid=mid)
                if family == "ipv6": data = ipv6_evidence(data)
                self.assertEqual(grade(*data, family=family)["exact_client_acks"], 1)
                for mutate in (lambda d: d[0].pop(),
                               lambda d: d[0][-1].update(source=d[2]["server"]),
                               lambda d: d[0][-1].update(hex="600000ff", forwarded_hex="600000ff")):
                    changed = copy.deepcopy(data); mutate(changed)
                    with self.subTest(family=family, mid=mid), self.assertRaises(AssertionError):
                        grade(*changed, family=family)

    def test_actual_first_piv_can_follow_sizing_but_cannot_escape_reserved_range(self):
        from oscore_qblock1 import campaign_review
        for sequence in (1700, 1701, 1798, 1699, 1799, 1800):
            record = campaign_evidence()
            data = ipv6_evidence(evidence(sequence=sequence)); data[3], data[4] = counts(4), counts(5)
            record["schedules"][-1].update(trace=data[0], proof=grade(*data, family="ipv6"))
            if sequence in (1700, 1701, 1798):
                self.assertEqual(campaign_review(record, family="ipv6")["fresh_upload_bindings"][-1], sequence)
            else:
                with self.assertRaisesRegex(AssertionError, "reserved upload sequence range"):
                    campaign_review(record, family="ipv6")

    def test_address_family_refuses_fallback(self):
        for data, family in ((evidence(), "ipv6"), (ipv6_evidence(evidence()), "ipv4"), (evidence(), "unknown")):
            with self.subTest(family=family), self.assertRaises(AssertionError): grade(*data, family=family)
        from oscore_qblock1 import campaign_review
        with self.assertRaisesRegex(AssertionError, "family changed"): campaign_review(campaign_evidence())

    def test_exact_ipv6_endpoint_and_socket_ownership_mutations(self):
        invalid = (["127.0.0.1", 1004], ["::ffff:127.0.0.1", 1004, 0, 0], ["::1", 1004],
                   ["::1", 1004, 0], ["::1", 1004, 0, 0, 0], ["::2", 1004, 0, 0],
                   ["::1", True, 0, 0], ["::1", 1004.0, 0, 0], ["::1", 0, 0, 0],
                   ["::1", 65536, 0, 0], ["::1", 1004, 1, 0], ["::1", 1004, 0, 1],
                   ["::1", 1004, False, 0], ["::1", 1004, 0, False],
                   ["::1", 1004, 0.0, 0], ["::1", 1004, 0, 0.0], ["::1", 9999, 0, 0])
        for key in ("source", "destination", "relay"):
            for endpoint in invalid:
                data = ipv6_evidence(evidence()); data[0][-1][key] = endpoint
                with self.subTest(key=key, endpoint=endpoint), self.assertRaises(AssertionError):
                    grade(*data, family="ipv6")
        for changes in ({"family": None}, {"family": "AF_INET"}, {"v6only": None},
                        {"v6only": [1, 0]}, {"v6only": [True, 1]}, {"v6only": [1, 1.0]}, {"v6only": [1]}):
            data = ipv6_evidence(evidence()); data[2].update(changes)
            with self.subTest(changes=changes), self.assertRaises(AssertionError): grade(*data, family="ipv6")

    def test_ipv6_authenticated_body_options_and_ciphertext_refusals(self):
        for data in (evidence(option=27), evidence(body=LARGE[:-1]+b"\xff")):
            with self.assertRaises(AssertionError): grade(*ipv6_evidence(data), family="ipv6")
        data = ipv6_evidence(evidence("drop-once")); wire = bytearray.fromhex(data[0][5]["hex"]); wire[-1] ^= 1
        data[0][5].update(hex=wire.hex(), forwarded_hex=wire.hex())
        with self.assertRaises(AssertionError): grade(*data, family="ipv6")

    def test_ipv6_loss_retry_and_ack_mutations(self):
        for mode, mutate in (("baseline", lambda d: d[0].pop()),
                             ("baseline", lambda d: d[0].pop(1)),
                             ("baseline", lambda d: d[0][-1].update(hex="600000ff", forwarded_hex="600000ff")),
                             ("drop-request", lambda d: d[0].pop(1)),
                             ("drop-request", lambda d: d[0][1].update(time_ns=100_000_000)),
                             ("drop-once", lambda d: d[0].pop(5)),
                             ("drop-once", lambda d: d[0][5].update(time_ns=100_000_000)),
                             ("drop-permanent", lambda d: d[0][-1].update(action="forward")),
                             ("wrong-key", lambda d: d[0].pop()),
                             ("wrong-key", lambda d: d[4].update(payload_hex=b"1:1".hex()))):
            data = ipv6_evidence(evidence(mode)); mutate(data)
            with self.subTest(mode=mode), self.assertRaises(AssertionError): grade(*data, family="ipv6")

    def test_effects_order_owner_binding_and_missing_recovery_refuse(self):
        from oscore_qblock1 import campaign_review
        record = campaign_evidence()
        for mutate in (lambda r: r["schedules"].pop(), lambda r: r["schedules"].reverse(),
                       lambda r: r["schedules"][-1].update(trace=r["schedules"][0]["trace"]),
                       lambda r: r["schedules"][-1]["endpoints"].update(server=["::1", 9999, 0, 0]),
                       lambda r: r["schedules"][-1]["proof"].update(body_bytes_observed=1999),
                       lambda r: r["schedules"][-1].update(before=counts(3), after=counts(4)),
                       lambda r: r.update(final_readback=counts(4)),
                       lambda r: r["server_ready"].update(port=True),
                       lambda r: r["schedules"][-1].update(sequence_start=1400)):
            changed = copy.deepcopy(record); mutate(changed)
            with self.assertRaises(AssertionError): campaign_review(changed, family="ipv6")

    def test_nonprotocol_and_premature_timeouts_or_partial_success_refuse(self):
        from oscore_qblock1 import campaign_review
        record = campaign_evidence()
        for index in (3, 4):
            for change in ({"message": "subprocess deadline"}, {"message": "deadline has elapsed"},
                           {"message": "crash"}, {"exit_code": -9}, {"exit_code": 0},
                           {"host_total_ns": 100_000_000}, {"host_total_ns": 11_000_000_000},
                           {"host_total_ns": True}, {"code": 65}, {"payload_hex": "00"}):
                value = copy.deepcopy(record); value["schedules"][index]["result"].update(change)
                with self.subTest(index=index, change=change), self.assertRaises(AssertionError):
                    campaign_review(value, family="ipv6")

    def test_actual_ipv6_relay_metadata(self):
        from run import Proxy
        from oscore_qblock1 import _relay_endpoints, _endpoint
        with Proxy(9, "pass", family="ipv6") as relay:
            endpoints = _relay_endpoints(relay, "ipv6")
            self.assertEqual(endpoints["family"], "AF_INET6")
            self.assertEqual(endpoints["v6only"], [1, 1])
            for key in ("front", "back", "server"): _endpoint(endpoints[key], "ipv6")

    def test_reused_authenticated_request_binding_between_schedules_refuses(self):
        from oscore_qblock1 import campaign_review
        record = campaign_evidence()
        data = ipv6_evidence(evidence(sequence=201))
        data[3], data[4] = counts(4), counts(5)
        record["schedules"][-1].update(trace=data[0], proof=grade(*data, family="ipv6"))
        with self.assertRaisesRegex(AssertionError, "PIV reused between uploads"):
            campaign_review(record, family="ipv6")

    def test_complete_runner_uses_one_server_and_fresh_family_bound_requests(self):
        import socket
        from unittest.mock import MagicMock, patch
        from oscore_qblock1 import workflow
        expected = campaign_evidence()
        service = MagicMock(); service.__enter__.return_value = service
        service.number = 1003; service.ready = {**expected["server_ready"], "libcoap_patch_sha256": "expected"}
        relays, results = [], []
        for case in expected["schedules"]:
            relay = MagicMock(); relay.__enter__.return_value = relay
            relay.dest = ("::1", 1003, 0, 0); relay.number = 1001; relay.trace = case["trace"]
            for sock, port in ((relay.front, 1001), (relay.back, 1002)):
                sock.getsockname.return_value = ("::1", port, 0, 0)
                sock.family = socket.AF_INET6; sock.getsockopt.return_value = 1
            relays.append(relay)
            results.extend([case["before"], case["result"], case["after"]])
        results.append(counts(5))
        with patch("run.Server", return_value=service) as server, patch("run.Proxy", side_effect=relays) as proxy, \
             patch("run.request", side_effect=results) as request:
            actual = workflow("client", "server", family="ipv6", patch={"patch_sha256": "expected"})
        self.assertTrue(actual["complete"])
        self.assertEqual(actual["proof"]["fresh_recovery_body_bytes"], 2000)
        self.assertEqual(actual["proof"]["final_effect"], [5, 5])
        server.assert_called_once_with("server", "oscore", family="ipv6")
        self.assertEqual([call.args[1] for call in proxy.call_args_list],
                         ["pass", "drop-oscore-request-once", "drop-oscore-final-once", "drop-oscore-final-permanent", "pass", "pass"])
        self.assertEqual([call.kwargs["sequence"] for call in request.call_args_list], list(range(100, 2000, 100)))
        self.assertTrue(all(call.kwargs["family"] == "ipv6" for call in request.call_args_list))
        self.assertTrue(all(call.kwargs["family"] == "ipv6" for call in proxy.call_args_list))

    def test_runner_threads_family_and_retains_joined_failed_trace(self):
        import socket
        from unittest.mock import MagicMock, patch
        from oscore_qblock1 import workflow
        service, relay = MagicMock(), MagicMock()
        service.__enter__.return_value = service; service.number = 1003
        service.ready = {"transport": "oscore", "port": 1003}
        relay.__enter__.return_value = relay; relay.dest = ("::1", 1003, 0, 0); relay.number = 1001
        for sock, port in ((relay.front, 1001), (relay.back, 1002)):
            sock.getsockname.return_value = ("::1", port, 0, 0)
            sock.family = socket.AF_INET6; sock.getsockopt.return_value = 1
        def joined(*_):
            relay.trace = [{"retained": "joined IPv6 failure"}]
            return False
        relay.__exit__.side_effect = joined
        record = {}
        with patch("run.Server", return_value=service) as server, patch("run.Proxy", return_value=relay) as proxy, \
             patch("run.request", side_effect=[counts(0), RuntimeError("subprocess deadline")]) as request:
            with self.assertRaisesRegex(AssertionError, "subprocess deadline"):
                workflow("client", "server", family="ipv6", record=record)
        server.assert_called_once_with("server", "oscore", family="ipv6")
        proxy.assert_called_once_with(1003, "pass", family="ipv6")
        self.assertEqual([c.kwargs["family"] for c in request.call_args_list], ["ipv6", "ipv6"])
        self.assertEqual([c.kwargs["sequence"] for c in request.call_args_list], [100, 200])
        self.assertEqual(record["schedules"][0]["trace"], [{"retained": "joined IPv6 failure"}])
        self.assertFalse(record["complete"])
        self.assertNotIn("proof", record)

    def test_patch_identity_mismatch_refuses_before_any_request(self):
        from unittest.mock import MagicMock, patch
        from oscore_qblock1 import workflow
        service = MagicMock(); service.__enter__.return_value = service
        service.ready = {"port": 1003, "transport": "oscore", "libcoap_patch_sha256": "wrong"}
        record = {}
        with patch("run.Server", return_value=service), patch("run.request") as request:
            with self.assertRaisesRegex(AssertionError, "expected dependency patch"):
                workflow("client", "server", family="ipv6", record=record, patch={"patch_sha256": "expected"})
        request.assert_not_called()
        self.assertFalse(record["complete"])
        self.assertEqual(record["schedules"], [])

    def test_cli_failure_keeps_selected_family_and_partial_evidence(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from oscore_qblock1 import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); peer = root/"peer"; output = root/"report.json"; manifest = root/"patch.json"
            peer.write_bytes(b"test-only binary identity")
            manifest.write_text('{"patch_sha256":"test-only-patch"}', encoding="utf-8")
            def failed(_client, _server, *, family, record, patch):
                self.assertEqual(family, "ipv6")
                self.assertEqual(patch, {"patch_sha256": "test-only-patch"})
                record["schedules"] = [{"retained": "test-only failure"}]
                raise RuntimeError("subprocess deadline")
            args = ["campaign", "--family", "ipv6", "--coaptic", str(peer), "--libcoap", str(peer), "--output", str(output), "--libcoap-patch-manifest", str(manifest)]
            with patch("sys.argv", args), patch("run.source_identity", return_value={"source": "test-only"}), \
                 patch("oscore_qblock1.workflow", side_effect=failed), patch("builtins.print"):
                self.assertEqual(main(), 1)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value["family"], "ipv6")
            self.assertEqual(value["libcoap_patch"], {"patch_sha256": "test-only-patch"})
            self.assertFalse(value["qualification_complete"])
            self.assertEqual(len(value["campaign"]["schedules"]), 1)
            self.assertIn("subprocess deadline", value["error"])


if __name__ == "__main__":
    unittest.main()
