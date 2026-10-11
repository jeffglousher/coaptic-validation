"""Synthetic baseline shapes only; actual protected peer qualification is hosted."""
import copy
import unittest
import aiocoap
from aiocoap.message import Direction
from oscore_qblock1 import FixtureContext, request_plain
from oscore_qblock2 import baseline, baseline_grade, campaign, campaign_grade, campaign_review, later_response
from run import LARGE, coap_message

ENDPOINTS = {"front": ["127.0.0.1", 1001], "back": ["127.0.0.1", 1002], "server": ["127.0.0.1", 1003]}
CLIENT = ["127.0.0.1", 1004]

def protected(context, wire, binding=None, explicit_piv=True):
    plain = aiocoap.Message.decode(wire)
    plain.direction = Direction.OUTGOING
    if binding is not None:
        binding.can_reuse_nonce = not explicit_piv
    value, _ = context.protect(plain, request_id=binding)
    value.mtype, value.mid, value.token = plain.mtype, plain.mid, plain.token
    return value.encode()

def evidence(separate=False, *, tag=b"tag", size=b"\x07\xd0", q_option=31, body=LARGE, wrong_binding=False, missing_piv=False, reused_piv=False, sequence=0, server_sequence=0):
    client, server = FixtureContext(server=False, sequence=sequence), FixtureContext(server=True, sequence=server_sequence)
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
        if reused_piv:
            server.sender_sequence_number = 0
        packets.append(("response", protected(server, plain, binding, not missing_piv)))
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

    def test_opposite_senders_may_choose_same_mid_in_both_families(self):
        def rewrite(data, old, new):
            for row in data[0]:
                wire = bytes.fromhex(row["hex"])
                if wire[2:4] == old.to_bytes(2, "big"):
                    wire = wire[:2] + new.to_bytes(2, "big") + wire[4:]
                    row.update(hex=wire.hex(), forwarded_hex=wire.hex())
        for family in ("ipv4", "ipv6"):
            for response_mid in (20, 21):
                data = evidence(True)
                rewrite(data, response_mid, 10)
                if family == "ipv6": data = ipv6_evidence(data)
                self.assertEqual(baseline_grade(*data, family=family)["body_bytes"], 2000)
            for mode in ("drop-once", "drop-permanent"):
                data = loss_evidence(mode)
                rewrite(data, 21, 10)
                if family == "ipv6": data = ipv6_evidence(data)
                self.assertEqual(campaign_grade(*data, mode, family=family)["delivered_body_bytes"],
                                 2000 if mode == "drop-once" else 1024)

    def test_same_sender_mid_reuse_and_wrong_ack_still_refuse(self):
        for family in ("ipv4", "ipv6"):
            for mode in ("baseline", "drop-once", "drop-permanent"):
                data = evidence(True) if mode == "baseline" else loss_evidence(mode)
                if mode == "baseline": data[1]["host_total_ns"] = 10_000_000
                for row in data[0]:
                    wire = bytes.fromhex(row["hex"])
                    if wire[2:4] == b"\x00\x15":
                        wire = wire[:2] + b"\x00\x14" + wire[4:]
                        row.update(hex=wire.hex(), forwarded_hex=wire.hex())
                if family == "ipv6": data = ipv6_evidence(data)
                with self.assertRaises(AssertionError): campaign_grade(*data, mode, family=family)
            data = evidence(True)
            data[0][3].update(hex="6000000a", forwarded_hex="6000000a")
            if family == "ipv6": data = ipv6_evidence(data)
            with self.assertRaisesRegex(AssertionError, "ACK"):
                baseline_grade(*data, family=family)

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

    def test_missing_or_reused_server_piv_refuses_authenticated_distinct_blocks(self):
        for change in ({"missing_piv": True}, {"reused_piv": True}):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, "explicit server PIVs"):
                baseline_grade(*evidence(**change))

    def test_separate_response_requires_initial_settlement(self):
        data=evidence(True);data[0].pop(1)
        with self.assertRaises(AssertionError):baseline_grade(*data)


def loss_evidence(mode="drop-once", **kwargs):
    data = evidence(True, **kwargs)
    trace, result, _ = data
    result["host_total_ns"] = 2_600_000_000
    trace[4]["action"] = "drop"
    retry = copy.deepcopy(trace[4])
    retry["time_ns"] = trace[4]["time_ns"] + 2_500_000_000
    retry["action"] = "forward" if mode == "drop-once" else "drop"
    trace.insert(5, retry)
    trace[6]["time_ns"] = retry["time_ns"] + 1_000_000
    if mode == "drop-permanent":
        trace.pop()
        data[1] = dict(event="error", exit_code=1, message="request timed out", host_total_ns=6_600_000_000)
    return data


def wrong_evidence(sequence=0):
    client = FixtureContext(server=False, wrong_key=True, sequence=sequence)
    req = protected(client, coap_message(1, 10, b"q", [(11, b"large"), (31, b"\x0e")], b""))
    reply = coap_message(128, 10, b"q", [(14, b"")], b"Decryption failed")
    reply = bytes([reply[0] | 0x20]) + reply[1:]
    trace = evidence(True)[0][:2]
    for row, wire in zip(trace, (req, reply)):
        row.update(hex=wire.hex(), forwarded_hex=wire.hex())
    return [trace, dict(event="error", exit_code=1, message="request timed out", host_total_ns=710_000_000), copy.deepcopy(ENDPOINTS)]


class CampaignTests(unittest.TestCase):
    def test_complete_loss_partial_refusal_and_wrong_key(self):
        for mode in ("drop-once", "drop-permanent"):
            proof = campaign_grade(*loss_evidence(mode), mode)
            self.assertEqual(proof["delivered_body_bytes"], 2000 if mode == "drop-once" else 1024)
            self.assertEqual(proof["exact_ciphertext_retries"], 1)
        self.assertEqual(campaign_grade(*wrong_evidence(), "wrong-key")["delivered_body_bytes"], 0)
        data = evidence(True); data[1]["host_total_ns"] = 10_000_000
        self.assertEqual(campaign_grade(*data, "baseline")["delivered_body_bytes"], 2000)

    def test_permanent_second_exponential_retry(self):
        data = loss_evidence("drop-permanent")
        retry = copy.deepcopy(data[0][-1]); data[0][-1]["time_ns"] = data[0][4]["time_ns"] + 2_050_000_000
        retry["time_ns"] = data[0][-1]["time_ns"] + 4_100_000_000
        data[0].append(retry); data[1]["host_total_ns"] = 6_600_000_000
        self.assertEqual(campaign_grade(*data, "drop-permanent")["exact_ciphertext_retries"], 2)
        data[0][-1]["time_ns"] -= 2_000_000_000
        with self.assertRaisesRegex(AssertionError, "RTO"):
            campaign_grade(*data, "drop-permanent")

    def test_later_backoff_is_bound_to_first_actual_interval(self):
        data = loss_evidence("drop-permanent")
        data[0][-1]["time_ns"] = data[0][4]["time_ns"] + 2_100_000_000
        retry = copy.deepcopy(data[0][-1]); retry["time_ns"] += 3_950_000_000
        data[0].append(retry)
        # 3.95s meets the generic second-RTO floor but improperly shortens
        # the observed 2.1s initial interval's 4.2s exponential backoff.
        with self.assertRaisesRegex(AssertionError, "observed exponential"):
            campaign_grade(*data, "drop-permanent")

    def test_loss_schedule_owner_ack_and_timer_mutations_refuse(self):
        mutations = (
            lambda d: d[0].pop(1),  # initial request ACK
            lambda d: d[0].pop(3),  # first block ACK
            lambda d: d[0].pop(),   # final block ACK
            lambda d: d[0].pop(5),  # actual retry
            lambda d: d[0][4].update(action="forward"),
            lambda d: d[0][5].update(action="drop"),
            lambda d: d[0][5].update(time_ns=10_000_000),
            lambda d: d[0][5].update(time_ns=3_500_000_000),
            lambda d: d[0][-1].update(source=["127.0.0.1", 9999]),
            lambda d: d[0][-1].update(hex="600000ff", forwarded_hex="600000ff"),
            lambda d: d[0][5].update(destination=["127.0.0.1", 9999]),
            lambda d: d[0][4].update(relay=["127.0.0.1", 9999]),
            lambda d: d[0][4].update(forwarded_hex=d[0][2]["hex"]),
            lambda d: d[0][5].update(hex=d[0][2]["hex"], forwarded_hex=d[0][2]["hex"]),
            lambda d: d[1].update(payload_hex=LARGE[:-1].hex()),
            lambda d: d[1].update(host_total_ns=11_000_000_000),
        )
        for index, mutate in enumerate(mutations):
            data = loss_evidence(); mutate(data)
            with self.subTest(mutation=index), self.assertRaises(AssertionError):
                campaign_grade(*data, "drop-once")

    def test_unrelated_retry_cannot_replace_lost_later_response_retry(self):
        data = loss_evidence()
        data[0].pop(5)
        earlier = copy.deepcopy(data[0][2]); earlier["time_ns"] = data[0][3]["time_ns"]
        data[0].insert(3, earlier)
        with self.assertRaises(AssertionError):
            campaign_grade(*data, "drop-once")

    def test_lost_authenticated_body_metadata_binding_and_piv_mutations(self):
        for changes in ({"tag": b"other"}, {"tag": b""}, {"tag": b"123456789"},
                        {"size": b"\x07\xd1"}, {"body": LARGE[:-1]+b"\xff"},
                        {"wrong_binding": True}, {"q_option": 23},
                        {"missing_piv": True}, {"reused_piv": True}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                campaign_grade(*loss_evidence("drop-permanent", **changes), "drop-permanent")
        data = loss_evidence(); wire = bytearray.fromhex(data[0][5]["hex"]); wire[-1] ^= 1
        data[0][5].update(hex=wire.hex(), forwarded_hex=wire.hex())
        with self.assertRaises(AssertionError):
            campaign_grade(*data, "drop-once")

    def test_retry_cannot_be_reencrypted_with_a_fresh_piv(self):
        data = loss_evidence()
        fresh = evidence(True, server_sequence=50)[0][4]
        data[0][5].update(hex=fresh["hex"], forwarded_hex=fresh["hex"])
        with self.assertRaisesRegex(AssertionError, "retry changed ciphertext"):
            campaign_grade(*data, "drop-once")

    def test_timeout_partial_and_bounded_process_outcome_mutations(self):
        for mutate in (
            lambda d: d[0].pop(2),
            lambda d: d[0].pop(),
            lambda d: d[0][0].update(action="drop"),
            lambda d: d[1].update(exit_code=0),
            lambda d: d[1].update(exit_code=-9),
            lambda d: d[1].update(event="response", code=69, payload_hex=LARGE.hex()),
            lambda d: d[1].update(payload_hex=LARGE[:1024].hex()),
            lambda d: d[1].update(host_total_ns=100_000_000),
            lambda d: d[1].pop("host_total_ns"),
        ):
            data = loss_evidence("drop-permanent"); mutate(data)
            with self.assertRaises(AssertionError): campaign_grade(*data, "drop-permanent")

    def test_nonprotocol_error_messages_cannot_qualify_timeout(self):
        for mode in ("drop-permanent", "wrong-key"):
            for message in ("subprocess deadline", "unrelated elapsed", "deadline has elapsed", "crash", "", None):
                data = wrong_evidence() if mode == "wrong-key" else loss_evidence(mode)
                data[1]["message"] = message
                with self.subTest(mode=mode, message=message), self.assertRaises(AssertionError):
                    campaign_grade(*data, mode)

    def test_wrong_key_exact_diagnostic_no_authenticated_progress(self):
        for mutate in (
            lambda d: d[0].pop(),
            lambda d: d[0][1].update(action="drop"),
            lambda d: d[0][1].update(source=["127.0.0.1", 9999]),
            lambda d: d[1].update(exit_code=0),
            lambda d: d[1].update(host_total_ns=50_000_000),
            lambda d: d[1].update(code=69),
            lambda d: d[0][0].update(hex=evidence(True)[0][0]["hex"], forwarded_hex=evidence(True)[0][0]["hex"]),
        ):
            data = wrong_evidence(); mutate(data)
            with self.assertRaises(AssertionError): campaign_grade(*data, "wrong-key")
        for wire in (coap_message(69, 10, b"q", [(14, b"")], b"Decryption failed"),
                     coap_message(128, 11, b"q", [(14, b"")], b"Decryption failed"),
                     coap_message(128, 10, b"x", [(14, b"")], b"Decryption failed"),
                     coap_message(128, 10, b"q", [], b"Decryption failed"),
                     coap_message(128, 10, b"q", [(9, b""), (14, b"")], b"Decryption failed"),
                     coap_message(128, 10, b"q", [(14, b"")], b"other")):
            wire = bytes([wire[0] | 0x20]) + wire[1:]
            data = wrong_evidence(); data[0][1].update(hex=wire.hex(), forwarded_hex=wire.hex())
            with self.assertRaises(AssertionError): campaign_grade(*data, "wrong-key")

    def test_relay_selector_authenticates_later_block_only(self):
        trace = evidence(True)[0]
        self.assertFalse(later_response(bytes.fromhex(trace[2]["hex"]), trace[:2]))
        self.assertTrue(later_response(bytes.fromhex(trace[4]["hex"]), trace[:4]))
        wire = bytearray.fromhex(trace[4]["hex"]); wire[-1] ^= 1
        with self.assertRaises(AssertionError): later_response(bytes(wire), trace[:4])

    def test_same_server_fresh_recovery_and_cross_schedule_nonce_ownership(self):
        from run import BODY
        record = {"setup": dict(event="response", code=69, payload_hex=BODY.hex(), exit_code=0),
                  "server_ready": {"port": 1003, "transport": "oscore"}, "schedules": []}
        for index, mode in enumerate(("baseline", "drop-once", "drop-permanent", "wrong-key", "baseline"), 1):
            kwargs = dict(sequence=index*100, server_sequence=index*10)
            data = (wrong_evidence(index*100) if mode == "wrong-key" else
                    loss_evidence(mode, **kwargs) if mode.startswith("drop") else evidence(True, **kwargs))
            if mode == "baseline": data[1]["host_total_ns"] = 10_000_000
            record["schedules"].append(dict(mode=mode, sequence_start=index*100, trace=data[0], result=data[1],
                                             endpoints=data[2], proof=campaign_grade(*data, mode)))
        self.assertEqual(campaign_review(record)["final_recovery_bytes"], 2000)
        reused = copy.deepcopy(record)
        data = evidence(True, sequence=500, server_sequence=10)
        data[1]["host_total_ns"] = 10_000_000
        reused["schedules"][-1].update(trace=data[0], result=data[1], proof=campaign_grade(*data, "baseline"))
        with self.assertRaisesRegex(AssertionError, "PIV reused between schedules"):
            campaign_review(reused)

        for mutate in (lambda r: r["schedules"].pop(),
                       lambda r: r["schedules"][-1].update(endpoints={**ENDPOINTS, "server": ["127.0.0.1", 9999]}),
                       lambda r: r["schedules"][-1].update(trace=r["schedules"][0]["trace"]),
                       lambda r: r["schedules"][-1]["proof"].update(body_bytes=1999)):
            changed = copy.deepcopy(record); mutate(changed)
            with self.assertRaises(AssertionError): campaign_review(changed)

    def test_failed_campaign_retains_successful_baseline_without_qualification_claim(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from oscore_qblock2 import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable, manifest, report = (root / name for name in ("peer", "manifest.json", "report.json"))
            executable.write_bytes(b"test-only executable identity")
            manifest.write_text('{"patch_sha256":"test-only"}')
            args = ["observer", "--campaign", "--coaptic", str(executable), "--libcoap", str(executable),
                    "--output", str(report), "--libcoap-patch-manifest", str(manifest)]
            def failed(_client, _server, record, _patch, *, family="ipv4"):
                record["schedules"] = [{"retained": "actual failed schedule would be here"}]
                raise AssertionError("strict campaign refused")
            with patch("sys.argv", args), patch("run.source_identity", return_value={"source": "test-only"}), \
                 patch("oscore_qblock2.baseline"), patch("oscore_qblock2.campaign", side_effect=failed), patch("builtins.print"):
                self.assertEqual(main(), 1)
            value = json.loads(report.read_text())
            self.assertTrue(value["baseline_passed"])
            self.assertFalse(value["campaign_passed"])
            self.assertFalse(value["qualification_complete"])
            self.assertIn("strict campaign refused", value["error"])
            self.assertEqual(len(value["campaign"]["schedules"]), 1)

    def test_campaign_retains_failed_schedule_joined_trace_and_single_server(self):
        from unittest.mock import MagicMock, patch
        service, relay = MagicMock(), MagicMock()
        service.__enter__.return_value = service; service.number = 1003
        service.ready = {"libcoap_patch_sha256": "patch"}
        relay.__enter__.return_value = relay; relay.dest = ENDPOINTS["server"]
        relay.front.getsockname.return_value = ENDPOINTS["front"]
        relay.back.getsockname.return_value = ENDPOINTS["back"]
        relay.trace = []
        def joined(*_):
            relay.trace = [{"retained": "partial evidence"}]
            return False
        relay.__exit__.side_effect = joined
        record = {}
        with patch("run.Server", return_value=service) as server, patch("run.Proxy", return_value=relay), \
             patch("run.expect"), patch("run.request", side_effect=[{}, RuntimeError("subprocess deadline")]):
            with self.assertRaisesRegex(RuntimeError, "subprocess deadline"):
                campaign(None, None, record, {"patch_sha256": "patch"})
        server.assert_called_once()
        self.assertEqual(record["schedules"][0]["trace"], relay.trace)
        self.assertNotIn("complete", record)


def ipv6_evidence(data):
    """Change only synthetic endpoint evidence; ciphertext remains authenticated."""
    data = copy.deepcopy(data)
    for row in data[0]:
        for key in ("source", "destination", "relay"):
            row[key] = ["::1", row[key][1], 0, 0]
    for key in ("front", "back", "server"):
        data[2][key] = ["::1", data[2][key][1], 0, 0]
    data[2].update(family="AF_INET6", v6only=[1, 1])
    return data


def ipv6_campaign():
    from run import BODY
    record = {"family": "ipv6", "setup": dict(event="response", code=69, payload_hex=BODY.hex(), exit_code=0),
              "server_ready": {"port": 1003, "transport": "oscore"}, "schedules": []}
    for index, mode in enumerate(("baseline", "drop-once", "drop-permanent", "wrong-key", "baseline"), 1):
        kwargs = dict(sequence=index*100, server_sequence=index*10)
        data = (wrong_evidence(index*100) if mode == "wrong-key" else
                loss_evidence(mode, **kwargs) if mode.startswith("drop") else evidence(True, **kwargs))
        if mode == "baseline": data[1]["host_total_ns"] = 10_000_000
        data = ipv6_evidence(data)
        record["schedules"].append(dict(mode=mode, sequence_start=index*100, trace=data[0], result=data[1],
                                         endpoints=data[2], proof=campaign_grade(*data, mode, family="ipv6")))
    return record


class IPv6Tests(unittest.TestCase):
    def test_authenticated_complete_loss_refusal_and_fresh_recovery(self):
        for separate in (False, True):
            self.assertEqual(baseline_grade(*ipv6_evidence(evidence(separate)), family="ipv6")["body_bytes"], 2000)
        record = ipv6_campaign()
        proof = campaign_review(record, family="ipv6")
        self.assertEqual(proof["same_server"], ["::1", 1003, 0, 0])
        self.assertEqual(proof["fresh_request_bindings"], 5)
        self.assertEqual(proof["distinct_server_pivs"], 8)
        self.assertEqual(proof["final_recovery_bytes"], 2000)
        self.assertEqual([case["proof"]["delivered_body_bytes"] for case in record["schedules"]],
                         [2000, 2000, 1024, 0, 2000])
        import json
        self.assertEqual(campaign_review(json.loads(json.dumps(record)), family="ipv6"), proof)

    def test_family_selection_refuses_fallback_and_unknown_family(self):
        for data, family in ((evidence(True), "ipv6"), (ipv6_evidence(evidence(True)), "ipv4"),
                             (evidence(True), "unknown")):
            data[1]["host_total_ns"] = 10_000_000
            with self.subTest(family=family), self.assertRaises(AssertionError):
                campaign_grade(*data, "baseline", family=family)
        with self.assertRaisesRegex(AssertionError, "family changed"):
            campaign_review(ipv6_campaign())

    def test_exact_endpoint_shape_owner_flow_scope_and_socket_evidence(self):
        invalid = (["127.0.0.1", 1004], ["::ffff:127.0.0.1", 1004, 0, 0], ["::1", 1004],
                   ["::1", 1004, 0], ["::1", 1004, 0, 0, 0], ["::2", 1004, 0, 0],
                   ["::1", True, 0, 0], ["::1", 0, 0, 0], ["::1", 65536, 0, 0],
                   ["::1", 1004.0, 0, 0], ["::1", 1004, 1, 0], ["::1", 1004, 0, 1],
                   ["::1", 1004, False, 0], ["::1", 1004, 0, False], ["::1", 1004, 0.0, 0],
                   ["::1", 1004, 0, 0.0], ["::1", 9999, 0, 0])
        for field in ("source", "destination", "relay"):
            for endpoint in invalid:
                data = ipv6_evidence(loss_evidence())
                data[0][-1][field] = endpoint
                with self.subTest(field=field, endpoint=endpoint), self.assertRaises(AssertionError):
                    campaign_grade(*data, "drop-once", family="ipv6")
        for changes in ({"family": "AF_INET"}, {"v6only": None}, {"v6only": [1, 0]},
                        {"v6only": [True, 1]}, {"v6only": [1, 1.0]}, {"v6only": [1]}):
            data = ipv6_evidence(loss_evidence()); data[2].update(changes)
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                campaign_grade(*data, "drop-once", family="ipv6")
        data = ipv6_evidence(loss_evidence()); data[2].pop("family")
        with self.assertRaises(AssertionError): campaign_grade(*data, "drop-once", family="ipv6")

    def test_ipv6_loss_retry_owner_ciphertext_and_false_timeout_mutations(self):
        for mutate in (lambda d: d[0].pop(5), lambda d: d[0].pop(3), lambda d: d[0].pop(),
                       lambda d: d[0][5].update(time_ns=10_000_000),
                       lambda d: d[0][5].update(action="drop"),
                       lambda d: d[0][5].update(hex=d[0][2]["hex"], forwarded_hex=d[0][2]["hex"]),
                       lambda d: d[0][4].update(forwarded_hex=d[0][2]["hex"]),
                       lambda d: d[1].update(payload_hex=LARGE[:-1].hex())):
            data = ipv6_evidence(loss_evidence()); mutate(data)
            with self.assertRaises(AssertionError): campaign_grade(*data, "drop-once", family="ipv6")
        for mode in ("drop-permanent", "wrong-key"):
            for mutate in (lambda d: d[1].update(message="subprocess deadline"),
                           lambda d: d[1].update(host_total_ns=100_000_000),
                           lambda d: d[1].update(code=69), lambda d: d[1].update(exit_code=-9),
                           lambda d: d[1].update(payload_hex=LARGE[:1024].hex())):
                data = ipv6_evidence(wrong_evidence() if mode == "wrong-key" else loss_evidence(mode)); mutate(data)
                with self.subTest(mode=mode), self.assertRaises(AssertionError):
                    campaign_grade(*data, mode, family="ipv6")

    def test_ipv6_authenticated_representation_binding_and_nonce_refusals(self):
        for changes in ({"tag": b"changed"}, {"size": b"\x07\xd1"}, {"body": LARGE[:-1]+b"\xff"},
                        {"wrong_binding": True}, {"missing_piv": True}, {"reused_piv": True}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                campaign_grade(*ipv6_evidence(loss_evidence("drop-permanent", **changes)),
                               "drop-permanent", family="ipv6")

    def test_missing_reordered_changed_or_stale_recovery_refuses(self):
        record = ipv6_campaign()
        for mutate in (lambda r: r["schedules"].pop(),
                       lambda r: r["schedules"].reverse(),
                       lambda r: r["schedules"][-1]["result"].update(payload_hex=LARGE[:-1].hex()),
                       lambda r: r["schedules"][-1]["endpoints"].update(server=["::1", 9999, 0, 0]),
                       lambda r: r["schedules"][-1].update(trace=r["schedules"][0]["trace"]),
                       lambda r: r["schedules"][-1]["proof"].update(body_bytes=1999),
                       lambda r: r["server_ready"].update(port=True)):
            changed = copy.deepcopy(record); mutate(changed)
            with self.assertRaises(AssertionError): campaign_review(changed, family="ipv6")
        data = ipv6_evidence(evidence(True, sequence=500, server_sequence=10))
        data[1]["host_total_ns"] = 10_000_000
        record["schedules"][-1].update(trace=data[0], result=data[1],
                                       proof=campaign_grade(*data, "baseline", family="ipv6"))
        with self.assertRaisesRegex(AssertionError, "PIV reused between schedules"):
            campaign_review(record, family="ipv6")

    def test_actual_loopback_relay_records_ipv6_only_socket_metadata(self):
        from run import Proxy
        from oscore_qblock2 import relay_endpoints, require_relay_family, loopback_endpoint
        with Proxy(9, "pass", family="ipv6") as relay:
            endpoints = relay_endpoints(relay, "ipv6")
            require_relay_family(endpoints, "ipv6")
            for key in ("front", "back", "server"):
                loopback_endpoint(endpoints[key], "ipv6")
            self.assertEqual(endpoints["server"], ("::1", 9, 0, 0))

    def test_ipv6_cli_retains_failed_campaign_and_selected_family(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from oscore_qblock2 import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable, manifest, report = (root / name for name in ("peer", "manifest.json", "report.json"))
            executable.write_bytes(b"test-only executable identity")
            manifest.write_text('{"patch_sha256":"test-only"}')
            args = ["observer", "--campaign", "--family", "ipv6", "--coaptic", str(executable),
                    "--libcoap", str(executable), "--output", str(report), "--libcoap-patch-manifest", str(manifest)]
            def failed(_client, _server, record, _patch, *, family):
                self.assertEqual(family, "ipv6")
                record["schedules"] = [{"retained": "test-only failed schedule"}]
                raise AssertionError("strict IPv6 campaign refused")
            with patch("sys.argv", args), patch("run.source_identity", return_value={"source": "test-only"}), \
                 patch("oscore_qblock2.baseline") as baseline_runner, \
                 patch("oscore_qblock2.campaign", side_effect=failed), patch("builtins.print"):
                self.assertEqual(main(), 1)
            self.assertEqual(baseline_runner.call_args.kwargs, {"family": "ipv6"})
            value = json.loads(report.read_text())
            self.assertEqual(value["family"], "ipv6")
            self.assertTrue(value["baseline_passed"])
            self.assertFalse(value["campaign_passed"])
            self.assertFalse(value["qualification_complete"])
            self.assertEqual(len(value["campaign"]["schedules"]), 1)
            self.assertIn("strict IPv6 campaign refused", value["error"])

    def test_runner_threads_ipv6_to_every_socket_and_request_and_retains_failure(self):
        import socket
        from unittest.mock import MagicMock, patch
        service, relay = MagicMock(), MagicMock()
        service.__enter__.return_value = service; service.number = 1003
        service.ready = {"libcoap_patch_sha256": "patch"}
        relay.__enter__.return_value = relay; relay.number = 1001
        relay.dest = ("::1", 1003, 0, 0)
        for sock, port in ((relay.front, 1001), (relay.back, 1002)):
            sock.getsockname.return_value = ("::1", port, 0, 0)
            sock.family = socket.AF_INET6; sock.getsockopt.return_value = 1
        def joined(*_):
            relay.trace = [{"retained": "joined IPv6 failure"}]
            return False
        relay.__exit__.side_effect = joined
        for runner in (baseline, campaign):
            record = {}
            with patch("run.Server", return_value=service) as server, patch("run.Proxy", return_value=relay) as proxy, \
                 patch("run.expect"), patch("run.request", side_effect=[{}, RuntimeError("subprocess deadline")]) as request:
                with self.assertRaisesRegex(RuntimeError, "subprocess deadline"):
                    runner("client", "server", record, {"patch_sha256": "patch"}, family="ipv6")
            server.assert_called_once_with("server", "oscore", family="ipv6")
            proxy.assert_called_once_with(1003, "pass", family="ipv6")
            self.assertTrue(all(call.kwargs["family"] == "ipv6" for call in request.call_args_list))
            saved = record["schedules"][0] if runner is campaign else record
            self.assertEqual(saved["trace"], [{"retained": "joined IPv6 failure"}])
            self.assertEqual(saved["endpoints"]["v6only"], [1, 1])
            self.assertEqual(saved["endpoints"]["server"], ("::1", 1003, 0, 0))
            self.assertNotIn("complete", record)
            self.assertNotIn("proof", saved)


if __name__ == "__main__": unittest.main()
