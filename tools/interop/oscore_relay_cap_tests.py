"""Authenticated synthetic oracles; no independent process success inferred."""
import copy
import unittest
from unittest.mock import MagicMock, patch
from oscore_qblock1 import FixtureContext, request_plain
from oscore_qblock2_tests import protected, ENDPOINTS, CLIENT
from oscore_relay_cap import grade, review, campaign, SCHEDULES
from run import LARGE, BODY, coap_message


def evidence(path="large", capped=False, sequence=100, server_sequence=1000, *, tag=b"tag", size=b"\x07\xd0", changed_body=False, wrong_binding=False, reused_piv=False, reuse_request_nonce=False, response_mid_base=20, duplicate_response_mid=False):
    client, server = FixtureContext(server=False, sequence=sequence), FixtureContext(server=True, sequence=server_sequence)
    token = b"r"
    packets = []
    refusal = path == "large" and capped
    for num in range(1 if path == "test" or refusal else 2):
        mid = 10+num
        opts = [(11,path.encode())] + ([(23,b"\x16")] if num else [])
        request = protected(client, coap_message(1, mid, token, opts))
        _, binding = request_plain(request)
        if wrong_binding:
            other = protected(client, coap_message(1, 50, token, opts))
            _, binding = request_plain(other)
        packets.extend([("request",request), ("response",b"\x60\x00"+mid.to_bytes(2,"big"))])
        opts = [(12,b"*"), (14,b"<")]
        body = BODY
        if path == "large":
            opts += [(4,b"tag" if num == 0 else tag), (23,b"\x0e" if num == 0 else b"\x16"), (28,size)]
            body = LARGE[num*1024:(num+1)*1024]
        if changed_body:body = bytes([body[0]^1])+body[1:]
        if reused_piv:server.sender_sequence_number = server_sequence
        response_mid = response_mid_base + (0 if duplicate_response_mid else num)
        response = protected(server, coap_message(69,response_mid,token,sorted(opts),body),binding, not reuse_request_nonce)
        packets.append(("response",response))
        if refusal:
            packets.append(("response",response))
        else:
            packets.append(("request",b"\x60\x00"+response_mid.to_bytes(2,"big")))
    trace = []
    for i,(direction,wire) in enumerate(packets):
        trace.append(dict(direction=direction, action="drop" if capped and len(wire)>256 else "forward",
            hex=wire.hex(), forwarded_hex=wire.hex(), time_ns=i*1_000_000 if not refusal or i<3 else 2_502_000_000,
            source=CLIENT if direction=="request" else ENDPOINTS["server"],
            destination=ENDPOINTS["server"] if direction=="request" else CLIENT,
            relay=ENDPOINTS["back"] if direction=="request" else ENDPOINTS["front"]))
    result = (dict(event="error", exit_code=1,message="request timed out",host_total_ns=6_600_000_000) if refusal else
              dict(event="response",exit_code=0,code=69,payload_hex=(LARGE if path=="large" else BODY).hex(),host_total_ns=20_000_000))
    return [trace,result,copy.deepcopy(ENDPOINTS)]


def complete_record():
    record={"server_ready":{"transport":"oscore","port":1003,"libcoap_patch_sha256":"patch"},
            "setup":dict(event="response",exit_code=0,code=69,payload_hex=BODY.hex()),"schedules":[]}
    for index,(name,path,capped) in enumerate(SCHEDULES,1):
        trace,result,endpoints=evidence(path,capped,index*100,index*1000)
        record["schedules"].append(dict(name=name,sequence_start=index*100,trace=trace,result=result,endpoints=endpoints,
                                        proof=grade(trace,result,endpoints,path=path,capped=capped)))
    return record


class RelayCapTests(unittest.TestCase):
    def test_direction_owned_mid_namespaces(self):
        for path,capped in (("large",False),("test",True),("large",True)):
            grade(*evidence(path,capped,response_mid_base=10),path=path,capped=capped)
        with self.assertRaisesRegex(AssertionError,"response sender reused MID"):
            grade(*evidence(duplicate_response_mid=True),path="large",capped=False)
        x=evidence(response_mid_base=10)
        x[0][7].update(hex="6000000a",forwarded_hex="6000000a")
        with self.assertRaisesRegex(AssertionError,"client ACK ownership"):
            grade(*x,path="large",capped=False)

    def test_complete_campaign(self):
        proof=review(complete_record(),{"patch_sha256":"patch"})
        self.assertEqual(proof["fresh_recovery_bytes"],2000)
        self.assertEqual(proof["schedules"],4)

    def test_classic_request_nonce_response_is_supported_but_explicit_reuse_refuses(self):
        self.assertEqual(grade(*evidence(reuse_request_nonce=True),path="large",capped=False)["delivered_authenticated_bytes"],2000)
        with self.assertRaises(AssertionError):grade(*evidence(reused_piv=True),path="large",capped=False)

    def test_authenticated_body_metadata_binding_refusal(self):
        for changes in ({"tag":b"changed"},{"size":b"x"},{"changed_body":True},{"wrong_binding":True}):
            with self.subTest(changes=changes),self.assertRaises(AssertionError):
                grade(*evidence(**changes),path="large",capped=False)

    def test_complete_response_owner_and_ack_mutations(self):
        mutations=[lambda x:x[0].pop(1),lambda x:x[0].pop(),
            lambda x:x[0][3].update(hex="60009999",forwarded_hex="60009999"),
            lambda x:x[0][4].update(source=["127.0.0.1",9999]),
            lambda x:x[2].update(server=["::1",1003,0,0]),
            lambda x:x[1].update(payload_hex=LARGE[:1024].hex()),
            lambda x:x[0][2].update(action="hold"),
            lambda x:x[0][0].update(action="drop"),
            lambda x:x[0][5].update(hex="6000000a",forwarded_hex="6000000a"),
            lambda x:x[0][0].update(forwarded_hex="00"),
            lambda x:x[0][6].update(time_ns=0)]
        for i,mutate in enumerate(mutations):
            x=evidence();mutate(x)
            with self.subTest(mutation=i),self.assertRaises(AssertionError):grade(*x,path="large",capped=False)

    def test_cap_exact_lengths_ciphertext_and_retry_refusal(self):
        mutations=[lambda x:x[0].pop(),lambda x:x[0][2].update(action="forward"),
            lambda x:x[0][1].update(action="drop"),
            lambda x:x[0][3].update(time_ns=100_000_000),
            lambda x:x[0][3].update(time_ns=4_000_000_000),
            lambda x:x[0][3].update(source=["127.0.0.1",1005]),
            lambda x:x[0][3].update(hex=x[0][3]["hex"][:-2]+"00",forwarded_hex=x[0][3]["hex"][:-2]+"00"),
            lambda x:x[0].append(dict(x[0][0],time_ns=3_000_000_000))]
        for i,mutate in enumerate(mutations):
            x=evidence(capped=True);mutate(x)
            with self.subTest(mutation=i),self.assertRaises(AssertionError):grade(*x,path="large",capped=True)

    def test_protocol_timeout_not_supervisor_or_partial_success(self):
        for values in ({"message":"subprocess deadline"},{"message":"unrelated elapsed"},{"message":""},
                       {"exit_code":2},{"event":"response"},{"code":69},{"payload_hex":"00"},
                       {"host_total_ns":500_000_000},{"host_total_ns":11_000_000_000}):
            x=evidence(capped=True);x[1].update(values)
            with self.subTest(values=values),self.assertRaises(AssertionError):grade(*x,path="large",capped=True)

    def test_small_control_requires_full_forwarded_authenticated_response(self):
        for changes in ({"changed_body":True},{"wrong_binding":True}):
            with self.subTest(changes=changes),self.assertRaises(AssertionError):grade(*evidence("test",True,**changes),path="test",capped=True)
        x=evidence("test",True);x[0][2]["action"]="drop"
        with self.assertRaises(AssertionError):grade(*x,path="test",capped=True)

    def test_campaign_requires_same_server_all_controls_and_fresh_bindings(self):
        for mutate in (lambda r:r["schedules"].pop(1), lambda r:r["schedules"].reverse(),
                       lambda r:r["server_ready"].update(port=9999),lambda r:r["server_ready"].update(libcoap_patch_sha256="other"),
                       lambda r:r["schedules"][3].update(sequence_start=100),
                       lambda r:r["schedules"][2]["proof"].update(delivered_authenticated_bytes=2000)):
            r=complete_record();mutate(r)
            with self.assertRaises(AssertionError):review(r,{"patch_sha256":"patch"})

    def test_ready_port_requires_exact_integer_type(self):
        for value in (True, 1003.0):
            record=complete_record();record["server_ready"]["port"]=value
            with self.subTest(value=value),self.assertRaisesRegex(AssertionError,"endpoint"):
                review(record,{"patch_sha256":"patch"})

    def test_supervisor_failure_retains_joined_trace_without_pass(self):
        service,relay=MagicMock(),MagicMock()
        service.__enter__.return_value=service;relay.__enter__.return_value=relay
        service.ready={"libcoap_patch_sha256":"patch"};service.number=1003
        relay.front.getsockname.return_value=ENDPOINTS["front"]
        relay.back.getsockname.return_value=ENDPOINTS["back"];relay.dest=ENDPOINTS["server"]
        relay.trace=[]
        def joined(*_):relay.trace=[{"retained":"partial"}];return False
        relay.__exit__.side_effect=joined
        record={}
        with patch("run.Server",return_value=service),patch("run.Proxy",return_value=relay),patch("run.expect"),patch("run.request",side_effect=[{},RuntimeError("subprocess deadline")]):
            with self.assertRaisesRegex(RuntimeError,"subprocess deadline"):campaign(None,None,record,{"patch_sha256":"patch"})
        self.assertEqual(record["schedules"][0]["trace"],[{"retained":"partial"}])
        self.assertNotIn("complete",record)
        self.assertNotIn("proof",record["schedules"][0])


if __name__=="__main__":unittest.main()
