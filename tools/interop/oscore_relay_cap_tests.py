"""Authenticated synthetic oracles; no independent process success inferred."""
import copy
import unittest
from unittest.mock import MagicMock, patch
from oscore_qblock1 import FixtureContext, request_plain
from oscore_qblock2_tests import protected, ENDPOINTS, CLIENT
from oscore_relay_cap import grade, review, campaign, SCHEDULES
from run import LARGE, BODY, coap_message


def evidence(path="large", capped=False, sequence=100, server_sequence=1000, *, tag=b"tag", size=b"\x07\xd0", changed_body=False, wrong_binding=False, reused_piv=False, reuse_request_nonce=False, response_mid_base=20, duplicate_response_mid=False, family="ipv4"):
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
    endpoints = copy.deepcopy(ENDPOINTS)
    if family == "ipv6":
        convert = lambda value: ("::1", value[1], 0, 0)
        endpoints = {key: convert(value) for key,value in endpoints.items()}
        endpoints.update(family="AF_INET6", v6only=[1,1])
        for row in trace:
            for key in ("source", "destination", "relay"): row[key] = convert(row[key])
    return [trace,result,endpoints]


def complete_record(family="ipv4"):
    record={"family":family,"server_ready":{"transport":"oscore","port":1003,"libcoap_patch_sha256":"patch"},
            "setup":dict(event="response",exit_code=0,code=69,payload_hex=BODY.hex()),"schedules":[]}
    for index,(name,path,capped) in enumerate(SCHEDULES,1):
        trace,result,endpoints=evidence(path,capped,index*100,index*1000,family=family)
        record["schedules"].append(dict(name=name,sequence_start=index*100,trace=trace,result=result,endpoints=endpoints,
                                        proof=grade(trace,result,endpoints,path=path,capped=capped,family=family)))
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



class IPv6RelayCapTests(unittest.TestCase):
    def test_complete_same_server_campaign_and_request_nonce_responses(self):
        proof=review(complete_record("ipv6"),{"patch_sha256":"patch"},family="ipv6")
        self.assertEqual(proof["fresh_recovery_bytes"],2000)
        self.assertEqual(proof["schedules"],4)
        self.assertIn("IPv6",proof["scope"])
        for path,capped in (("large",False),("test",True),("large",True)):
            for reuse in (False,True):
                data=evidence(path,capped,family="ipv6",response_mid_base=10,reuse_request_nonce=reuse)
                result=grade(*data,path=path,capped=capped,family="ipv6")
                self.assertEqual(result["delivered_authenticated_bytes"],0 if path=="large" and capped else len(LARGE if path=="large" else BODY))

    def test_wrong_family_endpoint_shapes_and_socket_metadata_refuse(self):
        invalid=(("127.0.0.1",1003),("::ffff:127.0.0.1",1003,0,0),("::1",1003),
                 ("::1",True,0,0),("::1",1003.0,0,0),("::1",0,0,0),("::1",65536,0,0),
                 ("::1",1003,1,0),("::1",1003,0,1),("::1",1003,False,0),("::1",1003,0,0.0))
        for value in invalid:
            for scope in ("endpoint","trace"):
                data=evidence(family="ipv6")
                (data[2] if scope=="endpoint" else data[0][1])["server" if scope=="endpoint" else "source"]=value
                with self.subTest(value=value,scope=scope),self.assertRaises(AssertionError):
                    grade(*data,path="large",capped=False,family="ipv6")
        for change in ({"family":"AF_INET"},{"v6only":[0,1]},{"v6only":[True,1]},{"v6only":[1]},
                       {"v6only":[1.0,1]},{"v6only":None}):
            data=evidence(family="ipv6");data[2].update(change)
            with self.subTest(change=change),self.assertRaises(AssertionError):grade(*data,path="large",capped=False,family="ipv6")
        data=evidence(family="ipv6");del data[2]["family"]
        with self.assertRaises(AssertionError):grade(*data,path="large",capped=False,family="ipv6")
        for family in ("ipv4","mapped","ipv6"):
            data=evidence(family="ipv6" if family!="ipv6" else "ipv4")
            with self.subTest(family=family),self.assertRaises(AssertionError):grade(*data,path="large",capped=False,family=family)

    def test_authenticated_body_metadata_binding_and_nonce_mutations_refuse(self):
        for change in ({"tag":b"other"},{"size":b"x"},{"changed_body":True},{"wrong_binding":True},
                       {"reused_piv":True},{"duplicate_response_mid":True}):
            with self.subTest(change=change),self.assertRaises(AssertionError):
                grade(*evidence(family="ipv6",**change),path="large",capped=False,family="ipv6")

    def test_ack_direction_owner_order_forwarded_bytes_and_complete_body_refuse(self):
        mutations=(lambda x:x[0].pop(1),lambda x:x[0].pop(),
                   lambda x:x[0][3].update(hex="60009999",forwarded_hex="60009999"),
                   lambda x:x[0][4].update(source=("::1",9999,0,0)),
                   lambda x:x[0][2].update(relay=x[2]["back"]),
                   lambda x:x[1].update(payload_hex=LARGE[:1024].hex()),
                   lambda x:x[0][2].update(action="hold"),lambda x:x[0][0].update(action="drop"),
                   lambda x:x[0][0].update(forwarded_hex="00"),lambda x:x[0][6].update(time_ns=0))
        for index,mutate in enumerate(mutations):
            data=evidence(family="ipv6");mutate(data)
            with self.subTest(index=index),self.assertRaises(AssertionError):grade(*data,path="large",capped=False,family="ipv6")

    def test_cap_exact_drop_and_retry_ciphertext_bounds_refuse(self):
        mutations=(lambda x:x[0].pop(),lambda x:x[0][2].update(action="forward"),
                   lambda x:x[0][1].update(action="drop"),lambda x:x[0][3].update(time_ns=100_000_000),
                   lambda x:x[0][3].update(time_ns=4_000_000_000),
                   lambda x:x[0][3].update(source=("::1",1005,0,0)),
                   lambda x:x[0][3].update(hex=x[0][3]["hex"][:-2]+"00",forwarded_hex=x[0][3]["hex"][:-2]+"00"),
                   lambda x:x[0].append(dict(x[0][0],time_ns=3_000_000_000)))
        for index,mutate in enumerate(mutations):
            data=evidence(capped=True,family="ipv6");mutate(data)
            with self.subTest(index=index),self.assertRaises(AssertionError):grade(*data,path="large",capped=True,family="ipv6")

    def test_timeout_is_protocol_refusal_and_small_control_is_authenticated(self):
        for change in ({"message":"subprocess deadline"},{"message":"crash"},{"exit_code":2},
                       {"event":"response"},{"code":69},{"payload_hex":"00"},
                       {"host_total_ns":500_000_000},{"host_total_ns":11_000_000_000},{"host_total_ns":True}):
            data=evidence(capped=True,family="ipv6");data[1].update(change)
            with self.subTest(change=change),self.assertRaises(AssertionError):grade(*data,path="large",capped=True,family="ipv6")
        for change in ({"changed_body":True},{"wrong_binding":True}):
            with self.subTest(change=change),self.assertRaises(AssertionError):
                grade(*evidence("test",True,family="ipv6",**change),path="test",capped=True,family="ipv6")
        data=evidence("test",True,family="ipv6");data[0][2]["action"]="drop"
        with self.assertRaises(AssertionError):grade(*data,path="test",capped=True,family="ipv6")

    def test_campaign_family_same_server_and_fresh_complete_recovery_required(self):
        mutations=(lambda r:r.pop("family"),lambda r:r.update(family="ipv4"),
                   lambda r:r["schedules"].pop(),lambda r:r["schedules"].reverse(),
                   lambda r:r["server_ready"].update(port=9999),lambda r:r["server_ready"].update(port=True),
                   lambda r:r["server_ready"].update(libcoap_patch_sha256="wrong"),
                   lambda r:r["schedules"][-1].update(sequence_start=100),
                   lambda r:r["schedules"][-1]["proof"].update(delivered_authenticated_bytes=1999),
                   lambda r:r["schedules"][-1]["endpoints"].update(server=("::1",9999,0,0)))
        for index,mutate in enumerate(mutations):
            record=complete_record("ipv6");mutate(record)
            with self.subTest(index=index),self.assertRaises(AssertionError):review(record,{"patch_sha256":"patch"},family="ipv6")
        record=complete_record("ipv6")
        data=evidence(sequence=100,server_sequence=4000,family="ipv6")
        record["schedules"][-1].update(trace=data[0],result=data[1],endpoints=data[2],proof=grade(*data,path="large",capped=False,family="ipv6"))
        with self.assertRaisesRegex(AssertionError,"starting binding"):
            review(record,{"patch_sha256":"patch"},family="ipv6")

    def test_actual_ipv6_relay_socket_metadata(self):
        from run import Proxy
        from oscore_qblock2 import relay_endpoints, require_relay_family, loopback_endpoint
        with Proxy(9,"pass",family="ipv6") as relay:
            endpoints=relay_endpoints(relay,"ipv6")
            require_relay_family(endpoints,"ipv6")
            for key in ("front","back","server"):loopback_endpoint(endpoints[key],"ipv6")
            self.assertEqual(endpoints["v6only"],[1,1])

    def mock_runner(self):
        import socket
        expected=complete_record("ipv6")
        service=MagicMock();service.__enter__.return_value=service
        service.number=1003;service.ready=expected["server_ready"]
        relays=[]
        for case in expected["schedules"]:
            relay=MagicMock();relay.__enter__.return_value=relay
            relay.number=1001;relay.dest=case["endpoints"]["server"];relay.trace=case["trace"]
            for sock,key in ((relay.front,"front"),(relay.back,"back")):
                sock.getsockname.return_value=case["endpoints"][key]
                sock.family=socket.AF_INET6;sock.getsockopt.return_value=1
            relays.append(relay)
        return expected,service,relays

    def test_complete_runner_preserves_family_one_server_and_four_schedules(self):
        expected,service,relays=self.mock_runner();record={}
        with patch("run.Server",return_value=service) as server,patch("run.Proxy",side_effect=relays) as proxy, \
             patch("run.request",side_effect=[expected["setup"],*[c["result"] for c in expected["schedules"]]]) as request:
            campaign("client","server",record,{"patch_sha256":"patch"},family="ipv6")
        self.assertTrue(record["complete"])
        self.assertEqual(record["family"],"ipv6")
        server.assert_called_once_with("server","oscore",family="ipv6")
        self.assertEqual([c.args[1] for c in proxy.call_args_list],["pass","cap-256","cap-256","pass"])
        self.assertEqual([c.kwargs["sequence"] for c in request.call_args_list],[0,100,200,300,400])
        self.assertTrue(all(c.kwargs["family"]=="ipv6" for c in request.call_args_list+proxy.call_args_list))

    def test_failure_retains_joined_trace_and_patch_mismatch_sends_nothing(self):
        expected,service,relays=self.mock_runner();record={};relay=relays[0]
        def joined(*_):relay.trace=[{"retained":"joined failure"}];return False
        relay.__exit__.side_effect=joined
        with patch("run.Server",return_value=service),patch("run.Proxy",return_value=relay), \
             patch("run.request",side_effect=[expected["setup"],RuntimeError("subprocess deadline")]):
            with self.assertRaisesRegex(RuntimeError,"subprocess deadline"):
                campaign("client","server",record,{"patch_sha256":"patch"},family="ipv6")
        self.assertEqual(record["family"],"ipv6")
        self.assertEqual(record["schedules"][0]["trace"],[{"retained":"joined failure"}])
        self.assertNotIn("complete",record)
        self.assertNotIn("proof",record)
        with patch("run.Server",return_value=service),patch("run.request") as request:
            with self.assertRaisesRegex(AssertionError,"patch mismatch"):
                campaign("client","server",{}, {"patch_sha256":"wrong"},family="ipv6")
        request.assert_not_called()

    def test_cli_default_and_ipv6_failure_retain_family_source_and_patch(self):
        import hashlib,json,tempfile
        from pathlib import Path
        from oscore_relay_cap import main
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);peer=root/"peer";output=root/"report.json";manifest=root/"patch.json"
            peer.write_bytes(b"test-only peer identity")
            manifest.write_text('{"patch_sha256":"patch"}',encoding="utf-8")
            for family,options in (("ipv4",[]),("ipv6",["--family","ipv6"])):
                def failed(_client,_server,record,manifest,*,family):
                    record.update(family=family,schedules=[{"retained":"test-only failure"}])
                    self.assertEqual(manifest,{"patch_sha256":"patch"})
                    raise RuntimeError("subprocess deadline")
                argv=["campaign","--coaptic",str(peer),"--libcoap",str(peer),"--output",str(output),"--libcoap-patch-manifest",str(manifest),*options]
                with patch("sys.argv",argv),patch("run.source_identity",return_value={"source":"test-only","suite_source":"test-only-suite"}), \
                     patch("oscore_relay_cap.campaign",side_effect=failed),patch("builtins.print"):
                    self.assertEqual(main(),1)
                value=json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(value["family"],family)
                self.assertEqual(value["campaign"]["family"],family)
                self.assertEqual(value["source"],"test-only")
                self.assertEqual(value["libcoap_patch"],{"patch_sha256":"patch"})
                self.assertEqual(value["executables"]["libcoap"]["sha256"],hashlib.sha256(peer.read_bytes()).hexdigest())
                self.assertFalse(value["qualification_complete"])
                self.assertEqual(len(value["campaign"]["schedules"]),1)
                self.assertIn("subprocess deadline",value["error"])


if __name__=="__main__":unittest.main()
