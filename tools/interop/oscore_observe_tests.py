"""Synthetic authenticated proofs, never a substitute for actual peer execution."""
import copy
import unittest
from unittest.mock import patch,MagicMock
from oscore_qblock1 import FixtureContext,request_plain
from oscore_qblock2_tests import protected,ENDPOINTS,CLIENT
from oscore_observe import observer_grade,exchange_grade,campaign_review,ObserveRelay,campaign
from run import coap_message


def rows(packets,offset=0):
    return [dict(direction=d,action=action,hex=w.hex(),forwarded_hex=w.hex(),time_ns=offset+i*1_000_000,
                 source=CLIENT if d=="request" else ENDPOINTS["server"],destination=ENDPOINTS["server"] if d=="request" else CLIENT,
                 relay=ENDPOINTS["back"] if d=="request" else ENDPOINTS["front"]) for i,(d,action,w) in enumerate(packets)]


def observer(start=0,replay=False,sequence=100,server_sequence=1000,*,wrong_binding=False,reused_piv=False,bad_body=False,missing_piv=False):
    client=FixtureContext(server=False,sequence=sequence);server=FixtureContext(server=True,sequence=server_sequence)
    req=protected(client,coap_message(1,10,b"o",[(6,b""),(11,b"counter")]))
    _,binding=request_plain(req)
    if wrong_binding:
        _,binding=request_plain(protected(client,coap_message(1,11,b"o",[(6,b""),(11,b"counter")])))
    packets=[("request","forward",req),("response","forward",b"\x60\x00\x00\x0a")]
    first=None
    for i in range(3):
        if reused_piv:server.sender_sequence_number=server_sequence
        wire=protected(server,coap_message(69,20+i,b"o",[(6,bytes([i+1]))],b"bad" if bad_body else str(start+i).encode()),binding,not missing_piv)
        if first is None:first=wire
        packets += [("response","forward",wire),("request","forward",b"\x60\x00"+(20+i).to_bytes(2,"big"))]
        if replay and i==1:packets += [("response","replay",first),("request","forward",b"\x60\x00\x00\x14")]
    return [rows(packets),dict(event="response",exit_code=0,code=69,payload_hex=','.join(str(start+i) for i in range(3)).encode().hex()),copy.deepcopy(ENDPOINTS)]


def exchange(method,body,sequence,offset):
    client=FixtureContext(server=False,sequence=sequence);server=FixtureContext(server=True,sequence=sequence+10000)
    req=protected(client,coap_message(method,50,b"w",[(11,b"counter")]))
    _,binding=request_plain(req)
    wire=protected(server,coap_message(68 if method==2 else 69,60,b"w",[],body),binding)
    trace=rows([("request","forward",req),("response","forward",b"\x60\x00\x00\x32"),("response","forward",wire),("request","forward",b"\x60\x00\x00\x3c")],offset)
    return dict(trace=trace,endpoints=copy.deepcopy(ENDPOINTS),result=dict(event="response",exit_code=0,code=68 if method==2 else 69,payload_hex=body.hex()))


def record():
    out={"server_ready":{"transport":"oscore","port":1003,"libcoap_patch_sha256":"patch"},"sessions":[],
         "setup":dict(event="response",exit_code=0,code=69,payload_hex=b"0".hex())}
    for index,mode in enumerate(("baseline","stale","fresh")):
        base=100+index*400
        trace,result,endpoints=observer(index*2,index==1,base,1000+index*100)
        case=dict(mode=mode,trace=trace,result=result,endpoints=endpoints,proof=observer_grade(trace,result,endpoints,index*2,index==1),
                  writes=[exchange(2,b"",base+100,3_500_000),exchange(2,b"",base+200,6_500_000)],readback=exchange(1,str(index*2+2).encode(),base+300,12_000_000),pending_after_replay=True)
        offset=index*100_000_000
        for row in case["trace"]:row["time_ns"]+=offset
        for part in [*case["writes"],case["readback"]]:
            for row in part["trace"]:row["time_ns"]+=offset
        case["writes"][1]["trace"][0]["time_ns"]=offset+(7_500_000 if index==1 else 5_500_000)
        for i,row in enumerate(case["writes"][1]["trace"][1:],1):row["time_ns"]=case["writes"][1]["trace"][0]["time_ns"]+i*100_000
        case["proof"]=observer_grade(case["trace"],case["result"],case["endpoints"],index*2,index==1)
        out['sessions'].append(case)
    return out


class ObserveTests(unittest.TestCase):
    def test_complete_baseline_stale_and_fresh_campaign(self):
        proof=campaign_review(record(),{"patch_sha256":"patch"})
        self.assertEqual(proof["complete_bodies"],[["0","1","2"],["2","3","4"],["4","5","6"]])
        self.assertEqual(proof["intact_stale_replays"],1)

    def test_authenticated_body_binding_and_nonce_refusal(self):
        for kw in ({"wrong_binding":True},{"reused_piv":True},{"bad_body":True},{"missing_piv":True}):
            with self.subTest(kw=kw),self.assertRaises(AssertionError):observer_grade(*observer(**kw),0,False)

    def test_endpoint_control_and_client_result_mutations(self):
        mutations=[lambda x:x[0].pop(1),lambda x:x[0].pop(),lambda x:x[0][3].update(hex="60000099",forwarded_hex="60000099"),
                   lambda x:x[0][2].update(source=["127.0.0.1",9999]),lambda x:x[0][2].update(action="drop"),
                   lambda x:x[0][2].update(forwarded_hex="00"),lambda x:x[0][3].update(time_ns=0),
                   lambda x:x[1].update(payload_hex=b"0,0,1".hex()),lambda x:x[1].update(exit_code=1),
                   lambda x:x[2].update(server=["::1",1003,0,0])]
        for i,mutate in enumerate(mutations):
            x=observer();mutate(x)
            with self.subTest(i=i),self.assertRaises(AssertionError):observer_grade(*x,0,False)

    def test_replay_requires_exact_old_bytes_after_newer_before_terminal(self):
        mutations=[lambda x:x[0].pop(6),lambda x:x[0][6].update(hex=x[0][4]["hex"],forwarded_hex=x[0][4]["hex"]),
                   lambda x:x[0][6].update(action="forward"),lambda x:x[0][6].update(source=["127.0.0.1",9999]),
                   lambda x:x[0].insert(4,x[0].pop(6))]
        for i,mutate in enumerate(mutations):
            x=observer(replay=True);mutate(x)
            with self.subTest(i=i),self.assertRaises(AssertionError):observer_grade(*x,0,True)

    def test_writer_authentication_and_readback_refuse_substitution(self):
        for mutate in (lambda x:x['result'].update(payload_hex=b"9".hex()),lambda x:x['trace'].pop(),
                       lambda x:x['trace'][1].update(hex="60000001",forwarded_hex="60000001"),
                       lambda x:x['trace'][2].update(source=["127.0.0.1",9999])):
            x=exchange(1,b"2",200,0);mutate(x)
            with self.assertRaises(AssertionError):exchange_grade(x,1,b"2",tuple(ENDPOINTS['server']))

    def test_campaign_refuses_missing_recovery_wrong_server_order_or_timing(self):
        mutations=[lambda r:r['sessions'].pop(),lambda r:r['sessions'].reverse(),
                   lambda r:r['server_ready'].update(port=True),lambda r:r['server_ready'].update(libcoap_patch_sha256="other"),
                   lambda r:r['sessions'][1].update(pending_after_replay=False),
                   lambda r:r['sessions'][1]['writes'][1]['trace'][0].update(time_ns=1),
                   lambda r:r['sessions'][2]['proof'].update(request_piv="00")]
        for i,mutate in enumerate(mutations):
            r=record();mutate(r)
            with self.subTest(i=i),self.assertRaises(AssertionError):campaign_review(r,{"patch_sha256":"patch"})

    def test_authenticated_cross_session_request_binding_reuse_refuses(self):
        r=record();case=r["sessions"][2]
        trace,result,endpoints=observer(4,False,100,1200)
        for row in trace:row["time_ns"]+=200_000_000
        case.update(trace=trace,result=result,endpoints=endpoints,proof=observer_grade(trace,result,endpoints,4,False))
        with self.assertRaisesRegex(AssertionError,"request binding reused"):campaign_review(r,{"patch_sha256":"patch"})

    def test_supervisor_failure_retains_partial_session_and_stops_own_process(self):
        service,relay,writer,proc=MagicMock(),MagicMock(),MagicMock(),MagicMock()
        service.__enter__.return_value=service;relay.__enter__.return_value=relay
        service.ready={"libcoap_patch_sha256":"patch"};service.number=1003
        relay.snapshot.return_value=[{"retained":"partial observer trace"}]
        proc.poll.return_value=None
        writer.__enter__.side_effect=RuntimeError("writer supervisor deadline")
        writer.trace=[{"retained":"failed writer trace"}]
        record={}
        with patch("oscore_observe.Server",return_value=service),patch("oscore_observe.ObserveRelay",return_value=relay),patch("oscore_observe.Proxy",return_value=writer),patch("oscore_observe.request",return_value=dict(exit_code=0,code=69,payload_hex=b"0".hex())),patch("oscore_observe.command",return_value=[]),patch("oscore_observe.subprocess.Popen",return_value=proc),patch("oscore_observe.authenticated_notifications",return_value=[(b"wire",b"0")]):
            with self.assertRaisesRegex(RuntimeError,"writer supervisor deadline"):campaign(None,None,record,{"patch_sha256":"patch"})
        self.assertEqual(record["sessions"][0]["trace"],[{"retained":"partial observer trace"}])
        self.assertNotIn("complete",record)
        self.assertEqual(record["sessions"][0]["writes"][0]["trace"],[{"retained":"failed writer trace"}])
        proc.kill.assert_called_once();proc.communicate.assert_called_once()

    def test_relay_refuses_bounds_and_short_send_before_trace_claim(self):
        relay=object.__new__(ObserveRelay);relay.trace=[];relay.dest=tuple(ENDPOINTS['server'])
        target=MagicMock();target.sendto.return_value=3
        with self.assertRaises(AssertionError):relay.record_send('response','forward',b'1234',ENDPOINTS['server'],target,CLIENT)
        self.assertEqual(relay.trace,[])
        relay.trace=[{}]*128
        with self.assertRaises(AssertionError):relay.record_send('response','forward',b'1234',ENDPOINTS['server'],target,CLIENT)


if __name__=='__main__':unittest.main()
