"""Authenticated Observe campaign oracle proofs; actual peer execution is separate."""
import copy
import itertools
import unittest
from unittest.mock import patch
from oscore_observe import campaign_review,observer_grade,exchange_grade,campaign
from oscore_observe_tests import record,exchange
from oscore_qblock1 import FixtureContext,request_plain
from oscore_qblock2_tests import protected
from run import coap_message,decoded_options,packet_token
from oscore_observe_cancel_tests import evidence as cancellation_evidence,ipv6_evidence as ipv6_cancellation_evidence
from oscore_observe_cancel import review as cancellation_review


def convert(part):
    for key in ('front','back','server'):
        part['endpoints'][key]=['::1',part['endpoints'][key][1],0,0]
    part['endpoints'].update(family='AF_INET6',v6only=[1,1])
    for row in part['trace']:
        for key in ('source','destination','relay'):
            row[key]=['::1',row[key][1],0,0]


def evidence(family='ipv4'):
    r=record()
    r['family']=family
    if family=='ipv6':
        for case in r['sessions']:
            for part in [case,*case['writes'],case['readback']]:convert(part)
            case['proof']=observer_grade(case['trace'],case['result'],case['endpoints'],
                                         r['sessions'].index(case)*2,case['mode']=='stale',family=family)
    return r


def replace_response(part,sequence,*,explicit=True):
    req=bytes.fromhex(part['trace'][0]['hex'])
    _,binding=request_plain(req)
    wire=protected(FixtureContext(server=True,sequence=sequence),
                   coap_message(part['result']['code'],60,b'w',[],bytes.fromhex(part['result']['payload_hex'])),
                   binding,explicit)
    part['trace'][2].update(hex=wire.hex(),forwarded_hex=wire.hex())


def overlap(part,left,right):
    owners={**part['endpoints'],'client':part['trace'][0]['source']}
    # Keep the expected independent server identity unchanged.
    if right=='server':left,right=right,left
    old,new=owners[right],owners[left]
    for key in ('front','back','server'):
        if part['endpoints'][key]==old:part['endpoints'][key]=copy.deepcopy(new)
    for row in part['trace']:
        for key in ('source','destination','relay'):
            if row[key]==old:row[key]=copy.deepcopy(new)


def nonminimal_response(part):
    wire=bytes.fromhex(part['trace'][2]['hex'])
    options=decoded_options(wire)
    oscore=options[9][0]
    count=oscore[0]&7
    # Preserve ciphertext and numeric nonce, changing only the compressed PIV.
    oscore=bytes([(oscore[0]&0xf8)|(count+1)])+b'\x00'+oscore[1:]
    options[9]=[oscore]
    rebuilt=coap_message(wire[1],int.from_bytes(wire[2:4],'big'),packet_token(wire),
                         [(key,value) for key,values in options.items() for value in values],
                         wire.split(b'\xff',1)[1])
    rebuilt=bytes([wire[0]])+rebuilt[1:]
    part['trace'][2].update(hex=rebuilt.hex(),forwarded_hex=rebuilt.hex())


class ObserveWaveTests(unittest.TestCase):
    def test_complete_ipv6_baseline_stale_and_fresh(self):
        proof=campaign_review(evidence('ipv6'),{'patch_sha256':'patch'},family='ipv6')
        self.assertEqual(proof['same_server'],['::1',1003,0,0])
        self.assertEqual(proof['complete_bodies'],[['0','1','2'],['2','3','4'],['4','5','6']])
        self.assertEqual(proof['intact_stale_replays'],1)

    def test_family_mismatch_refuses_before_process_launch(self):
        for family in ('ipv4','other'):
            with self.subTest(family=family),self.assertRaisesRegex(AssertionError,'family mismatch'):
                campaign_review(evidence('ipv6'),{'patch_sha256':'patch'},family=family)
        with patch('oscore_observe.Server') as server:
            with self.assertRaisesRegex(AssertionError,'address family'):
                campaign(None,None,{}, {},family='other')
            server.assert_not_called()

    def test_ipv6_all_sessions_and_exchanges_refuse_bad_endpoints(self):
        bad=[['127.0.0.1',1004],['::ffff:127.0.0.1',1004,0,0],['::1',1004],
             ['::1',1004,1,0],['::1',1004,0,1],['::1',1004,False,0],['::1',1004,0,'0']]
        for session in range(3):
            for part_index in range(4):
                for endpoint in bad:
                    r=evidence('ipv6');case=r['sessions'][session]
                    part=[case,*case['writes'],case['readback']][part_index]
                    part['trace'][0]['source']=endpoint
                    with self.subTest(session=session,part=part_index,endpoint=endpoint),self.assertRaises(AssertionError):
                        campaign_review(r,{'patch_sha256':'patch'},family='ipv6')

    def test_ipv6_all_relays_require_native_v6only_evidence(self):
        for session in range(3):
            for part_index in range(4):
                for value in (None,[1],[1,0],[True,1],[1,'1']):
                    r=evidence('ipv6');case=r['sessions'][session]
                    [case,*case['writes'],case['readback']][part_index]['endpoints']['v6only']=value
                    with self.subTest(session=session,part=part_index,value=value),self.assertRaisesRegex(AssertionError,'IPv6-only'):
                        campaign_review(r,{'patch_sha256':'patch'},family='ipv6')

    def test_writer_readback_every_owner_pair_collision_refuses(self):
        for family,method,pair in itertools.product(('ipv4','ipv6'),(1,2),itertools.combinations(('client','front','back','server'),2)):
            part=exchange(method,b'2' if method==1 else b'',200,0)
            if family=='ipv6':convert(part)
            server=tuple(part['endpoints']['server'])
            overlap(part,*pair)
            with self.subTest(family=family,method=method,pair=pair),self.assertRaisesRegex(AssertionError,'overlapping writer/readback'):
                exchange_grade(part,method,b'2' if method==1 else b'',server,family=family)

    def test_campaign_overlap_refuses_then_fresh_evidence_succeeds(self):
        for family in ('ipv4','ipv6'):
            for index in range(3):
                r=evidence(family);overlap(r['sessions'][index]['readback'],'front','back')
                with self.subTest(family=family,index=index),self.assertRaisesRegex(AssertionError,'overlapping writer/readback'):
                    campaign_review(r,{'patch_sha256':'patch'},family=family)
            self.assertEqual(campaign_review(evidence(family),{'patch_sha256':'patch'},family=family)['intact_stale_replays'],1)

    def test_same_and_cross_session_explicit_piv_reuse_refuses(self):
        for family in ('ipv4','ipv6'):
            for session,part_index,sequence in ((0,0,1000),(0,2,1100),(1,1,10200),(2,2,10300)):
                r=evidence(family);case=r['sessions'][session]
                replace_response([*case['writes'],case['readback']][part_index],sequence)
                with self.subTest(family=family,session=session,part=part_index),self.assertRaisesRegex(AssertionError,'server response PIV reused'):
                    campaign_review(r,{'patch_sha256':'patch'},family=family)
            self.assertEqual(campaign_review(evidence(family),{'patch_sha256':'patch'},family=family)['intact_stale_replays'],1)

    def test_implicit_request_bound_writer_responses_and_intact_replay_remain_valid(self):
        for family in ('ipv4','ipv6'):
            r=evidence(family)
            for case in r['sessions']:
                for part in [*case['writes'],case['readback']]:replace_response(part,0,explicit=False)
            self.assertEqual(campaign_review(r,{'patch_sha256':'patch'},family=family)['complete_bodies'],
                             [['0','1','2'],['2','3','4'],['4','5','6']])

    def test_zero_prefixed_authenticated_piv_alias_refuses_in_both_campaigns(self):
        for family in ('ipv4','ipv6'):
            for cancel in (False,True):
                r=(ipv6_cancellation_evidence() if family=='ipv6' else cancellation_evidence(fresh_token=b'n')) if cancel else evidence(family)
                part=r['writes'][0] if cancel else r['sessions'][0]['writes'][0]
                replace_response(part,1000)
                nonminimal_response(part)
                reviewer=cancellation_review if cancel else campaign_review
                with self.subTest(family=family,cancel=cancel),self.assertRaisesRegex(AssertionError,'noncanonical'):
                    reviewer(r,{'patch_sha256':'patch'},family=family)

    def test_canonical_zero_explicit_response_piv_remains_valid(self):
        for family in ('ipv4','ipv6'):
            for cancel in (False,True):
                r=(ipv6_cancellation_evidence() if family=='ipv6' else cancellation_evidence(fresh_token=b'n')) if cancel else evidence(family)
                replace_response(r['writes'][0] if cancel else r['sessions'][0]['writes'][0],0)
                reviewer=cancellation_review if cancel else campaign_review
                proof=reviewer(r,{'patch_sha256':'patch'},family=family)
                self.assertEqual(proof['complete_bodies'],['0','1','1','2','3','4'] if cancel else [['0','1','2'],['2','3','4'],['4','5','6']])

    def test_missing_ipv6_recovery_and_replay_faults_refuse(self):
        for mutate in (lambda r:r['sessions'].pop(),lambda r:r['sessions'][1].update(pending_after_replay=False),
                       lambda r:r['sessions'][1]['trace'][6].update(action='forward'),
                       lambda r:r['sessions'][2]['trace'][2].update(source=['::1',9999,0,0])):
            r=evidence('ipv6');mutate(r)
            with self.assertRaises(AssertionError):campaign_review(r,{'patch_sha256':'patch'},family='ipv6')


if __name__=='__main__':unittest.main()
