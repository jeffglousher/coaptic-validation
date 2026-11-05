"""Portable incoming campaign tests; native launches and inputs remain RAM mocks."""
import argparse
import copy
import contextlib
import hashlib
import io
import math
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import admission_wall_screen as api
import incoming_rx_wall as rx


def args(command='all'):
    return argparse.Namespace(contract='incoming-rx',command=command,output='R:/coaptic-incoming-rx',core='R:/core',expected_suite='a'*40)


def fixture(q=False):
    c=rx.contract()
    v=dict(schema='coaptic-incoming-rx-qualification/1' if q else 'coaptic-incoming-rx/1',method_sha256=rx.HASH,
      method_state='source-frozen-before-execution',measurement=rx.MEASUREMENT,status='PASS',cells=[],
      positive_census=copy.deepcopy(c['qualification']['positive_census']),memory=dict(
      bounded_json_requested_heap_bytes=1044480,json_vec_inline_bytes=24,calibration_scalar_bytes=16,
      calibration_retention='JSON values; one scalar scratch, no subtraction',audit_inline_nested_in_cell_bytes=1000,
      raw_master_material_temporary_bytes=24,qualification_extra_wire_scratch_peak_bytes=2944 if q else 0,
      failure_report_temporary_bytes=1000,unknown='allocator, initialization and generated stack/runtime costs'))
    for i,t in enumerate(c['qualification']['positive_traces']):
        u=i in (0,1,4,5); p=i%2==1; polls=[4,4,16,16,1,1,1,1][i]
        cell=dict(t,id=t['id'].split('.',1)[1],positive_trace_id=t['id'],warm_transfers=8,measured_transfers=0 if q else 64,
          timing_state='NOTRUN' if q else 'RECORDED',bytes_in=10000,bytes_out=10000,request_pivs=72*polls if p else 0,
          piv_255_to_256=p and i<4,public_audit_fnv64=12345,crypto=dict(request_seals=72*polls if p else 0,
          app_authenticated_receiving_polls=72*polls if p else 0,raw_peer_response_opens=72*polls if p and u else 0,
          response_seals=72*polls if p else 0),config=dict(routes=4 if u else 1,populated_routes=1 if u else 0,
          calls=1 if u else 4,deferred=0,associations=1,bindings=4,rx_slots=2 if u else 4,tx_slots=2 if u else 4,
          datagram_bytes=1152 if u else 1472,dedup=4 if u else 8,observe=2 if u else 4,rx_body_slots=1,
          rx_body_bytes=4096 if u else 16384,tx_body_slots=1,tx_body_bytes=4096 if u else 1024),memory=dict(
          app_including_transport_inline_bytes=10000,app_required_pool_heap_bytes=0 if u else 50000,
          fixed_partner_app_inline_bytes=0 if u else 200000,partner_required_pool_heap_bytes=0,
          raw_peer_optional_context_inline_bytes=200 if u else 0,service_body_static_shared_bytes=16384,
          download_collection_bytes=0 if u else 16384,upload_open_scratch_bytes=1472 if u else 0,
          cell_result_inline_bytes=20000,nested_transport_is_in_app=True,remaining='allocator/runtime/generated-stack/initialization unknown'))
        if not u:cell['partner_config']=dict(routes=32,populated_routes=1,calls=4,deferred=8,associations=1,bindings=4,
          rx_slots=32,tx_slots=32,datagram_bytes=1472,dedup=64,observe=32,rx_body_slots=4,tx_body_slots=4,rx_body_bytes=16384,tx_body_bytes=16384)
        if not q:cell['transfers_ns']=[dict(sum=polls*100,polls=[100]*polls) for _ in range(64)]
        v['cells'].append(cell)
    if q:v.update(calibration_state='NOTRUN',traces=copy.deepcopy(c['qualification']['negative_traces']))
    else:
        v['positive_census']['measured_receiving_polls']=2816
        v.update(calibration_samples=4096,calibration_ns=[0]*4096)
    return v


class IncomingTests(unittest.TestCase):
    def test_selector_and_purpose_isolation(self):
        d=api.resolve_contract('incoming-rx');self.assertEqual(d.cores,rx.CORES);self.assertEqual(d.trees,rx.TREES)
        self.assertEqual(d.root,'coaptic-incoming-rx');self.assertEqual(api.purpose(args('proof')),'incoming-qualification')
        self.assertEqual(api.purpose(args()),'incoming-screen')
        for s in ('incoming','arbitrary','incoming-rx-qualification'):
            with self.assertRaises(ValueError):api.resolve_contract(s)
        with self.assertRaises(ValueError):rx.check(rx.bound({},'incoming-qualification'),'incoming-screen')

    def test_exact_schedule(self):
        rows=rx.schedule();self.assertEqual(''.join(r['arm'] for r in rows),'AB'+'ABBA'*4)
        self.assertEqual(sum(r['seconds'] for r in rows),264);self.assertEqual(rx.schedule(True),rows[:2])
        self.assertEqual([r['mode'] for r in rows],['qualify']*2+['measure']*16)

    def test_both_native_schemas(self):
        for q in (False,True):self.assertEqual(rx.validate_native(api,rx.encoded(fixture(q)),qualification=q),fixture(q))

    def test_nested_unknown_keys(self):
        def paths(v,path=()):
            if type(v) is dict:
                yield path
                for k,x in v.items():yield from paths(x,path+(k,))
            elif type(v) is list:
                # Same schema for every transfer/calibration, all heterogeneous cells/traces.
                for i,x in enumerate(v if len(v)<30 else v[:1]):yield from paths(x,path+(i,))
        for q in (False,True):
            original=fixture(q)
            for path in paths(original):
                v=copy.deepcopy(original);n=v
                for k in path:n=n[k]
                n['unknown']=1
                with self.subTest(path=path,q=q),self.assertRaises(ValueError):rx.validate_native(api,rx.encoded(v),qualification=q)

    def test_nested_integer_types_and_bounds(self):
        def paths(v,path=()):
            if type(v) is dict:
                for k,x in v.items():yield from paths(x,path+(k,))
            elif type(v) is list:
                for i,x in enumerate(v if len(v)<30 else v[:1]):yield from paths(x,path+(i,))
            elif type(v) is int:yield path
        for q in (False,True):
            original=fixture(q)
            for path in paths(original):
                for bad in (True,-1,2**129):
                    v=copy.deepcopy(original);n=v
                    for k in path[:-1]:n=n[k]
                    n[path[-1]]=bad
                    with self.subTest(path=path,bad=bad),self.assertRaises(ValueError):rx.validate_native(api,rx.encoded(v),qualification=q)

    def test_corrupt_arrays_headers_counts_and_failures(self):
        for mutate in (lambda v:v['cells'].reverse(),lambda v:v['cells'].pop(),lambda v:v['cells'][0]['transfers_ns'].pop(),
          lambda v:v['cells'][0]['transfers_ns'][0]['polls'].pop(),lambda v:v['cells'][0]['transfers_ns'][0].update(sum=1),
          lambda v:v['calibration_ns'].pop(),lambda v:v.update(status='FAIL'),lambda v:v.update(method_sha256='0'*64)):
            v=fixture();mutate(v)
            with self.assertRaises(ValueError):rx.validate_native(api,rx.encoded(v))
        for raw in (b'{"a":1,"a":1}',b'{"a":NaN}',b'{"a":Infinity}',b'{'):
            with self.assertRaises(ValueError):rx.validate_native(api,raw)
        for err,code in ((b'error',0),(b'',1),(b'x'*rx.LIMIT,1)):
            with self.assertRaises(ValueError):rx.validate_native(api,rx.encoded(fixture()),err,code)
        v=fixture(True);v['traces'].reverse()
        with self.assertRaises(ValueError):rx.validate_native(api,rx.encoded(v),qualification=True)

    def test_statistics_independent_oracle_and_incomplete_pairs(self):
        s=.01; result=rx.compare([(1,math.exp(k*s)) for k in (-7,-5,-3,-1,1,3,5,7)],1.02)
        delta=1.894579*math.sqrt(168*s*s/7)/math.sqrt(8)
        self.assertAlmostEqual(result['mean_ratio'],1);self.assertAlmostEqual(result['upper95'],math.exp(delta))
        self.assertAlmostEqual(result['lower95'],math.exp(-delta))
        self.assertTrue(rx.compare([(100,96)]*8,.97)['passed']);self.assertFalse(rx.compare([(100,98)]*8,.97)['passed'])
        for pairs in ([(1,1)]*7,[(0,1)]*8,[(True,1)]*8,[(1,float('nan'))]*8,[(1e308,1e-308)]*8):
            with self.assertRaises((ValueError,OverflowError)):rx.compare(pairs,.97)

    def test_fresh_byte_anchor_both_arms_logs_source_no_reanchor(self):
        ram={'A.exe':b'aaaa','B.exe':b'bbbb','log':b'logs','source':b'code'}
        digest=lambda n:hashlib.sha256(ram[str(n)]).hexdigest()
        mock=SimpleNamespace(ds=SimpleNamespace(digest=digest));pins=tuple((n,digest(n)) for n in ram)
        with patch.object(rx,'source_check'):
            rx.verify_anchor(mock,args(),pins)
            for n in ram:
                old=ram[n];ram[n]=b'X'*len(old)
                with self.assertRaises(ValueError):rx.verify_anchor(mock,args(),pins)
                ram[n]=old
            ram['log']=b'fake'
            with self.assertRaises(ValueError):rx.verify_anchor(mock,args(),pins)

    def test_combined_output_keeps_honest_prefix(self):
        p=object.__new__(rx.limited_process(api));p.raw=[bytearray(),bytearray()];p.lock=__import__('threading').Lock();p.error=None
        p._read(0,io.BytesIO(b'a'*(rx.LIMIT-4096)))
        p._read(1,io.BytesIO(b'e'*4096))
        self.assertIsNone(p.error)
        self.assertEqual(sum(map(len,p.raw)),rx.LIMIT)
        self.assertEqual(p.raw[1],b'e'*4096)
        p._read(1,io.BytesIO(b'!'))
        self.assertIsInstance(p.error,ValueError)
        self.assertEqual(sum(map(len,p.raw)),rx.LIMIT)
        self.assertEqual(p.raw[1],b'e'*4096)

    def test_foreign_worker_and_orphan_mode(self):
        for spec in (rx.bound(dict(kind='unknown',args=vars(args())),'incoming-screen'),
          rx.bound(dict(kind='measure',args=vars(args('build'))),'incoming-screen'),
          rx.bound(dict(kind='measure',args=vars(args())),'incoming-qualification')):
            with self.assertRaises(ValueError):rx.worker(api,spec)

    def test_campaign_exact_launches_and_operational_failure_census(self):
        for command,fail in (('proof',None),('all',None),('all',0),('all',1),('all',5)):
            a=args(command);root=Path(a.output);saved={};calls=[];method=rx.contract()
            prepared={'artifacts':{arm:{'exe':{'path':arm+'.exe'}} for arm in 'AB'}}
            def child(cmd,budget,stem,**kw):
                kw['on_launch']();calls.append(cmd)
                if fail==len(calls)-1:raise ValueError('operational')
                return rx.encoded(fixture(cmd[-1]=='qualify'))
            mock=SimpleNamespace(Budget=Mock(return_value=Mock()),affinity=Mock(return_value=contextlib.nullcontext()),
              wp=SimpleNamespace(owned_size=lambda p:0),read_json=api.read_json,child_command=child,
              load=lambda p:dict(returncode=0),save=lambda root,name,v:saved.update({name:v}),report_preserving=api.report_preserving,failure=api.failure)
            with patch.object(rx,'contract',return_value=method),patch.object(rx,'verify_anchor'),patch.object(rx,'limited_process',return_value=None),patch.object(Path,'read_bytes',return_value=b''):
                if fail is None and command=='proof':rx.campaign(mock,a,root,rx.encoded(prepared),())
                else:
                    with self.assertRaises(ValueError):rx.campaign(mock,a,root,rx.encoded(prepared),())
            result=saved['result.json'];self.assertEqual(len(calls),2 if command=='proof' else 18 if fail is None else fail+1)
            self.assertEqual(result['measured'],'NOTRUN' if len(calls)<=2 else 'RECORDED')
            self.assertEqual(len(result['completed']),len(calls) if fail is None else fail)
            self.assertEqual(len(result['comparisons']),8 if command=='all' and fail is None else 0)
            self.assertEqual('qualification-complete.json' in saved,fail is None or fail>=2)


    def test_anchor_refuses_replacement_during_full_validation(self):
        ram={'build.json':b'original','A.exe':b'aaaa','A.pdb':b'AAAA','B.exe':b'bbbb','B.pdb':b'pppp'}
        digest=lambda p:hashlib.sha256(ram[Path(p).name]).hexdigest()
        value=dict(suite={'files':{}},records={'A':{'source':{'files':{}}}},tools={},inputs={'config_files':{}},
                   artifacts={a:{k:dict(path='R:/'+a+'.'+k,sha256=hashlib.sha256(ram[a+'.'+k]).hexdigest()) for k in ('exe','pdb')} for a in 'AB'})
        mock=SimpleNamespace(SUITE=Path('R:/suite'),ds=SimpleNamespace(digest=digest),
              wp=SimpleNamespace(native_artifact_pair=lambda raw,target:(Path('R:/B.exe'),Path('R:/B.pdb'))))
        def replace(*unused):
            ram['build.json']=b'replaced'
            return value
        with patch.object(Path,'rglob',return_value=iter([Path('R:/evidence/build.json')])), \
             patch.object(Path,'is_file',return_value=True),patch.object(Path,'exists',return_value=False), \
             patch.object(Path,'read_bytes',return_value=b'log'),patch.object(rx,'verify_build',side_effect=replace), \
             patch.object(rx,'owner',return_value={}),patch.object(rx,'source_check'):
            with self.assertRaisesRegex(ValueError,'anchored bytes changed'):rx.anchor(mock,args(),Path('R:/coaptic-incoming-rx'))

    def test_cargo_exact_censuses_before_normal_build_and_partial_refusal(self):
        method=rx.contract(); calls=[]; saved={}
        def child(cmd,budget,stem,**kw):
            calls.append(cmd)
            if cmd[1]=='build':return b'cargo-artifact'
            names=list(api.WALL_TESTS) if cmd[-3]=='batch_tests::wall_' else method['qualification']['native_tests']
            if cmd[-1]=='--list':return ('\n'.join(n+': test' for n in names)+'\n\n4 tests, 0 benchmarks\n').encode()
            return ('\n'.join('test '+n+' ... ok' for n in names)+'\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n').encode()
        mock=SimpleNamespace(Budget=Mock(return_value=Mock()),TARGET=api.TARGET,NATIVE=api.NATIVE,WALL_TESTS=api.WALL_TESTS,
             child_command=child,validate_census=api.validate_census,ds=SimpleNamespace(digest=lambda p:'a'*64),
             wp=SimpleNamespace(native_artifact_pair=lambda raw,target:(Path('A.exe'),Path('A.pdb'))),
             save=lambda root,name,v:saved.update({name:v}))
        spec=rx.bound(dict(args=vars(args()),root=args().output,arm='A',seconds=400,cargo='cargo.exe'),'incoming-screen')
        with patch.object(rx,'verify_worker_source'),patch.object(Path,'stat',return_value=SimpleNamespace(st_size=20)):
            rx.cargo_worker(mock,spec)
        self.assertEqual(len(calls),5);self.assertEqual([c[1] for c in calls],['test']*4+['build'])
        self.assertEqual(calls[0][-3:],['batch_tests::wall_','--','--list'])
        self.assertEqual(calls[2][-3:],['incoming_rx::tests::','--','--list'])
        self.assertEqual(saved['A-cargo.json']['incoming_tests'],method['qualification']['native_tests'])
        calls.clear();mock.child_command=Mock(return_value=b'only_one: test\n1 test, 0 benchmarks\n')
        with patch.object(rx,'verify_worker_source'),self.assertRaises(ValueError):rx.cargo_worker(mock,spec)
        self.assertEqual(mock.child_command.call_count,1)



    def test_reporting_failure_preserves_unknown_settlement(self):
        a=args();method=rx.contract();primary=ValueError('unknown settlement');primary.cleanup_unresolved=True
        mock=SimpleNamespace(Budget=Mock(return_value=Mock()),affinity=Mock(return_value=contextlib.nullcontext()),
            wp=SimpleNamespace(owned_size=lambda p:0),read_json=api.read_json,
            child_command=Mock(side_effect=primary),save=Mock(side_effect=OSError('receipt write failed')),
            report_preserving=api.report_preserving,failure=api.failure)
        prepared={'artifacts':{'A':{'exe':{'path':'A.exe'}}}}
        with patch.object(rx,'contract',return_value=method),patch.object(rx,'verify_anchor'),patch.object(rx,'allocation_check'), \
             patch.object(rx,'limited_process',return_value=None),self.assertRaises(ValueError) as caught:
            rx.campaign(mock,a,Path(a.output),rx.encoded(prepared),())
        self.assertIs(caught.exception,primary);self.assertTrue(primary.cleanup_unresolved)
        self.assertTrue(any('receipt write failed' in n for n in primary.__notes__))

    def test_foreign_prepared_owner_refuses_before_artifacts(self):
        mock=SimpleNamespace(load=Mock(return_value={'contract_id':'admission'}))
        with patch.object(rx,'allocation_check'),self.assertRaises(ValueError):
            rx.verify_build(mock,args(),Path(args().output),rx.bound({},'incoming-screen'))
        self.assertEqual(mock.load.call_count,1)



    def test_valid_worker_route_and_foreign_extra_field(self):
        a=args();spec=rx.receipt(dict(kind='measure',args=vars(a),prepared_hashes={'build.json':'a'*64}),a)
        mock=SimpleNamespace(load=Mock(return_value=spec),check_files=Mock())
        with patch.object(rx,'anchor',return_value=(b'{}',())),patch.object(rx,'campaign',return_value='routed') as campaign:
            self.assertEqual(rx.worker(mock,spec),'routed');self.assertEqual(campaign.call_count,1)
        spec=dict(spec,arbitrary_revision='b'*40)
        with self.assertRaises(ValueError):rx.worker(mock,spec)


if __name__=='__main__':unittest.main()
