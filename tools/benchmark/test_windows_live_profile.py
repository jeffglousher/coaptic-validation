import unittest
from unittest.mock import patch
from pathlib import Path
import windows_profile as w

def fixture():
    return dict(event='fixture', mode='server-app-live-c1/1', security='oscore', operations=1000000,
        warmup=128, workload_thread_id=5, client_thread_id=6, deadline_seconds=90,
        virtual_tick_ms=8, virtual_first_ms=0, virtual_last_ms=8001016, capacities=dict(w.LIVE_CAPACITIES),
        layout=dict(shared_slot=1, client_context=1, client_request_ref=1, client_decrypt_scratch=1472,
                    server_app_inline=1, server_requested_heap=1, helper_stack_requested=2097152))

def row(event, **fields):
    return dict(event=event, mode='server-app-live-c1/1', security='oscore', **fields)

def measured(p):
    p.receive(fixture()); p.receive(row('warmup', warmup_verified=128))
    assert p.receive(row('ready',kind='work')) == 'capture_then_run'

class LiveTests(unittest.TestCase):
    def test_plan_and_batch(self):
        self.assertEqual(w.live_plan(), [('unprotected','control',0),('unprotected','capture',0),
            ('oscore','control',0),('oscore','capture',0),('oscore','capture',1),('unprotected','capture',1)])
        self.assertEqual((w.OPERATIONS,w.WARMUP,len(w.plan())),(50000,128,18))
    def test_protocol(self):
        p=w.LiveProtocol('oscore'); measured(p)
        self.assertEqual(p.receive(row('measured',**w.LIVE_COUNTERS)),'stop_then_verify')
        self.assertIsNone(p.receive(row('verified',helper_settled=True,**w.LIVE_COUNTERS)))
        self.assertEqual(p.receive(row('complete',helper_settled=True,**w.LIVE_COUNTERS)),'exit')
        with self.assertRaises(ValueError): p.receive(row('complete',helper_settled=True,**w.LIVE_COUNTERS))
    def test_fixture_invalid(self):
        for key,value in [('operations',True),('deadline_seconds',91),('virtual_last_ms',0),
                          ('workload_thread_id',True),('client_thread_id',5),('client_thread_id',0),
                          ('mode','bad'),('security','unprotected')]:
            f=fixture(); f[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): w.LiveProtocol('oscore').receive(f)
        for section,key,value in [('capacities','calls',True),('capacities','routes',2),
            ('capacities','blockwise',1),('capacities','extra',1),('layout','shared_slot',True),
            ('layout','client_decrypt_scratch',0),('layout','helper_stack_requested',0),('layout','extra',0)]:
            f=fixture(); f[section][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): w.LiveProtocol('oscore').receive(f)
    def test_order_counts_settlement(self):
        with self.assertRaises(ValueError): w.LiveProtocol('oscore').receive(row('ready',kind='work'))
        with self.assertRaisesRegex(ValueError, 'native live workload failed'): w.LiveProtocol('oscore').receive(row('failed',reason='timeout',terminal=True))
        for key,value in [('verified',True),('prepared',999999),('slot_empty',1),('pending_binding',True)]:
            p=w.LiveProtocol('oscore'); measured(p); counters=dict(w.LIVE_COUNTERS); counters[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): p.receive(row('measured',**counters))
        p=w.LiveProtocol('oscore'); measured(p); p.receive(row('measured',**w.LIVE_COUNTERS))
        with self.assertRaises(ValueError): p.receive(row('verified',helper_settled=False,**w.LIVE_COUNTERS))
    def test_inventory(self):
        exe=str(Path('worker.exe').resolve())
        d=dict(pid=1,exe=exe,thread_ids=[5,6],process_start_utc='2026-10-30T12:00:00.0000000Z')
        w.target_start_utc(d,1,exe,5,6)
        for client in (5,7,True):
            with self.assertRaises(ValueError): w.target_start_utc(d,1,exe,5,client)
    def test_capture_stops_before_verify_and_bounds_wait(self):
        import argparse, json
        from unittest.mock import Mock
        from contextlib import ExitStack
        root=Path('mock-live').resolve(); timeline=[]; saved={}
        record=dict(sources={},native=dict(path=str(root/'native.exe'),sha256='a'*64,
                    pdb=str(root/'native.pdb'),pdb_sha256='b'*64),
                    tool=dict(dotnet='dotnet',path='tool',sha256='c'*64),platform='mock')
        rows=[fixture(),row('warmup',warmup_verified=128),row('ready',kind='work'),
              row('measured',**w.LIVE_COUNTERS),row('verified',helper_settled=True,**w.LIVE_COUNTERS),
              row('complete',helper_settled=True,**w.LIVE_COUNTERS)]
        native,collector=Mock(),Mock(); native.p.pid=42
        native.line.side_effect=lambda timeout: (timeline.append(('line',timeout)),rows.pop(0))[1]
        native.send.side_effect=lambda action: timeline.append(('send',action))
        collector.line.side_effect=[dict(status=x,capture_id='owned',detail={}) for x in ('armed','ready')]
        detail=dict(pid=42,exe=record['native']['path'],thread_ids=[5,6],process_start_utc='2026-10-30T12:00:00.0000000Z')
        def command(argv,*args,**kwargs):
            return (json.dumps(dict(detail=detail))+'\n').encode() if argv[2]=='target' else b''
        def save(path,value): saved[path.name]=value
        profile=dict(scope=dict(pid=42,tid=5),identity=None,stacks=[],totals=dict(samples=0),quality={})
        def load(_): profile['identity']=saved['config.json']['identity']; return profile
        with ExitStack() as stack:
            for name,value in [('verified_build',Mock(return_value=record)),('live_plan',Mock(return_value=[('oscore','capture',0)])),
                ('Process',Mock(side_effect=[native,collector])),('command',Mock(side_effect=command)),('save',Mock(side_effect=save)),
                ('source_identity',Mock(return_value={})),('stop_collector',Mock(side_effect=lambda *a,**k: timeline.append(('stop',)))),
                ('digest',Mock(return_value='d'*64)),('qualification',Mock(return_value={}))]:
                stack.enter_context(patch.object(w,name,value))
            stack.enter_context(patch.object(w.uuid,'uuid4',return_value='owned'))
            stack.enter_context(patch.object(Path,'mkdir'))
            stack.enter_context(patch.object(w.stack_profile,'read_text',return_value=''))
            stack.enter_context(patch.object(w.stack_profile,'load_json',side_effect=load))
            stack.enter_context(patch.object(w.stack_profile,'render_html',return_value=''))
            stack.enter_context(patch.object(w.stack_profile,'write_new'))
            args=argparse.Namespace(workload='live-c1',core='core',expected_core='a'*40,expected_suite='b'*40)
            budget=Mock(peak=0,observed_child_working_set_peak=0,rss_limit=1)
            w.capture_phase(args,root,budget)
            self.assertLess(timeline.index(('stop',)),timeline.index(('send','verify')))
            timeline.clear()
            rows[:]=[fixture(),row('warmup',warmup_verified=128),row('ready',kind='work'),row('measured',**w.LIVE_COUNTERS)]
            w.Process.side_effect=[native,collector]
            collector.line.side_effect=[dict(status=x,capture_id='owned',detail={}) for x in ('armed','ready')]
            w.stop_collector.side_effect=RuntimeError('stop failed')
            with self.assertRaisesRegex(RuntimeError,'stop failed'): w.capture_phase(args,root,budget)
            self.assertNotIn(('send','verify'),timeline)
        self.assertIn(('line',92),timeline)
        self.assertEqual(saved['config.json']['max_seconds'],120)
        self.assertEqual(saved['config.json']['tid'],5)

    def test_cli(self):
        args=['build','--core','core','--output','out','--expected-core','a'*40,'--expected-suite','b'*40]
        with patch.object(w,'execute') as execute:
            w.main(args); self.assertEqual(execute.call_args.args[0].workload,'batch')
            w.main(args+['--workload','live-c1']); self.assertEqual(execute.call_args.args[0].workload,'live-c1')

    def test_prepared_workload_and_owner_plan_mismatch_refuse_before_processes(self):
        import argparse, copy
        from unittest.mock import Mock
        root = Path('mock-prepared-live').resolve()
        for prepared, requested, mutation in [
                ('live-c1', 'batch', None), ('batch', 'live-c1', None),
                ('live-c1', 'live-c1', 'missing'), ('batch', 'batch', 'owner'),
                ('live-c1', 'live-c1', 'plan'), ('live-c1', 'live-c1', 'operations')]:
            args = argparse.Namespace(workload=requested, core='core', expected_core='a'*40, expected_suite='b'*40)
            contract = w.workload_identity(argparse.Namespace(workload=prepared))
            record = dict(workload=copy.deepcopy(contract))
            owner = dict(workload=copy.deepcopy(contract), plan=copy.deepcopy(contract['cohorts']))
            if mutation == 'missing': del record['workload']
            if mutation == 'owner': owner['workload']['name'] = 'live-c1'
            if mutation == 'plan': owner['plan'].pop()
            if mutation == 'operations': record['workload']['operations'] -= 1
            def read(path): return record if path.name == 'build.json' else owner
            with self.subTest(prepared=prepared, requested=requested, mutation=mutation), \
                    patch.object(w, 'read_json', side_effect=read), \
                    patch.object(w, 'source_identity') as identity, \
                    patch.object(w, 'command') as command, patch.object(w, 'Process') as process:
                with self.assertRaisesRegex(ValueError, 'prepared workload or ownership plan mismatch'):
                    w.capture_phase(args, root, Mock())
                identity.assert_not_called(); command.assert_not_called(); process.assert_not_called()

    def test_live_native_test_proof_refuses_failure_changed_log_and_escaped_log(self):
        import argparse
        from unittest.mock import Mock
        root = Path('mock-prepared-live').resolve()
        args = argparse.Namespace(workload='live-c1', core='core', expected_core='a'*40, expected_suite='b'*40)
        contract = w.workload_identity(args)
        base = dict(log=str(root / 'evidence/native-live-tests.log'), passed=True, log_sha256='a'*64)
        for receipt in (dict(base, passed=False), dict(base, log_sha256='b'*64),
                        dict(base, log=str(root.parent / 'outside.log'))):
            def read(path):
                if path.name == 'build.json': return dict(workload=contract, sources={})
                if path.name == 'owner.json': return dict(workload=contract, plan=contract['cohorts'])
                return receipt
            with self.subTest(receipt=receipt), patch.object(w, 'read_json', side_effect=read), \
                    patch.object(w, 'digest', return_value='a'*64), \
                    patch.object(w, 'source_identity', return_value={}), \
                    patch.object(w, 'command') as command, patch.object(w, 'Process') as process:
                with self.assertRaisesRegex(ValueError, 'live native test receipt missing or changed'):
                    w.capture_phase(args, root, Mock())
                command.assert_not_called(); process.assert_not_called()

    def test_native_test_census_requires_executed_tests(self):
        good = b'test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out; finished in 0.1s\n'
        self.assertEqual(w.native_test_result(good)['passed'], 12)
        self.assertEqual(w.native_test_result(good.replace(b'\n', b'\r\n'))['filtered_out'], 18)
        for output in (b'', good + good, good.replace(b'12 passed', b'0 passed'),
                       good.replace(b'0 failed', b'1 failed')):
            with self.subTest(output=output), self.assertRaises(ValueError):
                w.native_test_result(output)

if __name__ == '__main__': unittest.main()
