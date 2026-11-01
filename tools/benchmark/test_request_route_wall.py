"""Portable routing oracles; no native execution or persistent fixtures."""
import argparse
import copy
import hashlib
import itertools
import math
from pathlib import Path
import unittest
from unittest.mock import patch
import admission_wall_screen as w
import request_route_wall as r


def native(identifier='default32_full', security='oscore', mode='measure', latency=100):
    p,g = r.contract(), r.group(identifier)
    owners = dict.fromkeys(p['wire']['fixture_owner_keys'], 0)
    owners.update(latency_backing=128000 if mode=='measure' else 0,
                  calibration_backing=65536 if mode=='measure' else 0,
                  array_headers=48, metadata=1024, static_data=64)
    protocol = dict(prepared=8128, polled=8128, responded=8128, verified=8128,
        input_datagrams=8128, output_datagrams=8128, internal_datagrams=16256, udp_datagrams=0,
        first_mid=0, last_mid=8127, token_bytes=8, now_ms=1, max_outstanding=1,
        input_empty=True, output_empty=True, authenticated_responses=8128 if security=='oscore' else 0,
        bindings_consumed=8128 if security=='oscore' else 0,
        client_sender_seq_start=0 if security=='oscore' else None,
        client_sender_seq_end=8128 if security=='oscore' else None,
        request_piv_bytes_histogram=[0,256,7872,0,0,0] if security=='oscore' else None)
    value = dict(schema=p['native_schemas'][mode], contract=r.ID, method_sha256=r.METHOD_SHA256,
        purpose=p['wire']['purpose'][mode], phase=mode, group=identifier, security=security,
        profile=g['profile'], operations=8000,warmup=128,verified=8128,
        measured_polls=8000 if mode=='measure' else 0, calibration_samples=4096 if mode=='measure' else 0,
        payload_bytes=g['payload_bytes'],route_capacity=g['route_capacity'],registered_routes=g['registered_routes'],
        handler_calls=g['expected_handler_calls'],terminal='complete',trace_id='round-robin/1',
        capacities=copy.deepcopy(g['capacities']),protocol=protocol,
        layout=dict(app_inline_bytes=4096,app_align_bytes=8,pointer_bytes=8,
                    pool_heap_requested_bytes=0 if identifier.startswith('small_') else 8192,
                    site_inline_bytes=None,fixture_additional_bytes=sum(owners.values()),fixture_owners=owners),
        case_counts=[dict(id=c['id'],
            warmup_verified=sum(op%len(g['cases'])==j for op in range(128)),
            work_verified=sum(op%len(g['cases'])==j for op in range(128,8128)),
            handler_calls=sum(op%len(g['cases'])==j for op in range(8128))*c['handler_delta'])
            for j,c in enumerate(g['cases'])])
    if mode=='measure':
        value.update(latency_ns=[latency]*8000,calibration_ns=[0]*4096)
    return value


class ContractTests(unittest.TestCase):
    def test_native_problem_literals_match_canonical_titles(self):
        import ast
        import re
        source = (w.SUITE / r.SOURCE).read_text(encoding='utf-8')
        for name, title, code in (
                ('NOT_FOUND', 'Not Found', 132),
                ('NOT_ALLOWED', 'Method Not Allowed', 133)):
            literal = re.search(r'^const ' + name + r': &\[u8\] = (b"[^"]*");$',
                                source, re.M)
            self.assertIsNotNone(literal)
            title_bytes = title.encode('utf-8')
            self.assertLess(len(title_bytes), 24)
            expected = bytes((0xa2, 0x20, 0x60 + len(title_bytes))) + title_bytes
            expected += bytes((0x23, 0x18, code))
            self.assertEqual(ast.literal_eval(literal[1]), expected)

    def test_exact_public_method(self):
        raw = Path(r.__file__).with_name('request_route_plan.json').read_bytes()
        self.assertEqual(len(raw), 24294)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), r.METHOD_SHA256)
        self.assertTrue(raw.endswith(b'\n'))
        self.assertEqual(r.contract()['cores']['B']['commit'], dict(r.CORES)['B'])

    def test_selector_and_purpose_distinct_from_old_proof(self):
        selected = w.resolve_contract(r.ID, proof=True)
        self.assertEqual(w.binding(selected), r.binding())
        self.assertEqual(w.purpose(argparse.Namespace(contract=r.ID, command='proof')),
                         'request-route-qualification')
        self.assertNotEqual(w.purpose(argparse.Namespace(command='proof')),
                            'request-route-qualification')
        for selector in ('dedup-classified', 'regular-option-parser'):
            with self.assertRaises(ValueError):
                w.resolve_contract(selector, proof=True)

    def test_schedule_exact_serial_pairs(self):
        rows = r.schedule()
        self.assertEqual(len(rows), 160)
        self.assertEqual(len({tuple(x.values()) for x in rows}), 160)
        for i in range(0, 160, 2):
            a, b = rows[i:i+2]
            self.assertEqual(a['round'], a['arm'] + b['arm'])
            self.assertEqual({k:v for k,v in a.items() if k not in ('index','arm')},
                             {k:v for k,v in b.items() if k not in ('index','arm')})
        self.assertEqual([x['replicate'] for x in rows], sorted(x['replicate'] for x in rows))
        self.assertEqual(rows[:4], [
            dict(index=i, replicate=0, group='small_one', security='unprotected',
                 round='AB' if i < 2 else 'BA', arm='ABBA'[i]) for i in range(4)])

    def test_common_uses_own_ordinal_continuous_warmup(self):
        full = r.trace('default32_full')
        self.assertEqual(len(full), 8128)
        common = [x for x in full if x['id'] == 'common']
        for ordinal, x in enumerate(common):
            self.assertEqual(x['body_tag'], 31 if ordinal % 10 == 9 else 0)
        measured = [x for x in common if x['phase'] == 'measure']
        self.assertEqual(len(measured), 1000)
        self.assertEqual(sum(x['body_tag'] == 31 for x in measured), 100)
        self.assertEqual(sum(x['handler_delta'] for x in full), 5080)

    def test_all_trace_cases_counts(self):
        for g in r.contract()['groups']:
            trace = r.trace(g['id'])
            self.assertEqual(sum(x['handler_delta'] for x in trace), g['expected_handler_calls'])
            self.assertEqual(len({x['operation'] for x in trace}), 8128)
            self.assertEqual(sum(x['phase'] == 'warmup' for x in trace), 128)

    def test_labelled_means_every_selected_interval(self):
        values = list(range(8000))
        means = r.process_means(values, 'default32_full')
        for j, c in enumerate(r.group('default32_full')['cases']):
            selected = [v for i, v in enumerate(values) if (i+128) % 8 == j]
            self.assertEqual(means[c['id']], math.fsum(selected)/len(selected))

    def test_intervals_strict(self):
        for bad in ([True]*8000, [-1]*8000, [1.0]*8000, [2**128]*8000, [1]*7999):
            with self.assertRaises(ValueError):
                r.process_means(bad, 'small_one')


class StatisticsTests(unittest.TestCase):
    def test_identity_and_proportional(self):
        for ratio in (1, .5, .97, 1.02, 2):
            a = [100, 200, 300, 400]
            result = r.paired(a, [ratio*x for x in a])
            self.assertEqual(result['tuples'], 256)
            self.assertAlmostEqual(result['point'], ratio)
            self.assertAlmostEqual(result['upper95'], ratio)

    def test_asymmetric_independent_exact_oracle(self):
        a,b = [1, 2, 8, 32], [3, 1, 13, 17]
        expected = []
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    for l in range(4):
                        ix = [i,j,k,l]
                        expected.append(math.fsum(b[x] for x in ix)/math.fsum(a[x] for x in ix))
        expected.sort()
        pos = 255*.95
        upper = expected[int(pos)]*(1-(pos-int(pos))) + expected[math.ceil(pos)]*(pos-int(pos))
        self.assertEqual(r.paired(a,b), dict(point=math.fsum(b)/math.fsum(a), upper95=upper, tuples=256))

    def test_paired_refuses_invalid_means(self):
        for bad in ([0]*4, [True]*4, [math.nan]*4, [math.inf]*4, [1]*3):
            with self.assertRaises(ValueError):
                r.paired(bad, [1]*4)

    def records(self, ratio=1):
        return [dict(selection=row, latencies_ns=[100 if row['arm']=='A' else int(100*ratio)]*8000)
                for row in r.schedule()]

    def test_all84_required_with8_benefits(self):
        result = r.analyze(self.records())
        self.assertEqual(len(result),84)
        self.assertEqual(sum(x['passed'] for x in result),76)
        self.assertEqual(sum(x['role']=='benefit' for x in result),8)
        self.assertTrue(all(x['passed'] for x in r.analyze(self.records(.97))))

    def test_missing_duplicate_swapped_refuse(self):
        records = self.records()
        for bad in (records[:-1], records+[records[0]],
                    [records[1],records[0]]+records[2:], [records[0]]+records[:-1]):
            with self.assertRaises(ValueError):
                r.analyze(bad)

    def test_layout_growth_and_pool_guard(self):
        a = dict(app_inline_bytes=1000, app_align_bytes=8, pool_heap_requested_bytes=4096)
        b = dict(a, app_inline_bytes=1048)
        r.layout_pair(a,b,'default32_full')
        for bad in (dict(b,app_inline_bytes=1049),dict(b,pool_heap_requested_bytes=4097),
                    dict(b,app_align_bytes=True)):
            with self.assertRaises(ValueError):
                r.layout_pair(a,bad,'default32_full')


class CustodyTests(unittest.TestCase):
    def args(self, command='proof'):
        return argparse.Namespace(contract=r.ID, command=command, core='core',
                                  expected_suite='a'*40, output='output')

    def test_foreign_self_rehashed_method_rejected(self):
        selected = w.resolve_contract(r.ID)
        for foreign in (w.ADMISSION, w.DEDUP, w.REGULAR_OPTIONS):
            with self.assertRaises(ValueError):
                w.check_binding(w.bound(dict(purpose='request-route-benefit'), foreign), selected)
        value = r.binding()
        value['contract_sha256'] = hashlib.sha256(b'foreign').hexdigest()
        with self.assertRaises(ValueError):
            w.check_binding(value, selected)

    def test_purpose_and_selector_worker_mismatch_refused(self):
        selected = w.resolve_contract(r.ID)
        for args, stated in ((self.args(), 'ownership-proof'),
                             (argparse.Namespace(contract='admission', command='proof'), 'request-route-qualification')):
            spec = w.bound(dict(args=vars(args), purpose=stated), selected)
            with self.assertRaises(ValueError):
                r.verify_worker(w, spec, selected)

    def test_route_tests_exact_four_and_failclosed_census(self):
        expected = ('request_route::tests::metadata_and_body_refuse',
                    'request_route::tests::authentication_and_replay_refuse',
                    'request_route::tests::missing_and_extra_io_refuse',
                    'request_route::tests::count_and_state_refuse')
        self.assertEqual(r.route_tests(), expected)
        for listing in (True,False):
            raw = (''.join(x+': test\n' for x in expected)+'\n4 tests, 0 benchmarks\n'
                   if listing else 'running 4 tests\n'+
                   ''.join('test '+x+' ... ok\n' for x in expected)+
                   'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.01s\n').encode()
            w.validate_census(raw, listing=listing, expected=expected)
            for bad in (raw.replace(expected[0].encode(), expected[1].encode()),
                        raw.replace(expected[0].encode(), b'foreign::test'), b''):
                with self.assertRaises(ValueError):
                    w.validate_census(bad, listing=listing, expected=expected)

    def test_libtest_artifact_refused_before_pair_selection(self):
        for profile in ({}, {'test':True}, {'test':0}):
            raw = w.ds.encoded(dict(reason='compiler-artifact',
                target=dict(name='bench-core'), profile=profile))
            with patch.object(w.wp, 'native_artifact_pair') as select:
                with self.assertRaises(ValueError):
                    r.normal_artifact(w, raw, Path('target'))
                select.assert_not_called()

    def test_qualification_schedule_exact20_no_timing(self):
        rows = r.qualification_schedule()
        self.assertEqual(len(rows),20)
        self.assertEqual([x['arm'] for x in rows], ['A']*10+['B']*10)
        self.assertEqual([x['security'] for x in rows[:4]],
                         ['unprotected','oscore','unprotected','oscore'])
        self.assertEqual(set(rows[0]), {'index','group','security','arm'})

    def test_failure_report_cannot_mask_unresolved_custody(self):
        from suite_process import WorkerError
        error = WorkerError(['worker'], TimeoutError('primary'),
                            [RuntimeError('unsettled')], b'', b'', 1, None)
        self.assertTrue(error.cleanup_unresolved)
        w.report_preserving(error, 'secondary', lambda: (_ for _ in ()).throw(OSError('report')))
        self.assertTrue(error.cleanup_unresolved)
        self.assertIn('secondary', error.__notes__[-1])

    def test_bool_selection_index_not_integer(self):
        records = StatisticsTests().records()
        records[0] = dict(records[0], selection=dict(records[0]['selection'],index=False))
        with self.assertRaises(ValueError):
            r.analyze(records)


class WireTests(unittest.TestCase):
    def test_all20_phase_group_mode_shapes(self):
        for g in r.contract()['groups']:
            for security in ('unprotected','oscore'):
                for phase in ('qualify','measure'):
                    value = native(g['id'],security,phase)
                    r.validate_native(w,value,g['id'],security,phase)
                    self.assertEqual(len(value), len(r.contract()['wire']['root_required'])+
                                     (2 if phase=='measure' else 0))

    def test_root_case_protocol_and_layout_closed_types(self):
        value=native()
        for path in ((),('layout',),('layout','fixture_owners'),('protocol',),('capacities',)):
            bad=copy.deepcopy(value)
            current=bad
            for key in path: current=current[key]
            current['foreign']=0
            with self.assertRaises(ValueError):
                r.validate_native(w,bad,'default32_full','oscore','measure')
        for key in ('operations','handler_calls','verified','measured_polls','route_capacity'):
            bad=copy.deepcopy(value);bad[key]=True
            with self.assertRaises(ValueError): r.validate_native(w,bad,'default32_full','oscore','measure')
        for key in value['protocol']:
            bad=copy.deepcopy(value);bad['protocol'][key]='wrong'
            with self.assertRaises(ValueError): r.validate_native(w,bad,'default32_full','oscore','measure')
        for key in value['layout']:
            bad=copy.deepcopy(value);bad['layout'][key]=False
            with self.assertRaises(ValueError): r.validate_native(w,bad,'default32_full','oscore','measure')

    def test_qualification_arrays_absent_and_measure_arrays_strict(self):
        for key in ('latency_ns','calibration_ns'):
            for content in (None,[],[0]):
                value=native(mode='qualify');value[key]=content
                with self.assertRaises(ValueError): r.validate_native(w,value,'default32_full','oscore','qualify')
            for content in (None,[],[True]*8000,[1.0]*8000,[-1]*8000,[2**128]*8000):
                value=native();value[key]=content
                with self.assertRaises(ValueError): r.validate_native(w,value,'default32_full','oscore','measure')

    def test_missing_duplicate_swapped_case_counters(self):
        for mutation in ('missing','duplicate','swapped','handler','bool'):
            value=native()
            if mutation=='missing': value['case_counts'].pop()
            if mutation=='duplicate': value['case_counts'][1]=value['case_counts'][0]
            if mutation=='swapped': value['case_counts'].reverse()
            if mutation=='handler': value['case_counts'][3]['handler_calls']=1
            if mutation=='bool': value['case_counts'][0]['warmup_verified']=True
            with self.assertRaises(ValueError): r.validate_native(w,value,'default32_full','oscore','measure')

    def test_owner_sum_growth_and_phase_layout(self):
        q=native(mode='qualify')['layout'];t=native()['layout']
        r.same_layout(w,t,q)
        for key in ('app_inline_bytes','pool_heap_requested_bytes','site_inline_bytes'):
            bad=copy.deepcopy(t);bad[key]=999
            with self.assertRaises(ValueError): r.same_layout(w,bad,q)
        for mutate in ('sum','cap','backing'):
            value=native();lay=value['layout']
            if mutate=='sum':lay['fixture_additional_bytes']+=1
            if mutate=='cap':
                lay['fixture_owners']['other_explicit']=262144
                lay['fixture_additional_bytes']=sum(lay['fixture_owners'].values())
            if mutate=='backing':
                lay['fixture_owners']['latency_backing']=0
                lay['fixture_additional_bytes']=sum(lay['fixture_owners'].values())
            with self.assertRaises(ValueError):r.validate_native(w,value,'default32_full','oscore','measure')

    def test_native_stdout_stderr_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'evidence').mkdir()
            path=root/'evidence/test.stderr';path.write_bytes(b'')
            raw=w.ds.encoded(native())+b'\n'
            r.native_json(w,root,'test',raw)
            for bad in (raw+b'\n',b' '+raw,raw[:-1],raw+b'extra',b'{} {}\n'):
                with self.assertRaises(ValueError): r.native_json(w,root,'test',bad)
            path.write_bytes(b'warning')
            with self.assertRaises(ValueError):r.native_json(w,root,'test',raw)


class CampaignTests(unittest.TestCase):
    def run_campaign(self, fail=None, proof=False, reporting=False):
        import tempfile
        from contextlib import nullcontext
        from unittest.mock import Mock
        from suite_process import WorkerError
        directory=tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root=Path(directory.name);(root/'evidence').mkdir()
        args=argparse.Namespace(command='proof' if proof else 'all',contract=r.ID,output=str(root))
        selected=w.resolve_contract(r.ID)
        artifacts={a:dict(exe=dict(path=a+'.exe'),pdb=dict(path=a+'.pdb')) for a in 'AB'}
        spec=w.bound(dict(kind='measure',args=vars(args),purpose=r.purpose(args),prepared_hashes={}),selected)
        calls=[];saved={}
        def command(argv,budget,stem,**kwargs):
            calls.append(argv)
            if stem==fail:
                raise WorkerError(argv,TimeoutError('operational'),[RuntimeError('unsettled')],b'',b'',1,None)
            (root/'evidence'/(stem+'.stderr')).write_bytes(b'')
            return w.ds.encoded(native(argv[3],argv[4],argv[2],97 if argv[0]=='B.exe' else 100))+b'\n'
        def save(root,name,value):
            if reporting and name=='result.json':raise OSError('reporting')
            saved[name]=value
        with patch.object(r,'verify_worker',return_value=(args,root)), \
             patch.object(r,'prepared_check',return_value=dict(artifacts=artifacts)), \
             patch.object(w,'load',return_value=dict(prepared_hashes={})), \
             patch.object(w,'check_files'), patch.object(w,'Budget',return_value=Mock()), \
             patch.object(w,'affinity',return_value=nullcontext()), \
             patch.object(w,'child_command',side_effect=command),patch.object(w,'save',side_effect=save):
            if fail:
                with self.assertRaises(WorkerError) as caught:r.measure_worker(w,spec,selected)
                self.assertTrue(caught.exception.cleanup_unresolved)
                if reporting:self.assertTrue(any('routing result receipt' in x for x in caught.exception.__notes__))
            else:r.measure_worker(w,spec,selected)
        return calls,saved

    def test_full160_after20_qualification_and_all84_decisions(self):
        calls,saved=self.run_campaign()
        self.assertEqual(len(calls),180)
        self.assertTrue(all(x[2]=='qualify' for x in calls[:20]))
        self.assertTrue(all(x[2]=='measure' for x in calls[20:]))
        result=saved['result.json']
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['comparisons']),84)
        self.assertEqual(len(result['completed']),160)
        self.assertEqual(result['not_run'],[])

    def test_proof_runs20_qualifiers_without_timing(self):
        calls,saved=self.run_campaign(proof=True)
        self.assertEqual(len(calls),20)
        self.assertEqual(saved['result.json']['measurements'],'NOT RUN')
        self.assertEqual(saved['result.json']['completed'],[])

    def test_first_operational_failure_retains_incomplete_and_notrun(self):
        calls,saved=self.run_campaign(fail='sample-002')
        self.assertEqual(saved['result.json']['measurements'],'ATTEMPTED')
        result=saved['result.json']
        self.assertEqual(len(calls),23)
        self.assertEqual(len(result['completed']),2)
        self.assertEqual(len(result['attempted']),3)
        self.assertEqual(len(result['failed_or_incomplete']),1)
        self.assertEqual(len(result['not_run']),157)
        self.assertEqual(result['comparisons'],[])

    def test_qualification_failure_and_reporting_preserve_unresolved_error(self):
        calls,saved=self.run_campaign(fail='qualify-01')
        self.assertEqual(saved['result.json']['measurements'],'NOT RUN')
        self.assertEqual(len(calls),2)
        self.assertEqual(len(saved['result.json']['qualification_not_run']),18)
        self.assertEqual(len(saved['result.json']['not_run']),160)
        self.run_campaign(fail='sample-000',reporting=True)


class BuildWorkerTests(unittest.TestCase):
    def test_both_census_families_before_normal_binary_and_foreign_inputs_refuse(self):
        import tempfile
        from unittest.mock import Mock
        from test_admission_wall_screen import census
        selected=w.resolve_contract(r.ID)
        def route_census(listing):
            names=r.route_tests()
            return (''.join(n+': test\n' for n in names)+'\n4 tests, 0 benchmarks\n'
                    if listing else 'running 4 tests\n'+''.join('test '+n+' ... ok\n' for n in names)+
                    'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n').encode()
        for bad_index in (None,0,1,2,3,'foreign'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                args=argparse.Namespace(command='proof',contract=r.ID,output=str(root),core='core',expected_suite='f'*40)
                source=w.bound(dict(identity=dict(commit=dict(r.CORES)['A'],tree=dict(r.TREES)['A']),files={}),selected)
                suite=w.bound(dict(identity=dict(commit='f'*40,tree='e'*40),files={r.SOURCE:'x'}),selected)
                spec=w.bound(dict(kind='cargo',root=str(root),arm='A',args=vars(args),purpose=r.purpose(args),
                    tools=dict(cargo=dict(path='cargo')),flags=w.FLAGS,inputs={},cargo='cargo',
                    source=source,suite=suite,lock=dict(selected_sha256='d'*64),seconds=400),selected)
                frozen=w.bound(dict(owner={},tools=spec['tools'],flags=w.FLAGS,inputs={}),selected)
                if bad_index=='foreign':frozen['tools']={}
                calls=[];saved=[]
                def command(argv,*a,**kw):
                    index=len(calls);calls.append(argv)
                    return (b'0 tests' if index==bad_index else
                            [census(True),census(),route_census(True),route_census(False),b'normal artifact'][index])
                with patch.object(r,'verify_worker',return_value=(args,root)), \
                     patch.object(w,'owner',return_value={}),patch.object(w,'load',return_value=frozen), \
                     patch.object(w,'tool_check'),patch.object(w,'config_check'), \
                     patch.object(w.ds,'identity',return_value=source['identity']), \
                     patch.object(w,'verify_staged_suite'),patch.object(w,'check_files'), \
                     patch.dict(w.os.environ,w.FLAGS),patch.object(w,'Budget',return_value=Mock()), \
                     patch.object(w,'child_command',side_effect=command), \
                     patch.object(r,'normal_artifact',return_value=(Path('x.exe'),Path('x.pdb'))), \
                     patch.object(w,'save',side_effect=lambda *a:saved.append(a)):
                    if bad_index is None:
                        r.cargo_worker(w,spec,selected)
                        self.assertEqual(len(calls),5)
                        self.assertEqual(calls[0][-3:],['batch_tests::wall_','--','--list'])
                        self.assertEqual(calls[2][-3:],['request_route::tests::','--','--list'])
                        self.assertEqual(calls[-1][1],'build')
                        self.assertEqual(saved[0][-1]['route_tests'],list(r.route_tests()))
                    else:
                        with self.assertRaises(ValueError):r.cargo_worker(w,spec,selected)
                        self.assertEqual(len(calls),0 if bad_index=='foreign' else bad_index+1)
                        self.assertEqual(saved,[])

    def test_old_plan_schedule_and_bindings_remain_byte_exact(self):
        # Canonical-byte hashes independently frozen from immutable b069ed2.
        # No historical Git object is required in shallow CI checkouts.
        expected = {
            "ADMISSION": {
                "plan": "3af1f730d1f9e580cf7c4cf7beebfe19c58f323fcab642e10600850519f73e33",
                "schedule": "35074d03febe5ae69f2cac5d15833fd4ef5729bf355502f73caf899bdfea48b8",
                "binding": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
            },
            "DEDUP": {
                "plan": "76db03001435e2e89db2a401107fb03d4513d9c1b49c482539a68a2614716df5",
                "schedule": "35074d03febe5ae69f2cac5d15833fd4ef5729bf355502f73caf899bdfea48b8",
                "binding": "e9f2641f6d7a35e8c4f4ed6a782184f1b27c0c69d29d721a653730a4b9719bb7"
            },
            "REGULAR_OPTIONS": {
                "plan": "a0e04e199df6a6d88677778cf99ad15b66d9f8fcded043b13e17e75e6eca852c",
                "schedule": "173c2596d5b2de65e12f36e394e5b3c3360b72e0e25b83ae6b5f46b4a6ce18df",
                "binding": "bc80d2a40b2bee9c86213df6735fc5fd7e58a663fec058b91d53cef9ed607337"
            }
        }
        with patch('subprocess.check_output', side_effect=AssertionError('Git history unavailable')):
            for name, kinds in expected.items():
                selected = getattr(w, name)
                for kind, digest in kinds.items():
                    self.assertEqual(hashlib.sha256(w.ds.encoded(
                        getattr(w, kind)(selected))).hexdigest(), digest)


class WorkflowTests(unittest.TestCase):
    def test_new_selector_all_boolean_routes(self):
        import itertools,re
        ci=(w.SUITE/'.github/workflows/ci.yml').read_text()
        expressions=re.findall(r'^    if: \$\{\{ (.*?) \}\}',ci,re.M)
        self.assertEqual(len(expressions),4)
        keys=('admission_wall_screen','admission_pressure_proof','stack_profile',
              'stack_profile_replay','stack_profile_live','stack_profile_live_replay')
        for bits in itertools.product((False,True),repeat=6):
            inputs=dict(zip(keys,bits),wall_screen_contract=r.ID)
            def evaluate(expr):
                expr=expr.replace("github.event_name","'workflow_dispatch'")
                expr=re.sub(r'inputs\.(\w+)',lambda x:repr(inputs[x[1]]),expr)
                expr=re.sub(r'!(?!=)',' not ',expr)
                return bool(eval(expr.replace('&&',' and ').replace('||',' or '),{'__builtins__':{}}))
            routes=list(map(evaluate,expressions))
            valid=bits[0] and not any(bits[2:])
            self.assertEqual(routes,[not valid,False,False,valid],inputs)


if __name__ == '__main__':
    unittest.main()
