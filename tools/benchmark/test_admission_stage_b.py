"""Portable Stage B tests: all process launches mocked; tiny temporary fixtures removed."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import admission_wall_screen as w
import admission_stage_b as b
from suite_process import WorkerError


def native(row=None, *, context=b.ADMISSION):
    row = row or b.schedule(context=context)[0]
    c = b.contract(context=context)
    case = next(x for x in c['cases'] if x['id'] == row['case'])
    m = dict.fromkeys(b.MEMORY[:-1],0)
    m.update(app_inline_bytes=4096, app_pool_requested_heap_bytes=8192 if case['profile']=='Default' else 0,
             fixture_inline_bytes=180000, fixture_total_requested_bytes=180000,
             peer_context_nested_bytes=512,latency_bytes=case.get('latency_storage_bytes',48000),calibration_bytes=65536,
             token_ledger_bytes=case.get('token_ledger_storage_bytes',27072),serializer_buffer_bytes=8192,
             remaining='allocator/runtime/initialization/peak-stack costs unknown')
    return dict(schema=c['native_schema'],contract_sha256=context.sha256,contract=c,case=case['id'],security=row['security'],
        profile=case['profile'],operations=1000,warmup=128,calibration_samples=4096,verified_cycles=1128,
        latencies_ns={k:[100]*1000 for k in case['labels']},calibration_ns=[0]*4096,
        internal_datagrams=case['internal_datagrams_per_cycle']*1128,udp_datagrams=0,
        handler_calls=case['handler_calls_per_cycle']*1128,clock_ms=[0,279744000],
        metrics={k:case[k+'_per_cycle']*1128 for k in b.METRICS},memory=m,settled=dict.fromkeys(b.SETTLED,True),
        sender_sequences=None if row['security']=='unprotected' else (
            dict(app=[0,0],peer=[0,3384],fresh_app=0,fresh_peer=3384,max_piv_bytes=2)
            if case['id'].startswith('long_') else
            dict(app=[0,100],peer=[0,101],fresh_app=100,fresh_peer=101,max_piv_bytes=2)))


def output(value,qualification=False,crlf=False):
    marker='COAPTIC_STAGE_B_QUALIFICATION ' if qualification else 'COAPTIC_STAGE_B_RESULT '
    text='\nrunning 1 test\n\n'+marker+json.dumps(value,separators=(',',':'))+'\n.\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 21 filtered out; finished in 0.01s\n'
    return (text.replace('\n','\r\n') if crlf else text).encode()


def qual(name, *, context=b.ADMISSION):
    case,mode=b.test_cell(name,True,context=context)
    return dict(schema=context.qualification_schema,contract_sha256=context.sha256,case=case,security=mode,cycles=16,passed=True,measurement='NOT RUN')


class ContractTests(unittest.TestCase):
    def test_fresh_contract_and_pinned_hash(self):
        self.assertEqual(hashlib.sha256(b.encoded(b.contract())).hexdigest(),b.HASH)
        c=b.contract(); c['cases'][0]['id']='bad'
        self.assertEqual(b.contract()['cases'][0]['id'],'rx')

    def test_bridge(self):
        d=w.resolve_contract(b.ID)
        self.assertEqual(w.plan(d),b.contract())
        self.assertEqual(w.binding(d),b.binding())
        for command in ('proof','build','measure','all'):
            args=argparse.Namespace(contract=b.ID,command=command)
            self.assertEqual(w.purpose(args),'stage-b-qualification' if command=='proof' else 'stage-b-regression')

    def test_old_contracts_golden(self):
        goldens = {
            'admission': ('13ae3b764ea8dc047812ea6ea836833ccb8696d43f44d0bdb89e7431e60e5e70',
                '3af1f730d1f9e580cf7c4cf7beebfe19c58f323fcab642e10600850519f73e33',
                '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
            'dedup-classified': ('c79831702aa6c48bc21e80ba7648fea127a606bc4549443a8f6c4b1e3a05deed',
                '76db03001435e2e89db2a401107fb03d4513d9c1b49c482539a68a2614716df5',
                'e9f2641f6d7a35e8c4f4ed6a782184f1b27c0c69d29d721a653730a4b9719bb7')}
        # Derived from complete parent-frozen 6e30d03 source; independent of checkout history.
        for c in (w.ADMISSION,w.DEDUP):
            for value,expected in zip((c._asdict(),w.plan(c),w.binding(c)),goldens[c.id]):
                self.assertEqual(hashlib.sha256(w.ds.encoded(value)).hexdigest(),expected)

    def test_old_owner_golden_shape_and_values(self):
        expected = {'admission':'9c9ae5d03263bcc5f3e401ff06eff502be9b281057d392ffeb76413897cb6856',
                    'dedup-classified':'4f9161c460b2fd369f878c30a7ef0a10db89b327018e39122c995a0ddc0dd2f8'}
        for c in (w.ADMISSION,w.DEDUP):
            args=argparse.Namespace(contract=c.id,command='build',expected_suite='a'*40,core='core')
            value=w.owner(args,Path('golden'))
            # Normalize only host paths, hosted IDs and checkout EOL-dependent file hash.
            for key in ('core','owner','attempt','plan_sha256'):value[key]='<'+key+'>'
            self.assertEqual(hashlib.sha256(w.ds.encoded(value)).hexdigest(),expected[c.id])

    def test_schedule(self):
        rows=b.schedule()
        self.assertEqual(len(rows),40)
        self.assertEqual([r['index'] for r in rows],list(range(40)))
        self.assertEqual([r['arm'] for r in rows[:4]],list('ABBA'))
        self.assertEqual(len({(r['case'],r['security'],r['order'],r['arm']) for r in rows}),40)
        self.assertEqual(sum(len(next(c for c in b.contract()['cases'] if c['id']==r['case'])['labels'])*1000 for r in rows),72000)

    def test_binding_rejects_self_rehashed_foreign_and_purpose(self):
        p='stage-b-regression'; value=b.bound({},p)
        for key,val in [('contract_id','admission'),('contract_sha256','0'*64),('purpose','stage-b-qualification')]:
            with self.subTest(key=key),self.assertRaises(ValueError): b.check(dict(value,**{key:val}),p)


class ProtocolTests(unittest.TestCase):
    def test_all_cells_and_terse_formats(self):
        for row in b.schedule()[::4]:
            value=native(row);name='stage_b::'+row['case']+'_'+row['security']
            for crlf in (False,True):
                self.assertEqual(b.parse_result(w,output(value,crlf=crlf),name),value)

    def test_exact_all_fields(self):
        value=native()
        for key in value:
            bad=copy.deepcopy(value);del bad[key]
            with self.subTest(key=key),self.assertRaises(ValueError): b.validate_native(bad,b.schedule()[0])
        with self.assertRaises(ValueError): b.validate_native(dict(value,extra=0),b.schedule()[0])

    def test_nested_types_counts_arrays_memory(self):
        for path,val in [(('operations',),True),(('contract','operations'),999),(('metrics','observe_notify'),True),
                         (('settled','io_empty'),1),(('latencies_ns','poll'),[0]*1000),
                         (('latencies_ns','poll'),[True]*1000),(('latencies_ns','poll'),[30_000_000_001]*1000),
                         (('calibration_ns',),[0]*4095),(('clock_ms',),[0,1]),
                         (('memory','fixture_total_requested_bytes'),262145),(('memory','latency_bytes'),1),
                         (('memory','app_pool_requested_heap_bytes'),1),(('internal_datagrams',),1)]:
            bad=native();parent=bad
            for key in path[:-1]:parent=parent[key]
            parent[path[-1]]=val
            with self.subTest(path=path),self.assertRaises(ValueError): b.validate_native(bad,b.schedule()[0])

    def test_oscore_sequences(self):
        row=b.schedule()[4];good=native(row)
        for path,val in [('app',[1,100]),('peer',[0,11281]),('fresh_app',True),('fresh_peer',100),('max_piv_bytes',3),('extra',0)]:
            bad=copy.deepcopy(good);bad['sender_sequences'][path]=val
            with self.subTest(path=path),self.assertRaises(ValueError):b.validate_native(bad,row)

    def test_qualification_census_and_no_timings(self):
        for name in b.contract()['native_validation_tests']:
            for crlf in (False,True):
                self.assertEqual(b.parse_result(w,output(qual(name),True,crlf),name,True),qual(name))
            bad=qual(name);bad['latencies_ns']=[]
            with self.assertRaises(ValueError):b.parse_result(w,output(bad,True),name,True)

    def test_output_refusals(self):
        raw=output(native());name='stage_b::rx_unprotected'
        for bad in [raw+raw,raw[:raw.index(b'\n.\n')],raw.replace(b'1 passed',b'0 passed'),raw.replace(b'0 failed',b'1 failed'),
                    raw.replace(b'0 ignored',b'1 ignored'),raw+b'panic!',raw+b'test stray ... ok\n',
                    raw.replace(b'\n\nCOAPTIC',b'COAPTIC'),raw.replace(b'\nCOAPTIC',b'\n.COAPTIC'),
                    raw.replace(b'"operations":1000',b'"operations":1000,"operations":1000')]:
            with self.subTest(prefix=bad[:50]),self.assertRaises(ValueError):b.parse_result(w,bad,name)
        for kw in (dict(returncode=1),dict(stderr=b'IO error')):
            with self.assertRaises(ValueError):b.parse_result(w,raw,name,**kw)

    def test_listing_exact_no_duplicates_extras(self):
        names=b.contract()['native_validation_tests']
        raw=('\n'.join(n+': test' for n in names)+'\n\n12 tests, 0 benchmarks\n').encode()
        b.validate_listing(raw,names)
        for bad in (b'',raw+raw,raw.replace(b'12 tests',b'11 tests'),b'foreign: test\n'+raw):
            with self.assertRaises(ValueError):b.validate_listing(bad,names)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='stage-b-tiny-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.exe=self.root/'admission_stage_b-abc.exe';self.pdb=self.exe.with_suffix('.pdb')
        self.exe.write_bytes(b'exe');self.pdb.write_bytes(b'pdb')
        self.artifact=dict(reason='compiler-artifact',target=dict(name=b.ID,kind=['test']),profile=dict(test=True,opt_level='3'),
                           executable=str(self.exe),filenames=[str(self.exe),str(self.pdb)])
    def raw(self,value=None,finished=True):
        return b.encoded(value or self.artifact)+b'\n'+b.encoded(dict(reason='build-finished',success=finished))+b'\n'
    def test_pair_and_command(self):
        self.assertEqual(b.artifact_pair(w,self.raw(),self.root),(self.exe,self.pdb))
        command=b.cargo_command(w,'cargo')
        self.assertIn('--no-run',command);self.assertNotIn('--bin',command)
        self.assertIn(str(w.NATIVE/'servers/Cargo.toml'),command)
    def test_foreign_profile_pdb_duplicate_and_failed_build(self):
        for path,val in [(('target','name'),'bench-core'),(('target','kind'),['bin']),(('profile','test'),False),
                         (('profile','opt_level'),'0'),(('filenames',),[str(self.exe)]),
                         (('filenames',),[str(self.exe),str(self.pdb),str(self.pdb)]),(('executable',),'relative.exe')]:
            bad=copy.deepcopy(self.artifact);p=bad
            for k in path[:-1]:p=p[k]
            p[path[-1]]=val
            with self.subTest(path=path),self.assertRaises((ValueError,TypeError)):b.artifact_pair(w,self.raw(bad),self.root)
        for raw in (self.raw(finished=False),self.raw()+self.raw(),b.encoded(self.artifact)):
            with self.assertRaises(ValueError):b.artifact_pair(w,raw,self.root)
        with self.assertRaises(ValueError):b.artifact_pair(w,self.raw(),self.root/'nested')


class AnalysisTests(unittest.TestCase):
    def test_one_sided_inclusive_and_orientation(self):
        self.assertTrue(b.compare(w,{'A':[100]*1000,'B':[102]*1000})['passed'])
        self.assertFalse(b.compare(w,{'A':[100]*1000,'B':[103]*1000})['passed'])
        self.assertEqual(b.compare(w,{'B':[50]*1000,'A':[100]*1000})['mean_ratio'],.5)
    def test_zero_bool_invalid(self):
        for values in ([0]*1000,[True]*1000,[float('nan')]*1000):
            with self.assertRaises(ValueError):b.compare(w,{'A':values,'B':[1]*1000})
    def test_seed_draw_order_independent_reference(self):
        import random,math
        a=[50+i//50 for i in range(1000)]; bb=[51+i//50 for i in range(1000)]
        rng=random.Random(20261030);ratios=[]
        for _ in range(10000):
            aa=sum(rng.choices(list(range(50,70)),k=20))
            bv=sum(rng.choices(list(range(51,71)),k=20))
            ratios.append(bv/aa)
        self.assertAlmostEqual(b.compare(w,{'B':bb,'A':a})['upper95'],w.quantile(sorted(ratios),.95))


class CampaignTests(unittest.TestCase):
    def run_campaign(self,fail=None):
        args=argparse.Namespace(contract=b.ID,command='all',output='unused')
        spec=b.bound(dict(args=vars(args),prepared_hashes={}),b.purpose(args))
        saved={};calls=[]
        def run(api,budget,binary,name,stem,qualification, *, context=b.ADMISSION):
            calls.append(name)
            if len(calls)==fail:raise OSError('first IO failure')
            row=b.schedule()[len(calls)-1]
            return native(row)
        budget=Mock();budget.root=Path('unused')
        context=Mock();context.__enter__=Mock();context.__exit__=Mock(return_value=False)
        pair={a:{'exe':{'path':a+'.exe'}} for a in 'AB'}
        with patch.object(b,'verify_build',return_value={'artifacts':pair}),patch.object(w,'check_files'), \
             patch.object(w,'Budget',return_value=budget),patch.object(w,'affinity',return_value=context), \
             patch.object(b,'run_native',side_effect=run),patch.object(w.ds,'digest',return_value='a'*64), \
             patch.object(w,'save',side_effect=lambda root,name,v:saved.update({name:v})):
            if fail:
                with self.assertRaises(OSError):b.measure_worker(w,spec)
            else:b.measure_worker(w,spec)
        return calls,saved['result.json']
    def test_full_forty_then_thirtysix_decisions(self):
        calls,result=self.run_campaign()
        self.assertEqual(len(calls),40);self.assertEqual(len(result['comparisons']),36)
        self.assertTrue(result['passed']);self.assertEqual(result['not_run'],[])
    def test_first_failure_census(self):
        calls,result=self.run_campaign(3)
        self.assertEqual(len(calls),3);self.assertEqual(len(result['completed']),2)
        self.assertEqual(len(result['failed_or_incomplete']),1);self.assertEqual(len(result['not_run']),37)
        self.assertEqual(result['comparisons'],[]);self.assertFalse(result['passed'])
    def test_qualification_cannot_authorize_measure(self):
        args=argparse.Namespace(contract=b.ID,command='proof',output='unused')
        with self.assertRaises(ValueError),patch.object(w,'child_command') as launch:
            b.measure_worker(w,b.bound(dict(args=vars(args)),b.purpose(args)))
        launch.assert_not_called()
    def test_reporting_preserves_unresolved_worker_error(self):
        error=WorkerError(['mock'],TimeoutError('deadline'),[RuntimeError('unsettled')],b'',b'',1,None)
        w.report_preserving(error,'receipt',lambda:(_ for _ in ()).throw(OSError('disk full')))
        self.assertTrue(error.cleanup_unresolved)
        self.assertTrue(any('receipt' in note for note in error.__notes__))


class QualificationWorkerTests(unittest.TestCase):
    def test_twelve_separate_qualification_processes_no_timings(self):
        with tempfile.TemporaryDirectory(prefix='stage-b-qual-tiny-') as directory:
            root=Path(directory).resolve();(root/'evidence').mkdir()
            exe=root/'test.exe';pdb=root/'test.pdb';exe.write_bytes(b'e');pdb.write_bytes(b'p')
            calls=[];saved={}
            def child(command,budget,stem,**kw):
                calls.append(command)
                if '--no-run' in command:return b'cargo'
                names=b.contract()['native_validation_tests' if 'stage_b_validation::' in command else 'native_timing_tests']
                return ('\n'.join(n+': test' for n in names)+'\n\n'+str(len(names))+' tests, 0 benchmarks\n').encode()
            def retain(root,source,destination):
                return dict(path=str(source),sha256='a'*64,bytes=1)
            budget=Mock();budget.root=root
            spec=b.bound(dict(root=str(root),arm='A',seconds=400,cargo='mock'), 'stage-b-qualification')
            with patch.object(b,'verify_worker_source'),patch.object(w,'Budget',return_value=budget), \
                 patch.object(w,'child_command',side_effect=child),patch.object(b,'artifact_pair',return_value=(exe,pdb)), \
                 patch.object(w.wp,'retain_file',side_effect=retain),patch.object(w,'artifact_check'), \
                 patch.object(b,'run_native') as run,patch.object(w,'save',side_effect=lambda r,n,v:saved.update({n:v})):
                for stem in ('A-qualification-list','A-timing-list'):(root/'evidence'/(stem+'.stderr')).write_bytes(b'')
                b.cargo_worker(w,spec)
                self.assertEqual(run.call_count,12)
                self.assertEqual([x.args[3] for x in run.call_args_list],b.contract()['native_validation_tests'])
                self.assertTrue(all(x.args[-1] is True for x in run.call_args_list))
                self.assertEqual(sum('--ignored' in c for c in calls),1) # listing only
                self.assertEqual(saved['A-cargo.json']['measurements'],'NOT RUN')

    def test_native_returncode_stderr_receipt_before_success(self):
        with tempfile.TemporaryDirectory(prefix='stage-b-run-tiny-') as directory:
            root=Path(directory);(root/'evidence').mkdir();budget=Mock();budget.root=root
            (root/'evidence/q.stderr').write_bytes(b'')
            with patch.object(w,'child_command',return_value=output(qual(b.contract()['native_validation_tests'][0]),True)), \
                 patch.object(w,'load',return_value=dict(passed=True,returncode=1)):
                with self.assertRaises(ValueError):b.run_native(w,budget,'mock','stage_b_validation::rx_unprotected','q',True)


class PreparedRefusalTests(unittest.TestCase):
    def test_cross_contract_owner_refuses_before_tools_or_native(self):
        args=argparse.Namespace(contract=b.ID,command='all',output='unused',core='core',expected_suite='a'*40)
        for field,value in [('contract_id','admission'),('contract_sha256','0'*64),('purpose','stage-b-qualification')]:
            owned=b.owner(w,args,Path('unused'));owned[field]=value
            with self.subTest(field=field),patch.object(w,'load',return_value=owned),patch.object(w,'child_command') as native_call:
                with self.assertRaises(ValueError):b.verify_build(w,args,Path('unused'))
                native_call.assert_not_called()

    def test_bad_worker_spec_refuses_before_native(self):
        args=argparse.Namespace(contract=b.ID,command='all',output='unused')
        for field,value in [('contract_id','dedup-classified'),('contract_sha256','0'*64),('purpose','stage-b-qualification')]:
            spec=b.bound(dict(args=vars(args),kind='cargo'),'stage-b-regression');spec[field]=value
            with self.subTest(field=field),patch.object(w,'child_command') as native_call:
                with self.assertRaises(ValueError):b.worker(w,spec)
                native_call.assert_not_called()

    def test_contract_self_description_cannot_reauthorize(self):
        value=native();value['contract']['operations']=999
        value['contract_sha256']=hashlib.sha256(b.encoded(value['contract'])).hexdigest()
        with self.assertRaises(ValueError):b.validate_native(value,b.schedule()[0])


class SourceCustodyTests(unittest.TestCase):
    def test_source_tool_config_swap_before_any_child(self):
        self.source_tool_config_swap(b.ADMISSION)

    def test_parser_source_tool_config_swap_before_any_child(self):
        self.source_tool_config_swap(b.PARSER)

    def source_tool_config_swap(self, context):
        with tempfile.TemporaryDirectory(prefix='stage-b-source-tiny-') as directory:
            root=Path(directory).resolve();(root/'evidence').mkdir()
            source=root/'source.rs';source.write_bytes(b'source')
            tool=root/'cargo.exe';tool.write_bytes(b'tool')
            config=root/'config';config.write_bytes(b'config')
            lock=root/'tools/benchmark/native/Cargo.lock';lock.parent.mkdir(parents=True);lock.write_bytes(b'lock')
            args=argparse.Namespace(command='all',contract=context.identifier,output=str(root),core=str(root),expected_suite='a'*40)
            identity=b.contract(context=context)['cores']['A'];p=b.purpose(args, context=context)
            spec=b.bound(dict(args=vars(args),root=str(root),arm='A',cargo=str(tool),flags=w.FLAGS,
                source=b.bound(dict(identity=dict(commit=identity['commit'],tree=identity['tree']),files={'source.rs':w.ds.digest(source)}),p, context=context),
                suite=b.bound(dict(identity=dict(commit='a'*40,tree='b'*40),files={}),p, context=context),
                lock={'selected_sha256':w.ds.digest(lock)},
                tools={'cargo':b.bound(dict(path=str(tool),sha256=w.ds.digest(tool)),p, context=context)},inputs=b.bound({'config_files':{str(config):w.ds.digest(config)}},p, context=context)),p, context=context)
            with patch.object(w,'load',return_value=b.owner(w,args,root, context=context)),patch.object(w.ds,'identity',return_value=spec['source']['identity']), \
                 patch.object(w,'verify_staged_suite'),patch.object(w,'SUITE',root),patch.object(w,'child_command') as child:
                b.verify_worker_source(w,spec, context=context)
                for file in (source,tool,config):
                    before=file.read_bytes();file.write_bytes(b'changed')
                    try:
                        with self.subTest(file=file.name),self.assertRaises(ValueError):b.verify_worker_source(w,spec, context=context)
                    finally:file.write_bytes(before)
                bad=copy.deepcopy(spec);bad['source']['identity']['commit']='0'*40
                with self.assertRaises(ValueError):b.verify_worker_source(w,bad, context=context)
                child.assert_not_called()

    def test_source_contract_canonical_tamper(self):
        raw=b.encoded(b.contract())
        for bad in (raw,raw+b'\r\n',raw.replace(b'"operations":1000',b'"operations":999')+b'\n'):
            with patch.object(Path,'read_bytes',return_value=bad),self.assertRaises(ValueError):b.contract()

    def test_artifact_tamper_uses_existing_byte_and_root_custody(self):
        with tempfile.TemporaryDirectory(prefix='stage-b-pair-tiny-') as directory:
            root=Path(directory).resolve();pair={}
            (root/'evidence/A').mkdir(parents=True)
            for kind in ('exe','pdb'):
                file=root/'evidence/A'/('test.'+kind);file.write_bytes(kind.encode())
                pair[kind]=b.bound(dict(path=str(file),sha256=w.ds.digest(file),bytes=file.stat().st_size),'stage-b-regression')
            w.artifact_check(root,{'A':pair})
            file=Path(pair['pdb']['path']);file.write_bytes(b'tamper')
            with self.assertRaises(ValueError):w.artifact_check(root,{'A':pair})


class OuterRefusalTests(unittest.TestCase):
    def test_hosted_root_must_be_exact_child_before_source_or_native(self):
        with tempfile.TemporaryDirectory(prefix='stage-b-root-tiny-') as directory:
            root=Path(directory).resolve()
            for output_path in (root/'foreign',root/'nested'/b.ROOT,root):
                args=argparse.Namespace(contract=b.ID,command='all',output=str(output_path),core='core',expected_suite='a'*40)
                with self.subTest(root=output_path),patch.object(b.sys,'platform','win32'), \
                     patch.dict(b.os.environ,{'RUNNER_ENVIRONMENT':'github-hosted','RUNNER_TEMP':str(root)}), \
                     patch.object(b.shutil,'which',return_value=None),patch.object(w,'source_gate') as source, \
                     patch.object(w,'child_command') as native_call:
                    with self.assertRaises(ValueError):b.execute(w,args)
                    source.assert_not_called();native_call.assert_not_called()

    def test_unknown_contract_and_cli_overrides_refuse(self):
        for args in (['all','--contract','foreign'],['all','--contract',b.ID,'--operations','1'],
                     ['proof','--contract',b.ID,'--gate','2']):
            with patch.object(w,'execute') as execute,patch('sys.stderr'),self.assertRaises(SystemExit):w.main(args)
            execute.assert_not_called()




class ParserContextTests(unittest.TestCase):
    def test_immutable_allowlist_and_canonical_bytes(self):
        ctx=b.resolve_context('regular-option-parser-regression')
        self.assertEqual(ctx,b.PARSER)
        self.assertEqual(hashlib.sha256(b.encoded(b.contract(context=ctx))).hexdigest(),ctx.sha256)
        with self.assertRaises(AttributeError):ctx.root='foreign'
        for bad in ('foreign',True,None):
            with self.assertRaises(ValueError):b.resolve_context(bad)
        for bad in (ctx._replace(filename='admission_stage_b_contract.json'),
                    ctx._replace(sha256=b.HASH),ctx._replace(test_target='bench-core'),
                    ctx._replace(filename=Path('foreign.json')),ctx._replace(sha256=False)):
            with patch.object(Path,'read_bytes') as read,self.assertRaises(ValueError):b.contract(context=bad)
            read.assert_not_called()
        c=b.contract(context=ctx);c['cores']['A']['commit']='0'*40
        self.assertNotEqual(c,b.contract(context=ctx))

    def test_wall_bridge_and_purpose_isolation(self):
        ctx=b.PARSER;d=w.resolve_contract(ctx.identifier)
        self.assertEqual(w.plan(d),b.contract(context=ctx))
        self.assertEqual(w.binding(d),b.binding(context=ctx))
        self.assertEqual(d.root,ctx.root)
        for command in ('proof','build','measure','all'):
            args=argparse.Namespace(contract=ctx.identifier,command=command)
            expected='parser-regression-qualification' if command=='proof' else 'parser-regression'
            self.assertEqual(w.purpose(args),expected)
            with self.assertRaises(ValueError):b.purpose(args)
        with self.assertRaises(ValueError):b.purpose(argparse.Namespace(contract=b.ID,command='all'),context=ctx)

    def test_frozen_census_schedule_and_raw_totals(self):
        c=b.contract(context=b.PARSER);rows=b.schedule(context=b.PARSER)
        self.assertEqual(len(rows),56)
        self.assertEqual(rows[:40],b.schedule())
        self.assertEqual([r['index'] for r in rows],list(range(56)))
        self.assertEqual(len({(r['case'],r['security'],r['order'],r['arm']) for r in rows}),56)
        self.assertEqual(len(c['native_validation_tests'])*2,32)
        self.assertEqual(len(c['native_timing_tests']),14)
        self.assertEqual(sum(len(next(x for x in c['cases'] if x['id']==r['case'])['labels'])*1000 for r in rows),104000)
        self.assertEqual(len(rows)*4096,229376)
        self.assertEqual(sum(len(case['labels'])*len(c['modes'])*len(c['rounds']) for case in c['cases']),52)
        self.assertEqual([r['arm'] for r in rows[40:44]],list('ABBA'))
        self.assertEqual({r['profile'] for r in rows[40:]},{'SmallDevice','Default'})

    def test_native_all_cells_qualifiers_and_lf_crlf(self):
        ctx=b.PARSER;c=b.contract(context=ctx)
        for row in b.schedule(context=ctx)[::4]:
            name='stage_b::'+row['case']+'_'+row['security'];value=native(row,context=ctx)
            for crlf in (False,True):
                self.assertEqual(b.parse_result(w,output(value,crlf=crlf),name,context=ctx),value)
        for name in c['native_validation_tests']:
            for crlf in (False,True):
                value=qual(name,context=ctx)
                self.assertEqual(b.parse_result(w,output(value,True,crlf),name,True,context=ctx),value)
        self.assertEqual(c['native_schema'],b.contract()['native_schema'])
        self.assertEqual(ctx.qualification_schema,b.QUAL_SCHEMA)
        self.assertNotEqual(ctx.proof_schema,b.QUAL_SCHEMA)

    def test_long_case_actual_ledger_and_counts_are_required(self):
        row=b.schedule(context=b.PARSER)[40];good=native(row,context=b.PARSER)
        self.assertEqual(good['memory']['latency_bytes'],32000)
        self.assertEqual(good['memory']['token_ledger_bytes'],0)
        for path,value in [(('memory','latency_bytes'),48000),(('memory','token_ledger_bytes'),27072),
                           (('internal_datagrams',),6769),(('handler_calls',),3383),
                           (('latencies_ns','delta13_len13'),[100]*999),
                           (('latencies_ns','delta14_len269'),[True]*1000),
                           (('metrics','admission_refusal_sent'),1),(('settled','bodies_empty'),False),
                           (('profile',),'Default'),(('operations',),True)]:
            bad=copy.deepcopy(good);target=bad
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):b.validate_native(bad,row,context=b.PARSER)
        bad=copy.deepcopy(good);bad['latencies_ns']['poll']=[100]*1000
        with self.assertRaises(ValueError):b.validate_native(bad,row,context=b.PARSER)

    def test_long_oscore_sequence_budget_and_recovery_counts(self):
        row=b.schedule(context=b.PARSER)[44];good=native(row,context=b.PARSER)
        b.validate_native(good,row,context=b.PARSER)
        for key,value in [('app',[0,1]),('fresh_app',1),('peer',[0,3383]),('fresh_peer',3383),('max_piv_bytes',3)]:
            bad=copy.deepcopy(good);bad['sender_sequences'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):b.validate_native(bad,row,context=b.PARSER)
        with self.assertRaises(ValueError):b.parse_result(w,output(good), 'stage_b::long_small_device_unprotected',context=b.PARSER)

    def test_cross_context_native_and_evidence_rebinding_refuse(self):
        for ctx,other in ((b.PARSER,b.ADMISSION),(b.ADMISSION,b.PARSER)):
            row=b.schedule(context=ctx)[0];value=native(row,context=ctx)
            with self.assertRaises(ValueError):b.validate_native(value,row,context=other)
            for field,replacement in [('contract_sha256',other.sha256),('contract',b.contract(context=other))]:
                bad=copy.deepcopy(value);bad[field]=replacement
                with self.assertRaises(ValueError):b.validate_native(bad,row,context=ctx)
            p=b.contract(context=ctx)['purpose'];record=b.bound({},p,context=ctx)
            for key,replacement in [('contract_id',other.identifier),('contract_sha256',other.sha256),
                                    ('purpose',b.contract(context=ctx)['qualification_purpose'])]:
                with self.assertRaises(ValueError):b.check(dict(record,**{key:replacement}),p,context=ctx)

    def test_new_source_uses_selected_core_not_historical_baseline(self):
        ctx=b.PARSER;c=b.contract(context=ctx)
        core=dict(c['cores']['A']);identity=dict(commit=core['commit'],tree=core['tree'])
        with patch.object(w.ds,'identity',side_effect=[identity,dict(commit='a'*40)]):
            b.source_check(w,'core','a'*40,core['commit'],context=ctx)
        with patch.object(w.ds,'identity') as source,self.assertRaises(ValueError):
            b.source_check(w,'core','a'*40,w.BASELINE,context=ctx)
        source.assert_not_called()
        with patch.object(w.ds,'identity',return_value=dict(commit=core['commit'],tree='f'*40)),self.assertRaises(ValueError):
            b.source_check(w,'core','a'*40,core['commit'],context=ctx)

    def test_new_cargo_target_feature_and_artifact_identity(self):
        ctx=b.PARSER;command=b.cargo_command(w,'cargo',context=ctx)
        self.assertEqual(command[command.index('--test')+1],ctx.test_target)
        self.assertEqual(command[command.index('--features')+1],'admission-stage-b')
        self.assertIn('--no-run',command)
        with tempfile.TemporaryDirectory(prefix='parser-regression-artifact-') as directory:
            root=Path(directory).resolve();exe=root/'test.exe';pdb=exe.with_suffix('.pdb')
            exe.write_bytes(b'e');pdb.write_bytes(b'p')
            value=dict(reason='compiler-artifact',target=dict(name=ctx.test_target,kind=['test']),
                       profile=dict(test=True,opt_level='3'),executable=str(exe),filenames=[str(exe),str(pdb)])
            def raw(v):return b.encoded(v)+b'\n'+b.encoded(dict(reason='build-finished',success=True))+b'\n'
            self.assertEqual(b.artifact_pair(w,raw(value),root,context=ctx),(exe,pdb))
            for name in ('bench-core',b.ID):
                bad=copy.deepcopy(value);bad['target']['name']=name
                with self.assertRaises(ValueError):b.artifact_pair(w,raw(bad),root,context=ctx)
            with self.assertRaises(ValueError):b.artifact_pair(w,raw(value),root)

    def test_worker_wrong_selector_purpose_hash_refuses_before_child(self):
        ctx=b.PARSER;args=argparse.Namespace(contract=ctx.identifier,command='all',output='unused')
        purpose=b.purpose(args,context=ctx)
        for field,value in [('contract_id',b.ID),('contract_sha256',b.HASH),('purpose','parser-regression-qualification')]:
            spec=b.bound(dict(args=vars(args),kind='cargo'),purpose,context=ctx);spec[field]=value
            with patch.object(w,'child_command') as child,self.assertRaises(ValueError):b.worker(w,spec,context=ctx)
            child.assert_not_called()
        spec=b.bound(dict(args=vars(args),kind='measure'),purpose,context=ctx)
        with patch.object(w,'child_command') as child,self.assertRaises(ValueError):b.worker(w,spec)
        child.assert_not_called()

    def test_qualification_cannot_feed_timing(self):
        ctx=b.PARSER;args=argparse.Namespace(contract=ctx.identifier,command='proof',output='unused')
        spec=b.bound(dict(args=vars(args)),b.purpose(args,context=ctx),context=ctx)
        with patch.object(w,'child_command') as child,self.assertRaises(ValueError):b.measure_worker(w,spec,context=ctx)
        child.assert_not_called()

    def test_owner_cross_context_refuses_before_source_or_tools(self):
        ctx=b.PARSER;args=argparse.Namespace(contract=ctx.identifier,command='all',output='unused',core='core',expected_suite='a'*40)
        owned=b.owner(w,args,Path('unused'),context=ctx)
        for key,value in [('contract_id',b.ID),('contract_sha256',b.HASH),('purpose','parser-regression-qualification')]:
            bad=dict(owned,**{key:value})
            with patch.object(w,'load',return_value=bad),patch.object(w,'source_gate') as source,patch.object(w,'child_command') as child:
                with self.assertRaises(ValueError):b.verify_build(w,args,Path('unused'),context=ctx)
                source.assert_not_called();child.assert_not_called()

    def test_sixteen_qualifiers_and_two_listings_no_timing_execution(self):
        ctx=b.PARSER;c=b.contract(context=ctx)
        with tempfile.TemporaryDirectory(prefix='parser-regression-qualification-') as directory:
            root=Path(directory).resolve();(root/'evidence').mkdir()
            exe=root/'test.exe';pdb=root/'test.pdb';exe.write_bytes(b'e');pdb.write_bytes(b'p')
            commands=[];saved={};budget=Mock();budget.root=root
            def child(command,budget,stem,**kw):
                commands.append(command)
                if '--no-run' in command:return b'cargo'
                names=c['native_validation_tests' if 'stage_b_validation::' in command else 'native_timing_tests']
                return ('\n'.join(n+': test' for n in names)+'\n\n'+str(len(names))+' tests, 0 benchmarks\n').encode()
            def retain(root,source,destination):return dict(path=str(source),sha256='a'*64,bytes=1)
            p=c['qualification_purpose'];spec=b.bound(dict(root=str(root),arm='A',seconds=400,cargo='mock'),p,context=ctx)
            for stem in ('A-qualification-list','A-timing-list'):(root/'evidence'/(stem+'.stderr')).write_bytes(b'')
            with patch.object(b,'verify_worker_source'),patch.object(w,'Budget',return_value=budget), \
                 patch.object(w,'child_command',side_effect=child),patch.object(b,'artifact_pair',return_value=(exe,pdb)), \
                 patch.object(w.wp,'retain_file',side_effect=retain),patch.object(w,'artifact_check'), \
                 patch.object(b,'run_native') as run,patch.object(w,'save',side_effect=lambda r,n,v:saved.update({n:v})):
                b.cargo_worker(w,spec,context=ctx)
                self.assertEqual(run.call_count,16)
                self.assertEqual([x.args[3] for x in run.call_args_list],c['native_validation_tests'])
                self.assertTrue(all(x.args[-1] is True and x.kwargs['context']==ctx for x in run.call_args_list))
                self.assertEqual(sum('--ignored' in x for x in commands),1)
                self.assertEqual(saved['A-cargo.json']['timing_tests'],c['native_timing_tests'])
                b.check(saved['A-cargo.json'],p,context=ctx)

    def test_proof_summary_is_source_specific_thirtytwo_no_measurement(self):
        ctx=b.PARSER
        with tempfile.TemporaryDirectory(prefix='parser-regression-proof-') as directory:
            parent=Path(directory).resolve();root=parent/ctx.root;saved={}
            args=argparse.Namespace(contract=ctx.identifier,command='proof',output=str(root),core='core',expected_suite='a'*40)
            with patch.object(b.sys,'platform','win32'),patch.dict(b.os.environ,{'RUNNER_ENVIRONMENT':'github-hosted','RUNNER_TEMP':str(parent)}), \
                 patch.object(b.shutil,'which',return_value=None),patch.object(w,'preflight',return_value={}), \
                 patch.object(w,'source_gate') as source,patch.object(b,'build'),patch.object(b,'verify_build'), \
                 patch.object(w,'save',side_effect=lambda r,n,v:saved.update({n:v})),patch.object(w,'launch') as launch:
                b.execute(w,args,context=ctx)
                value=saved['proof-complete.json']
                self.assertEqual(value['qualification_executions'],32)
                self.assertEqual(value['schema'],ctx.proof_schema)
                self.assertEqual(value['measurements'],'NOT RUN')
                b.check(value,'parser-regression-qualification',context=ctx)
                self.assertEqual(source.call_args.args[2],b.contract(context=ctx)['cores']['A']['commit'])
                launch.assert_not_called()


class ParserCampaignTests(unittest.TestCase):
    def campaign(self,fail=None,reject_gate=False):
        ctx=b.PARSER;args=argparse.Namespace(contract=ctx.identifier,command='all',output='unused')
        spec=b.bound(dict(args=vars(args),prepared_hashes={}),b.purpose(args,context=ctx),context=ctx)
        saved={};calls=[];compared=[];rows=b.schedule(context=ctx)
        def run(api,budget,binary,name,stem,qualification,*,context):
            self.assertEqual(context,ctx);calls.append(name)
            if len(calls)==fail:raise OSError('selected IO failure')
            return native(rows[len(calls)-1],context=ctx)
        original=b.compare
        def compare(api,arms):
            self.assertEqual(len(calls),56)
            compared.append(len(compared))
            if reject_gate:return dict(mean_ratio=1.,upper95=1.03 if len(compared)==1 else 1.,passed=len(compared)!=1,orientation='B/A')
            return original(api,arms)
        budget=Mock();budget.root=Path('unused')
        context_manager=Mock();context_manager.__enter__=Mock();context_manager.__exit__=Mock(return_value=False)
        pair={a:{'exe':{'path':a+'.exe'}} for a in 'AB'}
        with patch.object(b,'verify_build',return_value={'artifacts':pair}),patch.object(w,'check_files'), \
             patch.object(w,'Budget',return_value=budget),patch.object(w,'affinity',return_value=context_manager), \
             patch.object(b,'run_native',side_effect=run),patch.object(w.ds,'digest',return_value='a'*64), \
             patch.object(b,'compare',side_effect=compare),patch.object(w,'save',side_effect=lambda root,name,v:saved.update({name:v})):
            if fail or reject_gate:
                with self.assertRaises((OSError,ValueError)):b.measure_worker(w,spec,context=ctx)
            else:b.measure_worker(w,spec,context=ctx)
        return calls,compared,saved['result.json']

    def test_fiftysix_then_fiftytwo_separate_decisions(self):
        calls,compared,result=self.campaign()
        self.assertEqual(len(calls),56);self.assertEqual(len(compared),52)
        self.assertTrue(result['passed']);self.assertEqual(result['not_run'],[])
        self.assertEqual(len(result['completed']),56)
        self.assertEqual(result['schema'],b.contract(context=b.PARSER)['schema'])
        self.assertEqual([x['label'] for x in result['comparisons'][-4:]],['delta13_len13','delta14_len269']*2)
        b.check(result,'parser-regression',context=b.PARSER)

    def test_failure_has_actual_prefix_no_comparisons_or_success(self):
        calls,compared,result=self.campaign(fail=3)
        self.assertEqual(len(calls),3);self.assertEqual(compared,[])
        self.assertEqual(len(result['completed']),2)
        self.assertEqual(len(result['failed_or_incomplete']),1)
        self.assertEqual(len(result['not_run']),53)
        self.assertFalse(result['passed'])

    def test_gate_rejection_keeps_every_process_and_decision(self):
        calls,compared,result=self.campaign(reject_gate=True)
        self.assertEqual((len(calls),len(compared)),(56,52))
        self.assertEqual((len(result['completed']),len(result['comparisons'])),(56,52))
        self.assertEqual(result['not_run'],[]);self.assertFalse(result['passed'])


class ParserCompatibilityTests(unittest.TestCase):
    # Derived from exact acdcd003 source in RAM; CI needs no old Git history.
    def test_compare_ast_is_exact_historical_function(self):
        import ast
        source=Path(b.__file__).read_text()
        fn=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='compare')
        self.assertEqual(hashlib.sha256(ast.dump(fn,include_attributes=False).encode()).hexdigest(),
                         '65e586d30ec613a218978c5c09cfb9c4d399002051bbd88877ff4f4ccaca8729')

    def test_default_admission_stage_b_outputs_match_immutable_source(self):
        expected={'contract': '161b7fd033cd7c2cc37b203f878b4307de913e2da2b651bacdbe9e84c186a83c', 'binding': '0dde4195ee8374f033993ca6206b7caeb3047fcefdb59b498c93c50fdcae9b5a', 'schedule': 'dd7d6c5d742c6568ef48f86ed443befafdd52a2a53e4a7ac8726808a1d5964c7', 'descriptor': '965beb22497b497eb5a0c7d78dc540dc93d480da846257628976b534155661d7', 'owner': {'all': '431e69ae3156e69b87d3cfed57084edcb9b75a365df94f5e8ed2821d0388b4a9', 'proof': '518776f90109e4f4c2b4f754aa0274c5f222ef931022acda18bf9c9a79fc450a', 'build': '431e69ae3156e69b87d3cfed57084edcb9b75a365df94f5e8ed2821d0388b4a9', 'measure': '431e69ae3156e69b87d3cfed57084edcb9b75a365df94f5e8ed2821d0388b4a9'}, 'cargo': '1a52fe3b83809f0ea7dd9fd4af3fa490146651f9396f2ca2ba8503639f884146', 'compare': '991124144e3e38e1943354324e89c65ad1a6d125d056c8d7a7fc41b25c851247'}
        def digest(value):return hashlib.sha256(b.encoded(value)).hexdigest()
        def normalize(value):
            value=dict(value)
            for key in ('core','root','owner','attempt','plan_sha256'):
                if key in value:value[key]='<'+key+'>'
            return value
        self.assertEqual(digest(b.contract()),expected['contract'])
        self.assertEqual(digest(b.binding()),expected['binding'])
        self.assertEqual(digest(b.schedule()),expected['schedule'])
        self.assertEqual(digest(b.descriptor(w)._asdict()),expected['descriptor'])
        for command,sha in expected['owner'].items():
            args=argparse.Namespace(contract=b.ID,command=command,expected_suite='a'*40,core='core')
            self.assertEqual(digest(normalize(b.owner(w,args,Path('old-golden')))),sha)
        command=b.cargo_command(w,'cargo');command[command.index('--manifest-path')+1]='<manifest>'
        self.assertEqual(digest(command),expected['cargo'])
        self.assertEqual(digest(b.compare(w,{'A':[99]*1000,'B':[100]*1000})),expected['compare'])


if __name__=='__main__':unittest.main()
