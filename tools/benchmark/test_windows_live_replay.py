"""Portable bounded mocks/synthetic ZIPs only; no download, tool or workload."""
import argparse
from collections import Counter
import copy
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error
import zipfile

import windows_live_replay as r


def temporary():
    return tempfile.TemporaryDirectory(prefix='live-replay-test-', dir=Path(__file__).parent)


def encoded(value):
    return json.dumps(value, ensure_ascii=True).encode('utf-8')


def fixture():
    pins = copy.deepcopy(r.load_pins())
    selected = {'binaries/bench-core.exe': b'exe', 'binaries/bench_core.pdb': b'pdb'}
    native = dict(path=pins['cohorts'][0]['capture']['config']['exe'],
                  pdb=pins['cohorts'][0]['capture']['config']['pdb'],
                  sha256=r.sha(b'exe'), pdb_sha256=r.sha(b'pdb'), bytes=3, pdb_bytes=3)
    for c in pins['cohorts']:
        name = c['name']
        etl = ('ETL-' + name).encode()
        for cfg in (c['capture']['config'], c['original_config']):
            cfg.update(exe_sha256=r.sha(b'exe'), pdb_sha256=r.sha(b'pdb'))
        c['capture']['image'].update(exe_sha256=r.sha(b'exe'), pdb_sha256=r.sha(b'pdb'))
        c['capture'].update(etl_sha256=r.sha(etl), etl_bytes=len(etl))
        selected[name + '/capture.etl'] = etl
        selected[name + '/capture.json'] = encoded(c['capture'])
        selected[name + '/config.json'] = encoded(c['original_config'])
    selected['build.json'] = encoded(dict(sources=pins['original_sources'], native=native))
    original, _ = profiles(pins['cohorts'][0])
    selected['unprotected-capture-00/profile.json'] = encoded(original)
    pins['selected_members'] = list(selected)
    pins['members'] = [dict(path=k, bytes=len(v), sha256=r.sha(v)) for k, v in selected.items()]
    return pins, selected


def repin(pins, selected, name, value):
    selected[name] = encoded(value)
    pin = next(p for p in pins['members'] if p['path'] == name)
    pin.update(bytes=len(selected[name]), sha256=r.sha(selected[name]))


def profiles(cohort):
    app = 'coaptic::app::poll_engine<complete-symbol>'
    paths = [('root', app, 'leaf'), ('root', app, 'leaf'),
             ('root', app, app, 'leaf'), ('root;delimiter', '[unresolved]', 'leaf;delimiter')]
    original = dict(schema='coaptic-stack-profile/1', identity=cohort['capture']['config']['identity'],
                    measurement=dict(kind='sampled_cpu', unit='samples'),
                    scope=dict(pid=cohort['capture']['config']['pid'], tid=cohort['capture']['config']['tid'],
                               label=cohort['capture']['config']['label'], cpu_mode='unknown'),
                    quality=dict(lost=0, refused=0, unresolved=1, notes='unknown unwind; diagnostic'),
                    totals=dict(samples=len(paths), weight=len(paths)), stacks=[])
    for frames in paths:
        original['stacks'].append(dict(frames=list(frames), samples=1, weight=1,
            event=dict(comm='bench-core', timestamp='1.000000000', period=1, name='SampledProfile',
                       addresses=['1'] * len(frames), dsos=['module'] * len(frames))))
    projected = copy.deepcopy(original)
    projected['quality']['notes'] = r.PROJECTION_NOTES
    projected['stacks'] = [dict(frames=list(path), weight=n, samples=n)
                           for path, n in Counter(paths).items()]
    return original, projected


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compression) as z:
        for name, raw in entries:
            z.writestr(name, raw)
    return out.getvalue()


def zip_pins(pins, entries, raw):
    pins = copy.deepcopy(pins)
    pins.update(zip_bytes=len(raw), zip_sha256=r.sha(raw), member_count=len(entries),
                expanded_bytes=sum(len(v) for _, v in entries),
                members=[dict(path=k, bytes=len(v), sha256=r.sha(v)) for k, v in entries])
    return pins


def metadata(pins):
    return dict(id=pins['artifact_id'], name=pins['artifact_name'], size_in_bytes=pins['zip_bytes'],
                digest='sha256:' + pins['zip_sha256'], expired=False,
                workflow_run=dict(id=pins['run_id'], head_sha=pins['original_sources']['suite']['commit']))


class Response(io.BytesIO):
    status = 200


class Tests(unittest.TestCase):
    def test_source_pins_fixed_and_old_route_untouched(self):
        p = r.load_pins()
        self.assertEqual((p['run_id'], p['run_attempt'], p['artifact_id']), (41038109816, 1, 12969046956))
        self.assertEqual((p['zip_bytes'], p['expanded_bytes'], p['member_count']), (6179117, 52995829, 62))
        self.assertEqual(p['cohorts'][0]['expected_original'], dict(samples=3164, app=1633, frames=42573,
                                                                  paths=332, symbols=341, unresolved=11260))
        self.assertEqual(r.old.RUN_ID, 41013864895)
        self.assertEqual(r.old.MEMBER_LIMIT, 16 * 1024**2)
        self.assertEqual(p['cohorts'][1]['capture']['config']['process_start_utc'],
                         '2026-10-30T10:12:01.671394+00:00')
        self.assertEqual(p['cohorts'][1]['original_config']['process_start_utc'],
                         '2026-10-30T10:12:01.6713940Z')

    def test_source_pin_hash_refusal_before_any_write(self):
        with patch.object(r, 'PINS_SHA256', '0' * 64), patch.object(r.old, 'fresh_root') as create:
            with patch.object(r.w, 'hosted_preflight'), self.assertRaises(ValueError):
                r.execute(SimpleNamespace())
            create.assert_not_called()

    def test_literal_receipt_config_build_and_root(self):
        p, selected = fixture()
        r.receipt_inputs(selected, p, p['original_root'])
        with self.assertRaises(ValueError): r.receipt_inputs(selected, p, 'D:/relocated')
        cases = [('pid', 1), ('tid', True), ('process_start_utc', '2026-10-30T10:11:33.265468Z'),
                 ('directory', 'D:\\other'), ('capture_id', '0' * 36)]
        for key, value in cases:
            pins, inputs = fixture()
            raw = copy.deepcopy(pins['cohorts'][0]['capture'])
            raw['config'][key] = value
            repin(pins, inputs, r.COHORTS[0] + '/capture.json', raw)
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.receipt_inputs(inputs, pins, pins['original_root'])
        for key, value in [('stopped', 1), ('start_qpc', 0), ('stop_qpc', 2), ('qpc_frequency', -1),
                           ('module_base_address', '0'), ('session_name', 'other')]:
            pins, inputs = fixture(); raw = copy.deepcopy(pins['cohorts'][0]['capture']); raw[key] = value
            repin(pins, inputs, r.COHORTS[0] + '/capture.json', raw)
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.receipt_inputs(inputs, pins, pins['original_root'])
        pins, inputs = fixture(); raw = copy.deepcopy(pins['cohorts'][0]['capture'])
        raw['image']['pdb_guid'] = '0' * 36
        repin(pins, inputs, r.COHORTS[0] + '/capture.json', raw)
        with self.assertRaises(ValueError): r.receipt_inputs(inputs, pins, pins['original_root'])

    def test_selected_byte_hash_missing_and_extra_refused(self):
        pins, inputs = fixture()
        for mutate in (lambda x: x.pop('build.json'), lambda x: x.update(extra=b'x'),
                       lambda x: x.update({'binaries/bench-core.exe': b'bad'})):
            changed = dict(inputs); mutate(changed)
            with self.assertRaises(ValueError): r.verify_buffers(changed, pins)

    def test_metadata_all_pins_and_types(self):
        pins = r.load_pins(); r.validate_metadata(metadata(pins), pins)
        for key, value in [('id', True), ('id', 1), ('size_in_bytes', 1), ('digest', 'bad'),
                           ('name', 'other'), ('expired', True)]:
            m = metadata(pins); m[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): r.validate_metadata(m, pins)
        m = metadata(pins); m['workflow_run']['head_sha'] = '0' * 40
        with self.assertRaises(ValueError): r.validate_metadata(m, pins)

    def test_redirect_strips_auth_and_never_logs_SAS(self):
        p = r.load_pins(); raw = b'zip'; p.update(zip_bytes=3, zip_sha256=r.sha(raw))
        location = 'https://x.blob.core.windows.net/a?SAS=DO_NOT_LOG'
        def opener(final):
            value = Mock()
            value.open.side_effect = [Response(encoded(metadata(p))),
                urllib.error.HTTPError(r.API, 302, 'found', {'Location': location}, None), final]
            return value
        op = opener(Response(raw))
        self.assertEqual(r.download(Mock(), 'SECRET', p, op)[1], raw)
        self.assertEqual([c.args[0].get_header('Authorization') for c in op.open.call_args_list],
                         ['Bearer SECRET', 'Bearer SECRET', None])
        op = opener(urllib.error.HTTPError(location, 302, 'again', {'Location': location}, None))
        with self.assertRaises(ValueError) as caught: r.download(Mock(), 'SECRET', p, op)
        self.assertNotIn('DO_NOT_LOG', str(caught.exception)); self.assertNotIn('SECRET', str(caught.exception))
        self.assertEqual(op.open.call_count, 3)
        for bad in ['http://x.blob.core.windows.net/a', 'https://evil.test/a',
                    'https://user@x.blob.core.windows.net/a', 'https://x.blob.core.windows.net:444/a']:
            with self.subTest(url=bad), self.assertRaises(ValueError): r.old.signed_location(bad)

    def test_download_metadata_failure_no_zip_and_byte_refusal(self):
        p = r.load_pins(); op = Mock(); op.open.return_value = Response(encoded(dict(metadata(p), id=1)))
        with self.assertRaises(ValueError): r.download(Mock(), 'token', p, op)
        self.assertEqual(op.open.call_count, 1)
        with self.assertRaises(ValueError): r.download(Mock(), 'bad\ntoken', p, op)
        with self.assertRaises(ValueError): r.old.bounded_read(Response(b'1234'), 3, Mock())
        with self.assertRaises(TimeoutError):
            r.old.bounded_read(Response(b'x'), 3, Mock(check=Mock(side_effect=TimeoutError())))

    def test_zip_streams_all_members_and_selects_only_pins(self):
        p, inputs = fixture(); entries = list(inputs.items()) + [('discarded.log', b'ignored')]
        raw = zip_bytes(entries); p = zip_pins(p, entries, raw)
        selected, manifest = r.inspect_zip(raw, Mock(), p)
        self.assertEqual(selected, inputs); self.assertEqual(len(manifest), len(entries))
        self.assertEqual(manifest[-1]['sha256'], r.sha(b'ignored'))

    def test_zip_header_duplicate_path_digest_size_CRC_refusals(self):
        p, inputs = fixture(); entries = list(inputs.items())
        for extra in [('build.json', b'duplicate'), ('../escape', b'x'), ('binaries', b'prefix'),
                      ('BUILD.JSON', b'case')]:
            rows = entries + [extra]
            raw = zip_bytes(rows)
            with self.subTest(extra=extra[0]), self.assertRaises(ValueError):
                r.inspect_zip(raw, Mock(), zip_pins(p, rows, raw))
        raw = zip_bytes(entries); pins = zip_pins(p, entries, raw)
        for damaged in [raw[:-1], b'BAD!' + raw[4:]]:
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                r.inspect_zip(damaged, Mock(), pins)
        pins['zip_sha256'] = '0' * 64
        with self.assertRaises(ValueError): r.inspect_zip(raw, Mock(), pins)
        # A real local member CRC failure, despite matching outer ZIP digest.
        rows = [('binaries/bench-core.exe', b'exe')]
        raw = bytearray(zip_bytes(rows, zipfile.ZIP_STORED)); n, e = struct.unpack_from('<HH', raw, 26)
        raw[30+n+e] ^= 1
        pins = zip_pins(p, rows, bytes(raw)); pins['selected_members'] = [rows[0][0]]
        with self.assertRaises(zipfile.BadZipFile): r.inspect_zip(bytes(raw), Mock(), pins)

    def test_live_large_ETL_exact_size_without_old_constant_mutation(self):
        info = zipfile.ZipInfo('oscore-capture-00/capture.etl')
        info.file_size = 17563648; info.compress_size = 1024**2
        self.assertEqual(r.live_member_name(info, dict(bytes=17563648)), info.filename)
        self.assertEqual(info.file_size, 17563648); self.assertEqual(r.old.MEMBER_LIMIT, 16777216)
        with self.assertRaises(ValueError): r.live_member_name(info, dict(bytes=1))
        for change in [('flag_bits', 1), ('external_attr', stat.S_IFLNK << 16),
                       ('filename', 'a/../b'), ('compress_type', zipfile.ZIP_BZIP2)]:
            probe = copy.copy(info); setattr(probe, *change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                r.live_member_name(probe, dict(bytes=17563648))

    def test_exact_equivalence_with_recursion_and_delimiters(self):
        original, projected = profiles(r.load_pins()['cohorts'][0])
        proof = r.equivalence(original, projected)
        self.assertTrue(proof['passed']); self.assertEqual(proof['exact_full_paths'], 3)
        self.assertEqual(proof['app_ancestry_samples'], 3)
        counts = r.projection_counts(projected, projected=True)
        app = 'coaptic::app::poll_engine<complete-symbol>'
        self.assertEqual(counts['symbols'][app], [0, 3])  # Recursive inclusive once per path.
        self.assertEqual(counts['prefixes'][('root', app, app)], 1)

    def test_equivalence_counterexamples_not_scalar_only(self):
        original, projected = profiles(r.load_pins()['cohorts'][0])
        mutations = [lambda p: p['stacks'][1]['frames'].reverse(),
                     lambda p: p['stacks'][1]['frames'].__setitem__(2, 'different-root'),
                     lambda p: p['stacks'][2]['frames'].__setitem__(0, 'root;different'),
                     lambda p: p['scope'].update(tid=1),
                     lambda p: p['identity'].update(cohort='other'),
                     lambda p: p['quality'].update(lost=1),
                     lambda p: p['quality'].update(refused=-1),
                     lambda p: p['stacks'][0].update(weight=1),
                     lambda p: p['stacks'][0].update(samples=True)]
        for mutate in mutations:
            p = copy.deepcopy(projected); mutate(p)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError): r.equivalence(original, p)
        p = copy.deepcopy(projected)
        p['stacks'][0]['frames'] = ['root;coaptic::app::poll_engine<complete-symbol>', 'leaf']
        with self.assertRaises(ValueError): r.equivalence(original, p)

    def test_duplicate_aggregate_event_and_negative_quality_refused(self):
        original, p = profiles(r.load_pins()['cohorts'][0])
        p['stacks'][0]['event'] = original['stacks'][0]['event']
        with self.assertRaises(ValueError): r.projection_counts(p, projected=True)
        _, p = profiles(r.load_pins()['cohorts'][0])
        p['stacks'].append(copy.deepcopy(p['stacks'][0])); p['totals'].update(samples=6, weight=6)
        with self.assertRaises(ValueError): r.projection_counts(p, projected=True)
        for key in ['lost', 'refused', 'unresolved']:
            _, p = profiles(r.load_pins()['cohorts'][0]); p['quality'][key] = -1
            with self.assertRaises(ValueError): r.projection_counts(p, projected=True)
        _, p = profiles(r.load_pins()['cohorts'][0]); p['quality']['notes'] = 'undisclosed projection'
        with self.assertRaises(ValueError): r.projection_counts(p, projected=True)

    def test_export_config_is_explicit_projection_original_input_and_fresh_output(self):
        p = r.load_pins(); root = Path(p['original_root']); c = p['cohorts'][0]
        cfg = r.export_config(root, c)
        self.assertIs(cfg['aggregate_exact_paths'], True)
        self.assertEqual(cfg['capture_receipt'], c['capture_receipt_path'])
        self.assertIn('evidence', cfg['output']); self.assertIn('live-replay', cfg['output'])
        self.assertIn('conversion-replay', cfg['scratch_directory'])
        self.assertEqual((cfg['max_etl_bytes'], cfg['max_conversion_bytes']), (128*1024**2, 256*1024**2))

    def test_materialization_and_final_preservation(self):
        pins, selected = fixture()
        with temporary() as tmp:
            root = Path(tmp); (root/'evidence').mkdir(); attempted = []
            r.materialize(root, selected, pins, attempted)
            r.verify_materialized(root, pins, attempted)
            with self.assertRaises(FileExistsError): r.materialize(root, selected, pins, [])
            (root/'evidence/binaries/bench-core.exe').write_bytes(b'bad')
            with self.assertRaises(ValueError): r.verify_materialized(root, pins, attempted)

    def export_fixture(self, *, receipt_change=None, profile_change=None, renderer_failure=False,
                       control=True):
        pins, selected = fixture()
        c = pins['cohorts'][0 if control else 1]
        original, projected = profiles(c)
        c['expected_original'] = (dict(samples=4, app=3, frames=13, paths=3, symbols=6, unresolved=1)
                                  if control else None)
        # Derive the fixture census independently of the code under test.
        if control:
            c['expected_original']['symbols'] = len(set(f for x in original['stacks'] for f in x['frames']))
            repin(pins, selected, c['name'] + '/profile.json', original)
        if profile_change: profile_change(projected)
        with temporary() as tmp:
            root = Path(tmp); (root/'evidence').mkdir()
            r.materialize(root, selected, pins, [])
            commands = []
            def command(argv, budget, log, **_):
                commands.append(argv)
                cfg = json.loads(Path(argv[-1]).read_text())
                r.w.save(Path(cfg['output']), projected)
                capture = c['capture']; original_cfg = capture['config']
                rec = dict(schema='coaptic-windows-stack-export/1',capture_id=original_cfg['capture_id'],
                    capture_receipt_sha256=r.w.digest(root/'evidence'/c['name']/'capture.json'),
                    etl_sha256=capture['etl_sha256'],image=capture['image'],
                    module_base_address=capture['module_base_address'],module_size=capture['module_size'],
                    window_start_qpc=capture['start_qpc'],window_stop_qpc=capture['stop_qpc'],
                    output_sha256=r.w.digest(cfg['output']),output_bytes=Path(cfg['output']).stat().st_size,
                    total_samples=4,unresolved_frame_occurrences=1,lost=0,
                    depth_truncated_samples=0,conversion_truncated=False)
                rec['projection']=dict(aggregate_exact_paths=True,kind='exact-full-symbol-paths',
                    notes=r.PROJECTION_NOTES,identity=original_cfg['identity'],pid=original_cfg['pid'],
                    tid=original_cfg['tid'],qpc_frequency=capture['qpc_frequency'],raw_samples=4,
                    output_distinct_rows=3,raw_frame_occurrences=13,weighted_output_frame_occurrences=13,
                    app_ancestry_samples=3,unresolved_frame_occurrences=1,total_samples=4,total_weight=4,
                    depth_truncated_samples=0,totals_conserved=True)
                if receipt_change:receipt_change(rec)
                r.w.save(Path(cfg['output']+'.receipt.json'), rec)
            with patch.object(r.w,'command',side_effect=command), \
                 patch.object(r.s,'render_html',side_effect=ValueError('HTML output too large')
                              if renderer_failure else None,return_value='<body>flame</body>'):
                try:
                    outcome = r.export_one(['dotnet','tool'],{},root,Mock(),c)
                except ValueError:
                    if not (receipt_change or profile_change or renderer_failure):raise
                    proof = root/'evidence/live-replay'/c['name']/'equivalence.json'
                    return None, json.loads(proof.read_text()) if proof.exists() else None, commands
                return outcome, json.loads((root/'evidence/live-replay'/c['name']/'equivalence.json').read_text()) \
                    if control else None, commands

    def test_export_success_equivalence_and_protected_no_control(self):
        outcome, proof, commands = self.export_fixture()
        self.assertTrue(proof['passed']);self.assertEqual(outcome['samples'],4)
        self.assertFalse(outcome['qualification']['qualified']);self.assertEqual(len(commands),1)
        self.assertEqual(commands[0][:3],['dotnet','tool','export'])
        outcome, proof, _ = self.export_fixture(control=False)
        self.assertIsNone(proof);self.assertIn('no original protected',outcome['equivalence'])

    def test_export_receipt_and_profile_tampering_refuse(self):
        for key,value in [('total_samples',3),('unresolved_frame_occurrences',0),('output_sha256','bad'),
                          ('capture_receipt_sha256','bad'),('window_stop_qpc',1),('capture_id','other'),
                          ('output_bytes',True)]:
            with self.subTest(key=key):
                outcome,_,_=self.export_fixture(receipt_change=lambda r,k=key,v=value:r.update({k:v}))
                self.assertIsNone(outcome)
        outcome,proof,_=self.export_fixture(profile_change=lambda p:p['stacks'][1]['frames'].reverse())
        self.assertIsNone(outcome);self.assertFalse(proof['passed'])
        for key,value in [('raw_samples',3),('raw_frame_occurrences',12),('total_weight',3),
                          ('app_ancestry_samples',4),('output_distinct_rows',4),('totals_conserved',1),
                          ('qpc_frequency',1),('aggregate_exact_paths',False),('notes','no disclosure')]:
            with self.subTest(projection_key=key):
                outcome,_,_=self.export_fixture(receipt_change=lambda row,k=key,v=value:
                                                row['projection'].update({k:v}))
                self.assertIsNone(outcome)

    def test_HTML_refusal_keeps_successful_equivalence_no_fallback(self):
        outcome,proof,commands=self.export_fixture(renderer_failure=True)
        self.assertIsNone(outcome);self.assertTrue(proof['passed']);self.assertEqual(len(commands),1)

    def phase(self, stage, *, tamper=False):
        pins, selected = fixture()
        with temporary() as tmp:
            root = Path(tmp); (root/'evidence').mkdir()
            budget = SimpleNamespace(peak=0, observed_child_working_set_peak=0, check=Mock(), rss_limit=4*1024**3)
            args = SimpleNamespace(core='unused', expected_core='core', expected_suite='suite')
            primary = ValueError('exact primary refusal')
            def build(*_):
                if tamper: (root/'evidence/binaries/bench-core.exe').write_bytes(b'bad')
                if stage == 'build': raise primary
                return ['dotnet', 'tool'], {}, dict(files=[])
            with patch.object(r.w, 'source_identity', return_value={'clean': True}), \
                 patch.object(r, 'load_pins', return_value=pins), \
                 patch.object(r, 'download', side_effect=primary if stage=='download' else None,
                              return_value=({}, b'zip')), \
                 patch.object(r, 'inspect_zip', return_value=(selected, [])), \
                 patch.object(r, 'receipt_inputs', return_value={}), \
                 patch.object(r.old, 'build_tool', side_effect=build) as builder, \
                 patch.object(r.w, 'command', side_effect=lambda argv,*a,**kw:
                     encoded(dict(status=argv[-1],capture_id='00000000-0000-0000-0000-000000000000',
                                  detail=dict(passed=113)))+b'\n') as command, \
                 patch.object(r, 'export_one', side_effect=primary) as export:
                with self.assertRaises(ValueError) as caught: r.replay_phase(args, root, budget, pins)
                self.assertIs(caught.exception, primary)
                receipt = json.loads((root/'evidence/live-replay-receipt.json').read_text())
                if stage=='download': builder.assert_not_called(); command.assert_not_called()
                if stage=='export': self.assertEqual(export.call_count, 1)
                return receipt

    def test_early_failure_receipt_and_no_tool_or_workload(self):
        receipt = self.phase('download')
        self.assertFalse(receipt['complete']); self.assertEqual(receipt['materialized_members'], [])
        self.assertTrue(all(x['status']=='NOTRUN' for x in receipt['cohorts']))
        self.assertEqual(receipt['failure']['detail'], 'exact primary refusal')

    def test_build_failure_still_checks_every_original_input(self):
        receipt = self.phase('build', tamper=True)
        self.assertFalse(receipt['complete'])
        check = next(x for x in receipt['preservation_finally'] if x['check']=='materialized original inputs')
        self.assertFalse(check['passed']); self.assertTrue(receipt['failure']['notes'])
        self.assertEqual(receipt['failure']['detail'], 'exact primary refusal')

    def test_first_export_refusal_stops_second_and_finally_preserves(self):
        receipt = self.phase('export')
        self.assertEqual([c['status'] for c in receipt['cohorts']], ['FAILED', 'NOTRUN'])
        self.assertTrue(all(c['passed'] for c in receipt['preservation_finally']))
        self.assertEqual(receipt['original_NOTRUN'], ['oscore-capture-01','unprotected-capture-01'])

    def test_caller_900_settlement_and_no_native_route(self):
        p = r.load_pins()
        with temporary() as tmp:
            root=Path(tmp); (root/'evidence').mkdir()
            args=SimpleNamespace(output=p['original_root'],core='unused',expected_core='core',expected_suite='suite')
            with patch.object(r.w,'hosted_preflight'), patch.object(r.w,'source_identity'), \
                 patch.object(r.shutil,'which',return_value=None), \
                 patch.object(r.old,'fresh_root',return_value=root), \
                 patch.dict(os.environ,{'RUNNER_TEMP':'unused'}), \
                 patch('suite_process.run_worker',return_value=SimpleNamespace(stdout=b'',stderr=b'',
                         duration_seconds=1,descendants_settled=True)) as worker:
                r.execute(args)
            call=worker.call_args
            self.assertEqual(call.kwargs['timeout'],900); self.assertTrue(call.kwargs['settle_build_auxiliaries'])
            self.assertEqual(call.args[0][1],'-B'); self.assertIn('_worker',call.args[0])
            self.assertEqual(json.loads((root/'evidence/live-replay-outer.json').read_text())['passed'],True)

    def test_outer_failure_retains_primary_cleanup_and_logs(self):
        p=r.load_pins()
        error=RuntimeError('worker refused')
        error.primary_cause=ValueError('primary cause')
        error.cleanup_errors=[RuntimeError('owned descendant unsettled')]
        error.cleanup_unresolved=True
        error.stdout=b'partial stdout';error.stderr=b'partial stderr'
        with temporary() as tmp:
            root=Path(tmp);(root/'evidence').mkdir()
            args=SimpleNamespace(output=p['original_root'],core='unused',expected_core='core',expected_suite='suite')
            with patch.object(r.w,'hosted_preflight'),patch.object(r.w,'source_identity'), \
                 patch.object(r.shutil,'which',return_value=None), \
                 patch.object(r.old,'fresh_root',return_value=root), \
                 patch.dict(os.environ,{'RUNNER_TEMP':'unused'}), \
                 patch('suite_process.run_worker',side_effect=error):
                with self.assertRaises(RuntimeError) as caught:r.execute(args)
            self.assertIs(caught.exception,error)
            outer=json.loads((root/'evidence/live-replay-outer.json').read_text())
            self.assertFalse(outer['passed']);self.assertTrue(outer['cleanup_unresolved'])
            self.assertEqual(outer['primary']['detail'],'primary cause')
            self.assertEqual(len(outer['cleanup_errors']),1);self.assertNotIn('etw_stop_proof',outer)
            self.assertIn(b'partial stdout',(root/'evidence/live-replay-outer.log').read_bytes())

    def test_both_requested_once_serial_build_once_and_actual_model_census(self):
        pins,selected=fixture()
        with temporary() as tmp:
            root=Path(tmp);(root/'evidence').mkdir()
            budget=SimpleNamespace(peak=1,observed_child_working_set_peak=2,check=Mock(),rss_limit=4*1024**3)
            args=SimpleNamespace(core='unused',expected_core='core',expected_suite='suite')
            def report(argv,*a,**kw):
                return encoded(dict(status=argv[-1],capture_id='00000000-0000-0000-0000-000000000000',
                                    detail=dict(passed=127)))+b'\n'
            with patch.object(r.w,'source_identity',return_value={'clean':True}), \
                 patch.object(r,'load_pins',return_value=pins), \
                 patch.object(r,'download',return_value=({},b'zip')), \
                 patch.object(r,'inspect_zip',return_value=(selected,[])), \
                 patch.object(r,'receipt_inputs',return_value={}), \
                 patch.object(r.old,'build_tool',return_value=(['dotnet','tool'],{},dict(files=[]))) as build, \
                 patch.object(r.w,'command',side_effect=report) as command, \
                 patch.object(r,'export_one',return_value={'export_succeeded':True}) as export:
                r.replay_phase(args,root,budget,pins)
            build.assert_called_once()
            self.assertEqual([c.args[-1]['name'] for c in export.call_args_list],list(r.COHORTS))
            self.assertEqual([c.args[0][-1] for c in command.call_args_list],['metadata','selftest'])
            self.assertEqual(budget.rss_limit,1024**3)
            receipt=json.loads((root/'evidence/live-replay-receipt.json').read_text())
            self.assertTrue(receipt['complete'])
            self.assertEqual(receipt['actual_tool_reports']['selftest']['detail']['passed'],127)

    def test_worker_830_build_RSS_handshake(self):
        with temporary() as tmp:
            args=dict(output=tmp,core='unused',expected_core='core',expected_suite='suite')
            stdin=SimpleNamespace(buffer=io.BytesIO(b'go\n'))
            budget=Mock()
            with patch.object(r.sys,'stdin',stdin), patch.object(r.w,'hosted_preflight'), \
                 patch.object(r.w,'read_json',return_value=args), \
                 patch.object(r,'ReplayBudget',return_value=budget) as make, \
                 patch.object(r,'replay_phase') as phase:
                r.worker('unused')
            self.assertEqual(make.call_args.args[1],830)
            self.assertEqual(make.call_args.kwargs['rss_limit'],4*1024**3)
            phase.assert_called_once(); budget.check.assert_called_once_with(force=True)
        with patch.object(r.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'no\n'))):
            with self.assertRaises(ValueError):r.worker('unused')

    def test_conversion_guard_is_aggregate_and_existing_caps(self):
        with temporary() as tmp:
            budget=r.ReplayBudget(Path(tmp),830)
            with patch.object(r.old.w.Budget,'check') as base, \
                 patch.object(r.w,'owned_size',return_value=256*1024**2+1) as size:
                with self.assertRaises(ValueError):budget.check(force=True)
            base.assert_called_once_with(force=True)
            self.assertEqual(size.call_args.args[0],Path(tmp)/'conversion-replay')
        self.assertEqual((r.w.BUILD_LIMIT,r.w.EVIDENCE_LIMIT,r.s.LIMIT),(8*1024**3,256*1024**2,16*1024**2))


if __name__ == '__main__':
    unittest.main()
