import copy
import argparse
import json
import unittest
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile
import queue
import json
import windows_profile as w


def fixture(mode):
    d = dict(event='fixture', security=mode, rows=50000, wire_bytes=25600000, limit_bytes=33554432, capture_datagram_bytes=256, app_datagram_bytes=1472)
    for k in ('requested_bytes', 'row_bytes', 'row_metadata_bytes', 'request_ref_bytes', 'optional_request_ref_bytes', 'app_heap_bytes', 'app_inline_bytes', 'fixture_inline_bytes', 'scratch_allowance_bytes'): d[k] = 1
    return d


def profile():
    return dict(schema='coaptic-stack-profile/1', identity={x:x for x in ('source','tool','workload','capture','platform','cohort')}, measurement=dict(kind='sampled_cpu', unit='samples'), quality=dict(lost=0, unresolved=0, refused=0, notes='complete'), scope=dict(pid=1,tid=2,label='one thread',cpu_mode='unknown'), totals=dict(samples=200,weight=200), stacks=[dict(frames=['App','leaf'],samples=200,weight=200)])


class Tests(unittest.TestCase):
    def test_cargo_artifact_pair_uses_reported_pdb(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d).resolve(); exe=target/'release/bench-core.exe'; pdb=target/'release/bench_core.pdb'
            artifact=dict(reason='compiler-artifact',target=dict(name='bench-core',kind=['bin']),
                          executable=str(exe),filenames=[str(exe),str(pdb)])
            def encoded(row,done=True):
                return (json.dumps(row)+'\n'+json.dumps(dict(reason='build-finished',success=done))+'\n').encode()
            self.assertEqual(w.native_artifact_pair(encoded(artifact),target),(exe,pdb))
            for files in ([str(exe)], [str(pdb),str(target/'other.pdb')], [str(target.parent/'foreign.pdb')]):
                with self.subTest(files=files), self.assertRaises(ValueError):
                    w.native_artifact_pair(encoded(dict(artifact,filenames=files)),target)
            with self.assertRaises(ValueError): w.native_artifact_pair(encoded(artifact,False),target)
            with self.assertRaises(ValueError): w.native_artifact_pair(encoded(dict(artifact,executable='relative.exe')),target)

    def test_size_scan_handles_churn_but_preserves_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(w.os,'walk',return_value=[(str(root),[],['vanished.tmp'])]):
                self.assertEqual(w.owned_size(root),0)
                with patch.object(Path,'lstat',side_effect=PermissionError('denied')):
                    with self.assertRaises(PermissionError): w.owned_size(root)
            def denied(*args,**kwargs):
                kwargs['onerror'](PermissionError('directory denied'))
                return []
            with patch.object(w.os,'walk',side_effect=denied):
                with self.assertRaises(PermissionError): w.owned_size(root)
    def test_reparse_refusal_preserves_bounded_entry_and_native_tag(self):
        from types import SimpleNamespace
        root = Path('owned')
        stat = SimpleNamespace(st_file_attributes=0x400, st_reparse_tag=0xA000000C)
        with patch.object(w.os, 'walk', return_value=[(str(root), [], ['compiler-link'])]), \
             patch.object(Path, 'lstat', return_value=stat), \
             patch.object(Path, 'is_symlink', return_value=False):
            with self.assertRaisesRegex(ValueError, "compiler-link.*attributes=0x400; tag=0xa000000c"):
                w.owned_size(root)
        with patch.object(w.os, 'walk', return_value=[(str(root), [], ['x' * 4096])]), \
             patch.object(Path, 'lstat', return_value=stat), \
             patch.object(Path, 'is_symlink', return_value=False):
            with self.assertRaises(ValueError) as caught:
                w.owned_size(root)
            self.assertLess(len(str(caught.exception)), 640)

    @unittest.skipUnless(w.os.name == 'nt', 'Windows compatibility junction paths')
    def test_owned_cache_alias_is_pruned_and_backing_counted_once(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            alias = root / 'user/AppData/Local/Microsoft/Windows/INetCache/Content.IE5'
            backing = alias.parent / 'IE'
            alias.mkdir(parents=True); backing.mkdir()
            (alias / 'do-not-traverse').write_bytes(b'not backing')
            (backing / 'cache.dat').write_bytes(b'abc')
            original = Path.lstat
            info = SimpleNamespace(st_file_attributes=0x2416, st_reparse_tag=0xA0000003)
            def state(path, *args, **kwargs):
                return info if path == alias else original(path, *args, **kwargs)
            with patch.object(Path, 'lstat', state), \
                 patch.object(w.os, 'readlink', return_value='\\\\?\\' + str(backing)) as readlink:
                self.assertEqual(w.owned_size(root), 3)
                readlink.assert_called_once_with(alias)

    @unittest.skipUnless(w.os.name == 'nt', 'Windows compatibility junction paths')
    def test_owned_cache_alias_refuses_foreign_ambiguous_and_chained_targets(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            alias = root / 'user/AppData/Local/Microsoft/Windows/INetCache/Content.IE5'
            backing = alias.parent / 'IE'
            alias.parent.mkdir(parents=True)
            info = SimpleNamespace(st_file_attributes=0x2416, st_reparse_tag=0xA0000003)
            for target in (str(root.parent / 'foreign'), str(root / 'other'), str(alias),
                           str(backing / '..'), '//server/share/IE', '//?/UNC/server/share/IE'):
                with self.subTest(target=target), patch.object(w.os, 'readlink', return_value=target):
                    with self.assertRaises(ValueError): w.owned_cache_alias(root, alias, info)
            with patch.object(w.os, 'readlink', return_value=str(backing)):
                self.assertTrue(w.owned_cache_alias(root, alias, info))  # Missing owned backing is bounded.
                with patch.object(Path, 'lstat', return_value=info):
                    with self.assertRaisesRegex(ValueError, 'target contains a reparse'):
                        w.owned_cache_alias(root, alias, info)
            with patch.object(w.os, 'readlink') as readlink:
                self.assertFalse(w.owned_cache_alias(root, root / 'unrelated', info))
                self.assertFalse(w.owned_cache_alias(root, alias, SimpleNamespace(st_reparse_tag=0xA000000C)))
                readlink.assert_not_called()

    def test_exact_dotnet_sdk_is_selected_before_tool_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            calls = []
            def command(argv, budget, log, *, env=None, cwd=None):
                selection = json.loads((cwd / 'global.json').read_text())
                self.assertEqual(selection, {'sdk': {'version': '8.0.427', 'rollForward': 'disable',
                                                     'allowPrerelease': False}})
                self.assertTrue(cwd.is_relative_to(root / 'evidence'))
                calls.append(argv)
                return b'8.0.427\n' if argv[-1] == '--version' else b'SDK info'
            with patch.object(w, 'command', side_effect=command):
                cwd, info, receipt = w.selected_dotnet_sdk('dotnet', root, None, {})
            self.assertEqual(calls, [['dotnet', '--version'], ['dotnet', '--info']])
            self.assertEqual(info, 'SDK info')
            self.assertEqual(receipt['sha256'], w.digest(receipt['path']))
            self.assertEqual(receipt['version'], '8.0.427')
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(w, 'command', return_value=b'10.0.403\n') as command:
            with self.assertRaisesRegex(ValueError, 'exact provisioned'):
                w.selected_dotnet_sdk('dotnet', Path(directory), None, {})
            command.assert_called_once()

    def test_source_identity_refusal_retains_bounded_dirty_path_census(self):
        import development_suite as suite
        for status in ('?? tools/benchmark/windows-stack/obj/', 'M ' + 'x' * 8192):
            with self.subTest(status_bytes=len(status)), \
                 patch.object(suite, 'git', return_value=status):
                with self.assertRaisesRegex(ValueError, 'requires clean committed sources') as caught:
                    suite.identity(Path('.'))
                note, = caught.exception.__notes__
                self.assertIn(status[:4096], note)
                self.assertLess(len(note), 4200)
                self.assertEqual('[truncated]' in note, len(status) > 4096)

    def test_tool_sources_are_copied_exactly_into_owned_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'original'; source.mkdir()
            inputs = {'Tool.csproj': b'<Project/>', 'Program.cs': b'class Program {}'}
            for name, data in inputs.items(): (source / name).write_bytes(data)
            project, receipt = w.stage_tool_sources(root, source)
            self.assertEqual(project, root / 'tool-source/Tool.csproj')
            for name, data in inputs.items():
                self.assertEqual((project.parent / name).read_bytes(), data)
                self.assertEqual((source / name).read_bytes(), data)
            manifest = w.read_json(receipt['path'])
            self.assertEqual(manifest['source'], str(source))
            self.assertEqual({row['file'] for row in manifest['files']}, set(inputs))
            self.assertEqual(receipt['sha256'], w.digest(receipt['path']))
            # Project-relative generated files belong to the monitored build root.
            (project.parent / 'NuGet').mkdir()
            (project.parent / 'NuGet/generated').write_bytes(b'owned')
            self.assertEqual(set(path.name for path in source.iterdir()), set(inputs))
            with self.assertRaises(FileExistsError): w.stage_tool_sources(root, source)

    def test_tool_source_staging_refuses_unknown_oversize_or_changed_inputs(self):
        for case in ('unknown', 'oversize', 'changed'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); source = root / 'original'; source.mkdir()
                (source / 'Tool.csproj').write_bytes(b'<Project/>')
                if case == 'unknown': (source / 'NuGet').mkdir()
                if case == 'oversize':
                    import io
                    (source / 'Large.cs').touch()
                    original_open = Path.open
                    def oversized(path, *args, **kwargs):
                        return (io.BytesIO(b'x' * (1024 * 1024 + 1)) if path.name == 'Large.cs'
                                else original_open(path, *args, **kwargs))
                    with patch.object(Path, 'open', oversized):
                        with self.assertRaisesRegex(ValueError, 'exceeds 1 MiB'):
                            w.stage_tool_sources(root, source)
                    continue
                if case == 'changed':
                    with patch.object(w, 'digest', return_value='wrong'):
                        with self.assertRaisesRegex(ValueError, 'changed during staging'):
                            w.stage_tool_sources(root, source)
                else:
                    with self.assertRaises(ValueError): w.stage_tool_sources(root, source)

    def receipt(self, capture_id='owned'):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'capture.json'
        path.write_text(json.dumps(dict(schema='coaptic-windows-stack-capture/1',
                                       config=dict(capture_id=capture_id), stopped=True,
                                       session_name='CoapticStack-' + capture_id)))
        return path

    def test_plan(self):
        p = w.plan(); self.assertEqual(len(p),18)
        self.assertEqual(p[:2], [('unprotected','capture',0),('oscore','capture',0)])
        self.assertEqual(p[-2:], [('unprotected','control',0),('oscore','control',0)])

    def test_sequence(self):
        p=w.BatchProtocol('oscore'); p.receive(fixture('oscore'))
        for kind,count in (('empty',16),('work',1)):
            for i in range(count):
                for event,command in (('ready','capture_then_run' if kind=='work' else 'run'),('measured','stop_then_verify' if kind=='work' else 'verify'),('verified',None)):
                    self.assertEqual(p.receive(dict(event=event,kind=kind,block=i,verified=50128 if kind=='work' and event=='verified' else 128)),command)
        self.assertEqual(p.receive(dict(event='complete',mode='server-app-batch-cpu',security='oscore',operations=50000,warmup=128,verified=50128,work_batches=1,batch_operations=50000,empty_gates=16,internal_datagrams=100256,udp_datagrams=0,black_box=True)),'exit')
        with self.assertRaises(ValueError): p.receive({})

    def test_mismatches(self):
        p=w.BatchProtocol('unprotected'); d=fixture('unprotected'); d['requested_bytes']=33554433
        with self.assertRaises(ValueError): p.receive(d)
        p.receive(fixture('unprotected'))
        for d in (dict(event='measured',kind='empty',block=0,verified=128),dict(event='ready',kind='empty',block=1,verified=128),dict(event='ready',kind='empty',block=0,verified=True)):
            with self.assertRaises(ValueError): p.receive(d)

    def test_quality(self):
        p=profile(); self.assertTrue(w.qualification(p,app_rooted=200,pdb_match=True,truncated=False)['qualified'])
        for key in ('lost','unresolved','refused'):
            q=copy.deepcopy(p); q['quality'][key]=None
            self.assertFalse(w.qualification(q,app_rooted=200,pdb_match=True,truncated=False)['qualified'])
        for n,match,truncated in ((199,True,False),(200,None,False),(200,True,None)):
            self.assertFalse(w.qualification(p,app_rooted=n,pdb_match=match,truncated=truncated)['qualified'])
        with self.assertRaises(ValueError): w.qualification(p,app_rooted=201,pdb_match=True,truncated=False)

    def test_bounded_event_and_growth(self):
        self.assertEqual(w.parse_event(b'{"event":"ready"}\n'), {'event':'ready'})
        for raw in (b'{"event":1,"event":2}\n', b'{}', b' ' * 4096 + b'\n', b'{"n":NaN}\n'):
            with self.assertRaises((ValueError, UnicodeError)): w.parse_event(raw)
        self.assertEqual(w.check_growth([5, 6], 11), 11)
        for sizes in ([5, 7], [None], [-1], [True]):
            with self.assertRaises(ValueError): w.check_growth(sizes, 11)

    def test_host(self):
        with self.assertRaises(ValueError): w.expected_sha('abc')
        with self.assertRaises(ValueError): w.hosted_preflight({},platform='win32',elevated=True)
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted'}
        with self.assertRaises(ValueError): w.hosted_preflight(env,platform='win32',elevated=False)
        w.hosted_preflight(env,platform='win32',elevated=True)

    def test_local_capture_refuses_before_source_or_process(self):
        with patch.object(w, 'hosted_preflight', side_effect=ValueError('hosted required')):
            with patch.object(w, 'source_identity') as identity, patch.object(w.subprocess, 'Popen') as spawn:
                with self.assertRaises(SystemExit) as e:
                    w.main(['all','--core','x','--output','y','--expected-core','a'*40,'--expected-suite','b'*40])
                self.assertEqual(e.exception.code,2)
                identity.assert_not_called(); spawn.assert_not_called()

    def test_stop_ack_before_exit(self):
        path = self.receipt()
        child=Mock(); child.line.return_value=dict(status='stopped',capture_id='owned',detail={'receipt':str(path)})
        self.assertEqual(w.stop_collector(child,'owned',receipt_path=path),{'receipt':str(path)})
        self.assertEqual([c[0] for c in child.method_calls],['send','line','finish'])
        child.send.assert_called_once_with('stop')
        child.line.return_value=dict(status='stopped',capture_id='foreign',detail={})
        with self.assertRaises(ValueError): w.stop_collector(child,'owned')

    def test_cleanup_eof_and_proof(self):
        child=Mock(); child.line.return_value=dict(status='failed',capture_id='owned',detail={'cleanup_settled':True})
        with patch.object(w.time, 'monotonic', return_value=100):
            w.stop_collector(child,'owned',cleanup=True)
        self.assertEqual([c[0] for c in child.method_calls],['p.stdin.close','line','p.wait'])
        child.line.assert_called_once_with(15,cleanup=True)
        child.line.return_value=dict(status='failed',capture_id='owned',detail={'cleanup_settled':False})
        with self.assertRaisesRegex(RuntimeError,'dispose'): w.stop_collector(child,'owned',cleanup=True)

    def test_cleanup_drains_queued_start_events_under_one_deadline(self):
        child = Mock()
        child.line.side_effect = [dict(status=status, capture_id='owned', detail=detail)
                                  for status, detail in [('armed', {}), ('ready', {}),
                                                         ('failed', {'cleanup_settled': True})]]
        with patch.object(w.time, 'monotonic', side_effect=[100, 101, 102, 104, 105, 110, 111]):
            w.stop_collector(child, 'owned', cleanup=True)
        self.assertEqual([call.args[0] for call in child.line.call_args_list], [14, 11, 5])
        child.p.wait.assert_called_once_with(timeout=5)
        child.send.assert_not_called()
        self.assertTrue(child.etw_cleanup_settled)

    def test_cleanup_queued_stopped_requires_durable_receipt(self):
        path = self.receipt()
        child = Mock()
        child.line.side_effect = [dict(status='ready', capture_id='owned', detail={}),
                                  dict(status='stopped', capture_id='owned', detail={'receipt':str(path)})]
        w.stop_collector(child, 'owned', cleanup=True, receipt_path=path)
        child.p.wait.assert_called_once_with(timeout=5)
        for change in ({'stopped': False}, {'config': {'capture_id': 'foreign'}},
                       {'session_name': 'CoapticStack-foreign'}, {'schema': 'unknown'}):
            with self.subTest(change=change):
                data = dict(schema='coaptic-windows-stack-capture/1', stopped=True,
                            config={'capture_id':'owned'}, session_name='CoapticStack-owned')
                data.update(change)
                path.write_text(json.dumps(data))
                child = Mock()
                child.line.return_value = dict(status='stopped', capture_id='owned', detail={'receipt':str(path)})
                with self.assertRaisesRegex(RuntimeError, 'dispose'):
                    w.stop_collector(child, 'owned', cleanup=True, receipt_path=path)
                self.assertFalse(child.etw_cleanup_settled)
                child.p.wait.assert_not_called()
        child.line.return_value['detail']['receipt'] = str(path.with_name('foreign.json'))
        with self.assertRaisesRegex(RuntimeError, 'receipt path mismatch'):
            w.stop_collector(child, 'owned', cleanup=True, receipt_path=path)

    def test_cleanup_foreign_events_never_send_stop(self):
        for status in ('armed', 'ready', 'failed', 'stopped'):
            child = Mock()
            child.line.return_value = dict(status=status, capture_id='foreign', detail={'cleanup_settled':True})
            with self.assertRaisesRegex(RuntimeError, 'dispose.*identity mismatch'):
                w.stop_collector(child, 'owned', cleanup=True)
            child.send.assert_not_called()
            child.p.kill.assert_not_called()
            self.assertFalse(child.etw_cleanup_settled)

    def test_cleanup_errors_preserve_grace_before_final_close_kills(self):
        for error in (RuntimeError('unexpected child stdout EOF'), OSError('pipe reader failed'),
                      TimeoutError('child event deadline'), ValueError('malformed event')):
            with self.subTest(error=error):
                now = [100.0]
                child = w.Process.__new__(w.Process)
                child.p = Mock(); child.p.poll.return_value = None
                child.budget = Mock()
                child.threads = []
                child.line = Mock(side_effect=error)
                child.send = Mock()
                def sleep(seconds):
                    now[0] += seconds
                with patch.object(w.time, 'monotonic', side_effect=lambda: now[0]), \
                     patch.object(w.time, 'sleep', side_effect=sleep):
                    with self.assertRaisesRegex(RuntimeError, 'dispose') as failure:
                        w.stop_collector(child, 'owned', cleanup=True)
                    self.assertIs(failure.exception.__cause__, error)
                    child.p.kill.assert_not_called()
                    child.p.kill.side_effect = lambda: self.assertGreaterEqual(now[0], 115)
                    child.close()
                child.p.kill.assert_called_once()
                self.assertEqual(now[0], 115)
                child.send.assert_not_called()

    def test_cleanup_pending_events_cannot_extend_time_budget(self):
        child = Mock()
        child.line.return_value = dict(status='armed', capture_id='owned', detail={})
        with patch.object(w.time, 'monotonic', side_effect=[100, 101, 114, 115]):
            with self.assertRaisesRegex(RuntimeError, 'dispose.*deadline'):
                w.stop_collector(child, 'owned', cleanup=True)
        child.line.assert_called_once_with(14, cleanup=True)
        self.assertEqual(child.etw_cleanup_deadline, 115)
        child.p.wait.assert_not_called()

    def test_cleanup_late_terminal_is_not_accepted(self):
        child = Mock()
        child.line.return_value = dict(status='failed', capture_id='owned', detail={'cleanup_settled':True})
        with patch.object(w.time, 'monotonic', side_effect=[100, 101, 115]):
            with self.assertRaisesRegex(RuntimeError, 'dispose.*deadline'):
                w.stop_collector(child, 'owned', cleanup=True)
        self.assertFalse(child.etw_cleanup_settled)

    def test_cleanup_proof_precedes_bounded_process_reap(self):
        child = Mock()
        child.line.return_value = dict(status='failed', capture_id='owned', detail={'cleanup_settled':True})
        child.p.wait.side_effect = TimeoutError('process reap deadline')
        with self.assertRaisesRegex(RuntimeError, 'dispose.*reap deadline'):
            w.stop_collector(child, 'owned', cleanup=True)
        self.assertTrue(child.etw_cleanup_settled)
        child.p.wait.assert_called_once_with(timeout=5)

    def test_build_environment_owns_nuget_sdk_and_plugin_caches(self):
        keys = ('CARGO_HOME', 'CARGO_TARGET_DIR', 'NUGET_PACKAGES', 'NUGET_HTTP_CACHE_PATH',
                'NUGET_PLUGINS_CACHE_PATH', 'DOTNET_CLI_HOME', 'DOTNET_BUNDLE_EXTRACT_BASE_DIR',
                'NUGET_SCRATCH',
                'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'MSBUILDDEBUGPATH', 'TMP', 'TEMP',
                'NUGET_CREDENTIALPROVIDER_MSAL_FILECACHE_LOCATION')
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(w.os.environ, {key:'foreign-cache' for key in keys}):
            root = Path(directory).resolve()
            (root / 'evidence').mkdir()
            env = w.build_environment(root)
            for key in keys:
                self.assertTrue(Path(env[key]).is_relative_to(root), key)
            self.assertEqual(env['NUGET_CREDENTIALPROVIDER_SESSIONTOKENCACHE_ENABLED'], 'false')
            self.assertEqual(env['NUGET_CREDENTIALPROVIDER_MSAL_FILECACHE_ENABLED'], 'false')
            self.assertEqual(env['DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE'], 'true')
            (Path(env['NUGET_HTTP_CACHE_PATH']) / 'cache').write_bytes(b'1234')
            with patch.object(w, 'BUILD_LIMIT', 3):
                with self.assertRaisesRegex(ValueError, 'budget'):
                    w.Budget(root, 10).check(force=True)

    def test_retain_file_checks_ownership_hash_and_evidence_budget_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'owned'; root.mkdir()
            (root / 'evidence').mkdir()
            source = root / 'worker.exe'; source.write_bytes(b'native')
            outside = Path(directory) / 'foreign.exe'; outside.write_bytes(b'foreign')
            destination = root / 'evidence/binaries/worker.exe'
            for src, dst, expected, message in (
                    (outside, destination, w.digest(outside), 'escaped'),
                    (source, outside, w.digest(source), 'escaped'),
                    (source, destination, '0' * 64, 'hash mismatch')):
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    w.retain_file(root, src, dst, expected)
                self.assertFalse(destination.exists())
            with patch.object(w, 'EVIDENCE_LIMIT', 5), patch.object(w, 'digest') as digest:
                with self.assertRaisesRegex(ValueError, 'budget'):
                    w.retain_file(root, source, destination)
                digest.assert_not_called()
            retained = w.retain_file(root, source, destination, w.digest(source))
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(retained, dict(path=str(destination.resolve()), sha256=w.digest(source), bytes=6))
            with self.assertRaises(FileExistsError):
                w.retain_file(root, source, destination)
            self.assertEqual(destination.read_bytes(), b'native')
            self.assertEqual(outside.read_bytes(), b'foreign')

    def test_retain_file_preserves_evidence_when_copy_or_source_hash_changes(self):
        for digests in (['expected', 'changed'], ['expected', 'expected', 'changed']):
            with self.subTest(digests=digests), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root / 'evidence').mkdir()
                source = root / 'worker.pdb'; source.write_bytes(b'pdb')
                destination = root / 'evidence/worker.pdb'
                with patch.object(w, 'digest', side_effect=digests):
                    with self.assertRaisesRegex(ValueError, 'copy/source hash mismatch'):
                        w.retain_file(root, source, destination, 'expected')
                self.assertEqual(source.read_bytes(), b'pdb')
                self.assertEqual(destination.read_bytes(), b'pdb')

    def test_retain_build_evidence_keeps_replay_pair_and_small_dependency_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assert_retained_build_evidence(Path(directory))

    def test_retain_build_evidence_normalizes_owned_root_before_containment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'alias').mkdir()
            # A lexical alias models the same canonical/noncanonical comparison
            # as Windows 8.3 temporary paths without requiring 8.3 volume support.
            self.assert_retained_build_evidence(root / 'alias' / '..')

    def assert_retained_build_evidence(self, root):
        (root / 'evidence').mkdir()
        (root / 'target').mkdir(); (root / 'tool').mkdir()
        binary, pdb = root / 'target/bench-core.exe', root / 'target/bench-core.pdb'
        tool = root / 'tool/Coaptic.WindowsStack.dll'
        files = {binary:b'exe', pdb:b'pdb', tool:b'tool', tool.with_suffix('.deps.json'):b'{"runtimeTarget":{}}',
                 root / 'tool-packages.lock.json':b'{"version":1}',
                 root / 'tool/TraceEvent.dll':b'traceevent', root / 'tool/tool.runtimeconfig.json':b'{}'}
        for path, data in files.items(): path.write_bytes(data)
        native, receipts = w.retain_build_evidence(root, binary, pdb, tool)
        for key, original in (('path', binary), ('pdb', pdb)):
            retained = Path(native[key])
            self.assertEqual(retained.parent, root.resolve() / 'evidence/binaries')
            self.assertEqual(retained.read_bytes(), files[original])
            self.assertEqual(w.digest(retained), w.digest(original))
        for key in ('package_lock', 'dependencies', 'files_manifest'):
            receipt = receipts[key]
            self.assertTrue(Path(receipt['path']).is_relative_to(root.resolve() / 'evidence'))
            self.assertEqual(receipt['sha256'], w.digest(receipt['path']))
        manifest = w.read_json(receipts['files_manifest']['path'])
        self.assertEqual({row['path'] for row in manifest['files']},
                         {path.name for path in files if path.parent == tool.parent})
        self.assertIn('bit-identical rebuilds are not claimed', manifest['notes'])
        record = dict(sources={}, native=native,
                      tool=dict(path=str(tool), sha256=w.digest(tool), retained_evidence=receipts))
        w.save(root / 'evidence/build.json', record)
        # Capture validates and uses the retained pair after target output is gone/changed.
        binary.write_bytes(b'changed'); pdb.write_bytes(b'changed')
        with patch.object(w, 'source_identity', return_value={}):
            args = argparse.Namespace(core='core', expected_core='a'*40, expected_suite='b'*40)
            self.assertEqual(w.verified_build(args, root)['native'], native)
            Path(receipts['dependencies']['path']).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'dependency evidence changed'):
                w.verified_build(args, root)
        self.assertLess(w.owned_size(root / 'evidence'), w.EVIDENCE_LIMIT)

    def test_capture_refuses_retained_evidence_over_budget_before_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'evidence').mkdir()
            (root / 'evidence/retained.pdb').write_bytes(b'1234')
            budget = w.Budget(root, 10)
            with patch.object(w, 'EVIDENCE_LIMIT', 3), patch.object(w, 'verified_build') as build, \
                 patch.object(w, 'command') as command, patch.object(w, 'Process') as process:
                with self.assertRaisesRegex(ValueError, 'budget'):
                    w.capture_phase(Mock(), root, budget)
            build.assert_not_called(); command.assert_not_called(); process.assert_not_called()

    def test_outer_failure_preserves_primary_and_cleanup_causes_and_logs(self):
        from suite_process import WorkerError
        primary = TimeoutError('worker deadline')
        primary.add_note('primary note')
        reasons = ['job observer identity changed', 'pipe reader did not stop within join deadline',
                   'job member exit observation failed/deadline']
        cleanup = [RuntimeError(reason) for reason in reasons]
        cleanup[0].add_note('job cleanup note')
        stdout, stderr = b'out\x00' * 10, b'err\xff' * 10
        error = WorkerError(['mock-worker'], primary, cleanup, stdout, stderr, 900, None)
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory).resolve()
            root = runner / 'coaptic-stack-test'
            args = argparse.Namespace(output=str(root), core='core', expected_core='a'*40,
                                      expected_suite='b'*40, command='build')
            with patch.object(w, 'hosted_preflight'), patch.object(w, 'source_identity'), \
                 patch.object(w.shutil, 'which', return_value=None), \
                 patch.dict(w.os.environ, RUNNER_TEMP=str(runner)), \
                 patch('suite_process.run_worker', side_effect=error) as run:
                with self.assertRaises(WorkerError) as failure:
                    w.execute(args)
            self.assertIs(failure.exception, error)
            run.assert_called_once()
            self.assertEqual(run.call_args.kwargs['limit'], w.LOG_LIMIT)
            record = w.read_json(root / 'evidence/build-outer.json')
            self.assertTrue(record['cleanup_unresolved'])
            self.assertEqual(record['primary'], dict(error='TimeoutError', detail='worker deadline', notes=['primary note']))
            self.assertEqual([cause['detail'] for cause in record['cleanup_errors']], reasons)
            self.assertEqual(record['cleanup_errors'][0]['notes'], ['job cleanup note'])
            self.assertIn('cleanup: RuntimeError: ' + reasons[1], record['notes'])
            self.assertEqual((root / 'evidence/build-outer.log').read_bytes(), stdout + b'\n--- stderr ---\n' + stderr)

    def test_outer_failure_structure_has_explicit_bounds(self):
        from suite_process import WorkerError
        primary = ValueError('p' * 10000)
        for _ in range(20): primary.add_note('n' * 5000)
        error = WorkerError([], primary, [RuntimeError('c' * 10000)] * 30, b'', b'', 0, None)
        record = w.outer_failure(error)
        self.assertEqual(len(record['cleanup_errors']), 16)
        self.assertEqual(record['cleanup_errors_omitted'], 14)
        self.assertEqual(len(record['primary']['detail']), 2048)
        self.assertEqual(len(record['primary']['notes']), 8)
        self.assertTrue(all(len(note) <= 1024 for note in record['notes'] + record['primary']['notes']))

    def test_deadline_and_growth(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'evidence').mkdir(); (root/'artifact').write_bytes(b'1234')
            b=w.Budget(root,10)
            with patch.object(w,'BUILD_LIMIT',3):
                with self.assertRaisesRegex(ValueError,'budget'): b.check(force=True)
            b.deadline=0
            with self.assertRaises(TimeoutError): b.check()

    def test_direct_child_memory_monitor(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'evidence').mkdir()
            budget=w.Budget(root,10,rss_limit=100)
            process=Mock(); process.poll.return_value=None
            budget.processes.add(process)
            with patch.object(w,'working_set',return_value=101):
                with self.assertRaisesRegex(ValueError,'working-set'): budget.check()
            with patch.object(w,'working_set',return_value=80):
                budget.check()
                self.assertEqual(budget.observed_child_working_set_peak,101)
            process.poll.return_value=0
            with patch.object(w,'working_set') as query:
                budget.check(); query.assert_not_called()

    def test_pipe_deadline_does_not_block_or_signal(self):
        p=w.Process.__new__(w.Process); p.events=queue.Queue(); p.error=None; p.budget=Mock()
        with self.assertRaises(TimeoutError): p.line(-1)
        p.events.put(None)
        with self.assertRaisesRegex(RuntimeError,'EOF'): p.line(1)
        p.events.put(b'{"status":"ready"}\n')
        self.assertEqual(p.line(1),{'status':'ready'})

    def test_owned_source_identity(self):
        def identity(root):
            return dict(commit='a'*40 if str(root)=='core' else 'b'*40,tree='c'*40)
        with patch('development_suite.identity',side_effect=identity), patch('development_suite.resolved_core',return_value=Path('core').resolve()):
            self.assertEqual(w.source_identity('core','a'*40,'b'*40)['core']['commit'],'a'*40)
            with self.assertRaises(ValueError): w.source_identity('core','d'*40,'b'*40)

if __name__ == '__main__': unittest.main()
