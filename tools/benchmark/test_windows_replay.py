"""Portable RAM/network/process mocks; no artifact access or native execution."""
import argparse
import copy
import io
import json
from pathlib import Path, PureWindowsPath
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error
import zipfile

import windows_replay as r


def temporary():
    # Tests never select the system C: temp/cache roots on the implementation host.
    return tempfile.TemporaryDirectory(prefix='replay-mock-', dir=Path(__file__).resolve().parent)


def metadata():
    return dict(id=r.ARTIFACT_ID, size_in_bytes=r.ZIP_BYTES, digest='sha256:' + r.ZIP_SHA256,
                expired=False, name=f'windows-stack-profile-{r.RUN_ID}-{r.ATTEMPT}',
                workflow_run=dict(id=r.RUN_ID, head_sha=r.ORIGINAL_SUITE))


def fixture():
    evidence = r.ORIGINAL_ROOT / 'evidence'
    exe, pdb, etl = b'exe', b'pdb', b'etl'
    sources = dict(core=dict(commit=r.ORIGINAL_CORE), suite=dict(commit=r.ORIGINAL_SUITE))
    config = dict(capture_id=r.CAPTURE_ID, directory=str(evidence / r.COHORT), pid=r.PID, tid=r.TID,
                  process_start_utc='2026-10-30T06:28:42.3648387+00:00', dedicated_hosted_vm=True,
                  exe=str(evidence / r.SELECTED[0]), pdb=str(evidence / r.SELECTED[1]),
                  exe_sha256=r.sha(exe), pdb_sha256=r.sha(pdb),
                  identity=dict(source=json.dumps(sources), capture=r.CAPTURE_ID, cohort=r.COHORT,
                                tool='original', platform='Windows', workload='App'))
    image = dict(exe_sha256=r.sha(exe), pdb_sha256=r.sha(pdb),
                 pdb_guid='9ca23107-0be2-4350-8416-05e83dd701b8', pdb_age=1,
                 image_id=1793341719, image_size=1249280, image_checksum=0)
    receipt = dict(schema='coaptic-windows-stack-capture/1', config=config, image=image,
                   session_name='CoapticStack-' + r.CAPTURE_ID, etl=str(evidence / r.SELECTED[3]),
                   etl_bytes=len(etl), etl_sha256=r.sha(etl), stopped=True,
                   module_base_address='7ff725180000', module_size=1249280)
    native = dict(path=config['exe'], pdb=config['pdb'], sha256=r.sha(exe), pdb_sha256=r.sha(pdb),
                  bytes=len(exe), pdb_bytes=len(pdb))
    selected = dict(zip(r.SELECTED, (exe, pdb, json.dumps(receipt).encode(), etl)))
    return selected, dict(sources=sources, native=native), receipt


def pins(selected):
    return {k: (len(v), r.sha(v)) for k, v in selected.items()}


def archive_bytes(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return buffer.getvalue()


class Response(io.BytesIO):
    status = 200


class Tests(unittest.TestCase):
    def test_all_original_pins(self):
        self.assertEqual((r.RUN_ID, r.ATTEMPT, r.ARTIFACT_ID), (41013864895, 1, 12959160518))
        self.assertEqual((r.MEMBERS, r.ZIP_BYTES, r.EXPANDED_BYTES), (34, 3368810, 14837202))
        self.assertEqual(r.ZIP_SHA256, '3eaee1ec332399c8ece875eb748836a01ebb377c5c67860501c24f1eca54c76a')
        self.assertEqual(r.INPUT_PINS, {
            'binaries/bench-core.exe': (1235968, '21ecbd7939bb8cdd76e82cf9ac394557a2b92c3b0676f8ad6bfb272a9b6a9f82'),
            'binaries/bench_core.pdb': (10153984, '7bd5df76e6a68bd5003599ef1825ed1667418fc7a86a7c4b14f47fd5d1a82ee6'),
            'unprotected-capture-00/capture.json': (2923, 'c07891467e66dfd553e4d0001565efb623c07656af2199125d7ed02916d5db8c'),
            'unprotected-capture-00/capture.etl': (3145728, 'fb936cd1054f7995e3891457018e01fcb6218e59cc3b14e4b197580ccc270c3e')})
        self.assertEqual(str(r.ORIGINAL_ROOT), 'D:\\a\\_temp\\coaptic-stack-profile')
        self.assertEqual(r.PROCESS_START, '2026-10-30T06:28:42.3648387+00:00')

    def test_metadata_refuses_other_artifact_run_revision_digest_size(self):
        r.validate_metadata(metadata())
        for key, value in [('id', 1), ('size_in_bytes', 1), ('digest', 'sha256:' + '0' * 64),
                           ('expired', True), ('name', 'other'), ('id', True)]:
            row = metadata(); row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): r.validate_metadata(row)
        for key, value in [('id', 1), ('head_sha', '0' * 40)]:
            row = metadata(); row['workflow_run'][key] = value
            with self.assertRaises(ValueError): r.validate_metadata(row)

    def test_redirect_allows_only_https_storage_without_auth(self):
        url = 'https://example.blob.core.windows.net/artifact?signed=private'
        redirect = urllib.error.HTTPError(r.API + '/zip', 302, 'Found', {'Location': url}, None)
        body = b'zip'
        with patch.object(r, 'ZIP_BYTES', len(body)), patch.object(r, 'ZIP_SHA256', r.sha(body)):
            opener = Mock()
            opener.open.side_effect = [Response(json.dumps(metadata()).encode()), redirect, Response(body)]
            self.assertEqual(r.download(Mock(), 'secret-token', opener)[1], body)
        requests = [c.args[0] for c in opener.open.call_args_list]
        self.assertEqual([x.get_header('Authorization') for x in requests],
                         ['Bearer secret-token', 'Bearer secret-token', None])
        self.assertTrue(all(c.kwargs['timeout'] == 15 for c in opener.open.call_args_list))
        self.assertIsNone(r.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_redirect_refusals_and_signed_url_redaction(self):
        for url in ('http://x.blob.core.windows.net/a', 'https://evil.test/a',
                    'https://x.blob.core.windows.net.evil.test/a', 'https://user@x.blob.core.windows.net/a',
                    'https://x.blob.core.windows.net:444/a', 'https://x.blob.core.windows.net/a#fragment',
                    'https://x.blob.core.windows.net/a\n'):
            with self.subTest(url=url), self.assertRaises(ValueError): r.signed_location(url)
        opener = Mock()
        url = 'https://x.blob.core.windows.net/a?secret=DO_NOT_LOG'
        opener.open.side_effect = [Response(json.dumps(metadata()).encode()),
                                  urllib.error.HTTPError(r.API, 302, 'Found', {'Location': url}, None),
                                  urllib.error.HTTPError(url, 302, 'Found', {'Location': url}, None)]
        with self.assertRaises(ValueError) as caught: r.download(Mock(), 'token', opener)
        self.assertNotIn('DO_NOT_LOG', str(caught.exception))
        self.assertEqual(opener.open.call_count, 3)

    def test_download_refuses_metadata_before_zip_and_missing_redirect(self):
        opener = Mock()
        opener.open.return_value = Response(json.dumps(dict(metadata(), id=1)).encode())
        with self.assertRaises(ValueError): r.download(Mock(), 'token', opener)
        self.assertEqual(opener.open.call_count, 1)
        opener.open.side_effect = [Response(json.dumps(metadata()).encode()), Response(b'not a redirect')]
        with self.assertRaises(ValueError): r.download(Mock(), 'token', opener)

    def test_bounded_reads_and_deadline(self):
        self.assertEqual(r.bounded_read(Response(b'123'), 3, Mock()), b'123')
        with self.assertRaises(ValueError): r.bounded_read(Response(b'1234'), 3, Mock())
        with self.assertRaises(TimeoutError):
            r.bounded_read(Response(b'x'), 3, Mock(check=Mock(side_effect=TimeoutError())))

    def test_unsafe_zip_names_types_and_ratios(self):
        for name in ('../a', '/a', '//server/a', 'C:/a', 'a\\b', 'a//b', 'a/./b', 'a/../b',
                     'a/NUL.txt', 'CON', 'COM1.txt', 'a.', 'a ', 'a:b', 'a\x00b', 'a?b', 'a/'):
            # ZipInfo itself truncates a NUL filename; emulate a hostile decoded entry.
            info = zipfile.ZipInfo('ordinary'); info.filename = name
            with self.subTest(name=name), self.assertRaises(ValueError): r.member_name(info)
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755):
            info = zipfile.ZipInfo('a'); info.external_attr = mode << 16
            with self.assertRaises(ValueError): r.member_name(info)
        for attribute in ('file_size', 'compress_type', 'flag_bits', 'external_attr'):
            info = zipfile.ZipInfo('a')
            setattr(info, attribute, {'file_size': r.MEMBER_LIMIT + 1, 'compress_type': zipfile.ZIP_BZIP2,
                                    'flag_bits': 1, 'external_attr': 0x400}[attribute])
            with self.assertRaises(ValueError): r.member_name(info)
        info = zipfile.ZipInfo('a'); info.file_size = 1001; info.compress_size = 1
        with self.assertRaises(ValueError): r.member_name(info)

    def inspect_fixture(self, entries=None, *, mutate=None, expanded=None):
        selected, build, _ = fixture()
        rows = list(selected.items()) + [('build.json', json.dumps(build).encode()), ('discarded.log', b'discard')]
        rows = rows if entries is None else entries
        data = archive_bytes(rows)
        if mutate: data = mutate(data)
        with patch.multiple(r, ZIP_BYTES=len(data), ZIP_SHA256=r.sha(data), MEMBERS=len(rows),
                            EXPANDED_BYTES=sum(len(v) for _, v in rows) if expanded is None else expanded,
                            INPUT_PINS=pins(selected)):
            return r.inspect_zip(data, Mock())

    def test_zip_all_members_crc_hashed_but_only_four_selected(self):
        selected, manifest, build = self.inspect_fixture()
        self.assertEqual(set(selected), set(r.SELECTED))
        self.assertEqual(len(manifest), 6)
        self.assertEqual(next(x for x in manifest if x['path'] == 'discarded.log')['sha256'], r.sha(b'discard'))
        self.assertEqual(build['sources']['suite']['commit'], r.ORIGINAL_SUITE)

    def test_zip_duplicate_case_prefix_expanded_and_missing(self):
        for rows in ([('a', b''), ('A', b'')], [('a', b''), ('a/b', b'')], [('safe', b'')]):
            with self.assertRaises(ValueError): self.inspect_fixture(rows)
        with self.assertRaises(ValueError): self.inspect_fixture(expanded=1)
        with self.assertRaises(ValueError): r.inspect_zip(b'foreign', Mock())

    def test_zip_crc_checked_even_discarded(self):
        def corrupt(data):
            data = bytearray(data)
            # Change central CRC of the discarded final member; no file extraction.
            offset = data.rfind(b'PK\x01\x02')
            data[offset + 16] ^= 1
            return bytes(data)
        with self.assertRaises(zipfile.BadZipFile): self.inspect_fixture(mutate=corrupt)

    def test_zip_preallocation_member_bound(self):
        def too_many(data):
            data = bytearray(data)
            struct.pack_into('<HH', data, len(data) - 14, 65, 65)
            return bytes(data)
        with patch.object(r.zipfile, 'ZipFile', wraps=zipfile.ZipFile) as constructor:
            with self.assertRaises(ValueError): self.inspect_fixture(mutate=too_many)
            # One invocation creates the fixture; the inspector refuses before constructing another.
            self.assertEqual(constructor.call_count, 1)

    def test_input_pin_refuses_changed_receipt_or_any_bytes(self):
        selected, _, _ = fixture()
        with patch.object(r, 'INPUT_PINS', pins(selected)):
            r.verify_input_pins(selected)
            for name in r.SELECTED:
                other = dict(selected); other[name] += b' '
                with self.assertRaises(ValueError): r.verify_input_pins(other)

    def test_original_paths_receipt_and_scope_not_rewritten(self):
        selected, build, receipt = fixture()
        with patch.object(r, 'INPUT_PINS', pins(selected)):
            original = dict(selected)
            self.assertEqual(r.receipt_inputs(selected, build, r.ORIGINAL_ROOT), receipt)
            self.assertEqual(selected, original)
            with self.assertRaisesRegex(ValueError, 'relocation refused'):
                r.receipt_inputs(selected, build, PureWindowsPath('C:/different/coaptic-stack-profile'))
        for target, key, value in [('config', 'pid', 1), ('config', 'tid', 1), ('config', 'process_start_utc', 'other'),
                                   ('config', 'process_start_utc', '2026-10-30T06:28:42.3648387Z'),
                                   ('config', 'directory', 'C:\\elsewhere'), ('image', 'image_id', 1),
                                   ('image', 'pdb_guid', 'other'), ('root', 'stopped', False),
                                   ('root', 'etl', 'C:\\relocated.etl')]:
            changed = copy.deepcopy(receipt)
            (changed if target == 'root' else changed[target])[key] = value
            current = dict(selected); current[r.SELECTED[2]] = json.dumps(changed).encode()
            with self.subTest(key=key), patch.object(r, 'INPUT_PINS', pins(current)), self.assertRaises(ValueError):
                r.receipt_inputs(current, build, r.ORIGINAL_ROOT)

    def test_receipt_build_input_hash_and_source_crosschecks(self):
        selected, build, _ = fixture()
        with patch.object(r, 'INPUT_PINS', pins(selected)):
            for name in ('sha256', 'pdb_sha256', 'bytes', 'pdb_bytes', 'path'):
                changed = copy.deepcopy(build); changed['native'][name] = 1
                with self.subTest(name=name), self.assertRaises(ValueError):
                    r.receipt_inputs(selected, changed, r.ORIGINAL_ROOT)
            changed = copy.deepcopy(build); changed['sources']['suite']['commit'] = '0' * 40
            with self.assertRaises(ValueError): r.receipt_inputs(selected, changed, r.ORIGINAL_ROOT)

    def test_exclusive_root_and_materialization(self):
        selected, _, _ = fixture()
        with temporary() as tmp, patch.object(r, 'INPUT_PINS', pins(selected)):
            parent = Path(tmp); root = r.fresh_root(parent / 'coaptic-stack-profile', parent)
            with self.assertRaises(FileExistsError): r.fresh_root(root, parent)
            with self.assertRaises(ValueError): r.fresh_root(parent / 'other', parent)
            r.materialize(root, selected)
            self.assertEqual({p.relative_to(root / 'evidence').as_posix() for p in (root / 'evidence').rglob('*') if p.is_file()}, set(r.SELECTED))
            r.verify_materialized(root)
            with self.assertRaises(FileExistsError): r.materialize(root, selected)
            path = root / 'evidence' / r.SELECTED[2]
            self.assertEqual(path.read_bytes(), selected[r.SELECTED[2]])
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError): r.verify_materialized(root)

    def test_reparse_ancestors_refused(self):
        info = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        with patch.object(Path, 'lstat', return_value=info), self.assertRaises(ValueError):
            r.ordinary_path(Path(__file__).absolute())

    def test_build_command_is_tooling_only(self):
        with temporary() as tmp:
            root = Path(tmp); (root / 'evidence').mkdir(); (root / 'tool').mkdir()
            (root / 'tool/x.runtimeconfig.json').write_bytes(b'{}')
            (root / 'tool/x.dll').write_bytes(b'dll')
            args = SimpleNamespace(core='core', expected_core=r.ORIGINAL_CORE, expected_suite='1' * 40)
            with patch.object(r.w, 'source_identity', return_value={}), \
                 patch.object(r.w, 'build_environment', return_value={'GITHUB_TOKEN': 'secret'}), \
                 patch.object(r.w, 'stage_tool_sources', return_value=(root / 'tool-source/x.csproj', {'path': 'staged'})), \
                 patch.object(r.w, 'read_json', return_value={'files': [0] * 8}), \
                 patch.object(r.shutil, 'which', return_value=str(root / 'tool/x.dll')), \
                 patch.object(r.w, 'selected_dotnet_sdk', return_value=(root, 'sdk-info', {})), \
                 patch.object(r, 'sdk_identity', return_value=[]), \
                 patch.object(r.w, 'retain_file', return_value={}), patch.object(r.w, 'command') as command:
                r.build_tool(args, root, Mock(observed_child_working_set_peak=0))
            argv = list(map(str, command.call_args.args[0]))
            self.assertEqual(argv[1], 'build')
            self.assertIn('tool-source', argv[2])
            self.assertIn('-p:UseSharedCompilation=false', argv)
            self.assertNotIn('GITHUB_TOKEN', command.call_args.kwargs['env'])
            self.assertEqual(command.call_count, 1)

    def test_sdk_identity_files_are_bounded_and_version_selected(self):
        with temporary() as tmp:
            sdk = Path(tmp) / '8.0.427'
            for name in ('MSBuild.dll', 'NuGet.Build.Tasks.dll', 'Roslyn/bincore/csc.dll'):
                path = sdk / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'sdk')
            self.assertEqual(len(r.sdk_identity(' Base Path: ' + str(sdk) + '\\')), 3)
            with self.assertRaises(ValueError): r.sdk_identity(' Base Path: ' + str(sdk.parent))
            with self.assertRaises(ValueError): r.sdk_identity('no SDK path')

    def test_export_selection_diagnostic_below_sample_floor(self):
        from test_windows_profile import profile
        selected, _, receipt = fixture()
        value = profile(); value['identity'] = receipt['config']['identity']
        value['scope'].update(pid=r.PID, tid=r.TID)
        value['totals'] = dict(samples=1, weight=1)
        value['stacks'] = [dict(frames=['coaptic::app::poll'], samples=1, weight=1)]
        def command(argv, *args, **kwargs):
            if argv[2] == 'export':
                config = r.w.read_json(argv[4])
                self.assertEqual(config['capture_receipt'], str(root / 'evidence' / r.SELECTED[2]))
                self.assertEqual(list(Path(config['scratch_directory']).iterdir()), [])
                r.w.save(config['output'], value)
        with temporary() as tmp:
            root = Path(tmp); (root / 'evidence').mkdir()
            with patch.object(r.w, 'command', side_effect=command) as calls:
                result = r.export_only(['dotnet', 'tool.dll'], {}, root, Mock(), receipt)
            self.assertEqual([c.args[0][2] for c in calls.call_args_list], ['metadata', 'selftest', 'export'])
            self.assertTrue(result['export_succeeded'])
            self.assertFalse(result['cpu_share_qualified'])
            self.assertFalse(result['qualification']['qualified'])
            self.assertIn('fewer than 200', result['qualification']['reasons'][0])
            self.assertIn('Diagnostic offline replay', (root / 'evidence/replay/profile.html').read_text())

    def test_outer_cleanup_failure_logs_are_structured_and_bounded(self):
        error = RuntimeError('worker cleanup failed')
        error.stdout = b'partial output'; error.stderr = b'export refused'
        error.cleanup_errors = (OSError('settlement refused'),); error.cleanup_unresolved = True
        with temporary() as tmp:
            root = Path(tmp) / 'coaptic-stack-profile'
            args = argparse.Namespace(core='core', expected_core=r.ORIGINAL_CORE,
                                      expected_suite='1' * 40, output=str(root))
            with patch.object(r.w, 'hosted_preflight'), patch.object(r.w, 'source_identity'), \
                 patch.object(r.shutil, 'which', return_value=None), patch.dict(r.os.environ, RUNNER_TEMP=tmp), \
                 patch('suite_process.run_worker', side_effect=error) as run:
                with self.assertRaises(RuntimeError): r.execute(args)
            row = r.w.read_json(root / 'evidence/replay-outer.json')
            self.assertTrue(row['cleanup_unresolved'])
            self.assertEqual(row['cleanup_errors'][0]['detail'], 'settlement refused')
            self.assertEqual(run.call_args.kwargs['timeout'], 900)
            self.assertTrue(run.call_args.kwargs['settle_build_auxiliaries'])
            self.assertEqual(run.call_args.args[0][-2], '_worker')
            self.assertIn(b'export refused', (root / 'evidence/replay-outer.log').read_bytes())

    def test_path_mismatch_retains_original_receipt_and_all_hashes_without_build(self):
        selected, build, _ = fixture()
        with temporary() as tmp:
            root = Path(tmp); (root / 'evidence').mkdir()
            budget = Mock(peak=0, observed_child_working_set_peak=0)
            with patch.object(r.w, 'source_identity', return_value={}), \
                 patch.object(r, 'download', return_value=({}, b'zip')), \
                 patch.object(r, 'inspect_zip', return_value=(selected, [{'sha256': 'manifest'}], build)), \
                 patch.object(r, 'INPUT_PINS', pins(selected)), patch.object(r, 'build_tool') as tooling:
                with self.assertRaisesRegex(ValueError, 'relocation refused'):
                    r.replay_phase(SimpleNamespace(core='core', expected_core='core', expected_suite='suite'), root, budget)
            row = r.w.read_json(root / 'evidence/replay-receipt.json')
            self.assertEqual(row['original_capture_receipt_bytes_utf8'].encode(), selected[r.SELECTED[2]])
            self.assertEqual(row['input_manifest'], [{'sha256': 'manifest'}])
            self.assertFalse(row['export_succeeded']); tooling.assert_not_called()

    def test_worker_requires_handshake_before_any_hosted_action(self):
        with patch.object(r.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(b'bad\n'))), \
             patch.object(r.w, 'hosted_preflight') as hosted, self.assertRaises(ValueError):
            r.worker('unused')
        hosted.assert_not_called()

    def test_failed_export_keeps_diagnostic_no_retry_or_profile(self):
        selected, build, receipt = fixture()
        with temporary() as tmp:
            root = Path(tmp); (root / 'evidence').mkdir()
            def command(argv, budget, log, **kwargs):
                if argv[2] == 'export':
                    diagnostic = root / 'evidence/replay/profile.json.module-diagnostic.json'
                    diagnostic.write_bytes(b'{"identity_match":false}')
                    Path(log).write_bytes(b'identity refused; stderr retained')
                    raise RuntimeError('child exited 2')
            with patch.object(r.w, 'source_identity', return_value={}), \
                 patch.object(r, 'download', return_value=({}, b'zip')), \
                 patch.object(r, 'inspect_zip', return_value=(selected, [], build)), \
                 patch.object(r, 'receipt_inputs', return_value=receipt), patch.object(r, 'materialize'), \
                 patch.object(r, 'build_tool', return_value=(['dotnet', 'tool.dll'], {}, {})), \
                 patch.object(r.w, 'command', side_effect=command) as commands:
                with self.assertRaisesRegex(RuntimeError, 'child exited 2'):
                    r.replay_phase(SimpleNamespace(core='c', expected_core='c', expected_suite='s'), root,
                                   Mock(peak=0, observed_child_working_set_peak=0))
            row = r.w.read_json(root / 'evidence/replay-receipt.json')
            self.assertFalse(row['export_succeeded'])
            self.assertEqual(row['module_diagnostic']['sha256'], r.sha(b'{"identity_match":false}'))
            self.assertFalse((root / 'evidence/replay/profile.json').exists())
            self.assertEqual([c.args[0][2] for c in commands.call_args_list], ['metadata', 'selftest', 'export'])
            self.assertIn(b'stderr retained', (root / 'evidence/replay/export.log').read_bytes())

    def test_conversion_watchdog_preserves_existing_outer_budgets(self):
        budget = r.ReplayBudget(Path(__file__).parent, 830, rss_limit=4 * 1024**3)
        with patch.object(r.w.Budget, 'check') as parent, \
             patch.object(r.w, 'owned_size', return_value=256 * 1024**2 + 1):
            with self.assertRaisesRegex(ValueError, 'conversion workspace'):
                budget.check(force=True)
        parent.assert_called_once_with(force=True)
        self.assertEqual((r.w.BUILD_LIMIT, r.w.EVIDENCE_LIMIT), (8 * 1024**3, 256 * 1024**2))

    def test_workflow_selection_skips_rust_and_preserves_default_capture(self):
        workflow = (r.w.SUITE / '.github/workflows/windows-stack-profile.yml').read_text()
        self.assertIn("if: ${{ !inputs.replay && !inputs.live_replay }}\n        with:\n          toolchain:", workflow)
        self.assertIn('python -B tools/benchmark/windows_profile.py all', workflow)
        self.assertIn('python -B tools/benchmark/windows_replay.py --core', workflow)
        self.assertIn('GITHUB_TOKEN: ${{ github.token }}', workflow)
        ci = (r.w.SUITE / '.github/workflows/ci.yml').read_text()
        self.assertIn('replay: ${{ inputs.stack_profile_replay }}', ci)
        self.assertIn('live_replay: ${{ inputs.stack_profile_live_replay }}', ci)
        self.assertIn('if: ${{ inputs.live_replay }}', workflow)
        self.assertIn('python -B tools/benchmark/windows_live_replay.py --core', workflow)


if __name__ == '__main__':
    unittest.main()
