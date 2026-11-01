"""Portable mocks and tiny temporary files only: no native execution or ref changes."""
import argparse
import copy
import gc
import hashlib
import json
from pathlib import Path, PureWindowsPath
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import admission_wall_screen as w
from suite_process import WorkerError, WorkerResult
from test_native_lock import BASE, SYN3, MANIFEST


def wall(profile='default', security='unprotected', latency=100):
    value = dict(operations=60000, warmup=128, security=security, black_box=True,
                 measurement=w.MEASUREMENT, latencies_ns=[latency] * 60000,
                 clock_calibration_ns=[0] * 4096)
    if profile == 'small-device':
        value.update(w.SMALL, scope=w.SMALL_SCOPE,
                     memory=dict(w.MEMORY_FIXED, **{k: 4096 for k in w.MEMORY_DYNAMIC}))
    return value


def census(listing=False):
    if listing:
        return ('\r\n'.join(n + ': test' for n in w.WALL_TESTS) + '\r\n\r\n4 tests, 0 benchmarks\r\n').encode()
    return ('running 4 tests\r\n' + '\r\n'.join('test ' + n + ' ... ok' for n in w.WALL_TESTS) +
            '\r\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.01s\r\n').encode()




def worker_error(unsettled=False):
    return WorkerError(['python'], TimeoutError('worker killed'),
                       [RuntimeError('Job exit proof unavailable')] if unsettled else [],
                       b'kept stdout', b'kept stderr', 5, None)


class TempTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='admission-mocks-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        (self.root / 'evidence').mkdir()

    def write(self, name, value):
        path = self.root / 'evidence' / name
        path.write_bytes(w.ds.encoded(value))


class ProtocolTests(unittest.TestCase):
    def test_default_is_exactly_seven_fields_and_source_derived(self):
        value = wall()
        self.assertEqual(len(value), 7)
        result = w.validate_wall(value, 'default', 'unprotected')
        self.assertEqual(result['completion'], 60128)
        self.assertEqual(result['capacities'], w.DEFAULT)
        self.assertIn('source-derived', result['completion_basis'])
        for extra in ('verified', 'capacities', 'profile', 'memory'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                w.validate_wall(dict(value, **{extra: 60128}), 'default', 'unprotected')

    def test_all_four_cells_actual_schema(self):
        for profile, security in w.plan()['cells']:
            with self.subTest(profile=profile, security=security):
                w.validate_wall(wall(profile, security), profile, security)

    def test_small_all_fields_and_types_are_checked(self):
        value = wall('small-device')
        for key in w.SMALL:
            broken = copy.deepcopy(value)
            broken[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                w.validate_wall(broken, 'small-device', 'unprotected')
        for key in value['memory']:
            broken = copy.deepcopy(value)
            broken['memory'][key] = True
            with self.subTest(memory=key), self.assertRaises(ValueError):
                w.validate_wall(broken, 'small-device', 'unprotected')
        for key in ('scope', 'measurement', 'black_box', 'operations', 'warmup', 'security'):
            broken = copy.deepcopy(value)
            del broken[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                w.validate_wall(broken, 'small-device', 'unprotected')

    def test_counts_uint128_zero_and_nonfinite(self):
        for key, count in (('latencies_ns', 60000), ('clock_calibration_ns', 4096)):
            for invalid in (-1, 2**128, True, 1.5, float('nan'), float('inf'), '1'):
                value = wall()
                value[key][5] = invalid
                with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError):
                    w.validate_wall(value, 'default', 'unprotected')
            for change in (-1, 1):
                value = wall()
                value[key] = [1] * (count + change)
                with self.assertRaises(ValueError):
                    w.validate_wall(value, 'default', 'unprotected')
        value = wall()
        value['latencies_ns'][0] = 0
        value['latencies_ns'][1] = 2**128 - 1
        w.validate_wall(value, 'default', 'unprotected')
        with self.assertRaisesRegex(ValueError, 'nonpositive'):
            w.validate_wall(wall(latency=0), 'default', 'unprotected')

    def test_json_rejects_duplicates_truncation_nonfinite_and_size(self):
        for raw in (b'{"a":1,"a":2}', b'{', b'{"a":NaN}', b'{"a":Infinity}', b'x' * (w.LOG_LIMIT + 1)):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                w.read_json(raw)

    def test_exact_native_census_source_frozen(self):
        source = (w.SUITE / w.FIXTURE).read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(hashlib.sha256(source).hexdigest(), w.FIXTURE_LF_SHA256)
        names = w.re.findall(rb'#\[test\]\s+fn (wall_\w+)\(', source)
        for match in w.re.finditer(rb'#\[test\]\s+fn (wall_\w+)\(', source):
            modules = w.re.findall(rb'^mod (\w+) \{', source[:match.start()], w.re.M)
            self.assertEqual(modules[-1], b'batch_tests')
        self.assertEqual(sorted('batch_tests::' + n.decode() for n in names), sorted(w.WALL_TESTS))
        self.assertEqual(len(w.WALL_TESTS), 4)

    def test_observed_native_module_listing_and_completion(self):
        # Literal qualified names from run 41084281643, independent of WALL_TESTS.
        listing = b'''batch_tests::wall_cli_bounds_and_mixed_flag_refusal: test
batch_tests::wall_exact_presets_both_payloads_verify_without_growth: test
batch_tests::wall_full_metadata_and_complete_payload_are_required: test
batch_tests::wall_missing_bad_response_and_authentication_refuse_then_recover: test

4 tests, 0 benchmarks
'''
        completed = b'\n'.join(b'test ' + row[:-6] + b' ... ok' for row in listing.splitlines()
                                if row.endswith(b': test'))
        completed += (b'\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; '
                      b'24 filtered out; finished in 0.01s\n')
        for raw, is_listing in ((listing, True), (completed, False)):
            for newline in (b'\n', b'\r\n'):
                observed = raw.replace(b'\n', newline)
                self.assertEqual(w.validate_census(observed, is_listing), list(w.WALL_TESTS))
                with self.assertRaises(ValueError):
                    w.validate_census(observed.replace(b'batch_tests::', b'tests::'), is_listing)

    def test_census_refuses_empty_extra_duplicate_failed_ignored(self):
        for listing in (False, True):
            raw = census(listing)
            self.assertEqual(w.validate_census(raw, listing), list(w.WALL_TESTS))
            variants = [b'', raw.replace(w.WALL_TESTS[0].encode(), b'tests::wall_unknown'),
                        raw.replace(w.WALL_TESTS[0].encode(), w.WALL_TESTS[1].encode()),
                        raw + raw, raw.replace(b'4 tests', b'0 tests') if listing else
                        raw.replace(b'4 passed', b'0 passed')]
            if not listing:
                variants += [raw.replace(b' ... ok', b' ... ignored', 1),
                             raw.replace(b'0 failed', b'1 failed'), raw.replace(b'0 ignored', b'1 ignored')]
            for broken in variants:
                with self.subTest(listing=listing, broken=broken[:50]), self.assertRaises(ValueError):
                    w.validate_census(broken, listing)


class AnalysisTests(unittest.TestCase):
    def test_schedule_counts_fresh_serial_order_and_mid_bound(self):
        rows = w.schedule()
        self.assertEqual(len(rows), 16)
        self.assertEqual([r['index'] for r in rows], list(range(16)))
        for offset in range(0, 16, 4):
            self.assertEqual(''.join(r['arm'] for r in rows[offset:offset + 4]), 'ABBA')
            self.assertEqual([r['round'] for r in rows[offset:offset + 4]], ['AB', 'AB', 'BA', 'BA'])
        self.assertEqual(16 * w.OPERATIONS, 960000)
        self.assertEqual(16 * w.WARMUP, 2048)
        self.assertLess(w.OPERATIONS + w.WARMUP, 65536)

    def test_gates_exact_boundaries(self):
        for mean, upper, mode, expected in ((.99, .999999, 'unprotected', True),
                (.99, 1, 'unprotected', False), (.990001, .999, 'unprotected', False),
                (1.01, 1.02, 'oscore', True), (.9, 1.020001, 'oscore', False),
                (0, .99, 'unprotected', False), (.9, float('nan'), 'oscore', False),
                (True, 1, 'oscore', False)):
            self.assertEqual(w.gate(mean, upper, mode), expected)

    def test_quantiles_linear_equal_tail(self):
        self.assertAlmostEqual(w.quantile([0, 10, 20, 30], .025), .75)
        self.assertAlmostEqual(w.quantile([0, 10, 20, 30], .975), 29.25)

    def test_ba_normalizes_B_over_A_and_seed_resets(self):
        a, b = [100] * 60000, [98] * 60000
        ab = w.compare({'A': a, 'B': b}, 'unprotected')
        ba = w.compare({'B': b, 'A': a}, 'unprotected')
        self.assertEqual(ab, ba)
        self.assertEqual(ab['mean_B_over_A'], .98)
        self.assertEqual(ab['upper95'], .98)
        self.assertTrue(ab['passed'])
        self.assertEqual(ab['block_means_ns']['A'], [100] * 60)

    def test_outlier_and_zero_kept_no_calibration_subtraction(self):
        a, b = [100] * 60000, [98] * 60000
        a[0], a[999] = 0, 100000
        with patch.object(w, 'REPLICATES', 20):
            result = w.compare({'A': a, 'B': b}, 'unprotected')
        self.assertEqual(result['block_means_ns']['A'][0], w.math.fsum(a[:1000]) / 1000)
        self.assertAlmostEqual(result['arm_mean_ns']['A'], w.math.fsum(a) / 60000)
        self.assertFalse(w.plan()['calibration_subtracted'])

    def test_bootstrap_independent_arms_exact_replicates(self):
        rng = Mock()
        rng.choices.side_effect = lambda values, k: list(values)
        with patch.object(w.random, 'Random', return_value=rng) as constructor:
            w.compare({'A': [100] * 60000, 'B': [99] * 60000}, 'unprotected')
        constructor.assert_called_once_with(20261030)
        self.assertEqual(rng.choices.call_count, 20000)
        self.assertEqual(rng.choices.call_args_list[0].args[0], [100] * 60)
        self.assertEqual(rng.choices.call_args_list[1].args[0], [99] * 60)

    def test_inconclusive_zero_resample_refuses(self):
        rng = Mock()
        rng.choices.side_effect = [[0] * 60, [100] * 60]
        a = [0] * 59000 + [1] * 1000
        with patch.object(w.random, 'Random', return_value=rng), self.assertRaisesRegex(ValueError, 'inconclusive'):
            w.compare({'A': a, 'B': [100] * 60000}, 'unprotected')

    def test_zero_numerator_resample_is_retained(self):
        rng = Mock()
        rng.choices.side_effect = [[100] * 60, [0] * 60, [100] * 60, [100] * 60]
        with patch.object(w.random, 'Random', return_value=rng), patch.object(w, 'REPLICATES', 2):
            result = w.compare({'A': [100] * 60000, 'B': [100] * 60000}, 'oscore')
        self.assertEqual(result['lower95'], .025)
        self.assertEqual(result['upper95'], .975)


class TransactionTests(unittest.TestCase):
    def run_transaction(self, failure=None, edit=False, branch=False):
        events, record = [], {}
        context = Mock()
        context.stage = Mock(return_value={'selected_sha256': 'selected'})
        context.restore = Mock(side_effect=lambda *a: events.append('restore-lock'))
        def git(core, *args):
            if args[0] == 'rev-parse':
                return 'initial-branch' if branch else 'HEAD'
            if args[0] == 'symbolic-ref':
                return 'initial-branch'
            if args[0] == 'checkout':
                events.append(('checkout', args[1:]))
                return ''
            self.fail('unexpected git ' + str(args))
        source = {'files': {}, 'identity': {}}
        def operation(lock):
            events.append('worker')
            if failure:
                raise failure
            return 42
        def gate(*args):
            if edit and 'restore-lock' in events:
                raise ValueError('unexpected edit preserved')
        with patch.object(w, 'source_gate', side_effect=gate), patch.object(w, 'snapshot', return_value=source), \
             patch.object(w.ds, 'git', side_effect=git), patch.object(w, 'check_files'), \
             patch.object(w, 'NativeStage', return_value=context):
            try:
                result = w.transaction('core', 'suite', w.CANDIDATE, operation, record)
                self.assertEqual(result, 42)
            except BaseException as caught:
                error = caught
            else:
                error = None
        return events, record, context, error

    def test_success_restores_lock_before_known_initial_ref(self):
        for branch in (False, True):
            events, record, context, error = self.run_transaction(branch=branch)
            self.assertIsNone(error)
            self.assertEqual(events[1:3], ['worker', 'restore-lock'])
            self.assertEqual(events[-1], ('checkout', ('initial-branch',) if branch else ('--detach', w.BASELINE)))
            self.assertEqual(record['restoration'], 'verified clean initial source')
            context.restore.assert_called_once()

    def test_killed_but_settled_worker_restores_and_preserves_primary(self):
        original = worker_error()
        events, record, context, error = self.run_transaction(original)
        self.assertIs(error, original)
        self.assertEqual(record['restoration'], 'verified clean initial source')
        self.assertFalse(record['cleanup_unresolved'])
        self.assertEqual(events[1:3], ['worker', 'restore-lock'])

    def test_unsettled_and_unknown_custody_never_exit_context_or_checkout(self):
        for original in (worker_error(True), KeyboardInterrupt('unknown owner death')):
            events, record, context, error = self.run_transaction(original)
            self.assertIs(error, original)
            self.assertTrue(error.cleanup_unresolved)
            self.assertIn('UNKNOWN', record['restoration'])
            self.assertEqual(len(events), 2)
            context.restore.assert_not_called()

    def test_unknown_edit_refuses_core_restore_and_keeps_failure_note(self):
        events, record, context, error = self.run_transaction(worker_error(), edit=True)
        self.assertEqual(len([e for e in events if isinstance(e, tuple)]), 1)
        self.assertIn('refused', record['restoration'])
        self.assertIn('unexpected edit preserved', '\n'.join(error.__notes__))

    def test_successful_worker_unknown_edit_is_failure(self):
        events, record, context, error = self.run_transaction(edit=True)
        self.assertIsInstance(error, ValueError)
        self.assertIn('refused', record['restoration'])


class ExecutionTests(TempTests):
    def test_separate_build_measure_handoff_and_refusal_of_repeat(self):
        root = self.root / 'coaptic-admission-wall'
        args = argparse.Namespace(command='build', output=str(root), core='core', expected_suite='a' * 40)
        prepared = {'tools': {}}
        def build(args, root, owner):
            w.save(root, 'build.json', prepared)
        def launch(root, name, spec, env, **kwargs):
            (root / 'measure-task.json').write_bytes(b'{}')
            w.save(root, 'result.json', {'passed': True})
        with patch.object(w.sys, 'platform', 'win32'), \
             patch.dict(w.os.environ, {'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_TEMP': str(self.root)}), \
             patch.object(w.shutil, 'which', return_value=None), patch.object(w, 'owner', return_value={}), \
             patch.object(w, 'source_gate'), patch.object(w, 'preflight', return_value={}), \
             patch.object(w, 'build', side_effect=build), patch.object(w, 'verify_build', return_value=prepared), \
             patch.object(w, 'environment', return_value={}), patch.object(w, 'launch', side_effect=launch) as run:
            w.execute(args)
            self.assertTrue((root / 'evidence/build-complete.json').is_file())
            args.command = 'measure'
            w.execute(args)
            self.assertTrue((root / 'evidence/build-final-source-check.json').is_file())
            self.assertTrue((root / 'evidence/measure-final-source-check.json').is_file())
            with self.assertRaisesRegex(ValueError, 'one attempt'):
                w.execute(args)
            self.assertEqual(run.call_count, 1)

    def stage_fixture(self, requirement='3'):
        core = self.root / 'core'
        manifest = core / 'crates/coaptic-io/Cargo.toml'
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes(MANIFEST.replace(b'version = "2"', ('version = "' + requirement + '"').encode()))
        native = self.root / 'native'
        native.mkdir()
        (native / 'Cargo.lock').write_bytes(BASE)
        (native / 'Cargo.syn3.lock').write_bytes(SYN3)
        return core, native

    def test_plain_staging_gc_has_no_restoration(self):
        core, native = self.stage_fixture()
        stage = w.NativeStage(core, native)
        receipt = stage.stage()
        self.assertEqual(receipt['selected_sha256'], hashlib.sha256(SYN3).hexdigest())
        self.assertEqual((native / 'Cargo.lock').read_bytes(), SYN3)
        self.assertNotIn('__del__', w.NativeStage.__dict__)
        self.assertNotIn('__exit__', w.NativeStage.__dict__)
        del stage
        gc.collect()
        self.assertEqual((native / 'Cargo.lock').read_bytes(), SYN3)

    def test_plain_staging_explicit_restore_and_unknown_edit_refusal(self):
        core, native = self.stage_fixture()
        stage = w.NativeStage(core, native)
        stage.stage()
        stage.restore()
        self.assertEqual((native / 'Cargo.lock').read_bytes(), BASE)
        stage.stage()
        (native / 'Cargo.lock').write_bytes(b'unexpected edit')
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            stage.restore()
        self.assertEqual((native / 'Cargo.lock').read_bytes(), b'unexpected edit')

    def test_plain_staging_validates_exact_alternate_and_requirement(self):
        core, native = self.stage_fixture('4')
        with self.assertRaisesRegex(ValueError, 'syn.version'):
            w.NativeStage(core, native)
        (native / 'Cargo.syn3.lock').write_bytes(BASE)
        with self.assertRaisesRegex(ValueError, 'edge differs'):
            w.NativeStage(core, native)

    def test_finite_budgets_fit_shared_wrapper(self):
        self.assertEqual((w.BUILD_SECONDS, w.CARGO_SECONDS, w.CARGO_OUTER), (830, 400, 450))
        self.assertEqual((w.MEASURE_SECONDS, w.MEASURE_OUTER, w.PROCESS_SECONDS), (300, 450, 30))
        self.assertLessEqual(2 * w.CARGO_OUTER, 900)
        self.assertEqual(w.BUILD_LIMIT, 8 * 1024**3)
        self.assertEqual(w.EVIDENCE_LIMIT, 64 * 1024**2)
        self.assertEqual(w.LOG_LIMIT, 2 * 1024**2)

    def test_launch_structured_failure_and_both_logs_preserved(self):
        original = worker_error(True)
        with patch.object(w, 'run_worker', side_effect=original) as run:
            with self.assertRaises(WorkerError):
                w.launch(self.root, 'A', {'kind': 'cargo'}, {}, timeout=450, build=True)
        self.assertEqual(run.call_args.kwargs['timeout'], 450)
        self.assertTrue(run.call_args.kwargs['settle_build_auxiliaries'])
        self.assertEqual((self.root / 'evidence/A-outer.stdout').read_bytes(), b'kept stdout')
        self.assertEqual((self.root / 'evidence/A-outer.stderr').read_bytes(), b'kept stderr')
        record = w.load(self.root / 'evidence/A-outer.json')
        self.assertTrue(record['cleanup_unresolved'])
        self.assertEqual(record['primary']['error'], 'TimeoutError')
        self.assertEqual(len(record['cleanup_errors']), 1)
        self.assertNotIn('etw_stop_proof', record)

    def test_launch_success_does_not_exceed_owner_timeout(self):
        for field in (False, True):
            name = str(field)
            result = WorkerResult([], 0, b'', b'', 2, field)
            with patch.object(w, 'run_worker', return_value=result):
                self.assertIs(w.launch(self.root, name, {}, {}, timeout=400, build=True), result)
            receipt = w.load(self.root / 'evidence' / (name + '-outer.json'))
            self.assertTrue(receipt['descendants_settled'])
            self.assertEqual(receipt['reported_pre_settlement_auxiliaries'], field)

    def test_reporting_failure_does_not_erase_unresolved_custody(self):
        original = worker_error(True)
        with patch.object(w, 'run_worker', side_effect=original), \
             patch.object(w, 'save', side_effect=OSError('receipt disk error')):
            with self.assertRaises(WorkerError) as caught:
                w.launch(self.root, 'A', {}, {}, timeout=450, build=True)
        self.assertIs(caught.exception, original)
        self.assertTrue(caught.exception.cleanup_unresolved)
        self.assertIn('receipt disk error', '\n'.join(caught.exception.__notes__))

    def test_reporting_failure_after_normal_return_remains_settled(self):
        result = WorkerResult([], 0, b'kept', b'', 1, False)
        with patch.object(w, 'run_worker', return_value=result), \
             patch.object(w, 'save', side_effect=OSError('receipt disk error')):
            with self.assertRaises(WorkerError) as caught:
                w.launch(self.root, 'A', {}, {}, timeout=450, build=True)
        self.assertFalse(caught.exception.cleanup_unresolved)
        self.assertEqual(caught.exception.stdout, b'kept')

    def test_environment_no_profile_redirect_and_strict_unknown_guard(self):
        tools = {'rustc': {'path': 'rustc.exe'}}
        with patch.dict(w.os.environ, {'USERPROFILE': 'original-user', 'CARGO_UNKNOWN': 'unsafe'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'unsupported ambient'):
                w.environment(self.root, tools)
        with patch.dict(w.os.environ, {'USERPROFILE': 'original-user'}, clear=True), \
             patch.object(w.ds, 'cargo_inputs', return_value={}):
            env = w.environment(self.root, tools)
        self.assertEqual(env['USERPROFILE'], 'original-user')
        self.assertEqual(env['CARGO_TARGET_DIR'], str(self.root / 'target'))
        self.assertEqual(env['CARGO_HOME'], str(self.root / 'cargo-home'))
        for key, value in w.FLAGS.items():
            self.assertEqual(env[key], value)
        self.assertEqual(env['RUSTC'], 'rustc.exe')

    def test_preflight_observes_memory_and_disk(self):
        with patch('psutil.virtual_memory', return_value=SimpleNamespace(available=1)), \
             patch.object(w.shutil, 'disk_usage', return_value=SimpleNamespace(free=20 * 1024**3)):
            with self.assertRaisesRegex(ValueError, 'RAM/disk'):
                w.preflight(self.root)

    def test_affinity_set_before_child_and_restore_even_failure(self):
        process = Mock()
        current = [2, 5]
        events = []
        def affinity(value=None):
            nonlocal current
            if value is not None:
                current = list(value)
                events.append(list(value))
            return list(current)
        process.cpu_affinity.side_effect = affinity
        with patch('psutil.Process', return_value=process), self.assertRaisesRegex(RuntimeError, 'sample'):
            with w.affinity(self.root):
                self.assertEqual(current, [2])
                events.append('native-created')
                raise RuntimeError('sample failed')
        self.assertEqual(events, [[2], 'native-created', [2, 5]])
        receipt = w.load(self.root / 'evidence/affinity.json')
        self.assertEqual(receipt['allowed_mask'], 36)
        self.assertEqual(receipt['selected_mask'], 4)

    def test_cargo_worker_uses_only_locked_release_tests_then_build(self):
        calls = []
        def command(argv, budget, stem, **kwargs):
            calls.append(argv)
            return census(True) if '--list' in argv else census() if 'wall_' in argv else b'artifacts'
        budget = Mock(root=self.root, observed_child_working_set_peak=20, peak=100)
        with patch.object(w, 'Budget', return_value=budget), patch.object(w, 'child_command', side_effect=command), \
             patch.object(w.wp, 'native_artifact_pair', return_value=(Path('x.exe'), Path('x.pdb'))):
            w.cargo_worker(dict(root=str(self.root), arm='A', seconds=400, cargo='cargo'))
        self.assertEqual(len(calls), 3)
        self.assertTrue(all('--locked' in c and '--release' in c for c in calls))
        self.assertEqual([c[1] for c in calls], ['test', 'test', 'build'])
        self.assertIn('--list', calls[0])
        self.assertIn('--test-threads=1', calls[1])
        self.assertIn('--message-format=json-render-diagnostics', calls[2])

    def test_empty_census_prevents_test_and_build(self):
        budget = Mock(root=self.root)
        with patch.object(w, 'Budget', return_value=budget), patch.object(w, 'child_command', return_value=b'0 tests') as command:
            with self.assertRaises(ValueError):
                w.cargo_worker(dict(root=str(self.root), arm='A', seconds=400, cargo='cargo'))
        self.assertEqual(command.call_count, 1)

    def test_evidence_receipt_capacity_no_overwrite(self):
        w.save(self.root, 'test.json', {'x': 1})
        with self.assertRaises(FileExistsError):
            w.save(self.root, 'test.json', {'x': 2})
        with patch.object(w.wp, 'owned_size', return_value=w.EVIDENCE_LIMIT):
            with self.assertRaises(ValueError):
                w.save(self.root, 'refused.json', {'x': 2})

    def test_child_failure_flushes_logs_and_close_failure_does_not_erase_them(self):
        child = Mock()
        child.lock = threading.Lock()
        child.raw = [bytearray(b'partial stdout'), bytearray(b'partial stderr')]
        child.p.poll.return_value = None
        child.p.returncode = None
        child.error = TimeoutError('inner deadline')
        child.close.side_effect = RuntimeError('close failed')
        budget = Mock(root=self.root)
        with patch.object(w.wp, 'Process', return_value=child):
            with self.assertRaisesRegex(TimeoutError, 'inner deadline'):
                w.child_command(['exe'], budget, 'partial', env={}, seconds=30)
        self.assertEqual((self.root / 'evidence/partial.stdout').read_bytes(), b'partial stdout')
        self.assertEqual((self.root / 'evidence/partial.stderr').read_bytes(), b'partial stderr')
        receipt = w.load(self.root / 'evidence/partial-process.json')
        self.assertEqual(receipt['primary']['error'], 'TimeoutError')
        self.assertEqual(receipt['cleanup'][0]['error'], 'RuntimeError')

    def test_artifact_actual_names_and_copy_corruption_refusal(self):
        target = self.root / 'target'
        target.mkdir()
        exe, pdb = target / 'bench-core.exe', target / 'bench_core.pdb'
        exe.write_bytes(b'executable')
        pdb.write_bytes(b'symbols')
        raw = (json.dumps(dict(reason='compiler-artifact', target=dict(name='bench-core', kind=['bin']),
                               executable=str(exe), filenames=[str(exe), str(pdb)])) + '\n' +
               json.dumps(dict(reason='build-finished', success=True))).encode()
        (self.root / 'evidence/A-build.stdout').write_bytes(raw)
        self.write('A-cargo.json', dict(purpose='stage-a-screen', pressure_tests=[], pressure_proof=None, native_tests=list(w.WALL_TESTS), artifacts=[str(exe), str(pdb)]))
        (self.root / 'evidence/A-tests-list.stdout').write_bytes(census(True))
        (self.root / 'evidence/A-tests.stdout').write_bytes(census())
        result = w.retain_pair(self.root, 'A')
        self.assertEqual(Path(result['pdb']['path']).name, 'bench_core.pdb')
        self.assertEqual(Path(result['exe']['path']).read_bytes(), b'executable')
        source = target / 'other.exe'
        source.write_bytes(b'data')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            w.wp.retain_file(self.root, source, self.root / 'evidence/bad.exe', expected='wrong')


class BindingTests(TempTests):
    def prepared(self):
        args = argparse.Namespace(core='core', expected_suite='a' * 40)
        contract = {'plan': w.plan(), 'expected_suite': args.expected_suite}
        source = dict(identity={'commit': w.BASELINE}, files={})
        records, artifacts = {}, {}
        for arm, commit in w.CORES.items():
            records[arm] = dict(source=dict(identity={'commit': commit}, files={}),
                                restoration='verified clean initial source')
            artifacts[arm] = {}
            directory = self.root / 'evidence' / arm
            directory.mkdir()
            for suffix in ('exe', 'pdb'):
                path = directory / ('bench-core.' + suffix)
                path.write_bytes(suffix.encode())
                artifacts[arm][suffix] = dict(path=str(path), bytes=len(suffix), sha256=w.ds.digest(path))
            self.write(arm + '-cargo.json', dict(purpose='stage-a-screen', pressure_tests=[], pressure_proof=None, native_tests=list(w.WALL_TESTS)))
            (self.root / 'evidence' / (arm + '-tests-list.stdout')).write_bytes(census(True))
            (self.root / 'evidence' / (arm + '-tests.stdout')).write_bytes(census())
        value = dict(owner=contract, purpose='stage-a-screen', plan=w.plan(), flags=w.FLAGS, suite=source, records=records,
                     tools={}, artifacts=artifacts, inputs={'config_files': {}})
        self.write('owner.json', contract)
        self.write('build.json', value)
        return args, contract, source, value

    def test_plan_owner_source_tests_and_final_bytes_bound_before_launch(self):
        args, contract, source, value = self.prepared()
        with patch.object(w, 'source_gate'), patch.object(w, 'snapshot', return_value=source):
            self.assertEqual(w.verify_build(args, self.root, contract), value)
            for mutate in (lambda v: v['plan'].update(operations=1),
                           lambda v: v['owner'].update(expected_suite='b' * 40),
                           lambda v: v['flags'].update(CARGO_INCREMENTAL='1'),
                           lambda v: v['records']['B']['source']['identity'].update(commit=w.BASELINE),
                           lambda v: v['artifacts']['A'].pop('pdb'),
                           lambda v: v['artifacts']['B']['exe'].update(sha256='bad')):
                broken = copy.deepcopy(value)
                mutate(broken)
                self.write('build.json', broken)
                with self.assertRaises(ValueError):
                    w.verify_build(args, self.root, contract)
            self.write('build.json', value)
            Path(value['artifacts']['A']['exe']['path']).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                w.verify_build(args, self.root, contract)

    def test_measurement_pins_receipt_bytes_not_just_self_described_hashes(self):
        path = self.root / 'evidence/build.json'
        path.write_bytes(b'original')
        pins = {'build.json': w.ds.digest(path)}
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'immutable input'):
            w.check_files(self.root / 'evidence', pins)

    def test_measure_all_commands_and_first_gate_failure_stops(self):
        args = dict(output=str(self.root), core='core', expected_suite='a' * 40, command='all')
        prepared = dict(artifacts={a: {'exe': {'path': a + '.exe'}} for a in 'AB'})
        budget = Mock(root=self.root, observed_child_working_set_peak=5)
        context = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
        def command(argv, *a, **kw):
            profile = 'small-device' if '--small-device' in argv else 'default'
            return w.ds.encoded(wall(profile, argv[2], 100 if argv[0] == 'A.exe' else 98))
        with patch.object(w, 'owner', return_value={}), patch.object(w, 'verify_build', return_value=prepared), \
             patch.object(w, 'check_files'), patch.object(w, 'Budget', return_value=budget), \
             patch.object(w, 'affinity', return_value=context), patch.object(w, 'child_command', side_effect=command) as run, \
             patch.object(w, 'compare', return_value={'passed': False}):
            with self.assertRaisesRegex(ValueError, 'Stage A gate failed'):
                w.measure_worker(dict(args=args, prepared_hashes={}))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0], ['A.exe', '60000', 'unprotected', '--small-device'])
        result = w.load(self.root / 'evidence/result.json')
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['completed']), 2)
        self.assertEqual(len(result['not_run']), 14)
        self.assertIn('no merge promotion', result['stage_b'])

    def mocked_measure(self, fail_native=False, fail_final=False):
        args = dict(output=str(self.root), core='core', expected_suite='a' * 40, command='all')
        prepared = dict(artifacts={a: {'exe': {'path': a + '.exe'}} for a in 'AB'})
        budget = Mock(root=self.root, observed_child_working_set_peak=5)
        context = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
        commands, checks = [], []
        def verify(*args):
            checks.append(1)
            if fail_final and len(checks) == 34:
                raise ValueError('final source corruption')
            return prepared
        def command(argv, *args, **kwargs):
            commands.append(argv)
            if fail_native and len(commands) == 3:
                raise RuntimeError('native failed')
            profile = 'small-device' if '--small-device' in argv else 'default'
            return w.ds.encoded(wall(profile, argv[2]))
        with patch.object(w, 'owner', return_value={}), patch.object(w, 'verify_build', side_effect=verify), \
             patch.object(w, 'check_files'), patch.object(w, 'Budget', return_value=budget), \
             patch.object(w, 'affinity', return_value=context), patch.object(w, 'child_command', side_effect=command), \
             patch.object(w, 'compare', return_value={'passed': True}):
            try:
                w.measure_worker(dict(args=args, prepared_hashes={}))
            except Exception as error:
                caught = error
            else:
                caught = None
        return commands, caught, w.load(self.root / 'evidence/result.json')

    def test_full_mocked_sixteen_processes_eight_comparisons(self):
        commands, error, result = self.mocked_measure()
        self.assertIsNone(error)
        self.assertEqual(len(commands), 16)
        self.assertEqual(len(result['comparisons']), 8)
        self.assertTrue(result['passed'])
        self.assertEqual(result['not_run'], [])
        self.assertEqual(result['failed_or_incomplete'], [])
        for command, row in zip(commands, w.schedule()):
            expected = [row['arm'] + '.exe', '60000', row['security']]
            if row['profile'] == 'small-device':
                expected.append('--small-device')
            self.assertEqual(command, expected)
            self.assertNotIn('--wall', command)

    def test_failed_native_is_attempted_not_reported_as_not_run(self):
        commands, error, result = self.mocked_measure(fail_native=True)
        self.assertEqual(len(commands), 3)
        self.assertEqual(str(error), 'native failed')
        self.assertEqual(len(result['completed']), 2)
        self.assertEqual(len(result['failed_or_incomplete']), 1)
        self.assertEqual(len(result['not_run']), 13)

    def test_final_source_failure_prevents_success(self):
        commands, error, result = self.mocked_measure(fail_final=True)
        self.assertEqual(len(commands), 16)
        self.assertIn('final source corruption', str(error))
        self.assertFalse(result['passed'])

    def test_cargo_configuration_bytes_pinned(self):
        path = self.root / 'config.toml'
        path.write_bytes(b'[net]\noffline=true\n')
        inputs = {'config_files': {str(path): w.ds.digest(path)}}
        w.config_check(inputs)
        path.write_bytes(b'[net]\noffline=false\n')
        with self.assertRaisesRegex(ValueError, 'Cargo config'):
            w.config_check(inputs)

    def test_build_overall_remaining_budget_reduces_second_worker(self):
        args = argparse.Namespace(core='core', expected_suite='a' * 40)
        tools = {name: {'path': name, 'sha256': name} for name in ('rustc', 'cargo')}
        records = []
        def transaction(core, sha, commit, operation, record, selected=w.ADMISSION):
            record.update(source={}, suite={}, restoration='verified clean initial source')
            return operation({})
        with patch.object(w.time, 'monotonic', side_effect=[0, 1, 445, 800]), \
             patch.object(w.ds, 'cargo_inputs', return_value={'config_files': {}}), \
             patch.object(w.ds, 'toolchain', return_value=('rustc 1.99.0 (x)\nhost: ' + w.TARGET, 'cargo 1.99.0 (x)', tools)), \
             patch.object(w.ds, 'digest', return_value='hash'), patch.object(w, 'environment', return_value={}), \
             patch.object(w, 'snapshot', return_value={}), patch.object(w, 'transaction', side_effect=transaction), \
             patch.object(w, 'launch', side_effect=lambda *a, **k: records.append((a[2], k))), \
             patch.object(w, 'retain_pair', return_value={}), patch.object(w, 'tool_check'), \
             patch.object(w, 'artifact_check'), \
             patch.object(w, 'source_gate'), patch.object(w.ds, 'host_identity', return_value={}):
            w.build(args, self.root, {})
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0][0]['seconds'], 400)
        self.assertEqual(records[0][1]['timeout'], 450)
        self.assertEqual(records[1][0]['seconds'], 335)
        self.assertEqual(records[1][1]['timeout'], 365)


class ReportingTests(TempTests):
    def test_build_final_receipt_failure_preserves_unresolved_worker(self):
        original = worker_error(True)
        args = argparse.Namespace(core='core', expected_suite='a' * 40)
        tools = {n: {'path': n, 'sha256': n} for n in ('rustc', 'cargo')}
        with patch.object(w.ds, 'cargo_inputs', return_value={}), \
             patch.object(w.ds, 'toolchain', return_value=('rustc 1.99.0 (x)\nhost: ' + w.TARGET, 'cargo 1.99.0 (x)', tools)), \
             patch.object(w.ds, 'digest', return_value='hash'), patch.object(w, 'environment', return_value={}), \
             patch.object(w, 'snapshot', return_value={}), patch.object(w, 'transaction', side_effect=original), \
             patch.object(w, 'save', side_effect=OSError('disk full')), \
             patch.object(w, 'source_gate') as final_source, \
             patch.object(w, 'tool_check') as final_tool:
            with self.assertRaises(WorkerError) as caught:
                w.build(args, self.root, {})
        self.assertIs(caught.exception, original)
        self.assertTrue(original.cleanup_unresolved)
        self.assertTrue(any('build-finally receipt: disk full' in n for n in original.__notes__))
        final_source.assert_not_called()
        final_tool.assert_not_called()

    def test_outer_failure_write_cannot_enable_settled_source_checks(self):
        original = worker_error(True)
        args = argparse.Namespace(command='all', core='core', expected_suite='a' * 40,
                                  output=str(self.root / 'coaptic-admission-wall'))
        def save(root, name, value):
            if name == 'failure.json':
                raise OSError('receipt refused')
        with patch.object(w.sys, 'platform', 'win32'), \
             patch.dict(w.os.environ, RUNNER_ENVIRONMENT='github-hosted', RUNNER_TEMP=str(self.root)), \
             patch.object(w.shutil, 'which', return_value=None), patch.object(w, 'owner', return_value={}), \
             patch.object(w, 'source_gate') as source, patch.object(w, 'preflight', return_value={}), \
             patch.object(w, 'save', side_effect=save), patch.object(w, 'build', side_effect=original):
            with self.assertRaises(WorkerError) as caught:
                w.execute(args)
        self.assertIs(caught.exception, original)
        self.assertTrue(original.cleanup_unresolved)
        self.assertEqual(source.call_count, 1)  # Initial source gate only.
        self.assertTrue(any('outer failure receipt: receipt refused' in n for n in original.__notes__))

    def test_secondary_reporting_errors_remain_notes_and_success_errors_raise(self):
        for original in (worker_error(True), ValueError('first'), KeyboardInterrupt('cancel')):
            w.report_preserving(original, 'receipt', lambda: (_ for _ in ()).throw(OSError('second')))
            self.assertTrue(any('receipt: second' in n for n in original.__notes__))
        with self.assertRaisesRegex(OSError, 'second'):
            w.report_preserving(None, 'receipt', lambda: (_ for _ in ()).throw(OSError('second')))


def pressure_census(listing=False):
    # Literal source namespace and census, independent of the runner constant.
    names = (
        'admission_pressure::block2_notification_under_rx_pressure_preserves_body_and_completes_oscore',
        'admission_pressure::block2_notification_under_rx_pressure_preserves_body_and_completes_unprotected',
        'admission_pressure::observe_cancel_under_tx_pressure_releases_relation_and_recovers_oscore',
        'admission_pressure::observe_cancel_under_tx_pressure_releases_relation_and_recovers_unprotected',
        'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_oscore',
        'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected',
        'admission_pressure::tx_credit_survives_refusal_and_release_recovers_oscore',
        'admission_pressure::tx_credit_survives_refusal_and_release_recovers_unprotected')
    return ((''.join(name + ': test\n' for name in names) + '\n8 tests, 0 benchmarks\n') if listing else
            ('running 8 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in names) +
             '\ntest result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; '
             '9 filtered out; finished in 0.01s\n')).encode()


class ProofTests(TempTests):
    def test_pressure_literal_lf_crlf(self):
        for listing in (True, False):
            for ending in (b'\n', b'\r\n'):
                self.assertEqual(w.validate_census(pressure_census(listing).replace(b'\n', ending),
                                 listing=listing, expected=w.PRESSURE_TESTS), list(w.PRESSURE_TESTS))

    def test_pressure_refuses_missing_wrong_extra_duplicate_failed_ignored_truncated(self):
        for listing in (True, False):
            raw = pressure_census(listing)
            for bad in (b'', raw.replace(b'admission_pressure::', b'wrong::'),
                        raw + raw, raw[:-30], raw.replace(b'8 test', b'7 test'),
                        raw.replace(b' ... ok', b' ... FAILED'), raw.replace(b' ... ok', b' ... ignored'),
                        raw + b'other::test: test\ntest other::test ... ok\n'):
                if bad == raw:
                    continue
                with self.subTest(listing=listing, bad=bad), self.assertRaises(ValueError):
                    w.validate_census(bad, listing=listing, expected=w.PRESSURE_TESTS)
        for expected in ((), ('x',), ('x::y', 'x::y')):
            with self.assertRaises(ValueError):
                w.validate_census(b'', expected=expected)

    def test_prior_rx_only_proof_cannot_satisfy_expanded_census(self):
        name = 'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected'
        for listing, raw in (
                (True, name + ': test\n\n1 test, 0 benchmarks\n'),
                (False, 'running 1 test\ntest ' + name + ' ... ok\n\ntest result: ok. 1 passed; '
                 '0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n')):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                w.validate_census(raw.encode(), listing=listing, expected=w.PRESSURE_TESTS)
        self.assertEqual(len(w.PRESSURE_TESTS), 8)

    def test_prior_three_case_proof_cannot_satisfy_protected_rx_census(self):
        names = (
            'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected',
            'admission_pressure::tx_credit_survives_refusal_and_release_recovers_oscore',
            'admission_pressure::tx_credit_survives_refusal_and_release_recovers_unprotected')
        old_listing = ''.join(name + ': test\n' for name in names) + '\n3 tests, 0 benchmarks\n'
        old_execution = ('running 3 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in names) +
                         '\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; '
                         '28 filtered out; finished in 0.00s\n')
        for listing, raw in ((True, old_listing), (False, old_execution)):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                w.validate_census(raw.encode(), listing=listing, expected=w.PRESSURE_TESTS)

    def test_prior_four_and_partial_six_case_proofs_cannot_satisfy_continuations(self):
        original = (
            'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_oscore',
            'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected',
            'admission_pressure::tx_credit_survives_refusal_and_release_recovers_oscore',
            'admission_pressure::tx_credit_survives_refusal_and_release_recovers_unprotected')
        observe = (
            'admission_pressure::observe_cancel_under_tx_pressure_releases_relation_and_recovers_oscore',
            'admission_pressure::observe_cancel_under_tx_pressure_releases_relation_and_recovers_unprotected')
        for names in (original, observe + original):
            n = len(names)
            listing = ''.join(name + ': test\n' for name in names) + f'\n{n} tests, 0 benchmarks\n'
            execution = (f'running {n} tests\n' + ''.join('test ' + name + ' ... ok\n' for name in names) +
                         f'\ntest result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; '
                         '28 filtered out; finished in 0.00s\n')
            for is_listing, raw in ((True, listing), (False, execution)):
                with self.subTest(count=n, listing=is_listing), self.assertRaises(ValueError):
                    w.validate_census(raw.encode(), listing=is_listing, expected=w.PRESSURE_TESTS)

    def test_pressure_source_hash_and_declared_census_guards(self):
        source = (w.SUITE / w.PRESSURE_SOURCE).read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(hashlib.sha256(source).hexdigest(), w.PRESSURE_LF_SHA256)
        with patch.object(w.wp, 'source_identity', return_value={}):
            w.source_gate('core', 'a' * 40, w.BASELINE)
            for field, value in (('PRESSURE_LF_SHA256', 'bad'),
                                 ('PRESSURE_TESTS', ('wrong::test',)),
                                 ('FIXTURE_LF_SHA256', 'bad')):
                with patch.object(w, field, value), self.assertRaises(ValueError):
                    w.source_gate('core', 'a' * 40, w.BASELINE)

    def test_proof_worker_requires_both_censuses_before_binary_build(self):
        for bad_index in (None, 2, 3):
            calls = []
            def command(argv, budget, stem, **kwargs):
                index = len(calls)
                calls.append(argv)
                if index == bad_index:
                    return b'0 tests'
                return [census(True), census(), pressure_census(True), pressure_census(), b'artifacts'][index]
            budget = Mock(root=self.root, observed_child_working_set_peak=20, peak=100)
            with patch.object(w, 'Budget', return_value=budget), patch.object(w, 'child_command', side_effect=command), \
                 patch.object(w.wp, 'native_artifact_pair', return_value=(Path('x.exe'), Path('x.pdb'))):
                spec = dict(root=str(self.root), arm='A', seconds=400, cargo='cargo', purpose='ownership-proof')
                if bad_index is None:
                    w.cargo_worker(spec)
                    receipt = w.load(self.root / 'evidence/A-cargo.json')
                    self.assertEqual(receipt['purpose'], 'ownership-proof')
                    self.assertEqual(receipt['pressure_tests'], list(w.PRESSURE_TESTS))
                    self.assertTrue(receipt['pressure_proof']['passed'])
                    self.assertEqual(receipt['pressure_proof']['execution_log'], 'A-pressure.stdout')
                    self.assertEqual([c[1] for c in calls], ['test'] * 4 + ['build'])
                    self.assertEqual(calls[2][-3:], ['admission_pressure::', '--', '--list'])
                else:
                    with self.assertRaises(ValueError):
                        w.cargo_worker(spec)
                    self.assertEqual(len(calls), bad_index + 1)
                    self.assertTrue(all(c[1] == 'test' for c in calls))

    def test_prepared_proof_requires_both_arms_and_cannot_be_stage_a(self):
        args, contract, source, value = BindingTests.prepared(self)
        args.command = 'proof'
        value['purpose'] = 'ownership-proof'
        for arm in w.CORES:
            self.write(arm + '-cargo.json', dict(purpose='ownership-proof',
                                               pressure_proof=w.pressure_result(arm, 'ownership-proof'),
                                               native_tests=list(w.WALL_TESTS),
                                               pressure_tests=list(w.PRESSURE_TESTS)))
            for suffix, listing in (('-pressure-list.stdout', True), ('-pressure.stdout', False)):
                (self.root / 'evidence' / (arm + suffix)).write_bytes(pressure_census(listing))
        self.write('build.json', value)
        with patch.object(w, 'source_gate'), patch.object(w, 'snapshot', return_value=source):
            self.assertEqual(w.verify_build(args, self.root, contract), value)
            args.command = 'measure'
            with self.assertRaisesRegex(ValueError, 'purpose'):
                w.verify_build(args, self.root, contract)
            args.command = 'proof'
            for arm in w.CORES:
                path = self.root / 'evidence' / (arm + '-pressure.stdout')
                path.write_bytes(b'failed')
                with self.assertRaises(ValueError):
                    w.verify_build(args, self.root, contract)
                path.write_bytes(pressure_census())

    def test_stage_a_prepared_cannot_be_proof(self):
        args, contract, source, value = BindingTests.prepared(self)
        args.command = 'proof'
        with patch.object(w, 'source_gate'), patch.object(w, 'snapshot', return_value=source):
            with self.assertRaisesRegex(ValueError, 'purpose'):
                w.verify_build(args, self.root, contract)

    def test_proof_command_builds_only_and_completion_waits_for_verified_both_arms(self):
        for valid in (True, False):
            root = self.root / 'coaptic-admission-wall'
            args = argparse.Namespace(command='proof', output=str(root), core='core', expected_suite='a' * 40)
            def build(args, root, contract):
                w.save(root, 'build.json', {'purpose': contract['purpose']})
            def verify(args, root, contract):
                if not valid:
                    raise ValueError('B proof incomplete')
                return {}
            with patch.object(w.sys, 'platform', 'win32'), \
                 patch.dict(w.os.environ, {'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_TEMP': str(self.root)}), \
                 patch.object(w.shutil, 'which', return_value=None), patch.object(w, 'source_gate'), \
                 patch.object(w, 'preflight', return_value={}), patch.object(w, 'build', side_effect=build) as build_call, \
                 patch.object(w, 'verify_build', side_effect=verify) as verified, patch.object(w, 'launch') as launch:
                if valid:
                    w.execute(args)
                    receipt = w.load(root / 'evidence/proof-complete.json')
                    self.assertTrue(receipt['passed'])
                    self.assertEqual(receipt['measurements'], 'NOT RUN')
                    self.assertEqual(sorted(receipt['arms']), ['A', 'B'])
                    self.assertEqual(receipt['unimplemented'], w.UNIMPLEMENTED)
                    self.assertEqual(verified.call_count, 2)
                else:
                    with self.assertRaisesRegex(ValueError, 'B proof incomplete'):
                        w.execute(args)
                    self.assertFalse((root / 'evidence/proof-complete.json').exists())
                launch.assert_not_called()
                build_call.assert_called_once()
                self.assertFalse((root / 'evidence/build-complete.json').exists())
            # Tiny exclusively owned temporary mock output only.
            import shutil
            shutil.rmtree(root)

    def test_measure_worker_refuses_proof_before_any_process(self):
        with patch.object(w, 'Budget') as budget, patch.object(w, 'launch') as launch:
            with self.assertRaisesRegex(ValueError, 'cannot launch'):
                w.measure_worker({'args': {'command': 'proof'}})
            budget.assert_not_called()
            launch.assert_not_called()

    def test_owner_purpose_allows_build_measure_handoff(self):
        args = argparse.Namespace(core='core', expected_suite='a' * 40, command='build')
        build = w.owner(args, self.root)
        for command in ('measure', 'all'):
            args.command = command
            self.assertEqual(w.owner(args, self.root), build)
        args.command = 'proof'
        self.assertEqual(w.owner(args, self.root)['purpose'], 'ownership-proof')
        self.assertNotEqual(w.owner(args, self.root), build)

    def test_workflow_all_boolean_routes_and_typed_direct_input(self):
        import itertools
        import re
        ci = (w.SUITE / '.github/workflows/ci.yml').read_text()
        jobs = ci.split('jobs:\n', 1)[1]
        expressions = re.findall(r'^    if: \$\{\{ (.+) \}\}$', jobs, re.M)
        self.assertEqual(len(expressions), 4)
        for event, screen, profile, proof in itertools.product(
                ('push', 'pull_request', 'workflow_dispatch'), (False, True), (False, True), (False, True)):
            def evaluate(expr):
                expr = expr.replace('github.event_name', repr(event))
                for name, val in [('admission_wall_screen', screen), ('stack_profile', profile),
                                  ('admission_pressure_proof', proof)]:
                    expr = re.sub(r'inputs\.' + name + r'\b', str(val), expr)
                expr = expr.replace('inputs.wall_screen_contract', repr('admission'))
                expr = re.sub(r'inputs\.stack_profile_\w+', 'False', expr)
                return bool(eval(re.sub(r'!(?!=)', ' not ', expr.replace('&&', ' and ').replace('||', ' or ')),
                                 {'__builtins__': {}}))
            routed = [evaluate(e) for e in expressions]
            manual = event == 'workflow_dispatch'
            self.assertEqual(routed, [manual and ((profile and screen) or (proof and (not screen or profile))),
                                      not profile and not screen and not proof,
                                      manual and profile and not screen and not proof,
                                      manual and screen and not profile])
        self.assertIn('proof_only: ${{ inputs.admission_pressure_proof }}', ci)
        workflow = (w.SUITE / '.github/workflows/admission-wall-screen.yml').read_text()
        self.assertEqual(workflow.count('      proof_only:'), 2)
        self.assertEqual(workflow.count('        type: boolean\n        default: false'), 2)
        self.assertIn("PROOF_ONLY: ${{ inputs.proof_only }}", workflow)
        self.assertIn("$env:PROOF_ONLY -cnotin @('true', 'false')", workflow)
        self.assertIn("if ($env:PROOF_ONLY -ceq 'true') { 'proof' } else { 'all' }", workflow)
        self.assertNotRegex(workflow, r'run:.*\$\{\{ inputs\.')


class StartingHeadGoldenTests(unittest.TestCase):
    def test_admission_plan_starting_head_golden(self):
        self.assertEqual(hashlib.sha256(w.ds.encoded(w.plan())).hexdigest(), '3af1f730d1f9e580cf7c4cf7beebfe19c58f323fcab642e10600850519f73e33')

    def test_admission_owner_starting_head_golden(self):
        args = argparse.Namespace(command='build', expected_suite='1'*40, core='C:/core')
        with patch.dict(w.os.environ, {'GITHUB_RUN_ID': 'gold-run', 'GITHUB_RUN_ATTEMPT': '2'}):
            root = Path('C:/gold-root')
            value = w.owner(args, root)
            raw = (w.HERE / 'admission_wall_plan.md').read_bytes()
            canonical_plan = '6e6bcb2378ea7ea4034b75d0f7b25c29bd66730700894343d93cb81eea177296'
            self.assertEqual(value['root'], str(root))
            self.assertEqual(value['core'], str(Path(args.core).resolve()))
            self.assertEqual(value['plan_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(hashlib.sha256(raw.replace(b'\r\n', b'\n')).hexdigest(), canonical_plan)
            # Freeze all logical fields against the original Windows/LF fixture,
            # after separately checking the three host-specific values above.
            value.update(root=str(PureWindowsPath('C:/gold-root')),
                         core=str(PureWindowsPath('C:/core')), plan_sha256=canonical_plan)
            self.assertEqual(hashlib.sha256(w.ds.encoded(value)).hexdigest(),
                             '0044677b30a9b6aefefe6b1b8b3d61f329bc6cdcd7f673d91dfdc8e4ff5d2a6c')

class ContractSelectionTests(TempTests):
    def args(self, contract='dedup-classified', command='all'):
        return dict(contract=contract, command=command, output=str(self.root),
                    core='core', expected_suite='a'*40)

    def test_dedup_frozen_identity_and_scope(self):
        selected = w.resolve_contract('dedup-classified')
        self.assertEqual(selected, w.DEDUP)
        self.assertEqual(w.plan(selected)['cores'], {
            'A': '623c82db1a6606ec86cd56bb52009988b9f0d87e',
            'B': '8f1f138c825f431149ed8a0a7eefbb6be6cb1b6a'})
        self.assertEqual(w.plan(selected)['core_trees'], {
            'A': '4f349c19039de513487dff283289658402593991',
            'B': '598db5cb5bd3851381d783f1bc02ecf664e778a5'})
        self.assertEqual(selected.artifact_prefix, 'dedup-classified-wall-screen')
        self.assertEqual(selected.root, 'coaptic-dedup-classified-wall')
        self.assertEqual(w.plan(selected)['schema'], 'coaptic-dedup-classified-wall/1')
        self.assertEqual(selected.owner_schema, 'coaptic-dedup-classified-owner/1')
        self.assertEqual(w.purpose(argparse.Namespace(**self.args())), 'rejection-screen')
        with self.assertRaises(AttributeError):
            selected.id = 'foreign'
        for phrase in ('Existing', '247s', 'MID 0..60127', 'pinned replies', 'all 16',
                       'replacement', 'spare capacity', 'whole memory', 'No gain established'):
            self.assertIn(phrase, w.plan(selected)['scope'])
        self.assertEqual(w.schedule(selected), w.schedule())

    def test_digest_covers_whole_descriptor_and_scope(self):
        expected = hashlib.sha256(w.ds.encoded(dict(
            descriptor=w.DEDUP._asdict(), plan=w.plan(w.DEDUP)))).hexdigest()
        self.assertEqual(w.binding(w.DEDUP)['contract_sha256'], expected)
        self.assertNotEqual(w.binding(w.DEDUP), w.binding())
        changed = w.DEDUP._replace(preregistration=w.DEDUP.preregistration + ('foreign',))
        self.assertNotEqual(w.binding(changed), w.binding(w.DEDUP))
        with patch.object(w.ds, 'digest', side_effect=AssertionError('admission document read')):
            owner = w.owner(argparse.Namespace(**self.args()), self.root)
        self.assertEqual(owner['plan_sha256'], expected)

    def test_unknown_and_proof_mix_refuse_before_tools(self):
        for identifier, command in [('unknown', 'all'), ('dedup-classified', 'proof')]:
            with patch.object(w, 'source_gate') as source, patch.object(w, 'preflight') as preflight:
                with self.assertRaises(ValueError):
                    w.execute(argparse.Namespace(**self.args(identifier, command)))
                source.assert_not_called()
                preflight.assert_not_called()

    def test_cross_contract_receipts_refuse_even_rehashed(self):
        for name in ('owner', 'build-complete', 'build', 'cargo', 'spec', 'source', 'artifact', 'sample'):
            for selected, foreign in ((w.DEDUP, w.ADMISSION), (w.ADMISSION, w.DEDUP)):
                value = w.bound({'name': name}, foreign)
                value['sha256'] = hashlib.sha256(w.ds.encoded(value)).hexdigest()
                with self.subTest(name=name, selected=selected.id), self.assertRaises(ValueError):
                    w.check_binding(value, selected)

    def test_workers_cannot_select_contract_from_spec(self):
        spec = w.bound(dict(kind='cargo', args=self.args()), w.DEDUP)
        with patch.object(w, 'child_command') as native:
            with self.assertRaises(ValueError):
                w.cargo_worker(spec)
            with self.assertRaises(ValueError):
                w.measure_worker(spec)
            native.assert_not_called()

    def test_tree_predicates_reject_same_commit_wrong_tree(self):
        for arm, commit in w.DEDUP.cores:
            tree = dict(w.DEDUP.trees)[arm]
            w.tree_check(dict(commit=commit, tree=tree), commit, tree)
            with self.assertRaises(ValueError):
                w.tree_check(dict(commit=commit, tree='0'*40), commit, tree)
            with self.assertRaises(ValueError):
                w.tree_check(dict(commit='0'*40, tree=tree), commit, tree)

    def measure(self, failed_process=None, uncertain=False):
        args = self.args()
        prepared = dict(artifacts={a: {'exe': {'path': a+'.exe'}} for a in 'AB'})
        budget = Mock(root=self.root, observed_child_working_set_peak=5)
        context = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
        commands, compared = [], []
        def command(argv, *a, **kw):
            commands.append(argv)
            self.assertEqual(compared, [])
            if len(commands) == failed_process:
                raise RuntimeError('native failed')
            profile = 'small-device' if '--small-device' in argv else 'default'
            return w.ds.encoded(wall(profile, argv[2], 100 if argv[0] == 'A.exe' else 98))
        def compare(arms, security, selected):
            self.assertEqual(len(commands), 16)
            self.assertEqual(selected, w.DEDUP)
            self.assertEqual(arms['A'][0], 100)
            self.assertEqual(arms['B'][0], 98)
            compared.append(security)
            if uncertain:
                raise ValueError('uncertain bootstrap denominator')
            return {'passed': False}
        with patch.object(w, 'owner', return_value={}), patch.object(w, 'verify_build', return_value=prepared),              patch.object(w, 'check_files'), patch.object(w, 'Budget', return_value=budget),              patch.object(w, 'affinity', return_value=context), patch.object(w, 'child_command', side_effect=command),              patch.object(w, 'compare', side_effect=compare):
            with self.assertRaises((ValueError, RuntimeError)):
                w.measure_worker(w.bound(dict(args=args, prepared_hashes={}), w.DEDUP), w.DEDUP)
        return commands, compared, w.load(self.root / 'evidence/result.json')

    def test_all_sixteen_before_eight_failed_gates_and_ba_orientation(self):
        commands, compared, result = self.measure()
        self.assertEqual(len(compared), 8)
        self.assertEqual(result['not_run'], [])
        self.assertEqual(len(result['completed']), 16)
        self.assertFalse(result['passed'])
        w.check_binding(result, w.DEDUP)
        for command, row in zip(commands, w.schedule(w.DEDUP)):
            expected = [row['arm']+'.exe', '60000', row['security']]
            if row['profile'] == 'small-device':
                expected.append('--small-device')
            self.assertEqual(command, expected)

    def test_uncertain_comparison_still_evaluates_all_eight(self):
        commands, compared, result = self.measure(uncertain=True)
        self.assertEqual(len(commands), 16)
        self.assertEqual(len(compared), 8)
        self.assertTrue(all(c['uncertain'] and not c['passed'] for c in result['comparisons']))
        self.assertFalse(result['passed'])

    def test_runtime_failure_retains_attempt_incomplete_notrun(self):
        commands, compared, result = self.measure(failed_process=3)
        self.assertEqual(len(commands), 3)
        self.assertEqual(compared, [])
        self.assertEqual(len(result['completed']), 2)
        self.assertEqual(len(result['failed_or_incomplete']), 1)
        self.assertEqual(len(result['not_run']), 13)
        self.assertFalse(result['passed'])

    def test_literal_workflow_negative_routing(self):
        import itertools
        ci = (w.SUITE / '.github/workflows/ci.yml').read_text()
        expressions = w.re.findall(r'^    if: \$\{\{ (.+) \}\}$', ci.split('jobs:\n', 1)[1], w.re.M)
        for contract, screen, proof, stack, replay in itertools.product(
                ('admission', 'dedup-classified', 'unknown'), (False, True), (False, True),
                (False, True), (False, True)):
            inputs = dict(wall_screen_contract=contract, admission_wall_screen=screen,
                          admission_pressure_proof=proof, stack_profile=stack,
                          stack_profile_replay=replay, stack_profile_live=False,
                          stack_profile_live_replay=False)
            def evaluate(expression):
                expression = expression.replace('github.event_name', repr('workflow_dispatch'))
                expression = w.re.sub(r'inputs\.(\w+)', lambda m: repr(inputs[m[1]]), expression)
                expression = w.re.sub(r'!(?!=)', ' not ', expression)
                return bool(eval(expression.replace('&&', ' and ').replace('||', ' or '),
                                 {'__builtins__': {}}))
            routes = list(map(evaluate, expressions))
            invalid = (contract == 'unknown' or
                       contract == 'dedup-classified' and (not screen or proof) or
                       screen and (stack or replay) or proof and (not screen or stack))
            self.assertEqual(routes[0], bool(invalid), inputs)
            if invalid:
                self.assertFalse(any(routes[1:]), inputs)
        workflow = (w.SUITE / '.github/workflows/admission-wall-screen.yml').read_text()
        self.assertIn("$env:WALL_CONTRACT -cnotin @('admission', 'dedup-classified')", workflow)
        self.assertIn('--contract $env:WALL_CONTRACT', workflow)
        self.assertIn('dedup-classified-wall-screen', workflow)
        self.assertIn('group: admission-wall-screen', workflow)
        self.assertIn('cancel-in-progress: false', workflow)

class DedupPreparedEvidenceTests(TempTests):
    def prepared(self, selected=w.DEDUP):
        args, _, source, value = BindingTests.prepared(self)
        args.command, args.contract, args.output = 'all', selected.id, str(self.root)
        contract = w.owner(args, self.root)
        source = dict(identity=dict(commit=w.baseline(selected), tree=dict(selected.trees)['A']), files={})
        suite = dict(identity=dict(commit=args.expected_suite, tree='b'*40), files={})
        value.update(w.binding(selected), owner=contract, purpose=w.purpose(args),
                     plan=w.plan(selected),
                     suite=w.bound(suite, selected) if selected == w.REGULAR_OPTIONS else suite)
        for arm, commit in selected.cores:
            value['records'][arm] = w.bound(dict(
                source=w.bound(dict(identity=dict(commit=commit, tree=dict(selected.trees)[arm]),
                                    files={}), selected),
                suite=w.bound(suite, selected), restoration='verified clean initial source'), selected)
            for kind in ('exe', 'pdb'):
                value['artifacts'][arm][kind].update(w.binding(selected))
            self.write(arm+'-cargo.json', w.bound(dict(
                purpose=w.purpose(args), pressure_tests=[], pressure_proof=None,
                native_tests=list(w.WALL_TESTS)), selected))
        self.write('owner.json', contract)
        self.write('build.json', value)
        return args, contract, source, suite, value

    def test_prepared_cross_plan_swaps_and_tree_edits_refuse(self):
        args, contract, source, suite, original = self.prepared()
        def snapshot(path):
            return source if str(path) == args.core else suite
        with patch.object(w, 'source_gate'), patch.object(w, 'snapshot', side_effect=snapshot):
            self.assertEqual(w.verify_build(args, self.root, contract), original)
            mutations = [
                lambda v: v.update(plan=w.plan()),
                lambda v: v.update(owner=dict(contract, schema='coaptic-admission-owner/1')),
                lambda v: v.pop('contract_id'),
                lambda v: v['records']['A'].pop('contract_id'),
                lambda v: v['records']['A']['source'].pop('contract_id'),
                lambda v: v['records']['B']['source']['identity'].update(tree='0'*40),
                lambda v: v['records']['B']['suite'].pop('contract_sha256'),
                lambda v: v['artifacts']['A']['exe'].pop('contract_sha256'),
            ]
            for mutate in mutations:
                value = copy.deepcopy(original)
                mutate(value)
                self.write('build.json', value)
                # Rewritten receipt hashes do not authorize this prepared content.
                self.write('build-complete.json', dict(
                    **w.binding(w.DEDUP), prepared_hashes={'build.json': w.ds.digest(
                        self.root / 'evidence/build.json')}))
                with self.assertRaises(ValueError):
                    w.verify_build(args, self.root, contract)
            self.write('build.json', original)
            receipt = w.load(self.root / 'evidence/A-cargo.json')
            receipt.pop('contract_sha256')
            self.write('A-cargo.json', receipt)
            with self.assertRaises(ValueError):
                w.verify_build(args, self.root, contract)

    def test_launch_refuses_foreign_spec_before_worker(self):
        for selected, foreign in ((w.ADMISSION, w.DEDUP), (w.DEDUP, w.ADMISSION)):
            with patch.object(w, 'run_worker') as run:
                with self.assertRaises(ValueError):
                    w.launch(self.root, 'foreign', w.bound({'kind': 'cargo'}, foreign), {},
                             timeout=450, selected=selected)
                run.assert_not_called()

    def test_cargo_tree_mismatch_refuses_before_tools(self):
        args, contract, source, suite, value = self.prepared()
        spec = w.bound(dict(root=str(self.root), arm='B', args=vars(args),
                            source=value['records']['B']['source'],
                            suite=value['records']['B']['suite']), w.DEDUP)
        bad = dict(commit=dict(w.DEDUP.cores)['B'], tree='0'*40)
        with patch.object(w.ds, 'identity', return_value=bad), patch.object(w, 'child_command') as child:
            with self.assertRaises(ValueError):
                w.cargo_worker(spec, w.DEDUP)
            child.assert_not_called()

class StagedSuiteTests(TempTests):
    def fixture(self, requirement='3'):
        self.suite = self.root / 'suite'
        self.native = self.suite / 'tools/benchmark/native'
        self.native.mkdir(parents=True)
        self.core = self.root / 'core'
        manifest = self.core / 'crates/coaptic-io/Cargo.toml'
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes(MANIFEST.replace(b'version = "2"',
                                              ('version = "' + requirement + '"').encode()))
        (self.native / 'Cargo.lock').write_bytes(BASE)
        (self.native / 'Cargo.syn3.lock').write_bytes(SYN3)
        self.held = dict(identity=dict(commit='a'*40, tree='b'*40), files={
            'tools/benchmark/native/Cargo.lock': hashlib.sha256(BASE).hexdigest(),
            'tools/benchmark/native/Cargo.syn3.lock': hashlib.sha256(SYN3).hexdigest()})
        self.stage = w.NativeStage(self.core, self.native)
        self.lock = self.stage.stage()

    def git(self, root, *args):
        self.assertEqual(Path(root), self.suite)
        self.assertEqual(args[0], 'rev-parse')
        return 'a'*40 if args[1] == 'HEAD' else 'b'*40

    def verify(self, status):
        with patch.object(w, 'SUITE', self.suite), patch.object(w, 'NATIVE', self.native), \
                patch.object(w.ds, 'git', side_effect=self.git), \
                patch.object(w.subprocess, 'check_output', return_value=status), \
                patch.object(w.ds, 'identity', side_effect=AssertionError('staged suite is intentionally dirty')):
            w.verify_staged_suite(self.core, 'a'*40, self.held, self.lock)

    def test_owned_syn3_substitution_is_accepted_and_restores(self):
        self.fixture()
        self.assertEqual((self.native / 'Cargo.lock').read_bytes(), SYN3)
        self.verify(b' M tools/benchmark/native/Cargo.lock\0')
        self.stage.restore()
        self.assertEqual((self.native / 'Cargo.lock').read_bytes(), BASE)

    def test_syn2_requires_clean_suite(self):
        self.fixture('2')
        self.verify(b'')
        with self.assertRaises(ValueError):
            self.verify(b' M tools/benchmark/native/Cargo.lock\0')

    def test_staged_index_untracked_and_other_edits_are_refused(self):
        self.fixture()
        for status in (b'', b'M  tools/benchmark/native/Cargo.lock\0', b'?? new-file\0',
                       b' M other.py\0', b' M tools/benchmark/native/Cargo.lock\0?? new-file\0'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.verify(status)

    def test_self_described_selection_cannot_authorize_wrong_lock(self):
        self.fixture()
        status = b' M tools/benchmark/native/Cargo.lock\0'
        self.lock['selected_sha256'] = '0'*64
        with self.assertRaises(ValueError):
            self.verify(status)
        (self.native / 'Cargo.lock').write_bytes(b'foreign')
        self.lock['selected_sha256'] = w.ds.digest(self.native / 'Cargo.lock')
        with self.assertRaises(ValueError):
            self.verify(status)

    def test_git_tree_and_base_hash_remain_mandatory(self):
        self.fixture()
        status = b' M tools/benchmark/native/Cargo.lock\0'
        self.held['identity']['tree'] = '0'*40
        with self.assertRaises(ValueError):
            self.verify(status)
        self.held['identity']['tree'] = 'b'*40
        self.lock['canonical_base_sha256'] = '0'*64
        with self.assertRaises(ValueError):
            self.verify(status)




class RegularOptionsTests(TempTests):
    def args(self, command='all'):
        return argparse.Namespace(contract='regular-option-parser', command=command,
                                  output=str(self.root), core='core', expected_suite='a'*40)

    def test_frozen_descriptor_and_cell_boundaries(self):
        selected = w.resolve_contract('regular-option-parser')
        self.assertIs(selected, w.REGULAR_OPTIONS)
        self.assertEqual(dict(selected.cores), {
            'A': 'c655b3aac485c3b88d3811b4da836b56210fce5b',
            'B': 'ca78a33b2cbf04bf43325b71c103c939caf341e4'})
        self.assertEqual(dict(selected.trees), {
            'A': 'bca85f7b74b322a0f903005b18636d3a8414fe46',
            'B': 'c482d7e288c2fd5f907dd17449018885f71467d0'})
        self.assertEqual(selected.root, 'coaptic-regular-option-parser-wall')
        self.assertEqual(selected.schema, 'coaptic-regular-option-parser-wall/1')
        self.assertEqual(selected.owner_schema, 'coaptic-regular-option-parser-owner/1')
        self.assertEqual(selected.artifact_prefix, 'regular-option-parser-wall-screen')
        self.assertEqual(w.purpose(self.args()), 'replicated-benefit-screen')
        expected = {p: {m: (dict(role='benefit', mean_max=.97, upper_exclusive=1.)
                            if m == 'unprotected'
                            else dict(role='regression', upper_inclusive=1.02))
                        for m in w.wp.MODES} for p in ('small-device', 'default')}
        self.assertEqual(w.plan(selected)['gates'], expected)
        self.assertEqual(w.plan(selected)['native_tests'], list(w.WALL_TESTS))
        self.assertEqual(w.plan(selected)['fixture_lf_sha256'],
                         'a645fdc88dee2aba922013c7af6553d25461d2122a0884cd75c70afa2d472398')
        for profile in ('small-device', 'default'):
            for mode in w.wp.MODES:
                benefit = mode == 'unprotected'
                self.assertTrue(w.gate(.97, .999999, mode, selected, profile=profile))
                self.assertEqual(w.gate(.98, .99, mode, selected, profile=profile), not benefit)
                self.assertEqual(w.gate(.96, 1., mode, selected, profile=profile), not benefit)
                if not benefit:
                    self.assertTrue(w.gate(1.02, 1.02, mode, selected, profile=profile))
                    self.assertFalse(w.gate(1., 1.0200001, mode, selected, profile=profile))
        self.assertEqual(len(w.schedule(selected)), 64)
        self.assertEqual({row['replicate'] for row in w.schedule(selected)}, set(range(4)))
        self.assertEqual(w.plan(selected)['measured_total'], 3840000)
        self.assertEqual(w.plan(selected)['warmup_total'], 8192)
        self.assertEqual(w.plan(selected)['calibration_total'], 262144)
        self.assertIn('performance unproven', w.plan(selected)['scope'])
        self.assertIn('extended-option', w.plan(selected)['scope'])

    def test_profile_required_and_never_selected_from_evidence(self):
        for profile in (None, '', 'SmallDevice', 'foreign'):
            with self.assertRaises(ValueError):
                w.gate(.96, .99, 'unprotected', w.REGULAR_OPTIONS, profile=profile)
            with self.assertRaises(ValueError):
                w.compare({'A': [100] * w.OPERATIONS, 'B': [98] * w.OPERATIONS},
                          'unprotected', w.REGULAR_OPTIONS, profile=profile)
        for mode in ('foreign', None):
            with self.assertRaises(ValueError):
                w.gate(.96, .99, mode, w.REGULAR_OPTIONS, profile='small-device')

    def test_unknown_and_proof_refuse_before_any_process(self):
        for selector, command in [('regular-option-parser', 'proof'),
                                  ('validated-request-options', 'all'), ('generated-response-stream', 'all'), ('borrowed-dedup-retirement', 'all'),
                                  ('unknown', 'all')]:
            args = self.args(command)
            args.contract = selector
            with patch.object(w, 'preflight') as preflight, patch.object(w, 'source_gate') as source, \
                 patch.object(w, 'child_command') as child:
                with self.assertRaises(ValueError):
                    w.execute(args)
                preflight.assert_not_called()
                source.assert_not_called()
                child.assert_not_called()

    def measure(self, timing=96, fail_at=None):
        selected = w.REGULAR_OPTIONS
        args = self.args()
        commands, gates = [], []
        real_compare = w.compare
        def command(argv, *a, **kw):
            self.assertEqual(gates, [])
            commands.append(argv)
            if len(commands) == fail_at:
                raise RuntimeError('source/runtime/resource refusal')
            profile = 'small-device' if '--small-device' in argv else 'default'
            return w.ds.encoded(wall(profile, argv[2], 100 if argv[0] == 'A.exe' else timing))
        def compare(arms, mode, contract, *, profile=None):
            self.assertEqual(len(commands), 64)
            self.assertIn(profile, ('small-device', 'default'))
            self.assertEqual([pair['replicate'] for pair in arms], list(range(4)))
            self.assertTrue(all(pair['arms']['A'][0] == 100 for pair in arms))
            self.assertTrue(all(pair['arms']['B'][0] == timing for pair in arms))
            result = real_compare(arms, mode, contract, profile=profile)
            gates.append(result)
            return result
        prepared = dict(artifacts={a: {'exe': {'path': a+'.exe'}} for a in 'AB'})
        context = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
        with patch.object(w, 'owner', return_value={}), \
             patch.object(w, 'verify_build', return_value=prepared), patch.object(w, 'check_files'), \
             patch.object(w, 'Budget', return_value=Mock(observed_child_working_set_peak=0)), \
             patch.object(w, 'affinity', return_value=context), \
             patch.object(w, 'child_command', side_effect=command), \
             patch.object(w, 'compare', side_effect=compare):
            spec = w.bound(dict(args=vars(args), prepared_hashes={}), selected)
            if timing > 97 or fail_at:
                with self.assertRaises((ValueError, RuntimeError)):
                    w.measure_worker(spec, selected)
            else:
                w.measure_worker(spec, selected)
        return commands, gates, w.load(self.root / 'evidence/result.json')

    def test_all_sixty_four_commands_before_all_eight_real_gates(self):
        commands, gates, result = self.measure()
        self.assertEqual(len(gates), 8)
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['completed']), 64)
        for argv, row in zip(commands, w.schedule(w.REGULAR_OPTIONS)):
            self.assertEqual(argv, [row['arm']+'.exe', '60000', row['security']] +
                             (['--small-device'] if row['profile'] == 'small-device' else []))
        for gate in gates:
            self.assertEqual(gate['mean_B_over_A'], .96)
            self.assertTrue(gate['passed'])
            w.check_binding(gate, w.REGULAR_OPTIONS)
        for index in range(64):
            w.check_binding(w.load(self.root / ('evidence/sample-%02d.json' % index)),
                            w.REGULAR_OPTIONS)

    def test_failed_unprotected_benefits_stop_despite_four_oscore_guards(self):
        commands, gates, result = self.measure(timing=98)
        self.assertEqual(len(commands), 64)
        self.assertEqual(len(gates), 8)
        self.assertEqual([c['passed'] for c in gates], [False, False, True, True, False, False, True, True])
        self.assertFalse(result['passed'])
        self.assertEqual(result['not_run'], [])
        self.assertEqual({c['security'] for c in result['comparisons']}, set(w.wp.MODES))

    def test_first_runtime_failure_retains_incomplete_and_notrun(self):
        commands, gates, result = self.measure(fail_at=3)
        self.assertEqual(len(commands), 3)
        self.assertEqual(gates, [])
        self.assertEqual(len(result['completed']), 2)
        self.assertEqual(len(result['failed_or_incomplete']), 1)
        self.assertEqual(len(result['not_run']), 61)

    def test_foreign_worker_specs_refuse_before_launch_even_rehashed(self):
        import itertools
        for selected, foreign in itertools.permutations(
                (w.ADMISSION, w.DEDUP, w.REGULAR_OPTIONS), 2):
            spec = w.bound(dict(kind='cargo', args=vars(self.args())), foreign)
            spec['sha256'] = hashlib.sha256(w.ds.encoded(spec)).hexdigest()
            with patch.object(w, 'run_worker') as run, patch.object(w, 'child_command') as child:
                with self.assertRaises(ValueError):
                    w.launch(self.root, 'foreign', spec, {}, timeout=450, selected=selected)
                with self.assertRaises(ValueError):
                    w.cargo_worker(spec, selected)
                with self.assertRaises(ValueError):
                    w.measure_worker(spec, selected)
                run.assert_not_called()
                child.assert_not_called()

    def test_selected_baseline_source_transaction_and_restoration(self):
        selected = w.REGULAR_OPTIONS
        events, record = [], {}
        def git(core, *args):
            if args[0] == 'rev-parse':
                return 'HEAD'
            events.append(args)
        stage = Mock(stage=Mock(return_value={'selected_sha256': 'held'}))
        with patch.object(w, 'source_gate') as gate, patch.object(w.ds, 'git', side_effect=git), \
             patch.object(w, 'snapshot', return_value=dict(files={})), patch.object(w, 'check_files'), \
             patch.object(w, 'NativeStage', return_value=stage):
            for arm, commit in selected.cores:
                events.clear()
                w.transaction('core', 'suite', commit, lambda lock: None, record, selected)
                self.assertEqual(gate.call_args_list[-3].args[2], w.baseline(selected))
                if arm == 'A':
                    self.assertEqual(events, [])
                else:
                    self.assertEqual(events, [('checkout', '--detach', commit),
                                              ('checkout', '--detach', w.baseline(selected))])
                self.assertEqual(record['restoration'], 'verified clean initial source')
        self.assertNotEqual(w.baseline(selected), w.BASELINE)

    def test_prepared_cross_contract_and_self_described_edits_refuse_before_process(self):
        args, contract, source, suite, original = DedupPreparedEvidenceTests.prepared(
            self, w.REGULAR_OPTIONS)
        def snapshot(path):
            return source if str(path) == args.core else suite
        mutations = [
            lambda v: v.update(plan=w.plan(w.DEDUP)),
            lambda v: v.update(owner=dict(contract, purpose='rejection-screen')),
            lambda v: v.update(w.binding(w.DEDUP)),
            lambda v: v['records']['A']['source'].update(w.binding(w.DEDUP)),
            lambda v: v['records']['B']['source']['identity'].update(tree='0'*40),
            lambda v: v['records']['B']['suite'].update(w.binding(w.DEDUP)),
            lambda v: v['artifacts']['A']['exe'].update(w.binding(w.DEDUP)),
            lambda v: v['artifacts']['B']['pdb'].update(sha256='0'*64),
        ]
        with patch.object(w, 'source_gate') as gate, patch.object(w, 'snapshot', side_effect=snapshot), \
             patch.object(w, 'child_command') as child:
            self.assertEqual(w.verify_build(args, self.root, contract), original)
            self.assertEqual(gate.call_args.args[2], w.baseline(w.REGULAR_OPTIONS))
            for mutate in mutations:
                value = copy.deepcopy(original)
                mutate(value)
                self.write('build.json', value)
                self.write('build-complete.json', w.bound(dict(prepared_hashes={
                    'build.json': w.ds.digest(self.root / 'evidence/build.json')}), w.REGULAR_OPTIONS))
                with self.assertRaises(ValueError):
                    w.measure_worker(w.bound(dict(args=vars(args), prepared_hashes={
                        'build.json': w.ds.digest(self.root / 'evidence/build.json')}),
                        w.REGULAR_OPTIONS), w.REGULAR_OPTIONS)
            self.write('build.json', original)
            for foreign in (w.ADMISSION, w.DEDUP):
                self.write('A-cargo.json', w.bound(dict(purpose='replicated-benefit-screen',
                    pressure_tests=[], pressure_proof=None, native_tests=list(w.WALL_TESTS)), foreign))
                with self.assertRaises(ValueError):
                    w.verify_build(args, self.root, contract)
            child.assert_not_called()

    def test_workflow_new_selector_routes_and_proof_refusal(self):
        import itertools
        ci = (w.SUITE / '.github/workflows/ci.yml').read_text()
        expressions = w.re.findall(r'^    if: \$\{\{ (.+) \}\}$', ci.split('jobs:\n', 1)[1], w.re.M)
        self.assertEqual(len(expressions), 4)
        for screen, proof, stack in itertools.product((False, True), repeat=3):
            inputs = dict(wall_screen_contract='regular-option-parser',
                          admission_wall_screen=screen, admission_pressure_proof=proof,
                          stack_profile=stack, stack_profile_replay=False,
                          stack_profile_live=False, stack_profile_live_replay=False)
            def evaluate(expression):
                expression = expression.replace('github.event_name', repr('workflow_dispatch'))
                expression = w.re.sub(r'inputs\.(\w+)', lambda m: repr(inputs[m[1]]), expression)
                expression = w.re.sub(r'!(?!=)', ' not ', expression)
                return bool(eval(expression.replace('&&', ' and ').replace('||', ' or '),
                                 {'__builtins__': {}}))
            routes = list(map(evaluate, expressions))
            valid = screen and not proof and not stack
            self.assertEqual(routes, [not valid, False, False, valid])
        workflow = (w.SUITE / '.github/workflows/admission-wall-screen.yml').read_text()
        self.assertIn("-ceq 'regular-option-parser' -and $env:PROOF_ONLY -ceq 'true'", workflow)
        self.assertIn('ref: ${{ env.WALL_BASELINE }}', workflow)
        for _, sha in w.REGULAR_OPTIONS.cores + w.REGULAR_OPTIONS.trees:
            self.assertIn(sha, workflow)


    def test_historical_dedup_and_stage_b_plan_bytes_unchanged(self):
        for value, expected in (
            (w.plan(w.DEDUP), '76db03001435e2e89db2a401107fb03d4513d9c1b49c482539a68a2614716df5'),
            (w.DEDUP._asdict(), 'c79831702aa6c48bc21e80ba7648fea127a606bc4549443a8f6c4b1e3a05deed'),
            (w.binding(w.DEDUP), 'e9f2641f6d7a35e8c4f4ed6a782184f1b27c0c69d29d721a653730a4b9719bb7'),
            (w.plan(w.resolve_contract('admission-stage-b')),
             '161b7fd033cd7c2cc37b203f878b4307de913e2da2b651bacdbe9e84c186a83c')):
            self.assertEqual(hashlib.sha256(w.ds.encoded(value)).hexdigest(), expected)

    def test_selected_cargo_worker_full_exact_census_and_purpose(self):
        selected = w.REGULAR_OPTIONS
        args, contract, source, suite, value = DedupPreparedEvidenceTests.prepared(self, selected)
        spec = w.bound(dict(root=str(self.root), args=vars(args), arm='B',
            source=value['records']['B']['source'], suite=value['records']['B']['suite'],
            purpose='replicated-benefit-screen', cargo='cargo', seconds=400,
            lock={'selected_sha256': 'held'}), selected)
        identity = dict(commit=dict(selected.cores)['B'], tree=dict(selected.trees)['B'])
        pair = (self.root / 'target/bench-core.exe', self.root / 'target/bench-core.pdb')
        with patch.object(w.ds, 'identity', return_value=identity), \
             patch.object(w, 'verify_staged_suite'), patch.object(w, 'check_files'), \
             patch.object(w, 'Budget', return_value=Mock(observed_child_working_set_peak=1, peak=2)), \
             patch.object(w.wp, 'native_artifact_pair', return_value=pair), \
             patch.object(w, 'child_command', side_effect=[census(True), census(), b'cargo-json']) as child:
            # Existing preparation wrote a receipt; remove only that test-owned mock receipt.
            (self.root / 'evidence/B-cargo.json').unlink()
            w.cargo_worker(spec, selected)
            self.assertEqual(len(child.call_args_list), 3)
            commands = [c.args[0] for c in child.call_args_list]
            self.assertEqual(commands[0][-3:], ['wall_', '--', '--list'])
            self.assertEqual(commands[1][-3:], ['wall_', '--', '--test-threads=1'])
            self.assertEqual(commands[2][1], 'build')
            self.assertIn('--locked', commands[2])
            receipt = w.load(self.root / 'evidence/B-cargo.json')
            w.check_binding(receipt, selected)
            self.assertEqual(receipt['purpose'], 'replicated-benefit-screen')
            self.assertEqual(receipt['native_tests'], list(w.WALL_TESTS))
            self.assertEqual(receipt['pressure_tests'], [])







    def test_execute_build_handoff_uses_selected_initial_and_final_baseline(self):
        selected = w.REGULAR_OPTIONS
        args = self.args('build')
        args.output = str(self.root / selected.root)
        def build(args, root, contract):
            w.save(root, 'build.json', w.bound(dict(owner=contract), selected))
        with patch.dict(w.os.environ, RUNNER_ENVIRONMENT='github-hosted', RUNNER_TEMP=str(self.root)), \
             patch.object(w.sys, 'platform', 'win32'), patch.object(w.shutil, 'which', return_value=None), \
             patch.object(w, 'preflight', return_value={}), patch.object(w, 'source_gate') as source, \
             patch.object(w, 'build', side_effect=build), patch.object(w, 'verify_build'):
            w.execute(args)
        self.assertEqual(len(source.call_args_list), 2)
        self.assertTrue(all(c.args[2:] == (w.baseline(selected), selected)
                            for c in source.call_args_list))
        root = Path(args.output)
        w.check_binding(w.load(root / 'evidence/build-complete.json'), selected)
        w.check_binding(w.load(root / 'evidence/owner.json'), selected)


    def test_selected_source_gates_reject_old_baseline_and_wrong_trees(self):
        selected = w.REGULAR_OPTIONS
        with patch.object(w.wp, 'source_identity', return_value={}), \
             patch.object(w.ds, 'identity') as identity:
            for arm, commit in selected.cores:
                core = dict(commit=commit, tree=dict(selected.trees)[arm])
                suite = dict(commit='a'*40, tree='b'*40)
                identity.side_effect = lambda path: core if str(path) == 'core' else suite
                w.source_gate('core', 'a'*40, commit, selected)
                core['tree'] = '0'*40
                with self.assertRaises(ValueError):
                    w.source_gate('core', 'a'*40, commit, selected)
            with self.assertRaises(ValueError):
                w.source_gate('core', 'a'*40, w.BASELINE, selected)

    def test_foreign_build_complete_refuses_before_worker_even_rehashed(self):
        selected = w.REGULAR_OPTIONS
        args = self.args('measure')
        args.output = str(self.root / selected.root)
        for foreign in (w.ADMISSION, w.DEDUP):
            receipt = w.bound(dict(prepared_hashes={'build.json': '0'*64}), foreign)
            with patch.dict(w.os.environ, RUNNER_ENVIRONMENT='github-hosted', RUNNER_TEMP=str(self.root)), \
                 patch.object(w.sys, 'platform', 'win32'), patch.object(w.shutil, 'which', return_value=None), \
                 patch.object(w, 'preflight', return_value={}), patch.object(w, 'source_gate'), \
                 patch.object(w, 'load', return_value=receipt), patch.object(w, 'launch') as launch:
                with self.assertRaises(ValueError):
                    w.execute(args)
                launch.assert_not_called()


    def test_historical_proof_dedup_stage_b_owner_bytes(self):
        for selector, command, expected in (
            ('admission', 'proof', 'f852edb45a149f64ec30f9c6a24ef7b45b9341f5ecb953d95b8ddbe847e48fca'),
            ('dedup-classified', 'all', '9da4f67f533e72fcb466018bd065d8220dc08e733f44551524cbf60fb82ef0f4'),
            ('admission-stage-b', 'all', 'b38cdbba733565dc9f936b53cd86106c9300ee0558286897ccd68aa531b1611a')):
            args = argparse.Namespace(contract=selector, command=command,
                                      expected_suite='1'*40, core='C:/core')
            with patch.dict(w.os.environ, GITHUB_RUN_ID='gold-run', GITHUB_RUN_ATTEMPT='2'):
                value = w.owner(args, Path('C:/gold-root'))
            value.update(root=str(PureWindowsPath('C:/gold-root')),
                         core=str(PureWindowsPath('C:/core')))
            if selector == 'admission':
                value['plan_sha256'] = '6e6bcb2378ea7ea4034b75d0f7b25c29bd66730700894343d93cb81eea177296'
            self.assertEqual(hashlib.sha256(w.ds.encoded(value)).hexdigest(), expected)


class ReplicatedStatisticsTests(TempTests):
    @staticmethod
    def pairs(a=(90, 100, 125, 200), b=(85, 96, 115, 189)):
        return [dict(replicate=i, arms={'A': [a[i]] * w.OPERATIONS,
                                      'B': [b[i]] * w.OPERATIONS}) for i in range(4)]

    def test_schedule_has_every_unique_adjacent_pair_in_frozen_order(self):
        selected = w.REGULAR_OPTIONS
        rows = w.schedule(selected)
        expected = [(k, p, m, order, arm) for k in range(4)
                    for p, m in w.plan(selected)['cells'] for order in ('AB', 'BA') for arm in order]
        self.assertEqual([(r['replicate'], r['profile'], r['security'], r['round'], r['arm'])
                          for r in rows], expected)
        self.assertEqual([r['index'] for r in rows], list(range(64)))
        self.assertEqual(len(set(expected)), 64)
        for i in range(0, 64, 2):
            x, y = rows[i:i + 2]
            self.assertEqual({x['arm'], y['arm']}, {'A', 'B'})
            self.assertEqual({k: v for k, v in x.items() if k not in ('index', 'arm')},
                             {k: v for k, v in y.items() if k not in ('index', 'arm')})
        self.assertEqual(64 * w.OPERATIONS, 3840000)
        self.assertEqual(64 * w.WARMUP, 8192)
        self.assertEqual(64 * w.CALIBRATION, 262144)

    def test_paired_process_bootstrap_matches_independent_reference(self):
        import math
        import random
        pairs = self.pairs()
        actual = w.compare_process_pairs(pairs, 'unprotected', profile='small-device')
        a, b = [90., 100., 125., 200.], [85., 96., 115., 189.]
        expected_rng = random.Random(20261101)
        ratios = []
        for _ in range(10000):
            indices = expected_rng.choices(range(4), k=4)
            ratios.append(math.fsum(b[i] for i in indices) / math.fsum(a[i] for i in indices))
        ratios.sort()
        def percentile(q):
            position = 9999 * q
            low = int(position)
            fraction = position - low
            return ratios[low] * (1 - fraction) + ratios[min(low + 1, 9999)] * fraction
        self.assertEqual(actual['process_means_ns'], dict(A=a, B=b))
        self.assertEqual(actual['arm_mean_ns'], dict(A=math.fsum(a) / 4, B=math.fsum(b) / 4))
        self.assertEqual(actual['mean_B_over_A'], math.fsum(b) / math.fsum(a))
        self.assertEqual(actual['lower95'], percentile(.025))
        self.assertEqual(actual['upper95'], percentile(.975))
        self.assertEqual(actual, w.compare_process_pairs(pairs, 'unprotected', profile='small-device'))
        for arm in 'AB':
            for process, mean in zip(actual['block_means_ns'][arm], actual['process_means_ns'][arm]):
                self.assertEqual(process, [mean] * 60)
        self.assertEqual(actual['block_mean_role'], 'descriptive only')

    def test_large_intervals_in_either_arm_are_never_excluded(self):
        import math
        pairs = self.pairs(a=(100, 100, 100, 100), b=(95, 95, 95, 95))
        pairs[0]['arms']['A'][17] = 4000000
        pairs[1]['arms']['B'][32] = 5000000
        before = [(math.fsum(p['arms']['A']), math.fsum(p['arms']['B'])) for p in pairs]
        result = w.compare_process_pairs(pairs, 'oscore', profile='default')
        self.assertEqual(result['process_means_ns']['A'][0], before[0][0] / 60000)
        self.assertEqual(result['process_means_ns']['B'][1], before[1][1] / 60000)
        self.assertGreater(result['block_means_ns']['A'][0][0], 100)
        self.assertGreater(result['block_means_ns']['B'][1][0], 95)
        self.assertEqual(result['mean_B_over_A'],
                         (math.fsum(y / 60000 for x, y in before) / 4) /
                         (math.fsum(x / 60000 for x, y in before) / 4))
        self.assertEqual([(math.fsum(p['arms']['A']), math.fsum(p['arms']['B'])) for p in pairs], before)

    def test_pair_census_and_invalid_observations_refuse(self):
        original = self.pairs()
        mutations = [lambda p: p.pop(), lambda p: p.append(copy.deepcopy(p[0])),
                     lambda p: p.reverse(), lambda p: p[1].update(replicate=0),
                     lambda p: p[0].update(replicate=False),
                     lambda p: p[0].update(profile='foreign'),
                     lambda p: p[0]['arms'].pop('B'),
                     lambda p: p[0]['arms'].update(C=p[0]['arms']['A']),
                     lambda p: p[0]['arms']['A'].pop(),
                     lambda p: p[0]['arms'].update(A=[0] * 60000),
                     lambda p: p[0]['arms']['B'].__setitem__(0, float('nan'))]
        for mutate in mutations:
            pairs = copy.deepcopy(original)
            mutate(pairs)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                w.compare_process_pairs(pairs, 'unprotected', profile='default')

    def test_unfrozen_source_descriptor_refuses_before_tools_or_native(self):
        frozen = w.REGULAR_OPTIONS
        bad = frozen._replace(cores=(('A', w.baseline(frozen)), ('B', 'DRAFT_UNFROZEN')))
        args = argparse.Namespace(contract='regular-option-parser', command='all')
        with patch.object(w, 'REGULAR_OPTIONS', bad), patch.object(w, 'preflight') as tools, \
             patch.object(w, 'child_command') as child:
            with self.assertRaisesRegex(ValueError, 'DRAFT_UNFROZEN'):
                w.execute(args)
            tools.assert_not_called()
            child.assert_not_called()



if __name__ == '__main__':
    unittest.main()
