"""Portable mocks and tiny temporary files only: no native execution or ref changes."""
import argparse
import copy
import gc
import hashlib
import json
from pathlib import Path
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
        def transaction(core, sha, commit, operation, record):
            record.update(source={}, restoration='verified clean initial source')
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
    # Literal observed source namespace: independent of the runner constant.
    name = 'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected'
    return ((name + ': test\n\n1 test, 0 benchmarks\n') if listing else
            ('running 1 test\ntest ' + name + ' ... ok\n\ntest result: ok. 1 passed; '
             '0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n')).encode()


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
                        raw + raw, raw[:-30], raw.replace(b'1 test', b'2 test'),
                        raw.replace(b' ... ok', b' ... FAILED'), raw.replace(b' ... ok', b' ... ignored'),
                        raw + b'other::test: test\ntest other::test ... ok\n'):
                if bad == raw:
                    continue
                with self.subTest(listing=listing, bad=bad), self.assertRaises(ValueError):
                    w.validate_census(bad, listing=listing, expected=w.PRESSURE_TESTS)
        for expected in ((), ('x',), ('x::y', 'x::y')):
            with self.assertRaises(ValueError):
                w.validate_census(b'', expected=expected)

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
                    expr = expr.replace('inputs.' + name, str(val))
                return bool(eval(expr.replace('&&', ' and ').replace('||', ' or ').replace('!', ' not '),
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


if __name__ == '__main__':
    unittest.main()
