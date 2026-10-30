"""Finite hosted Stage A admission screen. No CPU claim or Stage B promotion.

Only the outer process changes core checkout/native lock inputs. Cargo workers
own processes and monitored output, never source restoration. Unresolved cleanup
leaves staged inputs intact and requires retiring the ephemeral VM. Abrupt death
of the outer process leaves restoration UNKNOWN; this is not crash recovery.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import time

import development_suite as ds
import native_lock as locks
from suite_process import run_worker, WorkerError
import windows_profile as wp

HERE, SUITE, NATIVE = ds.HERE, ds.SUITE, ds.NATIVE
BASELINE = '623c82db1a6606ec86cd56bb52009988b9f0d87e'
CANDIDATE = '8782a6a0b0aef2facf51bec884cfe37f2a80f28d'
CORES = {'A': BASELINE, 'B': CANDIDATE}
OPERATIONS, WARMUP, CALIBRATION = 60000, 128, 4096
BLOCK_SIZE, BLOCKS, REPLICATES, SEED = 1000, 60, 10000, 20261030
BUILD_SECONDS, CARGO_SECONDS, CARGO_OUTER = 830, 400, 450
MEASURE_SECONDS, MEASURE_OUTER, PROCESS_SECONDS = 300, 450, 30
BUILD_LIMIT, EVIDENCE_LIMIT, LOG_LIMIT = 8 * 1024**3, 64 * 1024**2, 2 * 1024**2
RESERVE = 4 * 1024**2  # Keep room for failure and final source/settlement receipts.
TARGET = 'x86_64-pc-windows-msvc'
FIXTURE = 'tools/benchmark/native/servers/src/bin/bench-core.rs'
FIXTURE_LF_SHA256 = 'fe144de7598da4b753e668a17a8cbd91033896691a0ee045c5be711e784c0272'
WALL_TESTS = tuple('batch_tests::' + name for name in (
    'wall_cli_bounds_and_mixed_flag_refusal',
    'wall_exact_presets_both_payloads_verify_without_growth',
    'wall_full_metadata_and_complete_payload_are_required',
    'wall_missing_bad_response_and_authentication_refuse_then_recover'))
MEASUREMENT = ('server App::poll with optimizer barriers; request preparation and complete '
               'response verification outside clock; OSCORE responses authenticated; '
               'timer calibration separate and never subtracted')
MEMORY_REMAINING = ('allocator overhead, initialization scratch, generated peak stack and '
                    'runtime memory unknown; nested owners must not be added twice')
SMALL_SCOPE = ('socket-free wall supporting evidence only; fixture input/output copies remain '
               'inside App::poll; not native Mio memory equivalence, server CPU, socket latency, '
               'transport share, whole memory or either 50% acceptance')
SMALL = dict(profile='SmallDevice', pools='Constrained', storage='fixed', payload_bytes=32,
             concurrency=1, message_type='CON', routes=4, populated_routes=1, calls=1,
             deferred=0, associations=1, security_requests=4, blockwise=False, rx_slots=2,
             tx_slots=2, rx_datagram_bytes=1152, tx_datagram_bytes=1152, dedup=4, observe=2,
             rx_body_slots=0, tx_body_slots=0, verified=60128, calibration_samples=4096)
DEFAULT = dict(profile='Default', storage='allocated', payload_bytes=64, concurrency=1,
               message_type='CON', routes=1, populated_routes=1, calls=4, deferred=0,
               associations=1, security_requests=4, blockwise=True, rx_slots=4, tx_slots=4,
               rx_datagram_bytes=1472, tx_datagram_bytes=1472, dedup=8, observe=4,
               rx_body_slots=1, tx_body_slots=2, rx_body_bytes=1024, tx_body_bytes=1024)
MEMORY_FIXED = dict(fixed_pool_heap_bytes=0, transport_input_nested_bytes=1472,
                    transport_output_nested_bytes=1472,
                    separate_latency_requested_bytes=OPERATIONS * 16,
                    separate_calibration_requested_bytes=CALIBRATION * 16,
                    separate_timing_vec_headers_bytes=48, separate_verification_buffer_bytes=1472,
                    separate_representation_static_bytes=32, remaining=MEMORY_REMAINING)
MEMORY_DYNAMIC = ('app_including_transport_inline_bytes', 'transport_nested_in_app_inline_bytes',
                  'separate_optional_client_context_inline_bytes')
FLAGS = dict(RUSTFLAGS='-Cforce-frame-pointers=yes', CARGO_PROFILE_RELEASE_DEBUG='1',
             CARGO_PROFILE_RELEASE_LTO='thin', CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1',
             CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2')


def plan():
    return dict(schema='coaptic-admission-wall/1', cores=CORES,
                cells=[[p, s] for p in ('small-device', 'default') for s in wp.MODES],
                rounds=['AB', 'BA'], operations=OPERATIONS, warmup=WARMUP,
                calibration=CALIBRATION, processes=16, measured_total=960000, warmup_total=2048,
                unique_mids_per_process=60128, block_size=BLOCK_SIZE, blocks=BLOCKS,
                replicates=REPLICATES, seed_reset_each_comparison=SEED,
                quantiles='equal-tail .025/.975; linear interpolation at (n-1)*q',
                gates={'unprotected': {'mean_max': .99, 'upper_exclusive': 1.0},
                       'oscore': {'upper_inclusive': 1.02}},
                timing=MEASUREMENT, calibration_subtracted=False, outliers_removed=False,
                process_retries=0, small=SMALL, default_source_capacities=DEFAULT,
                native_tests=list(WALL_TESTS), flags=FLAGS, target=TARGET,
                budgets=dict(build=BUILD_SECONDS, cargo=CARGO_SECONDS, cargo_outer=CARGO_OUTER,
                             measure=MEASURE_SECONDS, measure_outer=MEASURE_OUTER,
                             native=PROCESS_SECONDS, log=LOG_LIMIT, build_bytes=BUILD_LIMIT,
                             evidence_bytes=EVIDENCE_LIMIT),
                scope='Conditional two-process comparisons, not CPU or general-host proof; '
                      'Stage B pressure/continuation required before any merge promotion')


def schedule():
    return [dict(index=i, profile=p, security=s, round=r, arm=a)
            for i, (p, s, r, a) in enumerate(
                (p, s, r, a) for p, s in plan()['cells'] for r in ('AB', 'BA') for a in r)]


def exact(actual, expected, message):
    # JSON equality alone conflates true and 1.
    if ds.encoded(actual) != ds.encoded(expected):
        raise ValueError(message)


def read_json(raw):
    if len(raw) > LOG_LIMIT:
        raise ValueError('JSON exceeds process allowance')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def load(path):
    with Path(path).open('rb') as stream:
        return read_json(stream.read(LOG_LIMIT + 1))


def save(root, name, value):
    data = ds.encoded(value)
    evidence = Path(root) / 'evidence'
    if len(data) > LOG_LIMIT or wp.owned_size(evidence) + len(data) > EVIDENCE_LIMIT:
        raise ValueError('evidence receipt budget exceeded')
    with (evidence / name).open('xb') as stream:
        stream.write(data)


def samples(values, count):
    if (type(values) is not list or len(values) != count
            or any(type(n) is not int or not 0 <= n < 2**128 for n in values)):
        raise ValueError('timing array count/u128 bound/type')
    return values


def validate_wall(value, profile, security):
    if profile not in ('small-device', 'default') or security not in wp.MODES:
        raise ValueError('unknown cell')
    common = dict(operations=OPERATIONS, warmup=WARMUP, security=security,
                  black_box=True, measurement=MEASUREMENT)
    required = set(common) | {'latencies_ns', 'clock_calibration_ns'}
    if profile == 'small-device':
        common.update(SMALL, scope=SMALL_SCOPE)
        required |= set(SMALL) | {'memory', 'scope'}
    if type(value) is not dict or set(value) != required:
        raise ValueError('actual wall schema mismatch')
    exact({k: value[k] for k in common}, common, 'wall identity/capacities differ')
    values = samples(value['latencies_ns'], OPERATIONS)
    samples(value['clock_calibration_ns'], CALIBRATION)
    if math.fsum(values) <= 0:
        raise ValueError('nonpositive overall timing mean')
    if profile == 'small-device':
        memory = value['memory']
        if type(memory) is not dict or set(memory) != set(MEMORY_FIXED) | set(MEMORY_DYNAMIC):
            raise ValueError('memory ledger schema')
        exact({k: memory[k] for k in MEMORY_FIXED}, MEMORY_FIXED, 'memory ledger values')
        if any(type(memory[k]) is not int or not 0 < memory[k] < 2**64 for k in MEMORY_DYNAMIC):
            raise ValueError('memory ledger size')
    return dict(completion=OPERATIONS + WARMUP,
                completion_basis=('emitted verified field plus pinned successful execution'
                                  if profile == 'small-device' else
                                  'source-derived: pinned wall_run successful exit after every verification'),
                capacities_basis='emitted ledger' if profile == 'small-device' else 'source-derived',
                capacities=SMALL if profile == 'small-device' else DEFAULT)


def quantile(ordered, q):
    index = (len(ordered) - 1) * q
    lo = int(index)
    fraction = index - lo
    return ordered[lo] * (1 - fraction) + ordered[min(lo + 1, len(ordered) - 1)] * fraction


def gate(mean, upper, security):
    if any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in (mean, upper)):
        return False
    if security == 'unprotected':
        return mean <= .99 and upper < 1
    if security == 'oscore':
        return upper <= 1.02
    raise ValueError('unknown security')


def compare(arms, security):
    if set(arms) != {'A', 'B'}:
        raise ValueError('comparison must name A and B, including BA')
    for values in arms.values():
        samples(values, OPERATIONS)
    blocks = {arm: [math.fsum(values[i:i + BLOCK_SIZE]) / BLOCK_SIZE
                    for i in range(0, OPERATIONS, BLOCK_SIZE)] for arm, values in arms.items()}
    means = {a: math.fsum(v) / BLOCKS for a, v in blocks.items()}
    if min(means.values()) <= 0:
        raise ValueError('nonpositive arm mean')
    rng = random.Random(SEED)
    ratios = []
    for _ in range(REPLICATES):
        a = math.fsum(rng.choices(blocks['A'], k=BLOCKS))
        b = math.fsum(rng.choices(blocks['B'], k=BLOCKS))
        if a <= 0:
            raise ValueError('inconclusive zero bootstrap denominator')
        ratios.append(b / a)
    ratios.sort()
    lower, upper = quantile(ratios, .025), quantile(ratios, .975)
    mean = means['B'] / means['A']
    return dict(block_means_ns=blocks, arm_mean_ns=means, mean_B_over_A=mean,
                lower95=lower, upper95=upper, passed=gate(mean, upper, security),
                scope=plan()['scope'])


def validate_census(raw, listing=False):
    text = '\n'.join(raw.decode('utf-8', errors='strict').splitlines())
    pattern = r'^(batch_tests::wall_\w+): test$' if listing else r'^test (batch_tests::wall_\w+) \.\.\. ok$'
    names = re.findall(pattern, text, re.M)
    if sorted(names) != sorted(WALL_TESTS):
        raise ValueError('native wall test census mismatch/empty/duplicate')
    if listing:
        if not re.search(r'^4 tests, 0 benchmarks$', text, re.M):
            raise ValueError('native test listing count mismatch')
    else:
        summaries = re.findall(r'^test result: (.+)$', text, re.M)
        if len(summaries) != 1 or not re.fullmatch(
                r'ok\. 4 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in .+', summaries[0]):
            raise ValueError('native test completion mismatch')
    return list(WALL_TESTS)


def snapshot(root):
    identity = ds.identity(root)
    paths = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z'], timeout=15)
    files = {}
    for relative in paths.decode('utf-8').split('\0'):
        if relative:
            path = Path(root) / relative
            if not path.is_file() or path.is_symlink():
                raise ValueError('nonregular tracked source: ' + relative)
            files[relative] = ds.digest(path)
    return dict(identity=identity, files=files)


def check_files(root, files):
    for name, expected in files.items():
        if ds.digest(Path(root) / name) != expected:
            raise ValueError('immutable input changed: ' + name)


def source_gate(core, suite_sha, core_sha):
    value = wp.source_identity(core, core_sha, suite_sha)
    normalized = (SUITE / FIXTURE).read_bytes().replace(b'\r\n', b'\n')
    if hashlib.sha256(normalized).hexdigest() != FIXTURE_LF_SHA256:
        raise ValueError('unchanged native fixture pin differs')
    names = re.findall(rb'#\[test\]\s+fn (wall_\w+)\(', normalized)
    exact(sorted('batch_tests::' + n.decode() for n in names), sorted(WALL_TESTS), 'source census differs')
    return value


def environment(root, tools):
    ds.cargo_inputs()  # Strict unknown ambient CARGO guard; workflow clears only known defaults.
    env = dict(os.environ)
    env.pop('CARGO_ENCODED_RUSTFLAGS', None)
    for key, relative in {'CARGO_HOME': 'cargo-home', 'CARGO_TARGET_DIR': 'target',
                          'TMP': 'tmp', 'TEMP': 'tmp', 'TMPDIR': 'tmp'}.items():
        path = Path(root) / relative
        path.mkdir(exist_ok=True)
        env[key] = str(path)
    env.update(FLAGS, RUSTC=tools['rustc']['path'], RUSTUP_TOOLCHAIN='1.99.0',
               PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=os.pathsep.join(sys.path))
    return env


class Budget(wp.Budget):
    def check(self, *, force=False):
        super().check(force=force)
        if wp.owned_size(self.root / 'evidence') > EVIDENCE_LIMIT - RESERVE:
            raise ValueError('64 MiB evidence monitor (failure reserve excluded)')
        if shutil.disk_usage(self.root).free < 1024**3:
            raise ValueError('owned volume free space below 1 GiB')


def preflight(root):
    import psutil
    memory = psutil.virtual_memory()
    disk = shutil.disk_usage(root.parent)
    if memory.available < 2 * 1024**3 or disk.free < BUILD_LIMIT + EVIDENCE_LIMIT + 1024**3:
        raise ValueError('insufficient observed available RAM/disk')
    return dict(available_ram=memory.available, available_disk=disk.free,
                python=ds.digest(sys._base_executable), python_version=sys.version,
                runtime_scope='Provisioned Rust/Python outside owned build/registry/tmp 8 GiB; '
                              'RSS/disk sampling is refusal monitoring, not a hard whole-RAM/quota claim')


def child_command(command, budget, stem, *, env, seconds):
    """Flush bounded pipe bytes while running, preserving logs even if worker is killed."""
    if wp.owned_size(budget.root / 'evidence') + LOG_LIMIT + RESERVE > EVIDENCE_LIMIT:
        raise ValueError('insufficient evidence allowance before child launch')
    budget.check(force=True)
    child, primary, cleanup = None, None, []
    streams = [(budget.root / 'evidence' / (stem + suffix)).open('xb')
               for suffix in ('.stdout', '.stderr')]
    offsets = [0, 0]
    def flush():
        if child:
            for i, stream in enumerate(streams):
                with child.lock:
                    data = bytes(child.raw[i][offsets[i]:])
                stream.write(data)
                stream.flush()
                offsets[i] += len(data)
    try:
        child = wp.Process(command, budget, env=env, cwd=SUITE)
        child.p.stdin.close()
        deadline = time.monotonic() + seconds
        while child.p.poll() is None:
            flush()
            budget.check()
            if child.error:
                raise child.error
            if time.monotonic() >= deadline:
                raise TimeoutError('child deadline')
            time.sleep(.02)
        child.finish(1)
        return bytes(child.raw[0])
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if child:
                child.close()
        except BaseException as error:
            cleanup.append(error)
            if primary is not None:
                primary.add_note('child cleanup: ' + str(error)[:1024])
        finally:
            for finish in (flush, *(stream.close for stream in streams)):
                try:
                    finish()
                except BaseException as error:
                    cleanup.append(error)
                    if primary is not None:
                        primary.add_note('child log finalization: ' + str(error)[:1024])
            report_preserving(primary or (cleanup[0] if cleanup else None), 'child-process receipt', lambda: save(budget.root, stem + '-process.json', dict(
                 command=list(map(str, command)), passed=primary is None and not cleanup,
                 returncode=child.p.returncode if child else None,
                 primary=failure(primary) if primary else None,
                 cleanup=[failure(error) for error in cleanup])))
        if cleanup and primary is None:
            raise cleanup[0]


def failure(error):
    result = wp.outer_failure(error)
    result.pop('etw_stop_proof')
    return result


def report_preserving(primary, label, action):
    """Reporting must not replace the exception that owns cleanup custody."""
    try:
        action()
    except BaseException as reporting:
        if primary is None:
            raise
        primary.add_note(label + ': ' + str(reporting)[:1024])


def launch(root, name, spec, env, *, timeout, build=False):
    path = root / (name + '-task.json')
    with path.open('xb') as stream:
        stream.write(ds.encoded(spec))
    result, error = None, None
    try:
        result = run_worker([sys._base_executable, '-B', str(Path(__file__).resolve()), '_worker', str(path)],
                            timeout=timeout, limit=LOG_LIMIT, cwd=SUITE, env=env,
                            settle_build_auxiliaries=build)
        return result
    except BaseException as caught:
        error = caught
        raise
    finally:
        # Logs are never substituted for a successful settlement receipt.
        try:
            for key in ('stdout', 'stderr'):
                data = getattr(result if result is not None else error, key, b'')[:LOG_LIMIT + 1]
                with (root / 'evidence' / (name + '-outer.' + key)).open('xb') as stream:
                    stream.write(data)
            save(root, name + '-outer.json', failure(error) if error else
                 dict(passed=True, descendants_settled=True, seconds=result.duration_seconds,
                      reported_pre_settlement_auxiliaries=result.descendants_settled))
        except BaseException as reporting:
            if error is not None:
                error.add_note('outer receipt/log failure: ' + str(reporting)[:1024])
            elif result is not None:
                # A receipt failure cannot erase the already-known settlement.
                raise WorkerError(result.args, reporting, [], result.stdout, result.stderr,
                                  result.duration_seconds, result.returncode) from reporting
            else:
                raise


class NativeStage:
    """Plain state; no context generator, finalizer, or implicit restoration.

    Reuse the installed native_lock input relationship and restoration checks.
    The outer owner alone calls restore, after known worker settlement.
    """
    def __init__(self, core, native=NATIVE):
        self.canonical, alternate = Path(native) / 'Cargo.lock', Path(native) / 'Cargo.syn3.lock'
        manifest = Path(core) / 'crates/coaptic-io/Cargo.toml'
        self.base, syn3, source = self.canonical.read_bytes(), alternate.read_bytes(), manifest.read_bytes()
        if syn3.replace(b'\r\n', b'\n') != locks._expected_syn3(self.base).replace(b'\r\n', b'\n'):
            raise ValueError('alternate native lock edge differs')
        syn = locks._toml(source).get('dependencies', {}).get('syn')
        requirement = syn.get('version') if isinstance(syn, dict) else None
        if requirement not in ('2', '3'):
            raise ValueError('unsupported coaptic-io syn.version')
        selected_path, self.selected = (self.canonical, self.base) if requirement == '2' else (alternate, syn3)
        self.inputs = ((alternate, syn3), (manifest, source))
        digest = lambda raw: hashlib.sha256(raw).hexdigest()
        self.record = dict(syn_requirement=requirement, selected_path=str(selected_path),
                           selected_sha256=digest(self.selected), canonical_path=str(self.canonical),
                           canonical_base_sha256=digest(self.base), syn3_path=str(alternate),
                           syn3_sha256=digest(syn3), core_manifest_path=str(manifest),
                           core_manifest_sha256=digest(source))

    def stage(self):
        for path, expected in ((self.canonical, self.base), *self.inputs):
            locks._unchanged(path, expected)
        if self.selected != self.base:
            self.canonical.write_bytes(self.selected)
        locks._unchanged(self.canonical, self.selected)
        return self.record

    def restore(self):
        locks._restore(self.canonical, self.selected, self.base, self.inputs)


def transaction(core, suite_sha, selected, operation, record):
    """Outer-owned source transaction; never restore into an unresolved worker."""
    source_gate(core, suite_sha, BASELINE)
    initial_ref = ds.git(core, 'symbolic-ref', '--short', '-q', 'HEAD') if ds.git(core, 'rev-parse', '--abbrev-ref', 'HEAD') != 'HEAD' else None
    initial = snapshot(core)
    stage, settled, primary, current, suite = None, True, None, None, None
    record.update(restoration='unknown', cleanup_unresolved=False)
    try:
        if selected != BASELINE:
            ds.git(core, 'checkout', '--detach', selected)
        source_gate(core, suite_sha, selected)
        current, suite = snapshot(core), snapshot(SUITE)
        stage = NativeStage(core)
        lock = stage.stage()
        staged = dict(suite['files'])
        staged['tools/benchmark/native/Cargo.lock'] = lock['selected_sha256']
        check_files(SUITE, staged)
        check_files(core, current['files'])
        record.update(source=current, suite=suite, lock=lock)
        # Until run_worker returns or raises its structured settled error, custody is unknown.
        settled = False
        try:
            value = operation(lock)
            settled = True
        except WorkerError as error:
            settled = not error.cleanup_unresolved
            raise
        finally:
            if settled:
                original = sys.exc_info()[1]
                errors = []
                for root, files in ((SUITE, staged), (core, current['files'])):
                    try:
                        check_files(root, files)
                    except BaseException as error:
                        errors.append(str(error)[:1024])
                if errors:
                    if original is None:
                        raise ValueError('; '.join(errors))
                    original.add_note('settled source check: ' + '; '.join(errors))
        return value
    except BaseException as error:
        primary = error
        raise
    finally:
        if not settled:
            record.update(cleanup_unresolved=True, restoration='UNKNOWN; preserve staged inputs; retire ephemeral VM')
            if primary is not None:
                primary.cleanup_unresolved = True
        else:
            try:
                if stage is not None:
                    stage.restore()
                # Refuse edits before checkout. Never reset/clean/overwrite them.
                if current is not None:
                    check_files(core, current['files'])
                if suite is not None:
                    check_files(SUITE, suite['files'])
                source_gate(core, suite_sha, selected)
                if selected != BASELINE:
                    ds.git(core, 'checkout', initial_ref or '--detach', *([] if initial_ref else [BASELINE]))
                exact(snapshot(core), initial, 'restored core bytes/ref identity differ')
                exact(ds.git(core, 'rev-parse', '--abbrev-ref', 'HEAD'), initial_ref or 'HEAD',
                      'initial symbolic/detached ref not restored')
                record['restoration'] = 'verified clean initial source'
            except BaseException as error:
                record['restoration'] = 'refused: ' + str(error)[:1024]
                if primary is None:
                    raise
                primary.add_note('source finally: ' + str(error)[:1024])


def cargo_worker(spec):
    root, arm = Path(spec['root']), spec['arm']
    budget = Budget(root, spec['seconds'], rss_limit=2 * 1024**3)
    prefix = [spec['cargo'], 'test', '--release', '--locked', '--target', TARGET,
              '--manifest-path', str(NATIVE / 'Cargo.toml'), '-p', 'bench-rust-server', '--bin', 'bench-core']
    listing = child_command(prefix + ['wall_', '--', '--list'], budget, arm + '-tests-list',
                            env=os.environ, seconds=spec['seconds'])
    validate_census(listing, listing=True)
    tests = child_command(prefix + ['wall_', '--', '--test-threads=1'], budget, arm + '-tests',
                          env=os.environ, seconds=spec['seconds'])
    validate_census(tests)
    prefix[1] = 'build'
    raw = child_command(prefix + ['--message-format=json-render-diagnostics'], budget, arm + '-build',
                        env=os.environ, seconds=spec['seconds'])
    pair = wp.native_artifact_pair(raw, root / 'target')
    save(root, arm + '-cargo.json', dict(native_tests=list(WALL_TESTS), artifacts=list(map(str, pair)),
         sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak,
         sampled_owned_build_peak_bytes=budget.peak))
    budget.check(force=True)


def retain_pair(root, arm):
    result = load(root / 'evidence' / (arm + '-cargo.json'))
    pair = wp.native_artifact_pair((root / 'evidence' / (arm + '-build.stdout')).read_bytes(), root / 'target')
    exact(result['native_tests'], list(WALL_TESTS), 'test receipt mismatch')
    exact(result['artifacts'], list(map(str, pair)), 'artifact receipt mismatch')
    retained = {}
    for kind, source in zip(('exe', 'pdb'), pair):
        if source.suffix.lower() != '.' + kind or not source.is_file():
            raise ValueError('actual Cargo EXE/PDB missing')
        if source.stat().st_size + wp.owned_size(root / 'evidence') + RESERVE > EVIDENCE_LIMIT:
            raise ValueError('both owned pairs must fit 64 MiB evidence')
        retained[kind] = wp.retain_file(root, source, root / 'evidence' / arm / source.name)
    return retained


def tool_check(tools):
    for value in tools.values():
        if ds.digest(value['path']) != value['sha256']:
            raise ValueError('tool bytes changed')


def config_check(inputs):
    for name, expected in inputs['config_files'].items():
        if ds.digest(name) != expected:
            raise ValueError('Cargo config bytes changed')


def artifact_check(root, artifacts):
    for arm, pair in artifacts.items():
        exact(sorted(pair), ['exe', 'pdb'], 'prepared artifact pair incomplete')
        for kind, artifact in pair.items():
            path = Path(artifact['path'])
            if path.parent.resolve() != (root / 'evidence' / arm).resolve() or path.suffix.lower() != '.' + kind:
                raise ValueError('prepared artifact ownership differs')
            if path.stat().st_size != artifact['bytes'] or ds.digest(path) != artifact['sha256']:
                raise ValueError('prepared final artifact bytes differ')


def owner(args, root):
    return dict(schema='coaptic-admission-owner/1', project='Coaptic', root=str(root),
                owner=os.environ.get('GITHUB_RUN_ID'), attempt=os.environ.get('GITHUB_RUN_ATTEMPT'),
                expected_suite=args.expected_suite, core=str(Path(args.core).resolve()), plan=plan(),
                plan_sha256=ds.digest(HERE / 'admission_wall_plan.md'),
                release='Retain through reviewed delivery; retire ephemeral VM after unresolved cleanup',
                abrupt_outer_death='restoration UNKNOWN; no universal crash recovery')


def build(args, root, contract):
    deadline = time.monotonic() + BUILD_SECONDS
    inputs = ds.cargo_inputs()
    compiler, cargo, tools = ds.toolchain()
    if (not compiler.startswith('rustc 1.99.0 ') or '\nhost: ' + TARGET not in compiler
            or not cargo.startswith('cargo 1.99.0 ')):
        raise ValueError('exact Rust/Cargo 1.99.0 host MSVC required')
    tools['python'] = dict(path=str(Path(sys._base_executable).resolve()), sha256=ds.digest(sys._base_executable))
    env = environment(root, tools)
    suite = snapshot(SUITE)
    records, artifacts = {}, {}
    primary = None
    try:
        for arm, commit in CORES.items():
            # Include wrapper settlement and outer finalization within the overall owner deadline.
            remaining = deadline - time.monotonic()
            if remaining <= 35:
                raise TimeoutError('830-second outer build owner deadline')
            outer = min(CARGO_OUTER, remaining - 20)
            inner = min(CARGO_SECONDS, outer - 30)
            record = records[arm] = {}
            transaction(args.core, args.expected_suite, commit,
                        lambda lock: launch(root, arm, dict(kind='cargo', root=str(root), arm=arm,
                                                           cargo=tools['cargo']['path'], seconds=inner),
                                            env, timeout=outer, build=True), record)
            artifacts[arm] = retain_pair(root, arm)
            tool_check(tools)
            config_check(inputs)
            exact(snapshot(SUITE), suite, 'suite changed after build')
        if time.monotonic() >= deadline:
            raise TimeoutError('830-second outer build owner deadline')
        result = dict(owner=contract, plan=plan(), suite=suite, records=records, artifacts=artifacts,
                      compiler=compiler, cargo=cargo, tools=tools, inputs=inputs, flags=FLAGS,
                      host=ds.host_identity())
        save(root, 'build.json', result)
        return result
    except BaseException as error:
        primary = error
        raise
    finally:
        checks = []
        if not getattr(primary, 'cleanup_unresolved', False):
            for check in (lambda: tool_check(tools), lambda: config_check(inputs),
                          lambda: artifact_check(root, artifacts),
                          lambda: exact(snapshot(SUITE), suite, 'suite changed in build finally'),
                          lambda: source_gate(args.core, args.expected_suite, BASELINE)):
                try:
                    check()
                except BaseException as error:
                    checks.append(str(error)[:1024])
        check_error = ValueError('; '.join(checks)) if checks and primary is None else None
        if checks and primary is not None:
            primary.add_note('build finally: ' + '; '.join(checks))
        report_preserving(primary or check_error, 'build-finally receipt', lambda: save(root, 'build-finally.json', dict(records=records, immutable_check_errors=checks,
             cleanup_unresolved=getattr(primary, 'cleanup_unresolved', False),
             abrupt_outer_death='Missing receipt means restoration UNKNOWN')))
        if check_error is not None:
            raise check_error


def verify_build(args, root, contract):
    exact(load(root / 'evidence/owner.json'), contract, 'owner/plan identity differs')
    value = load(root / 'evidence/build.json')
    exact(value['owner'], contract, 'prepared owner differs')
    exact(value['plan'], plan(), 'prepared plan differs')
    exact(value['flags'], FLAGS, 'prepared flags differ')
    source_gate(args.core, args.expected_suite, BASELINE)
    exact(snapshot(SUITE), value['suite'], 'prepared suite/source bytes differ')
    exact(snapshot(args.core), value['records']['A']['source'], 'prepared baseline source differs')
    tool_check(value['tools'])
    config_check(value['inputs'])
    exact(sorted(value['artifacts']), ['A', 'B'], 'prepared artifact arms differ')
    for arm, commit in CORES.items():
        record = value['records'][arm]
        if record['source']['identity']['commit'] != commit or record['restoration'] != 'verified clean initial source':
            raise ValueError('prepared source/restoration differs')
        receipt = load(root / 'evidence' / (arm + '-cargo.json'))
        exact(receipt['native_tests'], list(WALL_TESTS), 'prepared native census differs')
        validate_census((root / 'evidence' / (arm + '-tests-list.stdout')).read_bytes(), listing=True)
        validate_census((root / 'evidence' / (arm + '-tests.stdout')).read_bytes())
    artifact_check(root, value['artifacts'])
    return value


@contextmanager
def affinity(root):
    import psutil
    process = psutil.Process()
    allowed = process.cpu_affinity()
    if not allowed:
        raise ValueError('empty allowed CPU set')
    selected = [min(allowed)]
    receipt = dict(allowed_cpus=allowed, selected_cpus=selected,
                   allowed_mask=sum(1 << c for c in allowed), selected_mask=1 << selected[0],
                   policy='launcher pinned before native creation; inherited by each child')
    primary = None
    try:
        process.cpu_affinity(selected)
        exact(process.cpu_affinity(), selected, 'launcher CPU pin failed')
        save(root, 'affinity.json', receipt)
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        restored = False
        def restore():
            nonlocal restored
            process.cpu_affinity(allowed)
            exact(process.cpu_affinity(), allowed, 'launcher CPU restoration failed')
            restored = True
        report_preserving(primary, 'affinity restoration', restore)
        report_preserving(primary, 'affinity-finally receipt', lambda:
                          save(root, 'affinity-finally.json', dict(restored_cpus=allowed if restored else None)))


def measure_worker(spec):
    args = argparse.Namespace(**spec['args'])
    root = Path(args.output)
    budget = Budget(root, MEASURE_SECONDS)
    contract = owner(args, root)
    def verify():
        check_files(root / 'evidence', spec['prepared_hashes'])
        return verify_build(args, root, contract)
    prepared = verify()
    comparisons, completed, attempted = [], [], []
    primary = None
    try:
        with affinity(root):
            arms = {}
            for row in schedule():
                budget.check(force=True)
                verify()
                binary = prepared['artifacts'][row['arm']]['exe']['path']
                command = [binary, str(OPERATIONS), row['security']]
                if row['profile'] == 'small-device':
                    command.append('--small-device')
                stem = 'sample-' + str(row['index']).zfill(2)
                attempted.append(row)
                raw = child_command(command, budget, stem, env=os.environ, seconds=PROCESS_SECONDS)
                value = read_json(raw)
                facts = validate_wall(value, row['profile'], row['security'])
                verify()
                save(root, stem + '.json', dict(selection=row, command=command, facts=facts,
                                              raw_sha256=hashlib.sha256(raw).hexdigest()))
                completed.append(row)
                arms[row['arm']] = value['latencies_ns']
                if len(arms) == 2:
                    comparison = compare(arms, row['security'])
                    comparison.update(profile=row['profile'], security=row['security'], round=row['round'])
                    comparisons.append(comparison)
                    save(root, stem + '-comparison.json', comparison)
                    arms = {}
                    if not comparison['passed']:
                        raise ValueError('Stage A gate failed; no further samples or replacement')
        if len(completed) != 16 or len(comparisons) != 8:
            raise ValueError('incomplete fixed cohort')
        budget.check(force=True)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            verify()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.add_note('measurement source finally: ' + str(error)[:1024])
        report_preserving(primary, 'measurement-result receipt', lambda: save(root, 'result.json', dict(passed=primary is None, completed=completed,
             attempted=attempted, failed_or_incomplete=[r for r in attempted if r not in completed],
             not_run=schedule()[len(attempted):], comparisons=comparisons,
             failure=failure(primary) if primary else None, stage_b='unimplemented; no merge promotion',
             sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak,
             scope=plan()['scope'])))
        if primary is not None and sys.exc_info()[0] is None:
            raise primary


def execute(args):
    if sys.platform != 'win32' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise ValueError('dedicated hosted Windows runner required')
    if shutil.which('agent-resources'):
        raise ValueError('resource controller installed: require explicitly registered hosted lane')
    if not re.fullmatch('[0-9a-f]{40}', args.expected_suite):
        raise ValueError('immutable expected suite SHA required')
    root = Path(args.output).resolve()
    if root.parent != Path(os.environ['RUNNER_TEMP']).resolve() or root.name != 'coaptic-admission-wall':
        raise ValueError('output must be new RUNNER_TEMP/coaptic-admission-wall')
    args.output, args.core = str(root), str(Path(args.core).resolve())
    contract = owner(args, root)
    source_gate(args.core, args.expected_suite, BASELINE)
    observed = preflight(root)
    if args.command in ('build', 'all'):
        root.mkdir()
        (root / 'evidence').mkdir()
        save(root, 'owner.json', contract)
        save(root, 'preflight.json', observed)
    else:
        if (root / 'measure-task.json').exists() or (root / 'evidence/failure.json').exists():
            raise ValueError('one attempt only; prior failure/measurement refuses further work')
        # A partial build/abrupt outer death is not a successfully handed-off build.
        completed_build = load(root / 'evidence/build-complete.json')
        check_files(root / 'evidence', completed_build['prepared_hashes'])
        verify_build(args, root, contract)
    primary = None
    try:
        if args.command in ('build', 'all'):
            build(args, root, contract)
        if args.command in ('measure', 'all'):
            value = verify_build(args, root, contract)
            env = environment(root, value['tools'])
            pins = {name: ds.digest(root / 'evidence' / name) for name in ('owner.json', 'build.json')}
            launch(root, 'measure', dict(kind='measure', args=vars(args), prepared_hashes=pins),
                   env, timeout=MEASURE_OUTER)
            check_files(root / 'evidence', pins)
            exact(load(root / 'evidence/result.json')['passed'], True, 'Stage A did not pass')
    except BaseException as error:
        primary = error
        report_preserving(primary, 'outer failure receipt', lambda: save(root, 'failure.json', failure(error)))
        raise
    finally:
        if not getattr(primary, 'cleanup_unresolved', False):
            try:
                source_gate(args.core, args.expected_suite, BASELINE)
                if (root / 'evidence/build.json').exists():
                    verify_build(args, root, contract)
                save(root, args.command + '-final-source-check.json', dict(passed=True))
            except BaseException as error:
                report_preserving(primary or error, 'outer final-source receipt', lambda:
                                  save(root, args.command + '-final-source-check.json', failure(error)))
                if primary is None:
                    raise
                primary.add_note('outer source finally: ' + str(error)[:1024])
    if args.command == 'build':
        save(root, 'build-complete.json', dict(prepared_hashes={
             name: ds.digest(root / 'evidence' / name) for name in ('owner.json', 'build.json')}))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == '_worker':
        if sys.stdin.buffer.readline(4) != b'go\n':
            raise ValueError('owned worker handshake required')
        spec = load(argv[1])
        if spec['kind'] == 'cargo':
            cargo_worker(spec)
        elif spec['kind'] == 'measure':
            measure_worker(spec)
        else:
            raise ValueError('unknown worker')
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('build', 'measure', 'all'))
    parser.add_argument('--core', required=True)
    parser.add_argument('--expected-suite', required=True)
    parser.add_argument('--output', required=True)
    execute(parser.parse_args(argv))


if __name__ == '__main__':
    main()
