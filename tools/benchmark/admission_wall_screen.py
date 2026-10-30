"""Finite hosted Stage A screen or separate ownership proof. No Stage B promotion.

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
from typing import NamedTuple

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
FIXTURE_LF_SHA256 = 'a645fdc88dee2aba922013c7af6553d25461d2122a0884cd75c70afa2d472398'
WALL_TESTS = tuple('batch_tests::' + name for name in (
    'wall_cli_bounds_and_mixed_flag_refusal',
    'wall_exact_presets_both_payloads_verify_without_growth',
    'wall_full_metadata_and_complete_payload_are_required',
    'wall_missing_bad_response_and_authentication_refuse_then_recover'))
PRESSURE_SOURCE = 'tools/benchmark/native/servers/src/bin/bench_core/admission_pressure.rs'
PRESSURE_LF_SHA256 = 'ff787adae299f9abfde275652b9248b4bbd67b5ecf600f919fcc4ca0cf3e611a'
PRESSURE_TESTS = (
    'admission_pressure::block2_notification_under_rx_pressure_preserves_body_and_completes_oscore',
    'admission_pressure::block2_notification_under_rx_pressure_preserves_body_and_completes_unprotected',
    'admission_pressure::observe_cancel_under_tx_pressure_releases_relation_and_recovers_oscore',
    'admission_pressure::observe_cancel_under_tx_pressure_releases_relation_and_recovers_unprotected',
    'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_oscore',
    'admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected',
    'admission_pressure::tx_credit_survives_refusal_and_release_recovers_oscore',
    'admission_pressure::tx_credit_survives_refusal_and_release_recovers_unprotected')
PROOF_SCOPE = ('public-App SmallDevice retained-response RX and fixture-owned TX refusal/recovery; '
               'real Observe cancellation under TX pressure; allocated Default notification-backed Block2 '
               'under three retained completed-Call RX owners, exact body/fragment ownership and recovery; '
               'each in unprotected and OSCORE traffic with continuous security context; '
               'notification cell uses explicit full_responses, setup NON Call and NON notification, '
               'CON registration/followups; not ordinary stateless Block2 or timing qualification')
UNIMPLEMENTED = []


def purpose(args):
    if getattr(args, 'contract', 'admission') == 'dedup-classified':
        selection(args)
        return 'rejection-screen'
    return 'ownership-proof' if getattr(args, 'command', None) == 'proof' else 'stage-a-screen'


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


class Contract(NamedTuple):
    id: str
    schema: str
    owner_schema: str
    root: str
    artifact_prefix: str
    cores: tuple
    trees: tuple
    preregistration: tuple


ADMISSION = Contract('admission', 'coaptic-admission-wall/1', 'coaptic-admission-owner/1',
                     'coaptic-admission-wall', 'admission-wall-screen', tuple(CORES.items()), (), ())
DEDUP = Contract(
    'dedup-classified', 'coaptic-dedup-classified-wall/1', 'coaptic-dedup-classified-owner/1',
    'coaptic-dedup-classified-wall', 'dedup-classified-wall-screen',
    (('A', BASELINE), ('B', '8f1f138c825f431149ed8a0a7eefbb6be6cb1b6a')),
    (('A', '4f349c19039de513487dff283289658402593991'),
     ('B', '598db5cb5bd3851381d783f1bc02ecf664e778a5')),
    (
        'EARLY REJECTION screen only; no proof mode or promotion. No gain established. '
        'Core 717 all 11 checks passed at 8f per notification; source review NONE.',
        'Exactly 16 healthy fresh serial processes: AB then BA per profile/security cell. '
        'Measure all 16 before all eight gate comparisons; first source/runtime/resource failure '
        'aborts later work and records not-run. Failed or uncertain gate rejects this source screen.',
        'SmallDevice fixed Constrained 32B dedup4; allocated Default 64B dedup8; '
        'all existing route, Call, deferred, security and body capacities untouched.',
        '60000 measured plus 128 warmup per process; 960000 measured / 2048 warmup total; '
        '4096 separate calibrations/process. Native wall/default arguments and four exact wall tests unchanged.',
        '60 consecutive 1000-block means using math.fsum; 10000 bootstrap replicates; '
        'Random(20261030) reset per comparison, A60 draws then B60 draws; linear equal-tail '
        '.025/.975; B/A including BA. Each profile/order: unprotected mean<=.99 and upper95<1; '
        'OSCORE upper95<=1.02. No pooling, outlier drop, calibration subtraction, replacement or cap raises.',
        'Distinct MID 0..60127 and fixed endpoint; token changes alone do not prove keys. '
        'Responses fit inline replay 256B; warmup fills dedup4/8; ExchangeLifetime247s exceeds 30s/process. '
        'Timed fresh keys/full table: baseline misses twice before failed acquire/oldest eviction/ordinary retry; '
        'classified Full saves one initial search; remaining eviction/retry unchanged.',
        'No pinned replies measured. Existing, replacement, duplicate, custom store, missing payload and '
        'spare capacity performance unmeasured. Pass only admits future replacement/pin/pressure regression design; '
        'no merge, API, device, CPU, general host, stack or whole memory claim.',
        'Companion exact future commit supplied externally via expected-suite; Git tree and tracked source '
        'snapshots bound before launches. No admission plan document authorizes this contract.',
    ))


def resolve_contract(identifier='admission', proof=False):
    for selected in (ADMISSION, DEDUP):
        if identifier == selected.id:
            if proof and selected == DEDUP:
                raise ValueError('dedup-classified refuses proof mode')
            return selected
    raise ValueError('unknown contract selector')


def selection(args):
    return resolve_contract(getattr(args, 'contract', 'admission'),
                            getattr(args, 'command', None) == 'proof')


def binding(selected=ADMISSION):
    if selected == ADMISSION:
        return {}
    return dict(contract_id=selected.id, contract_sha256=hashlib.sha256(
        ds.encoded(dict(descriptor=selected._asdict(), plan=plan(selected)))).hexdigest())


def bound(value, selected=ADMISSION):
    return dict(value, **binding(selected))


def check_binding(value, selected=ADMISSION):
    expected = binding(selected)
    exact({k: value.get(k) for k in ('contract_id', 'contract_sha256')},
          {k: expected.get(k) for k in ('contract_id', 'contract_sha256')},
          'selected contract identity differs')


def tree_check(identity, commit, tree):
    exact(identity['commit'], commit, 'selected source commit differs')
    exact(identity['tree'], tree, 'selected source tree differs')


def plan(selected=ADMISSION):
    value = dict(schema=selected.schema, cores=dict(selected.cores),
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
    if selected == DEDUP:
        value.update(core_trees=dict(selected.trees), purpose='rejection-screen',
                     preregistration=list(selected.preregistration),
                     scope=' '.join(selected.preregistration), sampling='all 16 before all eight gates',
                     fixture_lf_sha256=FIXTURE_LF_SHA256, pressure_lf_sha256=PRESSURE_LF_SHA256,
                     evidence_reserve_bytes=RESERVE, artifact_prefix=selected.artifact_prefix)
    return value


def schedule(selected=ADMISSION):
    return [dict(index=i, profile=p, security=s, round=r, arm=a)
            for i, (p, s, r, a) in enumerate(
                (p, s, r, a) for p, s in plan(selected)['cells'] for r in ('AB', 'BA') for a in r)]


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


def compare(arms, security, selected=ADMISSION):
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
                scope=plan(selected)['scope'], **binding(selected))


def validate_census(raw, listing=False, expected=WALL_TESTS):
    if (not expected or len(set(expected)) != len(expected)
            or any(not re.fullmatch(r'(?:[A-Za-z_]\w*::)+[A-Za-z_]\w*', n) for n in expected)):
        raise ValueError('invalid declared exact census')
    text = '\n'.join(raw.decode('utf-8', errors='strict').splitlines())
    # Inspect every test, including unknown prefixes and non-ok completions.
    pattern = r'^([^\s]+): test$' if listing else r'^test ([^\s]+) \.\.\. (.+)$'
    observed = re.findall(pattern, text, re.M)
    names = observed if listing else [n for n, status in observed if status == 'ok']
    if sorted(names) != sorted(expected) or len(observed) != len(expected):
        raise ValueError('native test census mismatch/empty/duplicate')
    if listing:
        counts = re.findall(r'^(\d+) tests?, (\d+) benchmarks?$', text, re.M)
        if counts != [(str(len(expected)), '0')]:
            raise ValueError('native test listing count mismatch')
    else:
        running = re.findall(r'^running (\d+) tests?$', text, re.M)
        if running and running != [str(len(expected))]:
            raise ValueError('native running count mismatch')
        summaries = re.findall(r'^test result: (.+)$', text, re.M)
        if len(summaries) != 1 or not re.fullmatch(
                r'ok\. ' + str(len(expected)) +
                r' passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in .+', summaries[0]):
            raise ValueError('native test completion mismatch')
    return list(expected)


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


def source_gate(core, suite_sha, core_sha, selected=ADMISSION):
    value = wp.source_identity(core, core_sha, suite_sha)
    if selected == DEDUP:
        cores = dict(selected.cores)
        if core_sha not in cores.values():
            raise ValueError('foreign core revision')
        arm = next(a for a, sha in selected.cores if sha == core_sha)
        tree_check(ds.identity(core), core_sha, dict(selected.trees)[arm])
        exact(ds.identity(SUITE)['commit'], suite_sha, 'companion revision differs')
        if not re.fullmatch('[0-9a-f]{40}', ds.identity(SUITE)['tree']):
            raise ValueError('companion tree required')
    normalized = (SUITE / FIXTURE).read_bytes().replace(b'\r\n', b'\n')
    if hashlib.sha256(normalized).hexdigest() != FIXTURE_LF_SHA256:
        raise ValueError('native fixture pin differs')
    names = re.findall(rb'#\[test\]\s+fn (wall_\w+)\(', normalized)
    exact(sorted('batch_tests::' + n.decode() for n in names), sorted(WALL_TESTS), 'source census differs')
    pressure = (SUITE / PRESSURE_SOURCE).read_bytes().replace(b'\r\n', b'\n')
    exact(hashlib.sha256(pressure).hexdigest(), PRESSURE_LF_SHA256, 'pressure source pin differs')
    declared = re.findall(rb'#\[test\]\s+fn (\w+)\(', pressure)
    exact(sorted('admission_pressure::' + n.decode() for n in declared),
          sorted(PRESSURE_TESTS), 'pressure source census differs')
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


def launch(root, name, spec, env, *, timeout, build=False, selected=ADMISSION):
    check_binding(spec, selected)
    path = root / (name + '-task.json')
    with path.open('xb') as stream:
        stream.write(ds.encoded(spec))
    result, error = None, None
    try:
        result = run_worker([sys._base_executable, '-B', str(Path(__file__).resolve()), '_worker', str(path), selected.id],
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


def transaction(core, suite_sha, selected, operation, record, contract_selection=ADMISSION):
    """Outer-owned source transaction; never restore into an unresolved worker."""
    source_gate(core, suite_sha, BASELINE, contract_selection)
    initial_ref = ds.git(core, 'symbolic-ref', '--short', '-q', 'HEAD') if ds.git(core, 'rev-parse', '--abbrev-ref', 'HEAD') != 'HEAD' else None
    initial = snapshot(core)
    stage, settled, primary, current, suite = None, True, None, None, None
    record.update(restoration='unknown', cleanup_unresolved=False, **binding(contract_selection))
    try:
        if selected != BASELINE:
            ds.git(core, 'checkout', '--detach', selected)
        source_gate(core, suite_sha, selected, contract_selection)
        current, suite = snapshot(core), snapshot(SUITE)
        stage = NativeStage(core)
        lock = stage.stage()
        staged = dict(suite['files'])
        staged['tools/benchmark/native/Cargo.lock'] = lock['selected_sha256']
        check_files(SUITE, staged)
        check_files(core, current['files'])
        record.update(source=bound(current, contract_selection), suite=bound(suite, contract_selection), lock=lock)
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
                source_gate(core, suite_sha, selected, contract_selection)
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


def pressure_result(arm, selected_purpose):
    if selected_purpose != 'ownership-proof':
        return None
    return dict(passed=True, census=list(PRESSURE_TESTS),
                listing_log=arm + '-pressure-list.stdout', execution_log=arm + '-pressure.stdout',
                source_lf_sha256=PRESSURE_LF_SHA256, scope=PROOF_SCOPE)


def verify_staged_suite(core, expected_commit, held, lock):
    # The outer owner has intentionally substituted only the native lock.
    # A normal ds.identity() cleanliness check would reject that owned change.
    # Require the exact worktree-only delta, fixed Git identity, held sources,
    # and the lock selected by the unchanged core manifest instead.
    actual = dict(commit=ds.git(SUITE, 'rev-parse', 'HEAD'),
                  tree=ds.git(SUITE, 'rev-parse', 'HEAD^{tree}'))
    tree_check(actual, expected_commit, held['identity']['tree'])
    relative = 'tools/benchmark/native/Cargo.lock'
    base = held['files'][relative]
    manifest = locks._toml((Path(core) / 'crates/coaptic-io/Cargo.toml').read_bytes())
    syn = manifest.get('dependencies', {}).get('syn')
    requirement = syn.get('version') if isinstance(syn, dict) else None
    if requirement not in ('2', '3'):
        raise ValueError('unsupported staged core syn.version')
    expected = ds.digest(NATIVE / 'Cargo.syn3.lock') if requirement == '3' else base
    exact(lock['canonical_base_sha256'], base, 'staged lock base differs')
    exact(lock['selected_sha256'], expected, 'staged lock selection differs')
    exact(ds.digest(NATIVE / 'Cargo.lock'), expected, 'staged lock bytes differ')
    status = subprocess.check_output(
        ['git', '-C', str(SUITE), 'status', '--porcelain=v1', '-z', '--untracked-files=normal'], timeout=15)
    allowed = b' M ' + relative.encode() + b'\0' if expected != base else b''
    if status != allowed:
        raise ValueError('unexpected suite edits during staged lock')


def cargo_worker(spec, selected=ADMISSION):
    check_binding(spec, selected)
    def verify_source():
        if selected == DEDUP:
            args = argparse.Namespace(**spec['args'])
            exact(selection(args), selected, 'worker selection differs')
            exact(load(Path(spec['root']) / 'evidence/owner.json'), owner(args, Path(spec['root'])),
                  'Cargo owner differs')
            check_binding(spec['source'], selected)
            check_binding(spec['suite'], selected)
            arm = spec['arm']
            tree_check(spec['source']['identity'], dict(selected.cores)[arm], dict(selected.trees)[arm])
            tree_check(ds.identity(args.core), dict(selected.cores)[arm], dict(selected.trees)[arm])
            verify_staged_suite(args.core, args.expected_suite, spec['suite'], spec['lock'])
            check_files(args.core, spec['source']['files'])
            staged = dict(spec['suite']['files'])
            staged['tools/benchmark/native/Cargo.lock'] = spec['lock']['selected_sha256']
            check_files(SUITE, staged)
            exact(spec['purpose'], 'rejection-screen', 'Cargo purpose differs')
    verify_source()
    selected_purpose = spec.get('purpose', 'stage-a-screen')
    allowed = ('rejection-screen',) if selected == DEDUP else ('stage-a-screen', 'ownership-proof')
    if selected_purpose not in allowed:
        raise ValueError('unknown build purpose for selected contract')
    root, arm = Path(spec['root']), spec['arm']
    budget = Budget(root, spec['seconds'], rss_limit=2 * 1024**3)
    prefix = [spec['cargo'], 'test', '--release', '--locked', '--target', TARGET,
              '--manifest-path', str(NATIVE / 'Cargo.toml'), '-p', 'bench-rust-server', '--bin', 'bench-core']
    verify_source()
    listing = child_command(prefix + ['wall_', '--', '--list'], budget, arm + '-tests-list',
                            env=os.environ, seconds=spec['seconds'])
    validate_census(listing, listing=True)
    verify_source()
    tests = child_command(prefix + ['wall_', '--', '--test-threads=1'], budget, arm + '-tests',
                          env=os.environ, seconds=spec['seconds'])
    validate_census(tests)
    if selected_purpose == 'ownership-proof':
        verify_source()
        listing = child_command(prefix + ['admission_pressure::', '--', '--list'], budget,
                                arm + '-pressure-list', env=os.environ, seconds=spec['seconds'])
        validate_census(listing, listing=True, expected=PRESSURE_TESTS)
        tests = child_command(prefix + ['admission_pressure::', '--', '--test-threads=1'], budget,
                              arm + '-pressure', env=os.environ, seconds=spec['seconds'])
        validate_census(tests, expected=PRESSURE_TESTS)
    prefix[1] = 'build'
    verify_source()
    raw = child_command(prefix + ['--message-format=json-render-diagnostics'], budget, arm + '-build',
                        env=os.environ, seconds=spec['seconds'])
    pair = wp.native_artifact_pair(raw, root / 'target')
    save(root, arm + '-cargo.json', dict(native_tests=list(WALL_TESTS), purpose=selected_purpose,
         pressure_tests=list(PRESSURE_TESTS) if selected_purpose == 'ownership-proof' else [],
         pressure_proof=pressure_result(arm, selected_purpose),
         artifacts=list(map(str, pair)),
         sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak,
         sampled_owned_build_peak_bytes=budget.peak, **binding(selected)))
    budget.check(force=True)


def retain_pair(root, arm, selected_purpose='stage-a-screen', selected=ADMISSION):
    result = load(root / 'evidence' / (arm + '-cargo.json'))
    pair = wp.native_artifact_pair((root / 'evidence' / (arm + '-build.stdout')).read_bytes(), root / 'target')
    verify_tests(root, arm, result, selected_purpose, selected)
    exact(result['artifacts'], list(map(str, pair)), 'artifact receipt mismatch')
    retained = {}
    for kind, source in zip(('exe', 'pdb'), pair):
        if source.suffix.lower() != '.' + kind or not source.is_file():
            raise ValueError('actual Cargo EXE/PDB missing')
        if source.stat().st_size + wp.owned_size(root / 'evidence') + RESERVE > EVIDENCE_LIMIT:
            raise ValueError('both owned pairs must fit 64 MiB evidence')
        retained[kind] = bound(wp.retain_file(root, source, root / 'evidence' / arm / source.name), selected)
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
    selected = selection(args)
    value = dict(schema=selected.owner_schema, project='Coaptic', root=str(root),
                purpose=purpose(args), owner=os.environ.get('GITHUB_RUN_ID'), attempt=os.environ.get('GITHUB_RUN_ATTEMPT'),
                expected_suite=args.expected_suite, core=str(Path(args.core).resolve()), plan=plan(selected),
                plan_sha256=(ds.digest(HERE / 'admission_wall_plan.md') if selected == ADMISSION
                             else binding(selected)['contract_sha256']),
                release='Retain through reviewed delivery; retire ephemeral VM after unresolved cleanup',
                abrupt_outer_death='restoration UNKNOWN; no universal crash recovery')
    return bound(value, selected)


def build(args, root, contract):
    selected = selection(args)
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
        for arm, commit in selected.cores:
            # Include wrapper settlement and outer finalization within the overall owner deadline.
            remaining = deadline - time.monotonic()
            if remaining <= 35:
                raise TimeoutError('830-second outer build owner deadline')
            outer = min(CARGO_OUTER, remaining - 20)
            inner = min(CARGO_SECONDS, outer - 30)
            record = records[arm] = {}
            transaction(args.core, args.expected_suite, commit,
                        lambda lock: launch(root, arm, dict(kind='cargo', root=str(root), arm=arm,
                                                           cargo=tools['cargo']['path'], seconds=inner,
                                                           purpose=purpose(args), args=vars(args),
                                                           source=record['source'], suite=record['suite'],
                                                           lock=lock, **binding(selected)),
                                            env, timeout=outer, build=True, selected=selected), record, selected)
            artifacts[arm] = retain_pair(root, arm, purpose(args), selected)
            tool_check(tools)
            config_check(inputs)
            exact(snapshot(SUITE), suite, 'suite changed after build')
        if time.monotonic() >= deadline:
            raise TimeoutError('830-second outer build owner deadline')
        result = dict(owner=contract, purpose=purpose(args), plan=plan(selected), suite=suite, records=records, artifacts=artifacts,
                      compiler=compiler, cargo=cargo, tools=tools, inputs=inputs, flags=FLAGS,
                      host=ds.host_identity())
        save(root, 'build.json', bound(result, selected))
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
                          lambda: source_gate(args.core, args.expected_suite, BASELINE, selected)):
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


def verify_tests(root, arm, receipt, selected_purpose, selected=ADMISSION):
    check_binding(receipt, selected)
    exact(receipt['purpose'], selected_purpose, 'prepared test purpose differs')
    exact(receipt['native_tests'], list(WALL_TESTS), 'prepared native census differs')
    exact(receipt['pressure_proof'], pressure_result(arm, selected_purpose), 'prepared pressure result differs')
    expected = list(PRESSURE_TESTS) if selected_purpose == 'ownership-proof' else []
    exact(receipt['pressure_tests'], expected, 'prepared pressure census differs')
    validate_census((root / 'evidence' / (arm + '-tests-list.stdout')).read_bytes(), listing=True)
    validate_census((root / 'evidence' / (arm + '-tests.stdout')).read_bytes())
    if expected:
        validate_census((root / 'evidence' / (arm + '-pressure-list.stdout')).read_bytes(),
                        listing=True, expected=PRESSURE_TESTS)
        validate_census((root / 'evidence' / (arm + '-pressure.stdout')).read_bytes(),
                        expected=PRESSURE_TESTS)


def verify_build(args, root, contract):
    selected = selection(args)
    exact(load(root / 'evidence/owner.json'), contract, 'owner/plan identity differs')
    value = load(root / 'evidence/build.json')
    check_binding(value, selected)
    exact(value['owner'], contract, 'prepared owner differs')
    exact(value['purpose'], purpose(args), 'prepared build purpose differs')
    exact(value['plan'], plan(selected), 'prepared plan differs')
    exact(value['flags'], FLAGS, 'prepared flags differ')
    source_gate(args.core, args.expected_suite, BASELINE, selected)
    exact(snapshot(SUITE), value['suite'], 'prepared suite/source bytes differ')
    exact(bound(snapshot(args.core), selected), value['records']['A']['source'], 'prepared baseline source differs')
    tool_check(value['tools'])
    config_check(value['inputs'])
    exact(sorted(value['artifacts']), ['A', 'B'], 'prepared artifact arms differ')
    for arm, commit in selected.cores:
        record = value['records'][arm]
        if selected == DEDUP:
            check_binding(record, selected)
            check_binding(record['source'], selected)
            check_binding(record['suite'], selected)
            tree_check(record['source']['identity'], commit, dict(selected.trees)[arm])
            tree_check(record['suite']['identity'], args.expected_suite, value['suite']['identity']['tree'])
            for artifact in value['artifacts'][arm].values():
                check_binding(artifact, selected)
        if record['source']['identity']['commit'] != commit or record['restoration'] != 'verified clean initial source':
            raise ValueError('prepared source/restoration differs')
        receipt = load(root / 'evidence' / (arm + '-cargo.json'))
        verify_tests(root, arm, receipt, purpose(args), selected)
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


def measure_worker(spec, selected=ADMISSION):
    args = argparse.Namespace(**spec['args'])
    exact(selection(args), selected, 'measurement selection differs')
    check_binding(spec, selected)
    if purpose(args) not in ('stage-a-screen', 'rejection-screen'):
        raise ValueError('ownership proof cannot launch measurements')
    root = Path(args.output)
    budget = Budget(root, MEASURE_SECONDS)
    contract = owner(args, root)
    def verify():
        check_files(root / 'evidence', spec['prepared_hashes'])
        return verify_build(args, root, contract)
    comparisons, completed, attempted = [], [], []
    pending = []
    primary = None
    try:
        prepared = verify()
        with affinity(root):
            arms = {}
            for row in schedule(selected):
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
                                              raw_sha256=hashlib.sha256(raw).hexdigest(), **binding(selected)))
                completed.append(row)
                arms[row['arm']] = value['latencies_ns']
                if len(arms) == 2:
                    if selected == DEDUP:
                        pending.append((arms, dict(row)))
                        arms = {}
                        continue
                    comparison = compare(arms, row['security'], selected)
                    comparison.update(profile=row['profile'], security=row['security'], round=row['round'])
                    comparisons.append(comparison)
                    save(root, stem + '-comparison.json', comparison)
                    arms = {}
                    if not comparison['passed']:
                        raise ValueError('Stage A gate failed; no further samples or replacement')
        for arms, row in pending:
            budget.check(force=True)
            try:
                comparison = compare(arms, row['security'], selected)
            except ValueError as error:
                comparison = dict(passed=False, uncertain=True, failure=failure(error))
            comparison.update(profile=row['profile'], security=row['security'], round=row['round'],
                              **binding(selected))
            comparisons.append(comparison)
            save(root, 'sample-' + str(row['index']).zfill(2) + '-comparison.json', comparison)
        if selected == DEDUP and not all(c['passed'] for c in comparisons):
            raise ValueError('dedup rejection screen failed; no promotion')
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
             not_run=schedule(selected)[len(attempted):], comparisons=comparisons,
             failure=failure(primary) if primary else None, stage_b='unimplemented; no merge promotion',
             sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak,
             scope=plan(selected)['scope'], **binding(selected))))
        if primary is not None and sys.exc_info()[0] is None:
            raise primary


def execute(args):
    selected = selection(args)
    if sys.platform != 'win32' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise ValueError('dedicated hosted Windows runner required')
    if shutil.which('agent-resources'):
        raise ValueError('resource controller installed: require explicitly registered hosted lane')
    if not re.fullmatch('[0-9a-f]{40}', args.expected_suite):
        raise ValueError('immutable expected suite SHA required')
    root = Path(args.output).resolve()
    if root.parent != Path(os.environ['RUNNER_TEMP']).resolve() or root.name != selected.root:
        raise ValueError('output must be new RUNNER_TEMP/coaptic-admission-wall')
    args.output, args.core = str(root), str(Path(args.core).resolve())
    contract = owner(args, root)
    source_gate(args.core, args.expected_suite, BASELINE, selected)
    observed = preflight(root)
    if args.command in ('build', 'all', 'proof'):
        root.mkdir()
        (root / 'evidence').mkdir()
        save(root, 'owner.json', contract)
        save(root, 'preflight.json', observed)
    else:
        if (root / 'measure-task.json').exists() or (root / 'evidence/failure.json').exists():
            raise ValueError('one attempt only; prior failure/measurement refuses further work')
        # A partial build/abrupt outer death is not a successfully handed-off build.
        completed_build = load(root / 'evidence/build-complete.json')
        check_binding(completed_build, selected)
        check_files(root / 'evidence', completed_build['prepared_hashes'])
        verify_build(args, root, contract)
    primary = None
    try:
        if args.command in ('build', 'all', 'proof'):
            build(args, root, contract)
        if args.command in ('measure', 'all'):
            value = verify_build(args, root, contract)
            env = environment(root, value['tools'])
            pins = {name: ds.digest(root / 'evidence' / name) for name in ('owner.json', 'build.json')}
            launch(root, 'measure', dict(kind='measure', args=vars(args), prepared_hashes=pins, **binding(selected)),
                   env, timeout=MEASURE_OUTER, selected=selected)
            check_files(root / 'evidence', pins)
            exact(load(root / 'evidence/result.json')['passed'], True, 'Stage A did not pass')
    except BaseException as error:
        primary = error
        report_preserving(primary, 'outer failure receipt', lambda: save(root, 'failure.json', failure(error)))
        raise
    finally:
        if not getattr(primary, 'cleanup_unresolved', False):
            try:
                source_gate(args.core, args.expected_suite, BASELINE, selected)
                if (root / 'evidence/build.json').exists():
                    verify_build(args, root, contract)
                save(root, args.command + '-final-source-check.json', dict(passed=True))
            except BaseException as error:
                report_preserving(primary or error, 'outer final-source receipt', lambda:
                                  save(root, args.command + '-final-source-check.json', failure(error)))
                if primary is None:
                    raise
                primary.add_note('outer source finally: ' + str(error)[:1024])
    if args.command == 'proof':
        verify_build(args, root, contract)
        save(root, 'proof-complete.json', dict(
            passed=True, purpose='ownership-proof', measurements='NOT RUN',
            scope=PROOF_SCOPE, unimplemented=UNIMPLEMENTED,
            stage_b='NOT COMPLETE; no promotion', cores=CORES,
            arms={arm: dict(wall_tests=list(WALL_TESTS), pressure_tests=list(PRESSURE_TESTS))
                  for arm in CORES},
            prepared_hashes={name: ds.digest(root / 'evidence' / name)
                             for name in ('owner.json', 'build.json')}))
    if args.command == 'build':
        save(root, 'build-complete.json', dict(**binding(selected), prepared_hashes={
             name: ds.digest(root / 'evidence' / name) for name in ('owner.json', 'build.json')}))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == '_worker':
        if sys.stdin.buffer.readline(4) != b'go\n':
            raise ValueError('owned worker handshake required')
        spec = load(argv[1])
        selected = resolve_contract(argv[2] if len(argv) > 2 else 'admission')
        check_binding(spec, selected)
        if spec['kind'] == 'cargo':
            cargo_worker(spec, selected)
        elif spec['kind'] == 'measure':
            measure_worker(spec, selected)
        else:
            raise ValueError('unknown worker')
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('build', 'measure', 'all', 'proof'))
    parser.add_argument('--contract', choices=('admission', 'dedup-classified'), default='admission')
    parser.add_argument('--core', required=True)
    parser.add_argument('--expected-suite', required=True)
    parser.add_argument('--output', required=True)
    execute(parser.parse_args(argv))


if __name__ == '__main__':
    main()
