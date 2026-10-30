"""Verify retained text bytes and recompute frozen Stage A comparisons; stdlib only.
Pure functions/constants below are extracted via AST from immutable harness c58e47e.
No producer process, build, workload, or runner entrypoint is imported or invoked.
"""
import base64, gzip, hashlib, json, lzma, math, random, re
from pathlib import Path
from types import SimpleNamespace
OPERATIONS, WARMUP, CALIBRATION = (60000, 128, 4096)
BLOCK_SIZE, BLOCKS, REPLICATES, SEED = (1000, 60, 10000, 20261030)
BUILD_SECONDS, CARGO_SECONDS, CARGO_OUTER = (830, 400, 450)
MEASURE_SECONDS, MEASURE_OUTER, PROCESS_SECONDS = (300, 450, 30)
BUILD_LIMIT, EVIDENCE_LIMIT, LOG_LIMIT = (8 * 1024 ** 3, 64 * 1024 ** 2, 2 * 1024 ** 2)
wp = SimpleNamespace(MODES=('unprotected', 'oscore'))
ds = SimpleNamespace(encoded=lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
BASELINE = '623c82db1a6606ec86cd56bb52009988b9f0d87e'
CANDIDATE = '8782a6a0b0aef2facf51bec884cfe37f2a80f28d'
CORES = {'A': BASELINE, 'B': CANDIDATE}
RESERVE = 4 * 1024 ** 2
TARGET = 'x86_64-pc-windows-msvc'
FIXTURE = 'tools/benchmark/native/servers/src/bin/bench-core.rs'
FIXTURE_LF_SHA256 = 'fe144de7598da4b753e668a17a8cbd91033896691a0ee045c5be711e784c0272'
WALL_TESTS = tuple(('batch_tests::' + name for name in ('wall_cli_bounds_and_mixed_flag_refusal', 'wall_exact_presets_both_payloads_verify_without_growth', 'wall_full_metadata_and_complete_payload_are_required', 'wall_missing_bad_response_and_authentication_refuse_then_recover')))
MEASUREMENT = 'server App::poll with optimizer barriers; request preparation and complete response verification outside clock; OSCORE responses authenticated; timer calibration separate and never subtracted'
MEMORY_REMAINING = 'allocator overhead, initialization scratch, generated peak stack and runtime memory unknown; nested owners must not be added twice'
SMALL_SCOPE = 'socket-free wall supporting evidence only; fixture input/output copies remain inside App::poll; not native Mio memory equivalence, server CPU, socket latency, transport share, whole memory or either 50% acceptance'
SMALL = dict(profile='SmallDevice', pools='Constrained', storage='fixed', payload_bytes=32, concurrency=1, message_type='CON', routes=4, populated_routes=1, calls=1, deferred=0, associations=1, security_requests=4, blockwise=False, rx_slots=2, tx_slots=2, rx_datagram_bytes=1152, tx_datagram_bytes=1152, dedup=4, observe=2, rx_body_slots=0, tx_body_slots=0, verified=60128, calibration_samples=4096)
DEFAULT = dict(profile='Default', storage='allocated', payload_bytes=64, concurrency=1, message_type='CON', routes=1, populated_routes=1, calls=4, deferred=0, associations=1, security_requests=4, blockwise=True, rx_slots=4, tx_slots=4, rx_datagram_bytes=1472, tx_datagram_bytes=1472, dedup=8, observe=4, rx_body_slots=1, tx_body_slots=2, rx_body_bytes=1024, tx_body_bytes=1024)
MEMORY_FIXED = dict(fixed_pool_heap_bytes=0, transport_input_nested_bytes=1472, transport_output_nested_bytes=1472, separate_latency_requested_bytes=OPERATIONS * 16, separate_calibration_requested_bytes=CALIBRATION * 16, separate_timing_vec_headers_bytes=48, separate_verification_buffer_bytes=1472, separate_representation_static_bytes=32, remaining=MEMORY_REMAINING)
MEMORY_DYNAMIC = ('app_including_transport_inline_bytes', 'transport_nested_in_app_inline_bytes', 'separate_optional_client_context_inline_bytes')
FLAGS = dict(RUSTFLAGS='-Cforce-frame-pointers=yes', CARGO_PROFILE_RELEASE_DEBUG='1', CARGO_PROFILE_RELEASE_LTO='thin', CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2')

def plan():
    return dict(schema='coaptic-admission-wall/1', cores=CORES, cells=[[p, s] for p in ('small-device', 'default') for s in wp.MODES], rounds=['AB', 'BA'], operations=OPERATIONS, warmup=WARMUP, calibration=CALIBRATION, processes=16, measured_total=960000, warmup_total=2048, unique_mids_per_process=60128, block_size=BLOCK_SIZE, blocks=BLOCKS, replicates=REPLICATES, seed_reset_each_comparison=SEED, quantiles='equal-tail .025/.975; linear interpolation at (n-1)*q', gates={'unprotected': {'mean_max': 0.99, 'upper_exclusive': 1.0}, 'oscore': {'upper_inclusive': 1.02}}, timing=MEASUREMENT, calibration_subtracted=False, outliers_removed=False, process_retries=0, small=SMALL, default_source_capacities=DEFAULT, native_tests=list(WALL_TESTS), flags=FLAGS, target=TARGET, budgets=dict(build=BUILD_SECONDS, cargo=CARGO_SECONDS, cargo_outer=CARGO_OUTER, measure=MEASURE_SECONDS, measure_outer=MEASURE_OUTER, native=PROCESS_SECONDS, log=LOG_LIMIT, build_bytes=BUILD_LIMIT, evidence_bytes=EVIDENCE_LIMIT), scope='Conditional two-process comparisons, not CPU or general-host proof; Stage B pressure/continuation required before any merge promotion')

def schedule():
    return [dict(index=i, profile=p, security=s, round=r, arm=a) for i, (p, s, r, a) in enumerate(((p, s, r, a) for p, s in plan()['cells'] for r in ('AB', 'BA') for a in r))]

def exact(actual, expected, message):
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
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def samples(values, count):
    if type(values) is not list or len(values) != count or any((type(n) is not int or not 0 <= n < 2 ** 128 for n in values)):
        raise ValueError('timing array count/u128 bound/type')
    return values

def validate_wall(value, profile, security):
    if profile not in ('small-device', 'default') or security not in wp.MODES:
        raise ValueError('unknown cell')
    common = dict(operations=OPERATIONS, warmup=WARMUP, security=security, black_box=True, measurement=MEASUREMENT)
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
        if any((type(memory[k]) is not int or not 0 < memory[k] < 2 ** 64 for k in MEMORY_DYNAMIC)):
            raise ValueError('memory ledger size')
    return dict(completion=OPERATIONS + WARMUP, completion_basis='emitted verified field plus pinned successful execution' if profile == 'small-device' else 'source-derived: pinned wall_run successful exit after every verification', capacities_basis='emitted ledger' if profile == 'small-device' else 'source-derived', capacities=SMALL if profile == 'small-device' else DEFAULT)

def quantile(ordered, q):
    index = (len(ordered) - 1) * q
    lo = int(index)
    fraction = index - lo
    return ordered[lo] * (1 - fraction) + ordered[min(lo + 1, len(ordered) - 1)] * fraction

def gate(mean, upper, security):
    if any((type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in (mean, upper))):
        return False
    if security == 'unprotected':
        return mean <= 0.99 and upper < 1
    if security == 'oscore':
        return upper <= 1.02
    raise ValueError('unknown security')

def compare(arms, security):
    if set(arms) != {'A', 'B'}:
        raise ValueError('comparison must name A and B, including BA')
    for values in arms.values():
        samples(values, OPERATIONS)
    blocks = {arm: [math.fsum(values[i:i + BLOCK_SIZE]) / BLOCK_SIZE for i in range(0, OPERATIONS, BLOCK_SIZE)] for arm, values in arms.items()}
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
    lower, upper = (quantile(ratios, 0.025), quantile(ratios, 0.975))
    mean = means['B'] / means['A']
    return dict(block_means_ns=blocks, arm_mean_ns=means, mean_B_over_A=mean, lower95=lower, upper95=upper, passed=gate(mean, upper, security), scope=plan()['scope'])

def validate_census(raw, listing=False):
    text = '\n'.join(raw.decode('utf-8', errors='strict').splitlines())
    pattern = '^(batch_tests::wall_\\w+): test$' if listing else '^test (batch_tests::wall_\\w+) \\.\\.\\. ok$'
    names = re.findall(pattern, text, re.M)
    if sorted(names) != sorted(WALL_TESTS):
        raise ValueError('native wall test census mismatch/empty/duplicate')
    if listing:
        if not re.search('^4 tests, 0 benchmarks$', text, re.M):
            raise ValueError('native test listing count mismatch')
    else:
        summaries = re.findall('^test result: (.+)$', text, re.M)
        if len(summaries) != 1 or not re.fullmatch('ok\\. 4 passed; 0 failed; 0 ignored; 0 measured; \\d+ filtered out; finished in .+', summaries[0]):
            raise ValueError('native test completion mismatch')
    return list(WALL_TESTS)

def verify():
    root = Path(__file__).resolve().parent
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    index = json.loads((root / 'index.json').read_bytes())
    for name, spec in index['files'].items():
        raw = (root / name).read_bytes()
        assert len(raw) == spec['bytes'] and sha(raw) == spec['sha256'], name
        if name.endswith('.gz'):
            assert raw[4:8] == bytes(4)
            payload = gzip.decompress(raw)
            assert len(payload) == spec['payload_bytes'] and sha(payload) == spec['payload_sha256'], name
    collector = json.loads(gzip.decompress((root / 'collector.json.gz').read_bytes()))
    data = json.loads(gzip.decompress((root / 'data.json.gz').read_bytes()))
    payload = lzma.decompress(base64.b64decode(data['payload_base64'], validate=True), memlimit=128*1024**2)
    assert len(payload) == data['payload_bytes'] and sha(payload) == data['payload_sha256']
    original = collector['artifact']['manifest']
    retained = {}
    offset = 0
    for name, spec in data['members'].items():
        assert spec['offset'] == offset
        raw = payload[offset:offset+spec['bytes']]
        offset += spec['bytes']
        assert raw.decode('utf-8').encode('utf-8') == raw
        assert {'bytes':len(raw),'sha256':sha(raw)} == original[name]
        retained[name] = raw
    assert offset == len(payload)
    assert len(retained) == 109 and len(original) == 113
    assert set(original) - set(retained) == {'A/bench-core.exe','A/bench_core.pdb','B/bench-core.exe','B/bench_core.pdb'}
    rows = schedule()
    values = {}
    for row in rows:
        stem = 'sample-' + str(row['index']).zfill(2)
        raw = retained[stem + '.stdout']
        value = read_json(raw)
        facts = validate_wall(value, row['profile'], row['security'])
        receipt = json.loads(retained[stem + '.json'])
        assert receipt['selection'] == row and receipt['facts'] == facts and receipt['raw_sha256'] == sha(raw)
        expected_command = [json.loads(retained['build.json'])['artifacts'][row['arm']]['exe']['path'], '60000', row['security']]
        if row['profile'] == 'small-device': expected_command.append('--small-device')
        assert receipt['command'] == expected_command
        values[row['index']] = value
    for arm in ('A','B'):
        validate_census(retained[arm+'-tests-list.stdout'], listing=True)
        validate_census(retained[arm+'-tests.stdout'])
    for i in range(0,16,2):
        rows2 = rows[i:i+2]
        arms = {row['arm']:values[row['index']]['latencies_ns'] for row in rows2}
        result = compare(arms, rows2[0]['security'])
        stored = json.loads(retained['sample-' + str(i+1).zfill(2) + '-comparison.json'])
        for key, value in result.items(): assert stored[key] == value, (i,key)
        independent = collector['comparisons_independent'][i//2]
        assert independent['ratio'] == result['mean_B_over_A'] and independent['lower95'] == result['lower95'] and independent['upper95'] == result['upper95'] and independent['passed'] == result['passed']
        assert result['passed']
    assert sum(len(v['latencies_ns']) for v in values.values()) == 960000
    assert sum(len(v['clock_calibration_ns']) for v in values.values()) == 65536
    print('PASS: 109 exact UTF-8 members; 16 schemas/commands; 960000 latencies; 65536 calibrations; 8 unpooled comparisons; both native censuses; index/gzip hashes')

if __name__ == '__main__':
    verify()
