"""Standalone data-only verifier; stdlib. Pure definitions are AST-extracted from
immutable b0d4662 following the admission bundle strategy. No producer entrypoint,
native execution, subprocess or network. Statistics are recomputed from raw arrays;
source-map/compiler/API execution evidence is inherited from the pinned collector.
A reproduced failed gate is verification SUCCESS. Run python -B verify.py.
"""
import base64,gzip,hashlib,json,lzma,math,random,re,zlib
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple
wp=SimpleNamespace(MODES=('unprotected','oscore'))
ds=SimpleNamespace(encoded=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode())
BASELINE = '623c82db1a6606ec86cd56bb52009988b9f0d87e'
CANDIDATE = '8782a6a0b0aef2facf51bec884cfe37f2a80f28d'
CORES = {'A': BASELINE, 'B': CANDIDATE}
OPERATIONS, WARMUP, CALIBRATION = (60000, 128, 4096)
BLOCK_SIZE, BLOCKS, REPLICATES, SEED = (1000, 60, 10000, 20261030)
BUILD_SECONDS, CARGO_SECONDS, CARGO_OUTER = (830, 400, 450)
MEASURE_SECONDS, MEASURE_OUTER, PROCESS_SECONDS = (300, 450, 30)
BUILD_LIMIT, EVIDENCE_LIMIT, LOG_LIMIT = (8 * 1024 ** 3, 64 * 1024 ** 2, 2 * 1024 ** 2)
RESERVE = 4 * 1024 ** 2
TARGET = 'x86_64-pc-windows-msvc'
FIXTURE = 'tools/benchmark/native/servers/src/bin/bench-core.rs'
FIXTURE_LF_SHA256 = 'a645fdc88dee2aba922013c7af6553d25461d2122a0884cd75c70afa2d472398'
WALL_TESTS = tuple(('batch_tests::' + name for name in ('wall_cli_bounds_and_mixed_flag_refusal', 'wall_exact_presets_both_payloads_verify_without_growth', 'wall_full_metadata_and_complete_payload_are_required', 'wall_missing_bad_response_and_authentication_refuse_then_recover')))
PRESSURE_SOURCE = 'tools/benchmark/native/servers/src/bin/bench_core/admission_pressure.rs'
PRESSURE_LF_SHA256 = '67cd4f19969f7aa47eef9ae2a8e1101438cc0b94f163d6f3a2c966b7585b890a'
PRESSURE_TESTS = ('admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected',)
PROOF_SCOPE = 'public-App SmallDevice full_responses unprotected retained outbound response RX credit; incoming fresh GET refusal preserves slot/pin/occupancy; exact collection and fresh GET recovery'
UNIMPLEMENTED = ['protected', 'TX pressure', 'cancellation', 'Block2 continuation']
MEASUREMENT = 'server App::poll with optimizer barriers; request preparation and complete response verification outside clock; OSCORE responses authenticated; timer calibration separate and never subtracted'
MEMORY_REMAINING = 'allocator overhead, initialization scratch, generated peak stack and runtime memory unknown; nested owners must not be added twice'
SMALL_SCOPE = 'socket-free wall supporting evidence only; fixture input/output copies remain inside App::poll; not native Mio memory equivalence, server CPU, socket latency, transport share, whole memory or either 50% acceptance'
SMALL = dict(profile='SmallDevice', pools='Constrained', storage='fixed', payload_bytes=32, concurrency=1, message_type='CON', routes=4, populated_routes=1, calls=1, deferred=0, associations=1, security_requests=4, blockwise=False, rx_slots=2, tx_slots=2, rx_datagram_bytes=1152, tx_datagram_bytes=1152, dedup=4, observe=2, rx_body_slots=0, tx_body_slots=0, verified=60128, calibration_samples=4096)
DEFAULT = dict(profile='Default', storage='allocated', payload_bytes=64, concurrency=1, message_type='CON', routes=1, populated_routes=1, calls=4, deferred=0, associations=1, security_requests=4, blockwise=True, rx_slots=4, tx_slots=4, rx_datagram_bytes=1472, tx_datagram_bytes=1472, dedup=8, observe=4, rx_body_slots=1, tx_body_slots=2, rx_body_bytes=1024, tx_body_bytes=1024)
MEMORY_FIXED = dict(fixed_pool_heap_bytes=0, transport_input_nested_bytes=1472, transport_output_nested_bytes=1472, separate_latency_requested_bytes=OPERATIONS * 16, separate_calibration_requested_bytes=CALIBRATION * 16, separate_timing_vec_headers_bytes=48, separate_verification_buffer_bytes=1472, separate_representation_static_bytes=32, remaining=MEMORY_REMAINING)
MEMORY_DYNAMIC = ('app_including_transport_inline_bytes', 'transport_nested_in_app_inline_bytes', 'separate_optional_client_context_inline_bytes')
FLAGS = dict(RUSTFLAGS='-Cforce-frame-pointers=yes', CARGO_PROFILE_RELEASE_DEBUG='1', CARGO_PROFILE_RELEASE_LTO='thin', CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2')

class Contract(NamedTuple):
    id: str
    schema: str
    owner_schema: str
    root: str
    artifact_prefix: str
    cores: tuple
    trees: tuple
    preregistration: tuple
ADMISSION = Contract('admission', 'coaptic-admission-wall/1', 'coaptic-admission-owner/1', 'coaptic-admission-wall', 'admission-wall-screen', tuple(CORES.items()), (), ())
DEDUP = Contract('dedup-classified', 'coaptic-dedup-classified-wall/1', 'coaptic-dedup-classified-owner/1', 'coaptic-dedup-classified-wall', 'dedup-classified-wall-screen', (('A', BASELINE), ('B', '8f1f138c825f431149ed8a0a7eefbb6be6cb1b6a')), (('A', '4f349c19039de513487dff283289658402593991'), ('B', '598db5cb5bd3851381d783f1bc02ecf664e778a5')), ('EARLY REJECTION screen only; no proof mode or promotion. No gain established. Core 717 all 11 checks passed at 8f per notification; source review NONE.', 'Exactly 16 healthy fresh serial processes: AB then BA per profile/security cell. Measure all 16 before all eight gate comparisons; first source/runtime/resource failure aborts later work and records not-run. Failed or uncertain gate rejects this source screen.', 'SmallDevice fixed Constrained 32B dedup4; allocated Default 64B dedup8; all existing route, Call, deferred, security and body capacities untouched.', '60000 measured plus 128 warmup per process; 960000 measured / 2048 warmup total; 4096 separate calibrations/process. Native wall/default arguments and four exact wall tests unchanged.', '60 consecutive 1000-block means using math.fsum; 10000 bootstrap replicates; Random(20261030) reset per comparison, A60 draws then B60 draws; linear equal-tail .025/.975; B/A including BA. Each profile/order: unprotected mean<=.99 and upper95<1; OSCORE upper95<=1.02. No pooling, outlier drop, calibration subtraction, replacement or cap raises.', 'Distinct MID 0..60127 and fixed endpoint; token changes alone do not prove keys. Responses fit inline replay 256B; warmup fills dedup4/8; ExchangeLifetime247s exceeds 30s/process. Timed fresh keys/full table: baseline misses twice before failed acquire/oldest eviction/ordinary retry; classified Full saves one initial search; remaining eviction/retry unchanged.', 'No pinned replies measured. Existing, replacement, duplicate, custom store, missing payload and spare capacity performance unmeasured. Pass only admits future replacement/pin/pressure regression design; no merge, API, device, CPU, general host, stack or whole memory claim.', 'Companion exact future commit supplied externally via expected-suite; Git tree and tracked source snapshots bound before launches. No admission plan document authorizes this contract.'))

def binding(selected=DEDUP):
    if selected == ADMISSION:
        return {}
    return dict(contract_id=selected.id, contract_sha256=hashlib.sha256(ds.encoded(dict(descriptor=selected._asdict(), plan=plan(selected)))).hexdigest())

def plan(selected=DEDUP):
    value = dict(schema=selected.schema, cores=dict(selected.cores), cells=[[p, s] for p in ('small-device', 'default') for s in wp.MODES], rounds=['AB', 'BA'], operations=OPERATIONS, warmup=WARMUP, calibration=CALIBRATION, processes=16, measured_total=960000, warmup_total=2048, unique_mids_per_process=60128, block_size=BLOCK_SIZE, blocks=BLOCKS, replicates=REPLICATES, seed_reset_each_comparison=SEED, quantiles='equal-tail .025/.975; linear interpolation at (n-1)*q', gates={'unprotected': {'mean_max': 0.99, 'upper_exclusive': 1.0}, 'oscore': {'upper_inclusive': 1.02}}, timing=MEASUREMENT, calibration_subtracted=False, outliers_removed=False, process_retries=0, small=SMALL, default_source_capacities=DEFAULT, native_tests=list(WALL_TESTS), flags=FLAGS, target=TARGET, budgets=dict(build=BUILD_SECONDS, cargo=CARGO_SECONDS, cargo_outer=CARGO_OUTER, measure=MEASURE_SECONDS, measure_outer=MEASURE_OUTER, native=PROCESS_SECONDS, log=LOG_LIMIT, build_bytes=BUILD_LIMIT, evidence_bytes=EVIDENCE_LIMIT), scope='Conditional two-process comparisons, not CPU or general-host proof; Stage B pressure/continuation required before any merge promotion')
    if selected == DEDUP:
        value.update(core_trees=dict(selected.trees), purpose='rejection-screen', preregistration=list(selected.preregistration), scope=' '.join(selected.preregistration), sampling='all 16 before all eight gates', fixture_lf_sha256=FIXTURE_LF_SHA256, pressure_lf_sha256=PRESSURE_LF_SHA256, evidence_reserve_bytes=RESERVE, artifact_prefix=selected.artifact_prefix)
    return value

def schedule(selected=DEDUP):
    return [dict(index=i, profile=p, security=s, round=r, arm=a) for i, (p, s, r, a) in enumerate(((p, s, r, a) for p, s in plan(selected)['cells'] for r in ('AB', 'BA') for a in r))]

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

def compare(arms, security, selected=DEDUP):
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
    return dict(block_means_ns=blocks, arm_mean_ns=means, mean_B_over_A=mean, lower95=lower, upper95=upper, passed=gate(mean, upper, security), scope=plan(selected)['scope'], **binding(selected))

def validate_census(raw, listing=False, expected=WALL_TESTS):
    if not expected or len(set(expected)) != len(expected) or any((not re.fullmatch('(?:[A-Za-z_]\\w*::)+[A-Za-z_]\\w*', n) for n in expected)):
        raise ValueError('invalid declared exact census')
    text = '\n'.join(raw.decode('utf-8', errors='strict').splitlines())
    pattern = '^([^\\s]+): test$' if listing else '^test ([^\\s]+) \\.\\.\\. (.+)$'
    observed = re.findall(pattern, text, re.M)
    names = observed if listing else [n for n, status in observed if status == 'ok']
    if sorted(names) != sorted(expected) or len(observed) != len(expected):
        raise ValueError('native test census mismatch/empty/duplicate')
    if listing:
        counts = re.findall('^(\\d+) tests?, (\\d+) benchmarks?$', text, re.M)
        if counts != [(str(len(expected)), '0')]:
            raise ValueError('native test listing count mismatch')
    else:
        running = re.findall('^running (\\d+) tests?$', text, re.M)
        if running and running != [str(len(expected))]:
            raise ValueError('native running count mismatch')
        summaries = re.findall('^test result: (.+)$', text, re.M)
        if len(summaries) != 1 or not re.fullmatch('ok\\. ' + str(len(expected)) + ' passed; 0 failed; 0 ignored; 0 measured; \\d+ filtered out; finished in .+', summaries[0]):
            raise ValueError('native test completion mismatch')
    return list(expected)

COLLECTOR_SHA='df7db235354c84612c6baab58d5d6d15ff179e2e6027e1dd90f28987089490f3'
CONTRACT_SHA='0695f09dac05154c1a461d0816f060e8c5aee9945487e3312a181504870cb2a1'
SUITE='b0d46620d443e7dd63aa1ff3fb8d70c83f3841b0'
SUITE_TREE='f7353494b65141a09afaa3acf6c1fa503af0166c'
STOP_VECTOR=[True,True,True,True,False,False,False,True]
def verify(blobs=None):
    sha=lambda b:hashlib.sha256(b).hexdigest()
    root=Path(__file__).resolve().parent
    read=lambda n:blobs[n] if blobs is not None else (root/n).read_bytes()
    index=json.loads(read('index.json'))
    assert set(index['files'])=={'README.md','checks.json','collector.json.gz','data.json.gz','verify.py'} | set(index['optional'])
    for n,s in index['files'].items():
        b=read(n);assert len(b)==s['bytes'] and sha(b)==s['sha256'],n
        if n.endswith('.gz'):
            assert b[4:8]==bytes(4)
            d=gzip.decompress(b);assert len(d)==s['payload_bytes'] and sha(d)==s['payload_sha256'],n
    cb=gzip.decompress(read('collector.json.gz'));assert len(cb)==34814 and sha(cb)==COLLECTOR_SHA
    c=json.loads(cb)
    assert c['suite_tree']==SUITE_TREE and c['run']['head_sha']==SUITE and c['run']['id']==41110877140 and c['run']['run_attempt']==1
    assert c['cores']==dict(DEDUP.cores) and c['core_trees']==dict(DEDUP.trees)
    assert binding()==c['contract']==dict(contract_id='dedup-classified',contract_sha256=CONTRACT_SHA)
    assert c['artifact']['digest']=='sha256:3fb7ac36815a2a23e6ae772a5ea7e6d943a1ec7f3f7649e67c914fac5ed9a10c' and c['artifact']['id']==13003363402
    data=json.loads(gzip.decompress(read('data.json.gz')))
    payload=lzma.decompress(base64.b64decode(data['payload_base64'],validate=True),memlimit=128*1024**2)
    assert len(payload)==data['payload_bytes'] and sha(payload)==data['payload_sha256']
    original={n:(size,crc,h) for n,size,crc,h in c['archive']['manifest']}
    retained={};offset=0
    for n,s in data['members'].items():
        assert s['offset']==offset
        b=payload[offset:offset+s['bytes']];offset+=s['bytes']
        assert b.decode('utf-8','strict').encode('utf-8')==b
        assert (len(b),format(zlib.crc32(b)&0xffffffff,'08x'),sha(b))==original[n]
        retained[n]=b
    assert offset==len(payload) and len(retained)==110 and len(original)==114
    assert set(original)-set(retained)=={'A/bench-core.exe','A/bench_core.pdb','B/bench-core.exe','B/bench_core.pdb'}
    for a in 'AB':
        for k,n in [('exe','bench-core.exe'),('pdb','bench_core.pdb')]:
            s=c['binary_receipts'][a][k];assert (s['bytes'],s['sha256'])==(original[a+'/'+n][0],original[a+'/'+n][2])
    load=lambda n:read_json(retained[n])
    build=load('build.json');exact(build['plan'],plan(),'frozen plan')
    assert build['suite']['identity']['commit']==SUITE and build['suite']['identity']['tree']==SUITE_TREE
    assert build['artifacts']==c['binary_receipts']
    for a in 'AB':
        ident=build['records'][a]['source']['identity']
        assert ident['commit']==dict(DEDUP.cores)[a] and ident['tree']==dict(DEDUP.trees)[a]
    rows=schedule();values={}
    for row in rows:
        stem='sample-'+str(row['index']).zfill(2);b=retained[stem+'.stdout'];v=read_json(b)
        facts=validate_wall(v,row['profile'],row['security']);receipt=load(stem+'.json')
        command=[build['artifacts'][row['arm']]['exe']['path'],'60000',row['security']]
        if row['profile']=='small-device':command.append('--small-device')
        exact(receipt,dict(selection=row,command=command,facts=facts,raw_sha256=sha(b),**binding()),'sample receipt')
        process=load(stem+'-process.json')
        assert process['command']==command and process['passed'] is True and process['returncode']==0 and process['primary'] is None and process['cleanup']==[]
        values[row['index']]=v
    native=c['cohort']['native_subprocesses'];assert len(native)==22
    for r in native:
        p=load(r['receipt']);assert r['passed'] is True and r['returncode']==0 and p['passed'] is True and p['returncode']==0
    for a in 'AB':
        validate_census(retained[a+'-tests-list.stdout'],listing=True)
        validate_census(retained[a+'-tests.stdout'])
    vector=[]
    for i in range(0,16,2):
        pair=rows[i:i+2];row=pair[0]
        result=compare({r['arm']:values[r['index']]['latencies_ns'] for r in pair},row['security'])
        result.update(profile=row['profile'],security=row['security'],round=row['round'])
        exact(load('sample-'+str(i+1).zfill(2)+'-comparison.json'),result,'independent bootstrap mismatch')
        independent=c['statistics']['comparisons'][i//2]
        for k,v in [('ratio',result['mean_B_over_A']),('lower95',result['lower95']),('upper95',result['upper95']),('passed',result['passed']),('A_mean_ns',result['arm_mean_ns']['A']),('B_mean_ns',result['arm_mean_ns']['B'])]:assert independent[k]==v
        vector.append(result['passed'])
    assert vector==STOP_VECTOR
    assert sum(len(v['latencies_ns']) for v in values.values())==960000
    assert sum(len(v['clock_calibration_ns']) for v in values.values())==65536
    assert c['cohort']['not_run']==0 and c['cohort']['completed']==16
    assert b'dedup rejection screen failed; no promotion' in retained['measure-outer.stderr']
    print('PASS: 110 exact texts; pinned collector; 16 schemas/commands; 22 native receipts; 960000 latencies/65536 calibrations; eight unpooled exact bootstrap comparisons; frozen STOP vector')
    return retained
if __name__=='__main__':
    verify()
