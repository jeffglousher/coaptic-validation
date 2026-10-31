"""Frozen Stage B adapter. Native qualification and timing require separate purposes.

The caller supplies its actual runner module; importing this module cannot select
or mutate a runner contract. Evidence is checked against fresh frozen source.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import sys
import time

HASH = '161b7fd033cd7c2cc37b203f878b4307de913e2da2b651bacdbe9e84c186a83c'
ID = 'admission-stage-b'
ROOT = 'coaptic-admission-stage-b'
QUAL_SCHEMA = 'coaptic-admission-stage-b-qualification/1'
METRICS = ('admission_rx_refused', 'admission_tx_refused', 'admission_refusal_sent',
           'admission_refusal_unsent', 'observe_register', 'observe_cancel', 'observe_notify')
SETTLED = ('calls_collected_once', 'peer_bindings_consumed', 'rx_empty', 'tx_empty',
           'observe_empty', 'bodies_empty', 'pending_empty', 'io_empty', 'dedup_expired')
MEMORY = ('app_inline_bytes', 'app_pool_requested_heap_bytes', 'fixture_inline_bytes',
          'fixture_requested_heap_bytes', 'fixture_total_requested_bytes',
          'peer_context_nested_bytes', 'latency_bytes', 'calibration_bytes',
          'token_ledger_bytes', 'serializer_buffer_bytes', 'remaining')
NATIVE_KEYS = ('schema', 'contract_sha256', 'contract', 'case', 'security', 'profile',
               'operations', 'warmup', 'calibration_samples', 'verified_cycles', 'latencies_ns',
               'calibration_ns', 'internal_datagrams', 'udp_datagrams', 'handler_calls',
               'clock_ms', 'metrics', 'sender_sequences', 'memory', 'settled')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def equal(value, expected):
    # JSON equality must distinguish true from 1 throughout nested objects.
    if encoded(value) != encoded(expected):
        raise ValueError('frozen Stage B value differs')


def contract():
    raw = (Path(__file__).with_name('admission_stage_b_contract.json')).read_bytes()
    value = json.loads(raw)
    if raw != encoded(value)+b'\n':
        raise ValueError('canonical frozen contract bytes required')
    if hashlib.sha256(encoded(value)).hexdigest() != HASH:
        raise ValueError('frozen Stage B contract hash differs')
    return value


def descriptor(api):
    c = contract()
    return api.Contract(ID, c['schema'], c['owner_schema'], ROOT, ID,
                        tuple((a, v['commit']) for a, v in c['cores'].items()),
                        tuple((a, v['tree']) for a, v in c['cores'].items()), ())


def binding():
    contract()
    return dict(contract_id=ID, contract_sha256=HASH)


def purpose(args):
    equal(args.contract, ID)
    if args.command not in ('build', 'measure', 'all', 'proof'):
        raise ValueError('unknown Stage B command')
    return contract()['qualification_purpose' if args.command == 'proof' else 'purpose']


def check(value, selected_purpose):
    equal({k: value.get(k) for k in binding()}, binding())
    equal(value.get('purpose'), selected_purpose)


def bound(value, selected_purpose):
    return dict(value, **binding(), purpose=selected_purpose)


def source_check(api, core, suite_sha, core_sha):
    c = contract()
    known = {v['commit']: v['tree'] for v in c['cores'].values()}
    if core_sha not in known:
        raise ValueError('foreign Stage B core')
    api.tree_check(api.ds.identity(core), core_sha, known[core_sha])
    equal(api.ds.identity(api.SUITE)['commit'], suite_sha)


def schedule():
    rows = []
    for case in contract()['cases']:
        for mode in contract()['modes']:
            for order in contract()['rounds']:
                for arm in order:
                    rows.append(dict(index=len(rows), arm=arm, case=case['id'], security=mode,
                                     profile=case['profile'], order=order))
    return rows


def uint(value, maximum=2**128-1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('bounded unsigned integer required')
    return value


def keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('exact Stage B object keys required')


def array(value, count, maximum=2**128-1):
    if type(value) is not list or len(value) != count:
        raise ValueError('exact Stage B array length required')
    for item in value:
        uint(item, maximum)


def test_cell(name, qualification=False):
    c = contract()
    if name not in c['native_validation_tests' if qualification else 'native_timing_tests']:
        raise ValueError('unselected native test')
    stem = name.split('::')[1]
    mode = 'unprotected' if stem.endswith('_unprotected') else 'oscore'
    return stem[:-len(mode)-1], mode


def validate_native(value, row):
    c = contract()
    keys(value, NATIVE_KEYS)
    equal(value['schema'], c['native_schema'])
    equal(value['contract_sha256'], HASH)
    equal(value['contract'], c)
    case = next(x for x in c['cases'] if x['id'] == row['case'])
    for key, expected in dict(case=case['id'], security=row['security'], profile=case['profile'],
                              operations=1000, warmup=128, calibration_samples=4096,
                              verified_cycles=1128, internal_datagrams=case['internal_datagrams_per_cycle']*1128,
                              udp_datagrams=0, handler_calls=case['handler_calls_per_cycle']*1128,
                              clock_ms=[0,279744000]).items():
        equal(value[key], expected)
    keys(value['latencies_ns'], case['labels'])
    for values in value['latencies_ns'].values():
        array(values, 1000, 30_000_000_000)
        if math.fsum(values) <= 0:
            raise ValueError('nonpositive latency mean')
    array(value['calibration_ns'], 4096)
    equal(value['metrics'], {k: case[k+'_per_cycle']*1128 for k in METRICS})
    equal(value['settled'], dict.fromkeys(SETTLED, True))
    seq = value['sender_sequences']
    if row['security'] == 'unprotected':
        equal(seq, None)
    else:
        equal(row['security'], 'oscore')
        keys(seq, ('app', 'peer', 'fresh_app', 'fresh_peer', 'max_piv_bytes'))
        equal(seq['max_piv_bytes'], 2)
        for direction in ('app', 'peer'):
            array(seq[direction], 2, 11280)
            equal(seq[direction][0], 0)
            uint(seq['fresh_'+direction], 11280)
            equal(seq['fresh_'+direction], seq[direction][1]-seq[direction][0])
    mem = value['memory']
    keys(mem, MEMORY)
    for key in MEMORY[:-1]:
        uint(mem[key], 2**64-1)
    equal(mem['remaining'], 'allocator/runtime/initialization/peak-stack costs unknown')
    for key, n in dict(latency_bytes=48000, calibration_bytes=65536,
                       token_ledger_bytes=27072, serializer_buffer_bytes=8192).items():
        equal(mem[key], n)
    equal(mem['fixture_total_requested_bytes'], mem['fixture_inline_bytes']+mem['fixture_requested_heap_bytes'])
    if (mem['fixture_total_requested_bytes'] > 262144 or
            mem['fixture_total_requested_bytes'] < sum(mem[k] for k in
                ('latency_bytes','calibration_bytes','token_ledger_bytes','serializer_buffer_bytes')) or
            mem['peer_context_nested_bytes'] > mem['fixture_total_requested_bytes'] or mem['app_inline_bytes'] == 0):
        raise ValueError('fixture memory accounting differs')
    if case['profile'] == 'SmallDevice':
        equal(mem['app_pool_requested_heap_bytes'], 0)
    elif mem['app_pool_requested_heap_bytes'] == 0:
        raise ValueError('allocated App pool layout required')
    return value


def parse_result(api, raw, name, qualification=False, *, stderr=b'', returncode=0):
    if returncode != 0 or stderr:
        raise ValueError('failed native process')
    if len(raw)+len(stderr) > 2*1024**2:
        raise ValueError('native output budget exceeded')
    text = raw.decode('utf-8', errors='strict').replace('\r\n', '\n')
    marker = 'COAPTIC_STAGE_B_QUALIFICATION ' if qualification else 'COAPTIC_STAGE_B_RESULT '
    matches = list(re.finditer(r'(?m)^'+marker+r'([^\n]+)\n', text))
    if len(matches) != 1 or matches[0].start() == 0 or text[matches[0].start()-1] != '\n':
        raise ValueError('one newline-prefixed native marker required')
    match = matches[0]
    value = api.read_json(match.group(1).encode())
    rest = text[:match.start()]+text[match.end():]
    # libtest terse prints a dot separately from the marker under nocapture.
    pattern = (r'\s*running 1 test\s*\.\s*test result: ok\. 1 passed; 0 failed; '
               r'0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s\s*')
    if not re.fullmatch(pattern, rest):
        raise ValueError('unexpected terse libtest census/output')
    case, mode = test_cell(name, qualification)
    if qualification:
        equal(value, dict(schema=QUAL_SCHEMA, contract_sha256=HASH, case=case,
                          security=mode, cycles=16, passed=True, measurement='NOT RUN'))
    else:
        validate_native(value, dict(case=case, security=mode))
    return value


def validate_listing(raw, names):
    text = raw.decode('utf-8', errors='strict').replace('\r\n','\n')
    lines = text.strip().splitlines()
    if not lines:
        raise ValueError('empty native listing')
    equal(lines[-1], str(len(names))+' tests, 0 benchmarks')
    actual = [line[:-6] for line in lines[:-1] if line.endswith(': test')]
    if sorted(actual) != sorted(names) or len(actual) != len(names) or any(
            line and not line.endswith(': test') for line in lines[:-1]):
        raise ValueError('native listing differs')


def cargo_command(api, cargo):
    return [cargo, 'test', '--release', '--locked', '--target', api.TARGET,
            '--manifest-path', str(api.NATIVE/'servers/Cargo.toml'), '-p', 'bench-rust-server',
            '--test', ID, '--features', ID, '--no-run', '--message-format=json-render-diagnostics']


def artifact_pair(api, raw, target):
    artifacts, finished = [], []
    for line in raw.splitlines():
        value = api.read_json(line)
        if value.get('reason') == 'build-finished':
            finished.append(value.get('success') is True)
        if value.get('reason') == 'compiler-artifact' and value.get('target', {}).get('name') == ID:
            artifacts.append(value)
    if len(artifacts) != 1 or finished != [True]:
        raise ValueError('exactly one Stage B Cargo artifact required')
    value = artifacts[0]
    if (value['target'].get('kind') != ['test'] or value.get('profile', {}).get('test') is not True
            or str(value['profile'].get('opt_level')) != '3'):
        raise ValueError('optimized integration test artifact required')
    if (not isinstance(value.get('executable'), str) or not Path(value['executable']).is_absolute()
            or not isinstance(value.get('filenames'), list) or any(not isinstance(p,str) or not Path(p).is_absolute() for p in value['filenames'])):
        raise ValueError('absolute artifact filenames required')
    exe = Path(value['executable']).resolve()
    filenames = [Path(p).resolve() for p in value['filenames']]
    pdb = exe.with_suffix('.pdb')
    if (len(filenames) != len(set(filenames)) or filenames.count(exe) != 1 or filenames.count(pdb) != 1
            or len([p for p in filenames if p.suffix.lower() in ('.exe','.pdb')]) != 2):
        raise ValueError('matching artifact-owned EXE/PDB required')
    for path in (exe,pdb):
        if not path.is_relative_to(Path(target).resolve()) or not path.is_file() or path.suffix not in ('.exe','.pdb'):
            raise ValueError('artifact outside owned target')
    return exe,pdb


def compare(api, arms):
    blocks = {}
    for arm in ('A','B'):
        array(arms[arm],1000,30_000_000_000)
        blocks[arm] = [math.fsum(arms[arm][i:i+50])/50 for i in range(0,1000,50)]
        if any(x <= 0 or not math.isfinite(x) for x in blocks[arm]):
            raise ValueError('invalid block mean; inconclusive STOP')
    rng = random.Random(20261030)
    ratios = []
    for _ in range(10000):
        a = math.fsum(rng.choices(blocks['A'], k=20))/20
        b = math.fsum(rng.choices(blocks['B'], k=20))/20
        ratios.append(b/a)
    upper = api.quantile(sorted(ratios), .95)
    return dict(mean_ratio=math.fsum(arms['B'])/math.fsum(arms['A']), upper95=upper,
                passed=math.isfinite(upper) and upper <= 1.02, orientation='B/A')


def owner(api, args, root):
    return bound(dict(schema=contract()['owner_schema'], root=str(root), owner=os.environ.get('GITHUB_RUN_ID'),
                      attempt=os.environ.get('GITHUB_RUN_ATTEMPT'), expected_suite=args.expected_suite,
                      core=str(Path(args.core).resolve()), contract=contract(), flags=api.FLAGS), purpose(args))


def run_native(api, budget, binary, name, stem, qualification):
    command = [str(binary)] + ([] if qualification else ['--ignored']) + [
        '--exact', name, '--test-threads=1', '--nocapture', '--format=terse', '--color=never']
    raw = api.child_command(command, budget, stem, env=os.environ, seconds=30)
    receipt = api.load(budget.root/'evidence'/(stem+'-process.json'))
    equal(receipt['passed'], True)
    return parse_result(api, raw, name, qualification,
                        stderr=(budget.root/'evidence'/(stem+'.stderr')).read_bytes(),
                        returncode=receipt['returncode'])


def verify_worker_source(api, spec):
    args = argparse.Namespace(**spec['args'])
    p = purpose(args)
    check(spec,p)
    root = Path(args.output)
    equal(api.load(root/'evidence/owner.json'), owner(api,args,root))
    for tool in spec['tools'].values():
        check(tool,p)
    check(spec['inputs'],p)
    api.tool_check(spec['tools'])
    api.config_check(spec['inputs'])
    equal(spec['cargo'],spec['tools']['cargo']['path'])
    equal(spec['flags'],api.FLAGS)
    arm = spec['arm']
    identity = contract()['cores'][arm]
    api.tree_check(api.ds.identity(args.core),identity['commit'],identity['tree'])
    check(spec['source'],p)
    check(spec['suite'],p)
    equal(str(Path(spec['root']).resolve()), str(root.resolve()))
    api.tree_check(spec['source']['identity'],identity['commit'],identity['tree'])
    api.verify_staged_suite(args.core,args.expected_suite,spec['suite'],spec['lock'])
    api.check_files(args.core,spec['source']['files'])
    files = dict(spec['suite']['files'])
    files['tools/benchmark/native/Cargo.lock'] = spec['lock']['selected_sha256']
    api.check_files(api.SUITE,files)


def cargo_worker(api,spec):
    verify_worker_source(api,spec)
    root, arm, p = Path(spec['root']), spec['arm'], spec['purpose']
    budget = api.Budget(root,spec['seconds'],rss_limit=2*1024**3)
    raw = api.child_command(cargo_command(api,spec['cargo']), budget,arm+'-build',env=os.environ,seconds=spec['seconds'])
    pair = artifact_pair(api,raw,root/'target')
    retained = {}
    for kind,path in zip(('exe','pdb'),pair):
        if path.stat().st_size+api.wp.owned_size(root/'evidence')+api.RESERVE > api.EVIDENCE_LIMIT:
            raise ValueError('retained pair evidence budget')
        retained[kind] = bound(api.wp.retain_file(root,path,root/'evidence'/arm/path.name),p)
    api.artifact_check(root,{arm:retained})
    binary = retained['exe']['path']
    for qualification,names,prefix in ((True,contract()['native_validation_tests'],'stage_b_validation::'),
                                      (False,contract()['native_timing_tests'],'stage_b::')):
        cmd = [binary]+([] if qualification else ['--ignored'])+[prefix,'--list']
        stem = arm+('-qualification-list' if qualification else '-timing-list')
        listing = api.child_command(cmd,budget,stem,env=os.environ,seconds=30)
        if (root/'evidence'/(stem+'.stderr')).read_bytes():
            raise ValueError('unexpected listing stderr')
        validate_listing(listing,names)
    for i,name in enumerate(contract()['native_validation_tests']):
        verify_worker_source(api,spec)
        api.artifact_check(root,{arm:retained})
        run_native(api,budget,binary,name,arm+'-qualification-'+str(i),True)
    verify_worker_source(api,spec)
    api.artifact_check(root,{arm:retained})
    api.save(root,arm+'-cargo.json',bound(dict(artifacts=retained, native_tests=contract()['native_validation_tests'],
                  timing_tests=contract()['native_timing_tests'], measurements='NOT RUN'),p))


def build(api,args,root,owned):
    deadline = time.monotonic()+830
    inputs = bound(api.ds.cargo_inputs(),purpose(args))
    compiler,cargo,tools = api.ds.toolchain()
    if not compiler.startswith('rustc 1.99.0 ') or '\nhost: '+api.TARGET not in compiler or not cargo.startswith('cargo 1.99.0 '):
        raise ValueError('exact Rust/Cargo 1.99.0 host MSVC required')
    tools['python'] = dict(path=str(Path(sys._base_executable).resolve()),sha256=api.ds.digest(sys._base_executable))
    tools = {name:bound(value,purpose(args)) for name,value in tools.items()}
    env = api.environment(root,tools)
    suite = api.snapshot(api.SUITE)
    records,artifacts,primary = {},{},None
    p = purpose(args)
    try:
        for arm,identity in contract()['cores'].items():
            remaining = deadline-time.monotonic()
            if remaining <= 35:
                raise TimeoutError('830-second build owner deadline')
            outer = min(450,remaining-20)
            record = records[arm] = {}
            def operation(lock):
                record['source'] = bound(record['source'],p)
                record['suite'] = bound(record['suite'],p)
                return api.launch(root,arm,bound(dict(kind='cargo',root=str(root),arm=arm,cargo=tools['cargo']['path'],
                    seconds=min(400,outer-30),args=vars(args),source=record['source'],suite=record['suite'],lock=lock,
                    tools=tools,inputs=inputs,flags=api.FLAGS),p),
                    env,timeout=outer,build=True,selected=descriptor(api))
            api.transaction(args.core,args.expected_suite,identity['commit'],operation,record,descriptor(api))
            records[arm] = bound(record,p)
            receipt = api.load(root/'evidence'/(arm+'-cargo.json'))
            check(receipt,p)
            artifacts[arm] = receipt['artifacts']
            api.tool_check(tools)
            api.config_check(inputs)
            equal(api.snapshot(api.SUITE),suite)
        if time.monotonic() >= deadline:
            raise TimeoutError('830-second build owner deadline')
        api.save(root,'build.json',bound(dict(owner=owned,contract=contract(),suite=suite,records=records,
                 artifacts=artifacts,compiler=compiler,cargo=cargo,tools=tools,inputs=inputs,flags=api.FLAGS),p))
    except BaseException as error:
        primary = error
        raise
    finally:
        if not getattr(primary,'cleanup_unresolved',False):
            def immutable_checks():
                api.tool_check(tools)
                api.config_check(inputs)
                api.artifact_check(root,artifacts)
                equal(api.snapshot(api.SUITE),suite)
                api.source_gate(args.core,args.expected_suite,api.BASELINE,descriptor(api))
            api.report_preserving(primary,'build immutable checks',immutable_checks)
        api.report_preserving(primary,'build-finally receipt',lambda:api.save(root,'build-finally.json',
            bound(dict(records=records,cleanup_unresolved=getattr(primary,'cleanup_unresolved',False)),p)))


def verify_build(api,args,root):
    p = purpose(args)
    equal(api.load(root/'evidence/owner.json'),owner(api,args,root))
    value = api.load(root/'evidence/build.json')
    check(value,p)
    equal(value['owner'],owner(api,args,root))
    equal(value['contract'],contract())
    equal(value['flags'],api.FLAGS)
    api.source_gate(args.core,args.expected_suite,api.BASELINE,descriptor(api))
    equal(api.snapshot(api.SUITE),value['suite'])
    baseline = api.snapshot(args.core)
    equal(value['records']['A']['source'],bound(baseline,p))
    for tool in value['tools'].values():
        check(tool,p)
    check(value['inputs'],p)
    api.tool_check(value['tools'])
    api.config_check(value['inputs'])
    equal(sorted(value['artifacts']),['A','B'])
    equal(sorted(value['records']),['A','B'])
    for arm,identity in contract()['cores'].items():
        record = value['records'][arm]
        check(record,p)
        check(record['source'],p)
        check(record['suite'],p)
        api.tree_check(record['source']['identity'],identity['commit'],identity['tree'])
        equal(record['restoration'],'verified clean initial source')
        equal(record['suite'],bound(value['suite'],p))
        receipt = api.load(root/'evidence'/(arm+'-cargo.json'))
        check(receipt,p)
        equal(receipt['native_tests'],contract()['native_validation_tests'])
        equal(receipt['timing_tests'],contract()['native_timing_tests'])
        equal(receipt['artifacts'],value['artifacts'][arm])
        for artifact in value['artifacts'][arm].values():
            check(artifact,p)
        for qualification,names,stem in ((True,contract()['native_validation_tests'],'qualification'),
                                         (False,contract()['native_timing_tests'],'timing')):
            list_stem = arm+'-'+stem+'-list'
            listing_receipt = api.load(root/'evidence'/(list_stem+'-process.json'))
            equal(listing_receipt['passed'],True)
            equal(listing_receipt['returncode'],0)
            equal(listing_receipt['command'],[value['artifacts'][arm]['exe']['path']]+([] if qualification else ['--ignored'])+
                  ['stage_b_validation::' if qualification else 'stage_b::','--list'])
            equal((root/'evidence'/(list_stem+'.stderr')).read_text(),'')
            validate_listing((root/'evidence'/(list_stem+'.stdout')).read_bytes(),names)
        for i,name in enumerate(contract()['native_validation_tests']):
            stem = arm+'-qualification-'+str(i)
            receipt = api.load(root/'evidence'/(stem+'-process.json'))
            equal(receipt['passed'],True)
            equal(receipt['command'],[value['artifacts'][arm]['exe']['path'],'--exact',name,
                  '--test-threads=1','--nocapture','--format=terse','--color=never'])
            parse_result(api,(root/'evidence'/(stem+'.stdout')).read_bytes(),name,True,
                         stderr=(root/'evidence'/(stem+'.stderr')).read_bytes(),returncode=receipt['returncode'])
    api.artifact_check(root,value['artifacts'])
    return value


def measure_worker(api,spec):
    args = argparse.Namespace(**spec['args'])
    p = purpose(args)
    equal(p,contract()['purpose'])
    check(spec,p)
    root = Path(args.output)
    budget = api.Budget(root,300)
    completed,attempted,comparisons,data = [],[],[],{}
    primary = None
    def verify():
        api.check_files(root/'evidence',spec['prepared_hashes'])
        return verify_build(api,args,root)
    try:
        prepared = verify()
        with api.affinity(root):
            for row in schedule():
                budget.check(force=True)
                verify()
                pair = prepared['artifacts'][row['arm']]
                name = 'stage_b::'+row['case']+'_'+row['security']
                stem = 'sample-'+str(row['index']).zfill(2)
                attempted.append(row)
                result = run_native(api,budget,pair['exe']['path'],name,stem,False)
                verify()
                api.save(root,stem+'.json',bound(dict(selection=row,artifact=pair['exe'],
                    raw_sha256=api.ds.digest(root/'evidence'/(stem+'.stdout')),passed=True),p))
                data[(row['case'],row['security'],row['order'],row['arm'])] = result['latencies_ns']
                completed.append(row)
        for case in contract()['cases']:
            for mode in contract()['modes']:
                for order in contract()['rounds']:
                    for label in case['labels']:
                        budget.check(force=True)
                        try:
                            comparison = compare(api,{a:data[(case['id'],mode,order,a)][label] for a in 'AB'})
                        except ValueError as error:
                            comparison = dict(passed=False,inconclusive=True,failure=api.failure(error),orientation='B/A')
                        comparisons.append(dict(comparison,case=case['id'],security=mode,order=order,label=label))
        equal(len(completed),40)
        equal(len(comparisons),36)
        if not all(c['passed'] for c in comparisons):
            raise ValueError('Stage B gate failed; STOP')
        verify()
    except BaseException as error:
        primary = error
        raise
    finally:
        api.report_preserving(primary,'measurement-result receipt',lambda:api.save(root,'result.json',bound(dict(
            passed=primary is None,completed=completed,attempted=attempted,
            failed_or_incomplete=[r for r in attempted if r not in completed],not_run=schedule()[len(attempted):],
            comparisons=comparisons,failure=api.failure(primary) if primary else None,
            scope=contract()['measurement_scope']),p)))


def worker(api,spec):
    p = purpose(argparse.Namespace(**spec['args']))
    check(spec,p)
    if spec['kind'] == 'cargo':
        return cargo_worker(api,spec)
    if spec['kind'] == 'measure':
        return measure_worker(api,spec)
    raise ValueError('unknown Stage B worker')


def execute(api,args):
    p = purpose(args)
    if sys.platform != 'win32' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise ValueError('dedicated hosted Windows runner required')
    if shutil.which('agent-resources'):
        raise ValueError('registered hosted lane required')
    if not re.fullmatch('[0-9a-f]{40}',args.expected_suite):
        raise ValueError('immutable expected suite SHA required')
    root = Path(args.output).resolve()
    if root.parent != Path(os.environ['RUNNER_TEMP']).resolve() or root.name != ROOT:
        raise ValueError('owned Stage B output root required')
    args.output,args.core = str(root),str(Path(args.core).resolve())
    owned = owner(api,args,root)
    api.source_gate(args.core,args.expected_suite,api.BASELINE,descriptor(api))
    observed = api.preflight(root)
    if args.command != 'measure':
        root.mkdir()
        (root/'evidence').mkdir()
        api.save(root,'owner.json',owned)
        api.save(root,'preflight.json',bound(observed,p))
    else:
        if (root/'measure-task.json').exists() or (root/'evidence/failure.json').exists() or (root/'evidence/proof-complete.json').exists():
            raise ValueError('one attempt; qualification cannot authorize timing')
        receipt = api.load(root/'evidence/build-complete.json')
        check(receipt,p)
        api.check_files(root/'evidence',receipt['prepared_hashes'])
        verify_build(api,args,root)
    primary = None
    try:
        if args.command != 'measure':
            build(api,args,root,owned)
        verify_build(api,args,root)
        if args.command in ('measure','all'):
            value = verify_build(api,args,root)
            pins = {name:api.ds.digest(root/'evidence'/name) for name in ('owner.json','build.json')}
            api.launch(root,'measure',bound(dict(kind='measure',args=vars(args),prepared_hashes=pins),p),
                       api.environment(root,value['tools']),timeout=450,selected=descriptor(api))
            api.check_files(root/'evidence',pins)
            result = api.load(root/'evidence/result.json')
            check(result,p)
            equal(result['passed'],True)
        else:
            hashes = {path.name:api.ds.digest(path) for path in (root/'evidence').iterdir() if path.is_file()}
            api.save(root,'proof-complete.json' if args.command == 'proof' else 'build-complete.json',bound(dict(
                schema=QUAL_SCHEMA if args.command == 'proof' else contract()['schema'],passed=True,
                measurements='NOT RUN',qualification_executions=24,prepared_hashes=hashes),p))
    except BaseException as error:
        primary = error
        api.report_preserving(primary,'outer failure receipt',lambda:api.save(root,'failure.json',bound(api.failure(error),p)))
        raise
    finally:
        if not getattr(primary,'cleanup_unresolved',False):
            def final_check():
                api.source_gate(args.core,args.expected_suite,api.BASELINE,descriptor(api))
                if (root/'evidence/build.json').exists():
                    verify_build(api,args,root)
                api.save(root,args.command+'-final-source-check.json',bound(dict(passed=True),p))
            api.report_preserving(primary,'outer final source check',final_check)
