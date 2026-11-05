"""Closed incoming-App campaign adapter. Source freeze grants no execution authority.

Full build proof is parsed once per worker. An immutable tuple of SHA256 values
then guards fresh bytes at process boundaries, including both arms. Endpoint
checks cannot exclude transient changes. Producer restoration is an attestation;
it is separate from the consumer's actual source/artifact byte checks.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import time

ID = 'incoming-rx'
ROOT = 'coaptic-incoming-rx'
HASH = '7e1c6be071e61fb0e9176e0d5ed2e0f4c6cf6fd02bc2a8afe5815a7ee61fb02c'
CORES = (('A', 'c655b3aac485c3b88d3811b4da836b56210fce5b'),
         ('B', '13e2c32b82416b436f2fc24ede2bc86cdb82d23b'))
TREES = (('A', 'bca85f7b74b322a0f903005b18636d3a8414fe46'),
         ('B', '3538f474d634d63f3bc2247cd7f10d5c8b543d12'))
MEASUREMENT = ('complete receiving App::poll only; input/output copies and final upload handler whole-body comparison inside; '
               'partner/preparation/bridge/verification/collection outside; synthetic fresh-transfer-after-idle logical time; '
               'no throughput or Q speed claim')
LIMIT = 1024**2


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def equal(value, expected):
    if encoded(value) != encoded(expected):
        raise ValueError('incoming frozen value differs')


def keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('incoming exact object keys required')


def uint(value, maximum=2**64-1, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('incoming bounded unsigned integer required')
    return value


def array(value, count, maximum=2**128-1):
    if type(value) is not list or len(value) != count:
        raise ValueError('incoming exact array length required')
    for item in value:
        uint(item, maximum)


def contract():
    raw = Path(__file__).with_name('incoming_rx_plan.json').read_bytes().replace(b'\r\n', b'\n')
    if hashlib.sha256(raw).hexdigest() != HASH:
        raise ValueError('incoming frozen method SHA256 differs')
    return json.loads(raw)


def descriptor(api):
    contract()
    return api.Contract(ID, 'coaptic-incoming-rx-screen/1', 'coaptic-incoming-rx-owner/1',
                        ROOT, ROOT, CORES, TREES, ())


def binding():
    return dict(contract_id=ID, contract_sha256=HASH, method_sha256=HASH)


def purpose(args):
    equal(args.contract, ID)
    if args.command not in ('build', 'measure', 'all', 'proof'):
        raise ValueError('unknown incoming command')
    return 'incoming-qualification' if args.command == 'proof' else 'incoming-screen'


def bound(value, p):
    return dict(value, **binding(), purpose=p)


def receipt(value,args):
    return bound(dict(value,expected_suite=args.expected_suite,core_commits=dict(CORES),core_trees=dict(TREES)),purpose(args))


def check(value, p):
    equal({k:value.get(k) for k in binding()}, binding())
    equal(value.get('purpose'), p)


def source_check(api, core, suite_sha, core_sha):
    if core_sha not in dict(CORES).values():
        raise ValueError('foreign incoming source')
    arm = next(a for a,c in CORES if c == core_sha)
    value = api.wp.source_identity(core, core_sha, suite_sha)
    api.tree_check(api.ds.identity(core), core_sha, dict(TREES)[arm])
    equal(api.ds.identity(api.SUITE)['commit'], suite_sha)
    contract()
    return value


def owner(api, args, root):
    return api.owner(args, root)


def cargo_prefix(api, cargo):
    return [cargo, 'test', '--release', '--locked', '--target', api.TARGET,
            '--manifest-path', str(api.NATIVE/'Cargo.toml'), '-p', 'bench-rust-server', '--bin', 'bench-core']


def test_groups(api):
    return (('tests', 'batch_tests::wall_', tuple(api.WALL_TESTS)),
            ('incoming', 'incoming_rx::tests::', tuple(contract()['qualification']['native_tests'])))


def verify_worker_source(api, spec):
    args = argparse.Namespace(**spec['args'])
    p = purpose(args)
    check(spec, p)
    root = Path(args.output)
    equal(str(root.resolve()), str(Path(spec['root']).resolve()))
    equal(api.load(root/'evidence/owner.json'), owner(api,args,root))
    equal(spec['flags'], api.FLAGS)
    equal(spec['cargo'], spec['tools']['cargo']['path'])
    api.tool_check(spec['tools'])
    api.config_check(spec['inputs'])
    arm = spec['arm']
    api.tree_check(api.ds.identity(args.core),dict(CORES)[arm],dict(TREES)[arm])
    api.tree_check(spec['source']['identity'],dict(CORES)[arm],dict(TREES)[arm])
    api.verify_staged_suite(args.core,args.expected_suite,spec['suite'],spec['lock'])
    api.check_files(args.core,spec['source']['files'])
    files = dict(spec['suite']['files'])
    files['tools/benchmark/native/Cargo.lock'] = spec['lock']['selected_sha256']
    api.check_files(api.SUITE,files)


def cargo_worker(api, spec):
    verify_worker_source(api,spec)
    root, arm = Path(spec['root']), spec['arm']
    budget = api.Budget(root,spec['seconds'],rss_limit=2*1024**3)
    prefix = cargo_prefix(api,spec['cargo'])
    for label, selector, names in test_groups(api):
        for listing in (True,False):
            verify_worker_source(api,spec)
            stem = arm+'-'+label+('-list' if listing else '')
            raw = api.child_command(prefix+[selector,'--']+(['--list'] if listing else ['--test-threads=1']),
                                    budget,stem,env=os.environ,seconds=spec['seconds'],receipt_context=receipt({},argparse.Namespace(**spec['args'])))
            api.validate_census(raw,listing=listing,expected=names)
    verify_worker_source(api,spec)
    prefix[1] = 'build'
    raw = api.child_command(prefix+['--message-format=json-render-diagnostics'],budget,arm+'-build',
                            env=os.environ,seconds=spec['seconds'],receipt_context=receipt({},argparse.Namespace(**spec['args'])))
    pair = api.wp.native_artifact_pair(raw,root/'target')
    api.save(root,arm+'-cargo.json',bound(dict(native_tests=list(api.WALL_TESTS),
        incoming_tests=contract()['qualification']['native_tests'], artifacts=list(map(str,pair)), artifact_bytes={k:dict(sha256=api.ds.digest(path),bytes=path.stat().st_size) for k,path in zip(('exe','pdb'),pair)},
        pressure_tests=[],pressure_proof=None,measurements='NOTRUN'),spec['purpose']))


def verify_tests(api, root, arm, receipt, p):
    check(receipt,p)
    equal(receipt['native_tests'],list(api.WALL_TESTS))
    equal(receipt['incoming_tests'],contract()['qualification']['native_tests'])
    equal(receipt['measurements'],'NOTRUN')
    for label, selector, names in test_groups(api):
        for listing in (True,False):
            stem = arm+'-'+label+('-list' if listing else '')
            proc = api.load(root/'evidence'/(stem+'-process.json'))
            equal(proc['passed'],True)
            equal(proc['returncode'],0)
            cmd = proc['command']
            equal(cmd,cargo_prefix(api,cmd[0])+[selector,'--']+(['--list'] if listing else ['--test-threads=1']))
            api.validate_census((root/'evidence'/(stem+'.stdout')).read_bytes(),listing=listing,expected=names)
    proc = api.load(root/'evidence'/(arm+'-build-process.json'))
    equal(proc['passed'],True)
    equal(proc['returncode'],0)
    cmd = cargo_prefix(api,proc['command'][0]); cmd[1] = 'build'
    equal(proc['command'],cmd+['--message-format=json-render-diagnostics'])


def pair_allowance(root,added):
    used = sum(p.stat().st_size for p in (root/'evidence').rglob('*') if p.is_file() and p.suffix.lower() in ('.exe','.pdb'))
    if used+added>32*1024**2: raise ValueError('incoming retained pairs exceed 32 MiB')


def allocation_check(root):
    sizes = {'pairs':0,'process':0,'proof':0}
    for path in (root/'evidence').rglob('*'):
        if path.is_file():
            kind = 'pairs' if path.suffix.lower() in ('.exe','.pdb') else 'process' if path.name.startswith('incoming-') and path.suffix in ('.stdout','.stderr') else 'proof'
            sizes[kind] += path.stat().st_size
    for kind,limit in (('pairs',32*1024**2),('process',18*1024**2),('proof',10*1024**2)):
        if sizes[kind]>limit: raise ValueError('incoming '+kind+' evidence allocation exceeded')


def verify_build(api,args,root,owned):
    p = purpose(args)
    allocation_check(root)
    equal(api.load(root/'evidence/owner.json'),owned)
    value = api.load(root/'evidence/build.json')
    check(value,p)
    equal(value['owner'],owned)
    equal(value['plan'],contract())
    equal(value['flags'],api.FLAGS)
    if (not value['compiler'].startswith('rustc 1.99.0 ') or '\nhost: '+api.TARGET not in value['compiler']
            or not value['cargo'].startswith('cargo 1.99.0 ')):
        raise ValueError('incoming tool version/host differs')
    source_check(api,args.core,args.expected_suite,dict(CORES)['A'])
    equal(api.snapshot(api.SUITE),value['suite'])
    equal(api.bound(api.snapshot(args.core),descriptor(api)),value['records']['A']['source'])
    api.tool_check(value['tools']); api.config_check(value['inputs'])
    equal(sorted(value['artifacts']),['A','B']); equal(sorted(value['records']),['A','B'])
    for arm,commit in CORES:
        record = value['records'][arm]
        api.tree_check(record['source']['identity'],commit,dict(TREES)[arm])
        equal(record['suite'],api.bound(value['suite'],descriptor(api)))
        equal(record['restoration'],'verified clean initial source')
        equal(record['cleanup_unresolved'],False)
        receipt = api.load(root/'evidence'/(arm+'-cargo.json'))
        verify_tests(api,root,arm,receipt,p)
        raw = (root/'evidence'/(arm+'-build.stdout')).read_bytes()
        pair = api.wp.native_artifact_pair(raw,root/'target')
        equal(receipt['artifacts'],list(map(str,pair)))
        for kind,path in zip(('exe','pdb'),pair):
            equal(receipt['artifact_bytes'][kind],{k:value['artifacts'][arm][kind][k] for k in ('sha256','bytes')})
            if arm == 'B':
                equal(api.ds.digest(path),value['artifacts'][arm][kind]['sha256'])
                equal(path.stat().st_size,value['artifacts'][arm][kind]['bytes'])
    api.artifact_check(root,value['artifacts'])
    return value


def anchor(api,args,root):
    """One complete proof validation, then private immutable expected bytes."""
    evidence_before = tuple((str(path.resolve()),api.ds.digest(path))
        for path in (root/'evidence').rglob('*') if path.is_file())
    task = root/'measure-task.json'
    task_before = (str(task.resolve()),api.ds.digest(task)) if task.exists() else None
    value = verify_build(api,args,root,owner(api,args,root))
    pins = {}
    def add(path, digest):
        name = str(Path(path).resolve())
        if name in pins and pins[name] != digest:
            raise ValueError('contradictory immutable byte anchor')
        pins[name] = digest
    for base,files in ((api.SUITE,value['suite']['files']),
                       (Path(args.core),value['records']['A']['source']['files'])):
        for name,digest in files.items(): add(base/name,digest)
    for tool in value['tools'].values(): add(tool['path'],tool['sha256'])
    for name,digest in value['inputs']['config_files'].items(): add(name,digest)
    for pair in value['artifacts'].values():
        for artifact in pair.values(): add(artifact['path'],artifact['sha256'])
    # Includes every transcript, receipt, launcher, prepared owner and proof.
    for name,digest in evidence_before: add(name,digest)
    for arm in 'AB':
        pair = api.wp.native_artifact_pair((root/'evidence'/(arm+'-build.stdout')).read_bytes(),root/'target')
        # A's shared-target filename may now contain B; retained A is authoritative.
        # Both retained pairs above are checked at every boundary.
        if arm == 'B':
            for kind,path in zip(('exe','pdb'),pair): add(path,value['artifacts']['B'][kind]['sha256'])
    if task_before: add(*task_before)
    frozen = tuple(sorted(pins.items()))
    verify_anchor(api,args,frozen)
    return encoded(value), frozen


def verify_anchor(api,args,frozen):
    for name,digest in frozen:
        if api.ds.digest(name) != digest:
            raise ValueError('incoming anchored bytes changed: '+name)
    source_check(api,args.core,args.expected_suite,dict(CORES)['A'])


def validate_native(api,raw,stderr=b'',returncode=0,qualification=False):
    if returncode != 0 or stderr or len(raw)+len(stderr)>LIMIT or len(raw)>LIMIT-4096:
        raise ValueError('incoming failed process/output; prefix is evidence only')
    v = api.read_json(raw)
    modekeys = ('calibration_state','traces') if qualification else ('calibration_samples','calibration_ns')
    keys(v,('schema','method_sha256','method_state','measurement','memory','cells','positive_census','status')+modekeys)
    equal(v['schema'],'coaptic-incoming-rx-qualification/1' if qualification else 'coaptic-incoming-rx/1')
    equal(v['method_sha256'],HASH); equal(v['method_state'],'source-frozen-before-execution')
    equal(v['status'],'PASS'); equal(v['measurement'],MEASUREMENT)
    mem = v['memory']
    fixed = dict(bounded_json_requested_heap_bytes=LIMIT-4096,json_vec_inline_bytes=24,
        calibration_retention='JSON values; one scalar scratch, no subtraction',calibration_scalar_bytes=16,
        raw_master_material_temporary_bytes=24,qualification_extra_wire_scratch_peak_bytes=2944 if qualification else 0,
        unknown='allocator, initialization and generated stack/runtime costs')
    keys(mem,tuple(fixed)+('audit_inline_nested_in_cell_bytes','failure_report_temporary_bytes'))
    for k,x in fixed.items(): equal(mem[k],x)
    for k in ('audit_inline_nested_in_cell_bytes','failure_report_temporary_bytes'): uint(mem[k],LIMIT,1)
    if type(v['cells']) is not list or len(v['cells']) != 8: raise ValueError('eight ordered cells required')
    c = contract()
    for i,(cell,expected) in enumerate(zip(v['cells'],c['qualification']['positive_traces'])):
        upload,protected,guard = i%4<2,i%2==1,i>=4
        polls = 1 if guard else 4 if upload else 16
        required = ('id','positive_trace_id','warm_transfers','measured_transfers','timing_state','transfers',
            'requests','responses','receiving_polls','handler_calls','collections','released_body_owners',
            'bytes_in','bytes_out','fresh_tokens','request_pivs','piv_255_to_256','public_audit_fnv64','crypto','memory','config')
        keys(cell,required+(() if upload else ('partner_config',))+(() if qualification else ('transfers_ns',)))
        equal(cell['id'],c['cells_in_order'][i]['id']); equal(cell['positive_trace_id'],expected['id'])
        for k,x in expected.items():
            if k != 'id': equal(cell[k],x)
        for k,x in dict(warm_transfers=8,measured_transfers=0 if qualification else 64,
            timing_state='NOTRUN' if qualification else 'RECORDED',request_pivs=72*polls if protected else 0,
            piv_255_to_256=protected and not guard).items(): equal(cell[k],x)
        for k in ('bytes_in','bytes_out'): uint(cell[k],72*16*1472,1)
        uint(cell['public_audit_fnv64'])
        equal(cell['crypto'],dict(request_seals=72*polls if protected else 0,
            app_authenticated_receiving_polls=72*polls if protected else 0,
            raw_peer_response_opens=72*polls if protected and upload else 0,response_seals=72*polls if protected else 0))
        config = dict(routes=4 if upload else 1,populated_routes=1 if upload else 0,calls=1 if upload else 4,
            deferred=0,associations=1,bindings=4,rx_slots=2 if upload else 4,tx_slots=2 if upload else 4,
            datagram_bytes=1152 if upload else 1472,dedup=4 if upload else 8,observe=2 if upload else 4,
            rx_body_slots=1,rx_body_bytes=4096 if upload else 16384,tx_body_slots=1,tx_body_bytes=4096 if upload else 1024)
        equal(cell['config'],config)
        if not upload:
            equal(cell['partner_config'],dict(routes=32,populated_routes=1,calls=4,deferred=8,associations=1,
                bindings=4,rx_slots=32,tx_slots=32,datagram_bytes=1472,dedup=64,observe=32,
                rx_body_slots=4,tx_body_slots=4,rx_body_bytes=16384,tx_body_bytes=16384))
        m = cell['memory']
        fixed = dict(partner_required_pool_heap_bytes=0,service_body_static_shared_bytes=16384,
            download_collection_bytes=0 if upload else 16384,upload_open_scratch_bytes=1472 if upload else 0,
            nested_transport_is_in_app=True,remaining='allocator/runtime/generated-stack/initialization unknown')
        dynamic = ('app_including_transport_inline_bytes','app_required_pool_heap_bytes',
            'fixed_partner_app_inline_bytes','raw_peer_optional_context_inline_bytes','cell_result_inline_bytes')
        keys(m,tuple(fixed)+dynamic)
        for k,x in fixed.items(): equal(m[k],x)
        for k in dynamic: uint(m[k],8*1024**2)
        for k in ('app_including_transport_inline_bytes','cell_result_inline_bytes'): uint(m[k],8*1024**2,1)
        equal(m['app_required_pool_heap_bytes'],0) if upload else uint(m['app_required_pool_heap_bytes'],8*1024**2,1)
        equal(m['fixed_partner_app_inline_bytes'],0) if upload else uint(m['fixed_partner_app_inline_bytes'],8*1024**2,1)
        uint(m['raw_peer_optional_context_inline_bytes'],LIMIT,1) if upload else equal(m['raw_peer_optional_context_inline_bytes'],0)
        if not qualification:
            transfers = cell['transfers_ns']
            if type(transfers) is not list or len(transfers)!=64: raise ValueError('64 transfers required')
            for t in transfers:
                keys(t,('sum','polls')); array(t['polls'],polls); uint(t['sum'],2**128-1)
                equal(t['sum'],sum(t['polls']))
            mean(cell)
    census = dict(c['qualification']['positive_census']); census['measured_receiving_polls'] = 0 if qualification else 2816
    equal(v['positive_census'],census)
    if qualification:
        equal(v['calibration_state'],'NOTRUN'); equal(v['traces'],c['qualification']['negative_traces'])
    else:
        equal(v['calibration_samples'],4096); array(v['calibration_ns'],4096)
    return v


def mean(cell):
    x = math.fsum(t['sum'] for t in cell['transfers_ns'])/64
    if not math.isfinite(x) or x<=0: raise ValueError('positive finite process mean required')
    return x


def compare(pairs,limit):
    if len(pairs)!=8: raise ValueError('eight complete process pairs required')
    ds = []
    for a,b in pairs:
        if not all(type(x) in (int,float) and math.isfinite(x) and x>0 for x in (a,b)):
            raise ValueError('positive finite means required')
        ratio = b/a
        if not math.isfinite(ratio) or ratio<=0: raise ValueError('ratio range')
        ds.append(math.log(ratio))
    avg = math.fsum(ds)/8
    sd = math.sqrt(math.fsum((x-avg)**2 for x in ds)/7)
    delta = 1.894579*sd/math.sqrt(8)
    ratios = [math.exp(x) for x in (avg,avg-delta,avg+delta)]
    if not all(math.isfinite(x) and x>0 for x in ratios): raise ValueError('interval range')
    return dict(mean_ratio=ratios[0],lower95=ratios[1],upper95=ratios[2],passed=ratios[2]<=limit,
                orientation='B/A',pairs=8,scope='conditional paired process evidence; no simultaneous coverage or host-independent claim')


def schedule(qualification_only=False):
    rows = [dict(index=i,arm=a,mode='qualify',seconds=20) for i,a in enumerate('AB')]
    if not qualification_only:
        for pair in range(8):
            for arm in ('AB' if pair%2==0 else 'BA'):
                rows.append(dict(index=len(rows),arm=arm,mode='measure',seconds=14,pair=pair))
    return rows


def limited_process(api):
    class IncomingProcess(api.wp.Process):
        def _read(self,index,pipe):
            try:
                while block := pipe.read(4096):
                    with self.lock:
                        left = LIMIT-sum(map(len,self.raw))
                        self.raw[index].extend(block[:max(0,left)])
                        if len(block)>left:
                            raise ValueError('incoming combined output exceeds 1 MiB')
            except BaseException as error:
                self.error = error
    return IncomingProcess


def campaign(api,args,root,prepared_bytes,frozen):
    p = purpose(args)
    prepared = api.read_json(prepared_bytes)
    budget = api.Budget(root,300)
    rows = schedule(p=='incoming-qualification')
    attempted,launched,completed,data,comparisons = [],[],[],{},[]
    primary = None
    try:
        with api.affinity(root):
            for row in rows:
                budget.check(force=True); allocation_check(root); verify_anchor(api,args,frozen)
                if api.wp.owned_size(root/'evidence')>60*1024**2-LIMIT: raise ValueError('evidence allowance')
                pair = prepared['artifacts'][row['arm']]
                stem = 'incoming-'+str(row['index']).zfill(2)
                attempted.append(row)
                raw = api.child_command([pair['exe']['path'],'--incoming-rx',row['mode']],budget,stem,
                    env=os.environ,seconds=row['seconds'],process_factory=limited_process(api),
                    on_launch=lambda:launched.append(row),receipt_context=receipt({},args))
                proc = api.load(root/'evidence'/(stem+'-process.json'))
                value = validate_native(api,raw,(root/'evidence'/(stem+'.stderr')).read_bytes(),
                                        proc['returncode'],row['mode']=='qualify')
                verify_anchor(api,args,frozen)
                api.save(root,stem+'.json',bound(dict(selection=row,artifact=pair,expected_suite=args.expected_suite,
                    core_commits=dict(CORES),core_trees=dict(TREES),raw_sha256=hashlib.sha256(raw).hexdigest(),
                    process=proc,passed=True),p))
                data[row['index']] = value
                completed.append(row)
                if row['mode']=='measure':
                    qualifier = data[0 if row['arm']=='A' else 1]
                    equal([x['memory'] for x in value['cells']],[x['memory'] for x in qualifier['cells']])
                if len(completed)==2:
                    equal([x['memory'] for x in data[0]['cells']],[x['memory'] for x in data[1]['cells']])
                    api.save(root,'qualification-complete.json',bound(dict(passed=True,qualifications=2,
                        measurements='NOTRUN',expected_suite=args.expected_suite,core_trees=dict(TREES)),p))
            if p=='incoming-screen':
                equal(len(completed),18)
                for i,cell in enumerate(contract()['cells_in_order']):
                    pairs = []
                    for pair in range(8):
                        selected = [r for r in rows if r.get('pair')==pair]
                        byarm = {r['arm']:data[r['index']]['cells'][i] for r in selected}
                        equal(byarm['A']['memory'],byarm['B']['memory'])
                        pairs.append(tuple(mean(byarm[a]) for a in 'AB'))
                    comparisons.append(dict(compare(pairs,cell['upper_one_sided_95_ratio_max']),cell=cell['id']))
                if not all(x['passed'] for x in comparisons): raise ValueError('incoming gate failed; STOP')
            verify_anchor(api,args,frozen)
    except BaseException as error:
        primary = error
        raise
    finally:
        api.report_preserving(primary,'incoming result',lambda:api.save(root,'result.json',bound(dict(
            passed=primary is None,attempted=attempted,launched=launched,completed=completed,
            incomplete=[r for r in attempted if r not in completed],not_run=[r for r in rows if r not in attempted],
            measured='RECORDED' if any(r['mode']=='measure' for r in launched) else 'NOTRUN',
            comparisons=comparisons,failure=api.failure(primary) if primary else None,
            cleanup_unresolved=getattr(primary,'cleanup_unresolved',False),
            endpoint_limit='Endpoint hashes do not exclude transient changes',expected_suite=args.expected_suite,
            core_commits=dict(CORES),core_trees=dict(TREES)),p)))


def finite_seconds(value):
    if type(value) is not float or not math.isfinite(value) or not 0<value<=400:
        raise ValueError('incoming Cargo deadline required')


def worker(api,spec):
    keys(spec['args'],('command','contract','core','expected_suite','output'))
    args = argparse.Namespace(**spec['args']); p = purpose(args); check(spec,p)
    common = ('kind','args','purpose','contract_id','contract_sha256','method_sha256','expected_suite','core_commits','core_trees')
    if spec['kind']=='cargo':
        keys(spec,common+('root','arm','cargo','seconds','source','suite','lock','tools','inputs','flags'))
        uint(spec['seconds'],400,1) if type(spec['seconds']) is int else finite_seconds(spec['seconds'])
    elif spec['kind']=='measure':
        keys(spec,common+('prepared_hashes',))
    else: raise ValueError('unknown incoming worker mode')
    equal(spec['expected_suite'],args.expected_suite)
    equal(spec['core_commits'],dict(CORES)); equal(spec['core_trees'],dict(TREES))
    if spec['kind']=='cargo': return cargo_worker(api,spec)
    if spec['kind']!='measure' or args.command not in ('all','measure','proof'):
        raise ValueError('foreign/orphan incoming worker mode')
    root = Path(args.output)
    equal(api.load(root/'measure-task.json'),spec)
    equal(spec['expected_suite'],args.expected_suite)
    api.check_files(root/'evidence',spec['prepared_hashes'])
    prepared,frozen = anchor(api,args,root)
    return campaign(api,args,root,prepared,frozen)


def execute(api,args):
    p = purpose(args)
    if sys.platform!='win32' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('dedicated hosted Windows required')
    if shutil.which('agent-resources'): raise ValueError('registered hosted lane required')
    if not re.fullmatch('[0-9a-f]{40}',args.expected_suite): raise ValueError('immutable suite required')
    root = Path(args.output).resolve()
    if root.parent!=Path(os.environ['RUNNER_TEMP']).resolve() or root.name!=ROOT:
        raise ValueError('owned incoming output root required')
    args.output,args.core = str(root),str(Path(args.core).resolve())
    owned = owner(api,args,root)
    source_check(api,args.core,args.expected_suite,dict(CORES)['A'])
    observed = api.preflight(root)
    if args.command!='measure':
        root.mkdir(); (root/'evidence').mkdir()
        api.save(root,'owner.json',owned); api.save(root,'preflight.json',bound(observed,p))
    else:
        if (root/'measure-task.json').exists() or (root/'evidence/failure.json').exists() or (root/'evidence/qualification-complete.json').exists():
            raise ValueError('one attempt; foreign qualification cannot authorize timing')
        receipt = api.load(root/'evidence/build-complete.json'); check(receipt,p)
        api.check_files(root/'evidence',receipt['prepared_hashes'])
    primary = None
    try:
        if args.command!='measure': api.build(args,root,owned)
        value = verify_build(api,args,root,owned)
        pins = {str(path.relative_to(root/'evidence')):api.ds.digest(path)
                for path in (root/'evidence').rglob('*') if path.is_file()}
        if args.command=='build':
            api.save(root,'build-complete.json',receipt(dict(passed=True,measurements='NOTRUN',prepared_hashes=pins),args))
        else:
            api.launch(root,'measure',bound(dict(kind='measure',args=vars(args),expected_suite=args.expected_suite,
                core_commits=dict(CORES),core_trees=dict(TREES),prepared_hashes=pins),p),api.environment(root,value['tools']),timeout=450,selected=descriptor(api))
            api.check_files(root/'evidence',pins)
            result = api.load(root/'evidence/result.json'); check(result,p); equal(result['passed'],True)
    except BaseException as error:
        primary = error
        api.report_preserving(primary,'incoming outer failure',lambda:api.save(root,'failure.json',bound(api.failure(error),p)))
        raise
    finally:
        if not getattr(primary,'cleanup_unresolved',False):
            api.report_preserving(primary,'incoming final source',lambda:source_check(api,args.core,args.expected_suite,dict(CORES)['A']))
