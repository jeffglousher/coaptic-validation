"""Frozen ordinary request routing contract; independent paired process analysis.

No timing observations are accepted from qualification. The public method bytes,
including their final LF, are distinct from the final integrated suite revision.
"""
import hashlib
import itertools
import json
import math
from pathlib import Path

ID = 'request-route-permutation'
METHOD_SHA256 = 'ab04a97d50ff7ed244614ef409f0abb2209cea0cae4c15b80e5d1fc49aa4aa98'
METHOD_BYTES = 24294
SOURCE = 'tools/benchmark/native/servers/src/bin/bench_core/request_route.rs'
CORES = (
    ('A', 'c655b3aac485c3b88d3811b4da836b56210fce5b'),
    ('B', 'd1295035dbcbe5c07337d596de6aed64e61f1533'))
TREES = (
    ('A', 'bca85f7b74b322a0f903005b18636d3a8414fe46'),
    ('B', 'a2752c9f4cf1600809a3ed654701900e1e0c8584'))


def contract():
    raw = Path(__file__).with_name('request_route_plan.json').read_bytes()
    if len(raw) != METHOD_BYTES or hashlib.sha256(raw).hexdigest() != METHOD_SHA256:
        raise ValueError('canonical routing method bytes differ')
    return json.loads(raw)


def descriptor(m):
    contract()
    return m.Contract(ID, 'coaptic-request-route-wall/1',
                      'coaptic-request-route-owner/1', 'coaptic-request-route-wall',
                      'request-route-wall-screen', CORES, TREES, (METHOD_SHA256,))


def binding():
    contract()
    return dict(contract_id=ID, contract_sha256=METHOD_SHA256)


def purpose(args):
    if args.command == 'proof':
        return 'request-route-qualification'
    if args.command in ('build', 'all', 'measure'):
        return 'request-route-benefit'
    raise ValueError('unknown routing purpose')


def schedule():
    p = contract()
    return [dict(index=i, replicate=k, group=g, security=s, round=r, arm=a)
            for i, (k, g, s, r, a) in enumerate(
                (k, g['id'], s, r, a) for k in range(p['replicates'])
                for g in p['groups'] for s in p['security']
                for r in p['orders'] for a in r)]


def group(identifier):
    for g in contract()['groups']:
        if g['id'] == identifier:
            return g
    raise ValueError('unknown routing group')


def trace(identifier):
    g = group(identifier)
    result = []
    for op in range(8128):
        case = dict(g['cases'][op % len(g['cases'])])
        if case['id'] == 'common':
            last = (op // 8) % 10 == 9
            case.update(path='r31' if last else 'r00', body_tag=31 if last else 0)
        result.append(dict(operation=op, phase='warmup' if op < 128 else 'measure', **case))
    return result


def unsigned(value, label, maximum=2**128-1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('invalid unsigned ' + label)
    return value


def intervals(values, count):
    if type(values) is not list or len(values) != count:
        raise ValueError('interval census differs')
    for x in values:
        unsigned(x, 'interval')
    return values


def process_means(values, identifier):
    intervals(values, 8000)
    cases = group(identifier)['cases']
    return {case['id']: math.fsum(values[i] for i in range(8000)
                                 if (i + 128) % len(cases) == j) /
            sum((i + 128) % len(cases) == j for i in range(8000))
            for j, case in enumerate(cases)}


def paired(a, b):
    if len(a) != 4 or len(b) != 4:
        raise ValueError('four adjacent process pairs required')
    if any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in (*a, *b)):
        raise ValueError('positive finite process means required')
    point = math.fsum(b) / math.fsum(a)
    ratios = sorted(math.fsum(b[i] for i in ix) / math.fsum(a[i] for i in ix)
                    for ix in itertools.product(range(4), repeat=4))
    position = (len(ratios) - 1) * .95
    lo, hi = math.floor(position), math.ceil(position)
    frac = position - lo
    return dict(point=point, upper95=ratios[lo] * (1-frac) + ratios[hi] * frac,
                tuples=256)


def analyze(records):
    rows = schedule()
    if type(records) is not list or len(records) != 160:
        raise ValueError('all160 processes required before decisions')
    means = {}
    for expected, record in zip(rows, records):
        if json.dumps(record['selection'], sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError('missing/duplicate/swapped process evidence')
        key = tuple(expected[k] for k in ('group', 'security', 'round', 'replicate', 'arm'))
        means[key] = process_means(record['latencies_ns'], expected['group'])
    results = []
    p = contract()
    benefit = p['statistics']['benefit']
    for g in p['groups']:
        for security in p['security']:
            for order in p['orders']:
                for case in g['cases']:
                    a, b = ([means[(g['id'], security, order, k, arm)][case['id']]
                             for k in range(4)] for arm in 'AB')
                    result = paired(a, b)
                    required = (g['id'] == benefit['group'] and security == benefit['security']
                                and case['id'] in benefit['cases'])
                    passed = (result['point'] <= .97 and result['upper95'] < 1
                              if required else result['upper95'] <= 1.02)
                    results.append(dict(group=g['id'], security=security, round=order,
                                        case=case['id'], role='benefit' if required else 'regression',
                                        passed=passed, **result))
    if len(results) != 84 or sum(x['role'] == 'benefit' for x in results) != 8:
        raise ValueError('comparison census differs')
    return results


def layout_pair(a, b, identifier):
    n = group(identifier)['route_capacity']
    for x in (a, b):
        for key in ('app_inline_bytes', 'app_align_bytes', 'pool_heap_requested_bytes'):
            unsigned(x[key], key)
        align = x['app_align_bytes']
        if not align or align & (align-1):
            raise ValueError('App alignment is not a power of two')
    if b['app_inline_bytes'] > a['app_inline_bytes'] + n + 2*max(a['app_align_bytes'], b['app_align_bytes']):
        raise ValueError('App growth guard failed')
    if a['pool_heap_requested_bytes'] != b['pool_heap_requested_bytes']:
        raise ValueError('requested pool heap changed')


def source_check(m, suite_sha):
    m.exact(m.ds.identity(m.SUITE)['commit'], suite_sha, 'final routing suite revision differs')
    if suite_sha == 'b069ed2fcfc0a4edb103d1fae940bde739b6efcb':
        raise ValueError('starting suite is not integrated routing implementation')
    files = m.snapshot(m.SUITE)['files']
    for name in (m.FIXTURE, SOURCE, 'tools/benchmark/request_route_plan.json',
                 'tools/benchmark/request_route_plan.md', 'tools/benchmark/request_route_wall.py'):
        if name not in files:
            raise ValueError('full routing source inventory missing: ' + name)
    contract()


def route_tests():
    return tuple('request_route::tests::' + x for x in contract()['unit_test_filters']['route_names'])


def normal_artifact(m, raw, target):
    artifacts = []
    for line in raw.splitlines():
        if line.startswith(b'{'):
            row = m.read_json(line)
            if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'bench-core':
                artifacts.append(row)
    if len(artifacts) != 1 or artifacts[0].get('profile', {}).get('test') is not False:
        raise ValueError('normal non-libtest bench-core artifact required')
    return m.wp.native_artifact_pair(raw, target)


def verify_worker(m, spec, selected):
    m.check_binding(spec, selected)
    args = m.argparse.Namespace(**spec['args'])
    m.exact(m.selection(args), selected, 'worker selector differs')
    m.exact(spec['purpose'], purpose(args), 'worker purpose differs')
    root = Path(args.output)
    if root.resolve().name != selected.root or root.resolve().parent != Path(m.os.environ['RUNNER_TEMP']).resolve():
        raise ValueError('worker routing namespace differs')
    m.exact(str(Path(spec.get('root', root)).resolve()), str(root.resolve()), 'worker root differs')
    m.exact(m.load(root / 'evidence/owner.json'), m.owner(args, root), 'worker owner differs')
    return args, root


def cargo_worker(m, spec, selected):
    args, root = verify_worker(m, spec, selected)
    m.exact(spec['kind'], 'cargo', 'routing Cargo worker kind differs')
    if type(spec['seconds']) not in (int, float) or not math.isfinite(spec['seconds']) or not 0 < spec['seconds'] <= m.CARGO_SECONDS:
        raise ValueError('Cargo worker budget differs')
    frozen = m.load(root / 'evidence/build-inputs.json')
    m.check_binding(frozen, selected)
    m.exact(frozen['owner'], m.owner(args, root), 'frozen build owner differs')
    for key in ('tools', 'inputs', 'flags'):
        m.exact(spec[key], frozen[key], 'worker build input differs: ' + key)
    m.exact(spec['flags'], m.FLAGS, 'Cargo flags differ')
    m.tool_check(spec['tools'])
    m.config_check(spec['inputs'])
    m.exact(spec['cargo'], spec['tools']['cargo']['path'], 'Cargo tool differs')
    for key, value in m.FLAGS.items():
        m.exact(m.os.environ.get(key), value, 'Cargo environment flag differs')
    arm = spec['arm']
    if arm not in dict(CORES):
        raise ValueError('foreign build arm')
    def verify():
        verify_worker(m, spec, selected)
        m.tool_check(spec['tools'])
        m.config_check(spec['inputs'])
        for value in (spec['source'], spec['suite']):
            m.check_binding(value, selected)
        m.tree_check(spec['source']['identity'], dict(CORES)[arm], dict(TREES)[arm])
        m.tree_check(m.ds.identity(args.core), dict(CORES)[arm], dict(TREES)[arm])
        m.verify_staged_suite(args.core, args.expected_suite, spec['suite'], spec['lock'])
        m.check_files(args.core, spec['source']['files'])
        staged = dict(spec['suite']['files'])
        staged['tools/benchmark/native/Cargo.lock'] = spec['lock']['selected_sha256']
        m.check_files(m.SUITE, staged)
        if SOURCE not in staged:
            raise ValueError('routing module inventory missing')
    verify()
    budget = m.Budget(root, spec['seconds'], rss_limit=2*1024**3)
    prefix = [spec['cargo'], 'test', '--release', '--locked', '--target', m.TARGET,
              '--manifest-path', str(m.NATIVE / 'Cargo.toml'),
              '-p', 'bench-rust-server', '--bin', 'bench-core']
    for label, query, expected in (('tests', 'batch_tests::wall_', m.WALL_TESTS),
                                    ('route-tests', 'request_route::tests::', route_tests())):
        for listing in (True, False):
            verify()
            tail = ['--', '--list'] if listing else ['--', '--test-threads=1']
            raw = m.child_command(prefix + [query] + tail, budget,
                                  arm + '-' + label + ('-list' if listing else ''),
                                  env=m.os.environ, seconds=spec['seconds'])
            m.validate_census(raw, listing=listing, expected=expected)
    prefix[1] = 'build'
    verify()
    raw = m.child_command(prefix + ['--message-format=json-render-diagnostics'], budget,
                          arm + '-build', env=m.os.environ, seconds=spec['seconds'])
    pair = normal_artifact(m, raw, root / 'target')
    verify()
    m.save(root, arm + '-cargo.json', m.bound(dict(
        purpose=purpose(args), arm=arm, native_tests=list(m.WALL_TESTS),
        route_tests=list(route_tests()), artifacts=list(map(str, pair)),
        source=spec['source'], suite=spec['suite'], lock=spec['lock']), selected))
    budget.check(force=True)


def verify_tests(m, root, arm, receipt, selected_purpose, selected):
    m.check_binding(receipt, selected)
    m.exact(receipt['purpose'], selected_purpose, 'prepared routing purpose differs')
    m.exact(receipt['arm'], arm, 'prepared routing arm differs')
    m.exact(receipt['native_tests'], list(m.WALL_TESTS), 'legacy wall census differs')
    m.exact(receipt['route_tests'], list(route_tests()), 'routing census differs')
    for label, expected in (('tests', m.WALL_TESTS), ('route-tests', route_tests())):
        for listing in (True, False):
            raw = (root / 'evidence' / (arm + '-' + label +
                   ('-list' if listing else '') + '.stdout')).read_bytes()
            m.validate_census(raw, listing=listing, expected=expected)
    normal_artifact(m, (root / 'evidence' / (arm + '-build.stdout')).read_bytes(), root / 'target')


def prepared_check(m, args, root, selected):
    contract_owner = m.owner(args, root)
    complete = m.load(root / 'evidence/build-complete.json')
    m.check_binding(complete, selected)
    m.exact(complete['owner'], contract_owner, 'build-complete owner differs')
    m.exact(complete['purpose'], purpose(args), 'build-complete purpose differs')
    m.check_files(root / 'evidence', complete['prepared_hashes'])
    value = m.verify_build(args, root, contract_owner)
    frozen = m.load(root / 'evidence/build-inputs.json')
    m.check_binding(frozen, selected)
    m.exact(frozen['owner'], contract_owner, 'prepared build inputs owner differs')
    for key in ('tools', 'inputs', 'flags', 'suite', 'compiler', 'cargo'):
        m.exact(frozen[key], value[key], 'prepared build inputs differ: ' + key)
    for arm, record in value['records'].items():
        receipt = m.load(root / 'evidence' / (arm + '-cargo.json'))
        for name in ('source', 'suite', 'lock'):
            m.exact(receipt[name], record[name], 'build worker evidence differs: ' + name)
    return value


def qualification_schedule():
    return [dict(index=i, group=g['id'], security=s, arm=a)
            for i, (a,g,s) in enumerate((a,g,s) for a in 'AB'
                for g in contract()['groups'] for s in contract()['security'])]


def measure_worker(m, spec, selected):
    args, root = verify_worker(m, spec, selected)
    m.exact(spec['kind'], 'measure', 'routing worker kind differs')
    m.exact(spec['prepared_hashes'], m.load(root / 'evidence/build-complete.json')['prepared_hashes'],
            'measurement worker prepared inputs differ')
    timing = args.command != 'proof'
    budget = m.Budget(root, m.MEASURE_SECONDS)
    completed, attempted, qualification, qual_attempted, comparisons, records = [], [], [], [], [], []
    primary = None
    def verify():
        m.check_files(root / 'evidence', spec['prepared_hashes'])
        return prepared_check(m, args, root, selected)
    try:
        prepared = verify()
        layouts = {}
        with m.affinity(root):
            for row in qualification_schedule():
                budget.check(force=True)
                verify()
                binary = prepared['artifacts'][row['arm']]['exe']['path']
                command = [binary, '--request-route', 'qualify', row['group'], row['security']]
                stem = 'qualify-' + str(row['index']).zfill(2)
                qual_attempted.append(row)
                raw = m.child_command(command, budget, stem, env=m.os.environ, seconds=m.PROCESS_SECONDS)
                value = native_json(m, root, stem, raw)
                facts = validate_native(m, value, row['group'], row['security'], 'qualify')
                verify()
                m.save(root, stem + '.json', m.bound(dict(selection=row, command=command,
                    facts=facts, artifacts=prepared['artifacts'][row['arm']],
                    purpose=purpose(args), raw_sha256=hashlib.sha256(raw).hexdigest()), selected))
                layouts[(row['arm'], row['group'], row['security'])] = facts['layout']
                qualification.append(row)
            for g in contract()['groups']:
                for s in contract()['security']:
                    layout_pair(layouts[('A',g['id'],s)], layouts[('B',g['id'],s)], g['id'])
            if timing:
                for row in schedule():
                    budget.check(force=True)
                    verify()
                    binary = prepared['artifacts'][row['arm']]['exe']['path']
                    command = [binary, '--request-route', 'measure', row['group'], row['security']]
                    stem = 'sample-' + str(row['index']).zfill(3)
                    attempted.append(row)
                    raw = m.child_command(command, budget, stem, env=m.os.environ, seconds=m.PROCESS_SECONDS)
                    value = native_json(m, root, stem, raw)
                    facts = validate_native(m, value, row['group'], row['security'], 'measure')
                    same_layout(m, facts['layout'], layouts[(row['arm'],row['group'],row['security'])])
                    verify()
                    m.save(root, stem + '.json', m.bound(dict(selection=row, command=command,
                        facts=facts, artifacts=prepared['artifacts'][row['arm']],
                        purpose=purpose(args), raw_sha256=hashlib.sha256(raw).hexdigest()), selected))
                    records.append(dict(selection=row, latencies_ns=value['latency_ns']))
                    completed.append(row)
                comparisons = analyze(records)
                m.save(root, 'analysis.json', m.bound(dict(purpose=purpose(args),
                    comparisons=comparisons, method_sha256=METHOD_SHA256,
                    prepared_hashes=spec['prepared_hashes']), selected))
                if not all(x['passed'] for x in comparisons):
                    raise ValueError('request routing gates failed; STOP')
        budget.check(force=True)
    except BaseException as error:
        primary = error
        raise
    finally:
        if not getattr(primary, 'cleanup_unresolved', False):
            try:
                verify()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note('routing final source check: ' + str(error)[:1024])
        m.report_preserving(primary, 'routing result receipt', lambda: m.save(root, 'result.json',
            m.bound(dict(passed=primary is None, purpose=purpose(args),
                measurements='ATTEMPTED' if timing else 'NOT RUN',
                qualification_completed=qualification, qualification_attempted=qual_attempted,
                qualification_incomplete=[r for r in qual_attempted if r not in qualification],
                qualification_not_run=qualification_schedule()[len(qual_attempted):],
                completed=completed, attempted=attempted,
                failed_or_incomplete=[r for r in attempted if r not in completed],
                not_run=schedule()[len(attempted):], comparisons=comparisons,
                failure=m.failure(primary) if primary else None,
                scope=contract()['limits']), selected)))
        if primary is not None and m.sys.exc_info()[0] is None:
            raise primary


def execute(m, args):
    selected = m.selection(args)
    if m.sys.platform != 'win32' or m.os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise ValueError('dedicated hosted Windows runner required')
    if m.shutil.which('agent-resources'):
        raise ValueError('resource controller installed: registered hosted lane required')
    if not m.re.fullmatch('[0-9a-f]{40}', args.expected_suite):
        raise ValueError('immutable final suite revision required')
    root = Path(args.output).resolve()
    if root.parent != Path(m.os.environ['RUNNER_TEMP']).resolve() or root.name != selected.root:
        raise ValueError('routing output namespace differs')
    args.output, args.core = str(root), str(Path(args.core).resolve())
    owner = m.owner(args, root)
    m.source_gate(args.core, args.expected_suite, dict(CORES)['A'], selected)
    observed = m.preflight(root)
    creating = args.command in ('build', 'all', 'proof')
    if creating:
        root.mkdir()
        (root / 'evidence').mkdir()
        m.save(root, 'owner.json', owner)
        m.save(root, 'preflight.json', observed)
    else:
        for name in ('measure-task.json', 'evidence/failure.json', 'evidence/result.json'):
            if (root / name).exists():
                raise ValueError('routing campaign permits one attempt')
        prepared_check(m, args, root, selected)
    primary = None
    try:
        if creating:
            m.build(args, root, owner)
            pins = {name: m.ds.digest(root / 'evidence' / name)
                    for name in ('owner.json', 'build-inputs.json', 'build.json', 'A-cargo.json', 'B-cargo.json')}
            m.save(root, 'build-complete.json', m.bound(dict(owner=owner,
                purpose=purpose(args), prepared_hashes=pins), selected))
        if args.command in ('proof', 'measure', 'all'):
            value = prepared_check(m, args, root, selected)
            complete = m.load(root / 'evidence/build-complete.json')
            env = m.environment(root, value['tools'])
            m.launch(root, 'measure', m.bound(dict(kind='measure', args=vars(args),
                purpose=purpose(args), prepared_hashes=complete['prepared_hashes']), selected),
                env, timeout=m.MEASURE_OUTER, selected=selected)
            prepared_check(m, args, root, selected)
            result = m.load(root / 'evidence/result.json')
            m.check_binding(result, selected)
            m.exact(result['purpose'], purpose(args), 'routing result purpose differs')
            m.exact(result['passed'], True, 'routing campaign refused')
    except BaseException as error:
        primary = error
        m.report_preserving(primary, 'routing outer failure', lambda: m.save(root, 'failure.json', m.failure(error)))
        raise
    finally:
        if not getattr(primary, 'cleanup_unresolved', False):
            def finish():
                m.source_gate(args.core, args.expected_suite, dict(CORES)['A'], selected)
                if (root / 'evidence/build-complete.json').exists():
                    prepared_check(m, args, root, selected)
                m.save(root, args.command + '-final-source-check.json',
                       m.bound(dict(passed=True, purpose=purpose(args)), selected))
            try:
                finish()
            except BaseException as error:
                if primary is None:
                    raise
                primary.add_note('routing outer source finally: ' + str(error)[:1024])



def closed(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError('closed ' + label + ' fields differ')


def native_json(m, root, stem, raw):
    if not raw.startswith(b'{') or not raw.endswith(b'}\n'):
        raise ValueError('native stdout must be one JSON object plus LF')
    if (root / 'evidence' / (stem + '.stderr')).read_bytes() != b'':
        raise ValueError('successful native command wrote stderr')
    return m.read_json(raw)


def same_layout(m, timed, qualified):
    # Only timing backing and headers can differ for the exact same artifact.
    for key in timed:
        if key not in ('fixture_owners', 'fixture_additional_bytes'):
            m.exact(timed[key], qualified[key], 'timed artifact layout differs')
    for key in timed['fixture_owners']:
        if key not in ('latency_backing', 'calibration_backing', 'array_headers'):
            m.exact(timed['fixture_owners'][key], qualified['fixture_owners'][key],
                    'timed fixture owner differs: ' + key)


def validate_native(m, value, identifier, security, mode):
    p = contract()
    if mode not in ('qualify', 'measure') or security not in p['security']:
        raise ValueError('unknown native phase/security')
    g = group(identifier)
    wire = p['wire']
    keys = list(wire['root_required'])
    if mode == 'measure':
        keys += list(wire['measure_only_required'])
    closed(value, keys, 'native result')
    expected = dict(schema=p['native_schemas'][mode], contract=ID,
        method_sha256=METHOD_SHA256, purpose=wire['purpose'][mode], phase=mode,
        group=identifier, security=security, profile=g['profile'],
        operations=8000, warmup=128, verified=8128,
        measured_polls=8000 if mode == 'measure' else 0,
        calibration_samples=4096 if mode == 'measure' else 0,
        payload_bytes=g['payload_bytes'], route_capacity=g['route_capacity'],
        registered_routes=g['registered_routes'], handler_calls=g['expected_handler_calls'],
        terminal='complete', trace_id='round-robin/1', capacities=g['capacities'])
    for key, expected_value in expected.items():
        m.exact(value[key], expected_value, 'native ' + key + ' differs')
    if mode == 'measure':
        intervals(value['latency_ns'],8000)
        intervals(value['calibration_ns'],4096)
    cases = value['case_counts']
    if type(cases) is not list or len(cases) != len(g['cases']):
        raise ValueError('native per-case census differs')
    for j, (actual, case) in enumerate(zip(cases, g['cases'])):
        closed(actual, wire['case_count_required'], 'case counter')
        warmup = sum(op % len(cases) == j for op in range(128))
        work = sum(op % len(cases) == j for op in range(128,8128))
        m.exact(actual, dict(id=case['id'], warmup_verified=warmup,
            work_verified=work, handler_calls=case['handler_delta']*(warmup+work)),
            'case labels/counts/handler increments differ')
    protocol = value['protocol']
    closed(protocol, wire['protocol_required'], 'protocol')
    expected_protocol = dict(prepared=8128, polled=8128, responded=8128, verified=8128,
        input_datagrams=8128, output_datagrams=8128, internal_datagrams=16256,
        udp_datagrams=0, first_mid=0, last_mid=8127, token_bytes=8, now_ms=1,
        max_outstanding=1, input_empty=True, output_empty=True,
        authenticated_responses=8128 if security == 'oscore' else 0,
        bindings_consumed=8128 if security == 'oscore' else 0)
    for key, expected_value in expected_protocol.items():
        m.exact(protocol[key], expected_value, 'protocol ' + key + ' differs')
    seqkeys = ('client_sender_seq_start','client_sender_seq_end','request_piv_bytes_histogram')
    if security == 'unprotected':
        for key in seqkeys:
            m.exact(protocol[key], None, 'unprotected security state differs')
    else:
        start = unsigned(protocol[seqkeys[0]], seqkeys[0], 2**40-1)
        end = unsigned(protocol[seqkeys[1]], seqkeys[1], 2**40-1)
        if end-start != 8128:
            raise ValueError('OSCORE sequence delta differs')
        hist = intervals(protocol[seqkeys[2]],6)
        if sum(hist) != 8128 or hist[3:] != [0,0,0]:
            raise ValueError('observed PIV width census differs')
    layout = value['layout']
    closed(layout, wire['layout_required'], 'layout')
    for key in ('app_inline_bytes','app_align_bytes','pointer_bytes',
                'pool_heap_requested_bytes','fixture_additional_bytes'):
        unsigned(layout[key],key,2**64-1)
    if layout['app_inline_bytes'] == 0 or layout['app_align_bytes'] == 0:
        raise ValueError('App layout must be positive')
    align = layout['app_align_bytes']
    if align & (align-1) or layout['app_inline_bytes'] % align:
        raise ValueError('actual App alignment differs')
    m.exact(layout['pointer_bytes'],8,'routing target pointer width differs')
    site = layout['site_inline_bytes']
    if site is not None:
        unsigned(site,'Site inline',2**64-1)
        if site == 0 or site > layout['app_inline_bytes']:
            raise ValueError('Site inline cannot exceed enclosing App')
    heap = layout['pool_heap_requested_bytes']
    if (identifier.startswith('small_') and heap != 0) or (not identifier.startswith('small_') and heap == 0):
        raise ValueError('actual requested pool ownership differs')
    owners = layout['fixture_owners']
    closed(owners,wire['fixture_owner_keys'],'fixture owners')
    for key, count in owners.items():
        unsigned(count,key,2**64-1)
    m.exact(layout['fixture_additional_bytes'],sum(owners.values()),'fixture owner ledger sum differs')
    if layout['fixture_additional_bytes'] > p['layout']['fixture_additional_owner_cap']:
        raise ValueError('fixture additional owner cap exceeded')
    for key, count in (('latency_backing',128000),('calibration_backing',65536)):
        if mode == 'measure':
            m.exact(owners[key],count,'timing backing differs')
        elif owners[key] not in (0,count):
            raise ValueError('qualification reserved backing differs')
    return dict(layout=layout, case_counts=cases, protocol=protocol,
                verified=8128, handler_calls=g['expected_handler_calls'])
