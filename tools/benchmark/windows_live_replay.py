"""Hosted offline, exact-path projections of two immutable live-C1 ETLs.

No recording, workload, Rust build or session route exists here. Original input
bytes and identity strings are never rewritten. Projected JSON omits event/QPC,
addresses and module metadata; the original ETL remains authoritative.
"""
import argparse
from collections import Counter
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import struct
import sys
import urllib.error
import urllib.request
import zipfile

import stack_profile as s
import windows_profile as w
import windows_replay as old

PINS_PATH = Path(__file__).with_name('windows_live_replay_pins.json')
PINS_SHA256 = 'bc538e2547fd182b1b1410b60b2871c2a486825821039873caa73ad57acbe179'
API = 'https://api.github.com/repos/jeffglousher/coaptic-validation/actions/artifacts/12969046956'
META_LIMIT = 65536
COHORTS = ('unprotected-capture-00', 'oscore-capture-00')
OMISSIONS = ('Exact ordered full-symbol paths aggregated with integer occurrence weights. '
             'Per-event QPC/timestamps, order, addresses and module metadata omitted from projected JSON; '
             'original ETL authoritative. No timeline equivalence claim, pooling or qualified CPU shares.')
PROJECTION_NOTES = ('Explicit exact-full-symbol-path flame projection: canonical JSON omits per-event '
                    'timestamps, addresses, modules, comm and event order; it is not a trace timeline. '
                    'The retained original hash-bound ETL is authoritative for event metadata and '
                    'independent replay; aggregate JSON alone does not validate event timestamps.')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def literal_equal(left, right):
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(',', ':'), allow_nan=False)


def load_pins():
    path = old.ordinary_path(PINS_PATH)
    with path.open('rb') as stream:
        raw = stream.read(META_LIMIT + 1)
    if len(raw) > META_LIMIT or sha(raw) != PINS_SHA256:
        raise ValueError('live replay source pins byte budget/hash mismatch')
    pins = s.parse_json(raw.decode('utf-8'))
    if (pins.get('schema') != 'coaptic-windows-live-replay-pins/1'
            or (pins.get('run_id'), pins.get('run_attempt'), pins.get('artifact_id'))
            != (41038109816, 1, 12969046956)
            or tuple(c['name'] for c in pins['cohorts']) != COHORTS
            or len(pins['members']) != pins['member_count']):
        raise ValueError('live replay source pins contract mismatch')
    return pins


def validate_metadata(metadata, pins):
    required = dict(id=pins['artifact_id'], size_in_bytes=pins['zip_bytes'],
                    digest='sha256:' + pins['zip_sha256'], expired=False,
                    name=pins['artifact_name'])
    if not isinstance(metadata, dict) or any(type(metadata.get(k)) is not type(v)
                                           or metadata[k] != v for k, v in required.items()):
        raise ValueError('live artifact metadata pin mismatch')
    run = metadata.get('workflow_run', {})
    if (not isinstance(run, dict) or type(run.get('id')) is not int
            or run['id'] != pins['run_id']
            or run.get('head_sha') != pins['original_sources']['suite']['commit']):
        raise ValueError('live artifact run/source mismatch')
    return metadata


def download(budget, token, pins, opener=None):
    """Exactly three bounded requests; signed URLs and tokens never enter errors."""
    if not isinstance(token, str) or not token or '\r' in token or '\n' in token:
        raise ValueError('GITHUB_TOKEN with actions:read required')
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), old.NoRedirect())
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
               'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'coaptic-live-offline-replay'}
    try:
        budget.check()
        with opener.open(urllib.request.Request(API, headers=headers), timeout=15) as response:
            if response.status != 200:
                raise ValueError('live artifact metadata status refused')
            metadata = validate_metadata(s.parse_json(old.bounded_read(response, META_LIMIT, budget)
                                                      .decode('utf-8')), pins)
        budget.check()
        try:
            response = opener.open(urllib.request.Request(API + '/zip', headers=headers), timeout=15)
        except urllib.error.HTTPError as redirect:
            try:
                if redirect.code != 302:
                    raise ValueError('live artifact redirect status refused') from None
                location = old.signed_location(redirect.headers.get('Location'))
            finally:
                redirect.close()
        else:
            response.close()
            raise ValueError('live artifact requires one explicit redirect')
        budget.check()
        # A new request has no Authorization; NoRedirect remains active.
        with opener.open(urllib.request.Request(location, headers={'User-Agent': 'coaptic-live-offline-replay'}),
                         timeout=15) as response:
            if response.status != 200:
                raise ValueError('live artifact storage status refused')
            raw = old.bounded_read(response, pins['zip_bytes'], budget)
        if len(raw) != pins['zip_bytes'] or sha(raw) != pins['zip_sha256']:
            raise ValueError('live ZIP byte count/SHA256 mismatch')
        return metadata, raw
    except (urllib.error.URLError, OSError, UnicodeError) as error:
        raise ValueError('bounded live artifact request failed: ' + type(error).__name__) from None


def live_member_name(info, pin):
    """Reuse ordinary-name/type rules without changing the old 16MiB route.

    Live ETLs have exact pinned sizes (the largest is 17,563,648 bytes). Check
    those first; only the lexical/type probe receives a zero size. The actual
    header and actual stream are both checked against this immutable manifest.
    """
    if (pin is None or info.file_size != pin['bytes'] or info.compress_size < 0
            or info.file_size > max(1, info.compress_size) * 1000):
        raise ValueError('live member size/ratio pin mismatch')
    probe = copy.copy(info)
    probe.file_size = 0
    return old.member_name(probe)


def inspect_zip(raw, budget, pins):
    if len(raw) != pins['zip_bytes'] or sha(raw) != pins['zip_sha256']:
        raise ValueError('live ZIP byte count/SHA256 mismatch')
    if len(raw) < 22 or raw[-22:-18] != b'PK\x05\x06':
        raise ValueError('ordinary live ZIP end record required')
    _, disk, cdisk, dcount, count, cbytes, offset, comment = struct.unpack('<4s4H2IH', raw[-22:])
    if (disk or cdisk or dcount != count or count != pins['member_count'] or count > 64
            or cbytes > 64 * 4096 or offset + cbytes != len(raw) - 22 or comment):
        raise ValueError('live ZIP central-directory layout/budget refused')
    expected = {p['path']: p for p in pins['members']}
    if len(expected) != count or len(set(pins['selected_members'])) != len(pins['selected_members']):
        raise ValueError('ambiguous live source member pins')
    selected, manifest, seen, total = {}, [], set(), 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist()) != count:
            raise ValueError('live ZIP member count mismatch')
        for info in archive.infolist():
            budget.check()
            pin = expected.get(info.filename)
            name = live_member_name(info, pin)
            folded = name.casefold()
            if folded in seen or any(folded.startswith(n + '/') or n.startswith(folded + '/') for n in seen):
                raise ValueError('duplicate/prefix live member ambiguity')
            seen.add(folded)
            total += info.file_size
            if total > pins['expanded_bytes']:
                raise ValueError('live ZIP expanded budget exceeded')
            # ZipFile verifies local headers and CRC while the bounded stream is consumed.
            with archive.open(info) as stream:
                content = old.bounded_read(stream, pin['bytes'], budget)
            if len(content) != pin['bytes'] or sha(content) != pin['sha256']:
                raise ValueError('live member size/SHA256 mismatch: ' + name)
            manifest.append(dict(pin, crc32=f'{info.CRC:08x}', compressed_bytes=info.compress_size))
            if name in pins['selected_members']:
                selected[name] = content
    if total != pins['expanded_bytes'] or set(selected) != set(pins['selected_members']):
        raise ValueError('live ZIP selected/expanded pin mismatch')
    verify_buffers(selected, pins)
    return selected, manifest


def verify_buffers(selected, pins):
    expected = {p['path']: p for p in pins['members']}
    if set(selected) != set(pins['selected_members']):
        raise ValueError('live selected input set mismatch')
    for name, raw in selected.items():
        pin = expected[name]
        if len(raw) != pin['bytes'] or sha(raw) != pin['sha256']:
            raise ValueError('live selected input changed: ' + name)


def receipt_inputs(selected, pins, root):
    verify_buffers(selected, pins)
    if PureWindowsPath(str(root)) != PureWindowsPath(pins['original_root']):
        raise ValueError('original live input root relocation refused')
    build = s.parse_json(selected['build.json'].decode('utf-8'))
    if build['sources'] != pins['original_sources']:
        raise ValueError('original live build source mismatch')
    evidence = PureWindowsPath(pins['original_root']) / 'evidence'
    for c in pins['cohorts']:
        name = c['name']
        raw = selected[name + '/capture.json']
        config_raw = selected[name + '/config.json']
        if len(raw) > META_LIMIT or len(config_raw) > META_LIMIT:
            raise ValueError('live original receipt/config budget exceeded')
        receipt = s.parse_json(raw.decode('utf-8'))
        config = s.parse_json(config_raw.decode('utf-8'))
        # Full literal equality includes exact source strings, image header/GUID,
        # PID/TID, seven-digit config UTC, receipt UTC spelling and QPC window.
        if not literal_equal(receipt, c['capture']) or not literal_equal(config, c['original_config']):
            raise ValueError('original live receipt/config/lifetime literal mismatch')
        cfg = receipt['config']
        paths = dict(directory=str(evidence / name), exe=str(evidence / 'binaries/bench-core.exe'),
                     pdb=str(evidence / 'binaries/bench_core.pdb'))
        if (any(cfg.get(k) != v for k, v in paths.items())
                or c['capture_receipt_path'] != str(evidence / name / 'capture.json')
                or c['config_path'] != str(evidence / name / 'config.json')
                or receipt['etl'] != str(evidence / name / 'capture.etl')
                or cfg['identity']['cohort'] != name
                or cfg['identity']['capture'] != cfg['capture_id']
                or receipt['stopped'] is not True or cfg['dedicated_hosted_vm'] is not True
                or receipt['session_name'] != 'CoapticStack-' + cfg['capture_id']
                or not 0 < receipt['start_qpc'] < receipt['stop_qpc'] or receipt['qpc_frequency'] <= 0
                or s.parse_json(cfg['identity']['source']) != pins['original_sources']):
            raise ValueError('original live path/window/identity mismatch')
        for member, value in [('binaries/bench-core.exe', cfg['exe_sha256']),
                              ('binaries/bench_core.pdb', cfg['pdb_sha256']),
                              (name + '/capture.etl', receipt['etl_sha256'])]:
            if sha(selected[member]) != value:
                raise ValueError('original live byte identity mismatch')
        native = build['native']
        if (native['path'] != cfg['exe'] or native['pdb'] != cfg['pdb']
                or native['sha256'] != cfg['exe_sha256'] or native['pdb_sha256'] != cfg['pdb_sha256']
                or receipt['image']['exe_sha256'] != cfg['exe_sha256']
                or receipt['image']['pdb_sha256'] != cfg['pdb_sha256']
                or receipt['etl_bytes'] != len(selected[name + '/capture.etl'])):
            raise ValueError('original live build/image consistency mismatch')
    return build


def materialize(root, selected, pins, attempted):
    verify_buffers(selected, pins)
    for name in pins['selected_members']:
        path = old.ordinary_path(root / 'evidence' / name)
        path.parent.mkdir(parents=True, exist_ok=True)
        old.ordinary_path(path)
        # Track even a partial write for the finally preservation check.
        with path.open('xb') as stream:
            attempted.append(name)
            stream.write(selected[name])
        if w.digest(path) != sha(selected[name]):
            raise ValueError('materialized live input changed')


def verify_materialized(root, pins, attempted):
    expected = {p['path']: p for p in pins['members']}
    for name in attempted:
        path = old.ordinary_path(root / 'evidence' / name)
        if path.stat().st_size != expected[name]['bytes'] or w.digest(path) != expected[name]['sha256']:
            raise ValueError('original live input not preserved: ' + name)


def projection_counts(profile, *, projected):
    s.validate_profile(profile)
    if profile['measurement'] != dict(kind='sampled_cpu', unit='samples'):
        raise ValueError('live projection must count sampled events')
    if projected and PROJECTION_NOTES not in profile['quality']['notes']:
        raise ValueError('canonical projection omission disclosure missing')
    paths, symbols, prefixes = Counter(), {}, Counter()
    frames = app = unresolved = 0
    for row in profile['stacks']:
        n = row['samples']
        if type(row['weight']) is not int or row['weight'] != n:
            raise ValueError('live path weight/sample mismatch')
        if projected and 'event' in row:
            raise ValueError('aggregate projection must omit event metadata')
        if not projected and (n != 1 or row.get('event', {}).get('name') != 'SampledProfile'):
            raise ValueError('original equivalence control must retain per-event samples')
        path = tuple(row['frames'])
        if projected and path in paths:
            raise ValueError('duplicate aggregate exact path')
        paths[path] += n
        frames += len(path) * n
        app += n * any('coaptic::app::' in f for f in path)
        unresolved += n * sum('[unresolved]' in f or '[missing-stack]' in f
                              or '[truncated-root-ancestry]' in f for f in path)
        for f in set(path):
            symbols.setdefault(f, [0, 0])[1] += n
        symbols[path[-1]][0] += n
        for length in range(1, len(path) + 1):
            prefixes[path[:length]] += n  # Tuple keys preserve recursion and delimiters.
    if unresolved != profile['quality']['unresolved']:
        raise ValueError('weighted unresolved occurrence mismatch')
    return dict(paths=paths, symbols=symbols, prefixes=prefixes, frames=frames, app=app,
                samples=sum(paths.values()), unresolved=unresolved)


def equivalence(original, projected):
    left = projection_counts(original, projected=False)
    right = projection_counts(projected, projected=True)
    for key in ('identity', 'scope', 'measurement', 'totals'):
        if original[key] != projected[key]:
            raise ValueError('live equivalence ' + key + ' mismatch')
    for key in ('lost', 'refused', 'unresolved'):
        if original['quality'][key] != projected['quality'][key]:
            raise ValueError('live equivalence quality mismatch')
    if left != right:
        raise ValueError('live exact path/symbol/ordered-prefix equivalence mismatch')
    paths = sorted([[list(k), v] for k, v in left['paths'].items()])
    digest = sha(json.dumps(paths, ensure_ascii=True, separators=(',', ':')).encode('utf-8'))
    return dict(passed=True, exact_full_paths=len(left['paths']), full_symbols=len(left['symbols']),
                ordered_flame_prefixes=len(left['prefixes']), totals=original['totals'],
                weighted_frame_occurrences=left['frames'], app_ancestry_samples=left['app'],
                unresolved_frame_occurrences=left['unresolved'], exact_path_counter_sha256=digest,
                checked='full tuple path multiplicities; every symbol self/inclusive; every ordered prefix including recursion',
                omissions=OMISSIONS)


def export_config(root, cohort):
    directory = root / 'evidence/live-replay' / cohort['name']
    return dict(capture_receipt=cohort['capture_receipt_path'], output=str(directory / 'profile.json'),
                scratch_directory=str(root / 'conversion-replay' / cohort['name']),
                max_etl_bytes=128 * 1024**2, max_conversion_bytes=256 * 1024**2,
                aggregate_exact_paths=True)


def export_one(tool, env, root, budget, cohort):
    config = export_config(root, cohort)
    directory = old.ordinary_path(root / 'evidence/live-replay' / cohort['name'])
    directory.mkdir(parents=True)
    old.ordinary_path(config['scratch_directory']).mkdir(parents=True)
    w.save(directory / 'export.json', config)
    w.command(tool + ['export', '--config', str(directory / 'export.json')], budget,
              directory / 'export.log', env=env)
    output = old.ordinary_path(config['output'])
    profile = s.load_json(s.read_text(output))
    counts = projection_counts(profile, projected=True)
    capture = cohort['capture']
    original = capture['config']
    if (profile['identity'] != original['identity']
            or profile['scope']['pid'] != original['pid'] or profile['scope']['tid'] != original['tid']
            or profile['scope']['label'] != original['label'] or profile['scope']['cpu_mode'] != 'unknown'):
        raise ValueError('live projected identity/PID/TID/cohort mismatch')
    receipt_path = old.ordinary_path(str(output) + '.receipt.json')
    if receipt_path.stat().st_size > META_LIMIT:
        raise ValueError('live export receipt budget exceeded')
    receipt = w.read_json(receipt_path)
    checks = dict(schema='coaptic-windows-stack-export/1', capture_id=original['capture_id'],
                  capture_receipt_sha256=w.digest(root / 'evidence' / cohort['name'] / 'capture.json'),
                  etl_sha256=capture['etl_sha256'], image=capture['image'],
                  module_base_address=capture['module_base_address'], module_size=capture['module_size'],
                  window_start_qpc=capture['start_qpc'], window_stop_qpc=capture['stop_qpc'],
                  output_sha256=w.digest(output), output_bytes=output.stat().st_size,
                  total_samples=counts['samples'], unresolved_frame_occurrences=counts['unresolved'],
                  lost=profile['quality']['lost'])
    if any(not literal_equal(receipt.get(k), v) for k, v in checks.items()):
        raise ValueError('live export receipt identity/count/hash mismatch')
    projection = receipt.get('projection')
    expected_projection = dict(aggregate_exact_paths=True, kind='exact-full-symbol-paths',
        notes=PROJECTION_NOTES, identity=original['identity'], pid=original['pid'], tid=original['tid'],
        qpc_frequency=capture['qpc_frequency'], raw_samples=counts['samples'],
        output_distinct_rows=len(profile['stacks']), raw_frame_occurrences=counts['frames'],
        weighted_output_frame_occurrences=counts['frames'], app_ancestry_samples=counts['app'],
        unresolved_frame_occurrences=counts['unresolved'], total_samples=counts['samples'],
        total_weight=counts['samples'], totals_conserved=True,
        depth_truncated_samples=receipt.get('depth_truncated_samples'))
    if (not isinstance(projection, dict)
            or any(not literal_equal(projection.get(k), v) for k, v in expected_projection.items())
            or type(receipt.get('depth_truncated_samples')) is not int
            or not 0 <= receipt['depth_truncated_samples'] <= counts['samples']
            or type(receipt.get('conversion_truncated')) is not bool
            or counts['samples'] > 100000 or counts['frames'] > 200000):
        raise ValueError('live projection conservation receipt mismatch')
    # Existing qualification retains unknown truncation; no C# false becomes unwind proof.
    outcome = dict(export_succeeded=True, omissions=OMISSIONS, profile_sha256=w.digest(output),
                   samples=counts['samples'], paths=len(counts['paths']), symbols=len(counts['symbols']),
                   weighted_frame_occurrences=counts['frames'], app_ancestry_samples=counts['app'],
                   quality=profile['quality'], export_receipt=receipt,
                   qualification=w.qualification(profile, app_rooted=counts['app'], pdb_match=True, truncated=None))
    if cohort['expected_original'] is not None:
        proof = dict(passed=False, omissions=OMISSIONS)
        try:
            control = s.load_json(s.read_text(root / 'evidence' / cohort['name'] / 'profile.json'))
            proof.update(equivalence(control, profile))
            actual = dict(samples=counts['samples'], app=counts['app'], frames=counts['frames'],
                          paths=len(counts['paths']), symbols=len(counts['symbols']), unresolved=counts['unresolved'])
            if actual != cohort['expected_original']:
                proof['passed'] = False
                raise ValueError('original control census mismatch after full equivalence comparison')
        except BaseException as error:
            proof['failure'] = failure(error)
            raise
        finally:
            w.save(directory / 'equivalence.json', proof)
        outcome['equivalence'] = proof
    else:
        outcome['equivalence'] = 'NOT_APPLICABLE: no original protected canonical profile; fresh same-ETL projection only'
    html = s.render_html(profile).replace('<body>', '<body><p>' + OMISSIONS + '</p>', 1)
    s.write_new(directory / 'profile.html', html)  # Retain refusal; no fallback renderer/cap.
    return outcome


def failure(error):
    return dict(error=type(error).__name__, detail=str(error)[:2048],
                notes=[str(n)[:1024] for n in getattr(error, '__notes__', ())[:8]])


class ReplayBudget(old.ReplayBudget):
    """Reuse 8GiB/256MiB and aggregate 256MiB conversion-replay sampled guards."""


def replay_phase(args, root, budget, pins):
    sources = selected = tooling = None
    attempted = []
    error = None
    result = dict(schema='coaptic-windows-live-replay/1', original_run=pins['run_id'],
                  original_attempt=pins['run_attempt'], artifact_id=pins['artifact_id'],
                  zip_sha256=pins['zip_sha256'], source_pins_sha256=PINS_SHA256,
                  original_sources=pins['original_sources'], original_collection_result=pins['original_collection_result'],
                  original_NOTRUN=pins['unrun_original_cohorts'], omissions=OMISSIONS,
                  cpu_share_qualified=False, complete=False,
                  cohorts=[dict(name=c['name'], status='NOTRUN') for c in pins['cohorts']])
    try:
        sources = w.source_identity(args.core, args.expected_core, args.expected_suite)
        metadata, raw = download(budget, os.environ.get('GITHUB_TOKEN'), pins)
        selected, manifest = inspect_zip(raw, budget, pins)
        del raw
        result.update(metadata=metadata, original_member_manifest=manifest,
                      original_build=receipt_inputs(selected, pins, root))
        # No selected byte is written and no tool built until all literal pins pass.
        materialize(root, selected, pins, attempted)
        verify_materialized(root, pins, attempted)
        budget.check(force=True)
        tool, env, tooling = old.build_tool(args, root, budget)
        result['current_tooling'] = tooling
        budget.rss_limit = 1024**3
        result['actual_tool_reports'] = {}
        for verb in ('metadata', 'selftest'):
            raw_report = w.command(tool + [verb], budget, root / ('evidence/live-replay-' + verb + '.log'), env=env)
            report = w.parse_event(raw_report)
            if (report.get('status') != verb or not isinstance(report.get('detail'), dict)
                    or report.get('capture_id') != '00000000-0000-0000-0000-000000000000'):
                raise ValueError('live tool metadata/selftest report mismatch')
            if verb == 'selftest' and (type(report['detail'].get('passed')) is not int
                                      or report['detail']['passed'] < 1):
                raise ValueError('live tool pure model test census missing')
            result['actual_tool_reports'][verb] = report
        for index, cohort in enumerate(pins['cohorts']):
            row = result['cohorts'][index]
            row['status'] = 'STARTED'
            try:
                row.update(export_one(tool, env, root, budget, cohort), status='COMPLETE')
            except BaseException as caught:
                row.update(status='FAILED', failure=failure(caught))
                proof = root / 'evidence/live-replay' / cohort['name'] / 'equivalence.json'
                if cohort['expected_original'] is not None and not proof.exists():
                    proof.parent.mkdir(parents=True, exist_ok=True)
                    w.save(proof, dict(passed=False, comparison='NOTRUN: refused before equivalence completed',
                                       failure=failure(caught), omissions=OMISSIONS))
                raise
            finally:
                verify_materialized(root, pins, attempted)
        result['complete'] = True
    except BaseException as caught:
        error = caught
        result['failure'] = failure(caught)
    finally:
        preservation = []
        checks = [('source pins', lambda: load_pins()),
                  ('materialized original inputs', lambda: verify_materialized(root, pins, attempted))]
        if selected is not None:
            checks.append(('RAM original inputs', lambda: verify_buffers(selected, pins)))
        if sources is not None:
            def source_check():
                if sources != w.source_identity(args.core, args.expected_core, args.expected_suite):
                    raise ValueError('current sources changed during live replay')
            checks.append(('current sources', source_check))
        if tooling is not None:
            def tool_check():
                if any(w.digest(old.ordinary_path(root / f['path'])) != f['sha256'] for f in tooling['files']):
                    raise ValueError('current exporter/tool dependency changed')
            checks.append(('exporter tool files', tool_check))
        for label, check in checks:
            try:
                check()
                preservation.append(dict(check=label, passed=True))
            except BaseException as caught:
                preservation.append(dict(check=label, passed=False, failure=failure(caught)))
                result['complete'] = False
                if error is None:
                    error = caught
                else:
                    error.add_note(label + ': ' + type(caught).__name__ + ': ' + str(caught)[:512])
        result.update(preservation_finally=preservation, materialized_members=attempted,
                      sampled_owned_build_peak_bytes=budget.peak,
                      sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak,
                      budget_notes='8GiB build/256MiB evidence/256MiB aggregate conversion sampled refusal bounds; '
                                   '4GiB build and 1GiB export per-child working-set monitor, not hard quotas or whole-job peaks; '
                                   'outer Job descendant settlement is reported separately. No ETW session started.')
        if error is not None:
            result['failure'] = failure(error)
        w.save(root / 'evidence/live-replay-receipt.json', result)
    if error is not None:
        raise error


def worker(config):
    if sys.stdin.buffer.readline(4) != b'go\n':
        raise ValueError('outer ownership handshake missing')
    w.hosted_preflight()
    pins = load_pins()
    args = argparse.Namespace(**w.read_json(config))
    root = old.ordinary_path(args.output)
    budget = ReplayBudget(root, 830, rss_limit=4 * 1024**3)
    replay_phase(args, root, budget, pins)
    budget.check(force=True)


def execute(args):
    from suite_process import run_worker
    w.hosted_preflight()
    pins = load_pins()  # Source pins and current clean identity precede filesystem writes.
    w.source_identity(args.core, args.expected_core, args.expected_suite)
    if shutil.which('agent-resources'):
        raise ValueError('installed resource controller requires an explicitly registered compatible hosted lane')
    if PureWindowsPath(str(args.output)) != PureWindowsPath(pins['original_root']):
        raise ValueError('original live root relocation refused')
    root = old.fresh_root(args.output, os.environ['RUNNER_TEMP'])
    w.save(root / 'evidence/owner.json', dict(project='Coaptic', owner=os.environ.get('GITHUB_RUN_ID'),
           release='Ephemeral hosted VM; evidence retention14days', build_limit=w.BUILD_LIMIT,
           evidence_limit=w.EVIDENCE_LIMIT, source_pins_sha256=PINS_SHA256,
           mode='two fixed live ETLs offline; no native execution or ETW session'))
    w.save(root / 'evidence/live-replay-pins.json', pins)
    config = root / 'live-replay-task.json'
    w.save(config, vars(args))
    result = None
    stdout = stderr = b''
    try:
        result = run_worker([sys._base_executable, '-B', str(Path(__file__).resolve()), '_worker', str(config)],
                            timeout=900, limit=w.LOG_LIMIT, cwd=w.SUITE,
                            env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path), PYTHONDONTWRITEBYTECODE='1'),
                            settle_build_auxiliaries=True)
        w.save(root / 'evidence/live-replay-outer.json', dict(passed=True, seconds=result.duration_seconds,
               descendants_settled=True, build_auxiliaries_terminated=result.descendants_settled))
    except BaseException as error:
        stdout, stderr = getattr(error, 'stdout', b''), getattr(error, 'stderr', b'')
        record = w.outer_failure(error)
        record.pop('etw_stop_proof', None)
        record['mode'] = 'offline live replay; no ETW session or native workload started'
        w.save(root / 'evidence/live-replay-outer.json', record)
        raise
    finally:
        if result is not None:
            stdout, stderr = result.stdout, result.stderr
        with (root / 'evidence/live-replay-outer.log').open('xb') as stream:
            stream.write(stdout[:w.LOG_LIMIT] + b'\n--- stderr ---\n' + stderr[:max(0, w.LOG_LIMIT - len(stdout))])


def main(argv=None):
    if argv is None and len(sys.argv) == 3 and sys.argv[1] == '_worker':
        worker(sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'output', 'expected-core', 'expected-suite'):
        parser.add_argument('--' + name, required=True,
                            **({'type': w.expected_sha} if name.startswith('expected-') else {}))
    args = parser.parse_args(argv)
    try:
        execute(args)
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(2, 'error: ' + str(error)[:2048] + '\n')


if __name__ == '__main__':
    main()
