"""Hosted offline exporter replay of the single preserved Windows ETW cohort.

There is deliberately no capture, target, workload execution or native build route.
The artifact pin is code, not a user-selectable download API.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import stat
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import stack_profile
import windows_profile as w

RUN_ID = 41013864895
ATTEMPT = 1
ARTIFACT_ID = 12959160518
ZIP_SHA256 = '3eaee1ec332399c8ece875eb748836a01ebb377c5c67860501c24f1eca54c76a'
ZIP_BYTES = 3368810
EXPANDED_BYTES = 14837202
MEMBERS = 34
ORIGINAL_SUITE = 'a074120d6f50b1c061e2ab5b0940837c9d51b63e'
ORIGINAL_CORE = '8af71fe4aa73b3bb76a921a836a1a9647d75f361'
CAPTURE_ID = 'b9ca443c-4f73-4316-8219-8d9f4e346a48'
COHORT = 'unprotected-capture-00'
PID, TID = 4936, 7436
PROCESS_START = '2026-10-30T06:28:42.3648387Z'
ORIGINAL_ROOT = PureWindowsPath('D:/a/_temp/coaptic-stack-profile')
SELECTED = ('binaries/bench-core.exe', 'binaries/bench_core.pdb',
            COHORT + '/capture.json', COHORT + '/capture.etl')
INPUT_PINS = {
    SELECTED[0]: (1235968, '21ecbd7939bb8cdd76e82cf9ac394557a2b92c3b0676f8ad6bfb272a9b6a9f82'),
    SELECTED[1]: (10153984, '7bd5df76e6a68bd5003599ef1825ed1667418fc7a86a7c4b14f47fd5d1a82ee6'),
    SELECTED[2]: (2923, 'c07891467e66dfd553e4d0001565efb623c07656af2199125d7ed02916d5db8c'),
    SELECTED[3]: (3145728, 'fb936cd1054f7995e3891457018e01fcb6218e59cc3b14e4b197580ccc270c3e'),
}
API = 'https://api.github.com/repos/jeffglousher/coaptic-validation/actions/artifacts/' + str(ARTIFACT_ID)
COMPRESSED_LIMIT = 8 * 1024**2
EXPANDED_LIMIT = 32 * 1024**2
MEMBER_LIMIT = 16 * 1024**2
METADATA_LIMIT = 64 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def bounded_read(response, limit, budget):
    data = bytearray()
    while True:
        budget.check()
        block = response.read(min(65536, limit + 1 - len(data)))
        if not block:
            return bytes(data)
        data.extend(block)
        if len(data) > limit:
            raise ValueError('network response byte budget exceeded')


def signed_location(value):
    """Only GitHub artifact storage, with no credential-bearing next redirect."""
    if not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 33 for c in value):
        raise ValueError('invalid artifact redirect')
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError('artifact redirect host/scheme refused') from None
    host = (parsed.hostname or '').lower()
    allowed = (host.endswith('.blob.core.windows.net') or host.endswith('.actions.githubusercontent.com')
               or host.endswith('.actionsusercontent.com'))
    if (parsed.scheme != 'https' or not allowed or port not in (None, 443)
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise ValueError('artifact redirect host/scheme refused')
    return value


def validate_metadata(metadata):
    required = {'id': ARTIFACT_ID, 'size_in_bytes': ZIP_BYTES, 'digest': 'sha256:' + ZIP_SHA256,
                'expired': False, 'name': f'windows-stack-profile-{RUN_ID}-{ATTEMPT}'}
    if not isinstance(metadata, dict) or any(
            type(metadata.get(k)) is not type(v) or metadata[k] != v for k, v in required.items()):
        raise ValueError('pinned artifact metadata mismatch')
    run = metadata.get('workflow_run', {})
    if (not isinstance(run, dict) or type(run.get('id')) is not int or run['id'] != RUN_ID
            or run.get('head_sha') != ORIGINAL_SUITE):
        raise ValueError('pinned artifact workflow identity mismatch')
    return metadata


def download(budget, token, opener=None):
    """Three finite requests; never put a signed URL or HTTP exception in logs."""
    if not token or '\r' in token or '\n' in token:
        raise ValueError('GITHUB_TOKEN with actions:read is required')
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
               'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'coaptic-offline-replay'}
    try:
        budget.check()
        with opener.open(urllib.request.Request(API, headers=headers), timeout=15) as response:
            if response.status != 200:
                raise ValueError('artifact metadata status refused')
            metadata = validate_metadata(stack_profile.parse_json(
                bounded_read(response, METADATA_LIMIT, budget).decode('utf-8')))
        budget.check()
        request = urllib.request.Request(API + '/zip', headers=headers)
        try:
            response = opener.open(request, timeout=15)
        except urllib.error.HTTPError as redirect:
            try:
                if redirect.code != 302:
                    raise ValueError('artifact API redirect status refused') from None
                location = signed_location(redirect.headers.get('Location'))
            finally:
                redirect.close()
        else:
            response.close()
            raise ValueError('artifact API must return one explicit redirect')
        budget.check()
        # A NEW Request has no Authorization header. NoRedirect also applies here.
        with opener.open(urllib.request.Request(location, headers={'User-Agent': 'coaptic-offline-replay'}),
                         timeout=15) as response:
            if response.status != 200:
                raise ValueError('artifact storage status refused')
            data = bounded_read(response, COMPRESSED_LIMIT, budget)
        if len(data) != ZIP_BYTES or sha(data) != ZIP_SHA256:
            raise ValueError('pinned ZIP byte count/SHA256 mismatch')
        return metadata, data
    except (urllib.error.URLError, OSError, UnicodeError) as error:
        # HTTPError text contains the URL (including SAS); suppress its chain too.
        raise ValueError('bounded artifact request failed: ' + type(error).__name__) from None


def member_name(info):
    name = info.filename
    if (not name or len(name) > 512 or '\\' in name or ':' in name or name.startswith('/')
            or any(ord(c) < 32 or ord(c) > 126 for c in name)):
        raise ValueError('unsafe ZIP member path')
    parts = name.split('/')
    for part in parts:
        stem = part.split('.')[0].upper()
        if (part in ('', '.', '..') or part.endswith((' ', '.'))
                or any(c in part for c in '<>"|?*')
                or stem in ('CON', 'PRN', 'AUX', 'NUL', 'CLOCK$')
                or re.fullmatch(r'(COM|LPT)[0-9]', stem)):
            raise ValueError('ambiguous ZIP member path')
    mode = info.external_attr >> 16
    if (info.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
            or info.external_attr & 0x410 or info.flag_bits & 1
            or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
        raise ValueError('nonordinary/encrypted ZIP member')
    if (not 0 <= info.file_size <= MEMBER_LIMIT or info.compress_size < 0
            or info.file_size > max(1, info.compress_size) * 1000):
        raise ValueError('ZIP member size/compression ratio refused')
    return name


def inspect_zip(data, budget):
    """Validate every member CRC/hash in RAM; retain only four input buffers."""
    if len(data) > COMPRESSED_LIMIT or len(data) != ZIP_BYTES or sha(data) != ZIP_SHA256:
        raise ValueError('pinned ZIP byte count/SHA256 mismatch')
    # Bound central-directory allocation before ZipFile builds its Python objects.
    # This fixed producer uses a single-disk ZIP without ZIP64 or archive comments.
    if len(data) < 22 or data[-22:-18] != b'PK\x05\x06':
        raise ValueError('ordinary ZIP end record required')
    _, disk, central_disk, disk_count, count, central_bytes, offset, comment = struct.unpack('<4s4H2IH', data[-22:])
    if (disk or central_disk or disk_count != count or count != MEMBERS or count > 64
            or central_bytes > 64 * 4096 or offset + central_bytes != len(data) - 22 or comment):
        raise ValueError('ZIP central-directory budget/layout refused')
    selected, manifest, build = {}, [], None
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) != MEMBERS or len(infos) > 64:
            raise ValueError('ZIP member count refused')
        names, total, compressed = set(), 0, 0
        for info in infos:
            budget.check()
            name = member_name(info)
            if name.casefold() in names:
                raise ValueError('duplicate ZIP member path')
            # Also reject file/directory prefix collisions, even for discarded files.
            if any(name.casefold().startswith(n + '/') or n.startswith(name.casefold() + '/') for n in names):
                raise ValueError('ZIP member prefix collision')
            names.add(name.casefold())
            total += info.file_size
            compressed += info.compress_size
            if total > EXPANDED_LIMIT or compressed > COMPRESSED_LIMIT:
                raise ValueError('ZIP aggregate budget exceeded')
            with archive.open(info) as stream:
                content = bounded_read(stream, min(MEMBER_LIMIT, info.file_size), budget)
            if len(content) != info.file_size:
                raise ValueError('ZIP member byte count mismatch')
            manifest.append(dict(path=name, bytes=len(content), compressed_bytes=info.compress_size,
                                 crc32=f'{info.CRC:08x}', sha256=sha(content)))
            if name in SELECTED:
                selected[name] = content
            elif name == 'build.json':
                if len(content) > METADATA_LIMIT:
                    raise ValueError('original build receipt byte budget exceeded')
                build = stack_profile.parse_json(content.decode('utf-8'))
        if total != EXPANDED_BYTES or set(selected) != set(SELECTED) or build is None:
            raise ValueError('pinned ZIP contents/expanded size mismatch')
    verify_input_pins(selected)
    return selected, manifest, build


def verify_input_pins(selected):
    if set(selected) != set(INPUT_PINS):
        raise ValueError('only four pinned replay inputs are accepted')
    for name, (size, expected) in INPUT_PINS.items():
        if len(selected[name]) != size or sha(selected[name]) != expected:
            raise ValueError('pinned replay input byte count/SHA256 mismatch: ' + name)


def receipt_inputs(selected, build, root):
    verify_input_pins(selected)
    raw = selected[COHORT + '/capture.json']
    if len(raw) > METADATA_LIMIT:
        raise ValueError('capture receipt byte budget exceeded')
    receipt = stack_profile.parse_json(raw.decode('utf-8'))
    config, image = receipt['config'], receipt['image']
    if PureWindowsPath(str(root)) != ORIGINAL_ROOT:
        raise ValueError('RUNNER_TEMP does not match original capture receipt paths; relocation refused')
    evidence = ORIGINAL_ROOT / 'evidence'
    expected_paths = {'directory': evidence / COHORT, 'exe': evidence / SELECTED[0], 'pdb': evidence / SELECTED[1]}
    # Exact strings, not rewritten provenance or normalized surrogate receipts.
    if any(config.get(k) != str(v) for k, v in expected_paths.items()):
        raise ValueError('original capture absolute input paths mismatch')
    if receipt.get('etl') != str(evidence / SELECTED[3]):
        raise ValueError('original ETL absolute path mismatch')
    required = {'capture_id': CAPTURE_ID, 'pid': PID, 'tid': TID, 'process_start_utc': PROCESS_START,
                'dedicated_hosted_vm': True}
    if any(type(config.get(k)) is not type(v) or config[k] != v for k, v in required.items()):
        raise ValueError('original capture scope/lifetime mismatch')
    if (receipt.get('schema') != 'coaptic-windows-stack-capture/1' or receipt.get('stopped') is not True
            or receipt.get('session_name') != 'CoapticStack-' + CAPTURE_ID
            or config['identity']['capture'] != CAPTURE_ID or config['identity']['cohort'] != COHORT):
        raise ValueError('original stopped cohort receipt mismatch')
    sources = stack_profile.parse_json(config['identity']['source'])
    for source in (sources, build['sources']):
        if source['core']['commit'] != ORIGINAL_CORE or source['suite']['commit'] != ORIGINAL_SUITE:
            raise ValueError('original source identity mismatch')
    image_pin = dict(pdb_guid='9ca23107-0be2-4350-8416-05e83dd701b8', pdb_age=1,
                     image_id=1793341719, image_size=1249280, image_checksum=0)
    if (any(type(image.get(k)) is not type(v) or image[k] != v for k, v in image_pin.items())
            or receipt.get('module_base_address') != '7ff725180000' or receipt.get('module_size') != 1249280):
        raise ValueError('original captured image mapping mismatch')
    native = build['native']
    checks = ((SELECTED[0], config['exe_sha256'], image['exe_sha256'], native['sha256'], native['bytes']),
              (SELECTED[1], config['pdb_sha256'], image['pdb_sha256'], native['pdb_sha256'], native['pdb_bytes']),
              (SELECTED[3], receipt['etl_sha256'], receipt['etl_sha256'], receipt['etl_sha256'], receipt['etl_bytes']))
    for name, config_hash, image_hash, build_hash, size in checks:
        actual = sha(selected[name])
        if (not re.fullmatch('[0-9a-f]{64}', config_hash) or actual != config_hash
                or actual != image_hash or actual != build_hash or len(selected[name]) != size):
            raise ValueError('original selected input size/SHA256 mismatch')
    if native['path'] != config['exe'] or native['pdb'] != config['pdb']:
        raise ValueError('original build/capture binary path mismatch')
    return receipt


def ordinary_path(path):
    """Inspect lexical existing ancestors before resolving; never follow reparses."""
    raw = str(path)
    if os.name == 'nt':
        if (not re.match(r'^[A-Za-z]:[\\/]', raw) or ':' in raw[2:]
                or any(c in raw for c in '?*"<>|')):
            raise ValueError('ordinary absolute drive path required')
        for part in raw[3:].replace('\\', '/').split('/'):
            if part in ('', '.', '..') or part.endswith((' ', '.')):
                raise ValueError('ambiguous absolute path refused')
    path = Path(path).absolute()
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('reparse/symlink path refused')
        if component != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('non-directory ancestor refused')
    return path


def fresh_root(output, runner_temp):
    root, temp = ordinary_path(output), ordinary_path(runner_temp)
    if root != temp / 'coaptic-stack-profile':
        raise ValueError('replay output must be exactly RUNNER_TEMP/coaptic-stack-profile')
    root.mkdir()  # Exclusive ownership: never reuse even a failed replay root.
    (root / 'evidence').mkdir()
    return root


def materialize(root, selected):
    verify_input_pins(selected)
    for name in SELECTED:
        destination = ordinary_path(root / 'evidence' / name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        ordinary_path(destination)
        with destination.open('xb') as stream:
            stream.write(selected[name])
        if w.digest(destination) != sha(selected[name]):
            raise ValueError('materialized replay input hash mismatch')


def verify_materialized(root):
    for name, (size, expected) in INPUT_PINS.items():
        path = ordinary_path(root / 'evidence' / name)
        if path.stat().st_size != size or w.digest(path) != expected:
            raise ValueError('original replay input changed')


def sdk_identity(info):
    """Hash selected compiler/restore entry points, not a whole SDK inventory."""
    matches = re.findall(r'^\s*Base Path:\s*([^\r\n]+)', info, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('selected SDK base path missing/ambiguous')
    directory = ordinary_path(matches[0].strip().rstrip('/\\'))
    if directory.name != '8.0.427':
        raise ValueError('selected SDK base path/version mismatch')
    files, total = [], 0
    for name in ('MSBuild.dll', 'NuGet.Build.Tasks.dll', 'Roslyn/bincore/csc.dll'):
        path = ordinary_path(directory / name)
        size = path.stat().st_size
        total += size
        if not path.is_file() or size > 32 * 1024**2 or total > 64 * 1024**2:
            raise ValueError('selected SDK identity file budget exceeded')
        files.append(dict(path=str(path), bytes=size, sha256=w.digest(path)))
    return files


def build_tool(args, root, budget):
    sources = w.source_identity(args.core, args.expected_core, args.expected_suite)
    env = w.build_environment(root)
    # The credential is used only by the bounded Python downloader, never MSBuild.
    env.pop('GITHUB_TOKEN', None)
    env.update(DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_CLI_UI_LANGUAGE='en-US', MSBUILDDISABLENODEREUSE='1')
    project, staged = w.stage_tool_sources(root)
    if len(w.read_json(staged['path'])['files']) != 8:
        raise ValueError('expected the eight pinned tooling source files')
    dotnet = shutil.which('dotnet')
    if not dotnet:
        raise ValueError('.NET SDK unavailable')
    directory, sdk, selection = w.selected_dotnet_sdk(dotnet, root, budget, env)
    sdk_files = sdk_identity(sdk)
    w.command([dotnet, 'build', project, '--configuration', 'Release', '--output', root / 'tool',
               '-p:BaseIntermediateOutputPath=' + str(root / 'dotnet-obj') + os.sep,
               '-p:NuGetLockFilePath=' + str(root / 'tool-packages.lock.json'),
               '-p:RestorePackagesWithLockFile=true', '-p:UseSharedCompilation=false', '-nodeReuse:false'],
              budget, root / 'evidence/tool-build.log', env=env, cwd=directory)
    configs = list((root / 'tool').glob('*.runtimeconfig.json'))
    if len(configs) != 1:
        raise ValueError('tool executable receipt ambiguous')
    tool = configs[0].with_name(configs[0].name.removesuffix('.runtimeconfig.json') + '.dll')
    files = []
    for index, path in enumerate((root / 'tool').rglob('*'), 1):
        if index > 256:
            raise ValueError('tool dependency entry budget exceeded')
        ordinary_path(path)
        if path.is_file():
            files.append(dict(path=path.relative_to(root).as_posix(), bytes=path.stat().st_size, sha256=w.digest(path)))
    if sources != w.source_identity(args.core, args.expected_core, args.expected_suite):
        raise ValueError('source changed during replay tool build')
    if sdk_files != sdk_identity(sdk):
        raise ValueError('selected SDK files changed during replay tool build')
    lock = w.retain_file(root, root / 'tool-packages.lock.json', root / 'evidence/build-inputs/tool-packages.lock.json')
    record = dict(sources=sources, staged_sources=staged, sdk_selection=selection,
                  sdk_info_sha256=sha(sdk.encode('utf-8')), sdk_entry_points=sdk_files,
                  dotnet_sha256=w.digest(dotnet),
                  package_lock=lock, tool_sha256=w.digest(tool), files=files,
                  sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak)
    w.save(root / 'evidence/replay-build.json', record)
    return [dotnet, str(tool)], env, record


def export_only(tool, env, root, budget, receipt):
    for verb in ('metadata', 'selftest'):
        w.command(tool + [verb], budget, root / ('evidence/replay-' + verb + '.log'), env=env)
    directory = root / 'evidence/replay'
    directory.mkdir()
    scratch = root / 'conversion-replay'
    scratch.mkdir()
    output = directory / 'profile.json'
    config = directory / 'export.json'
    w.save(config, dict(capture_receipt=str(root / 'evidence' / SELECTED[2]), output=str(output),
                        scratch_directory=str(scratch), max_etl_bytes=128 * 1024**2,
                        max_conversion_bytes=256 * 1024**2))
    w.command(tool + ['export', '--config', str(config)], budget, directory / 'export.log', env=env)
    profile = stack_profile.load_json(stack_profile.read_text(output))
    if (profile['identity'] != receipt['config']['identity'] or profile['scope']['pid'] != PID
            or profile['scope']['tid'] != TID):
        raise ValueError('replayed profile identity/scope mismatch')
    app = sum(s['samples'] for s in profile['stacks'] if any('coaptic::app::' in f for f in s['frames']))
    quality = w.qualification(profile, app_rooted=app, pdb_match=True, truncated=None)
    # Preserve the original profile identity and canonical renderer. This banner is
    # presentation only; the source profile and capture receipt remain unchanged.
    html = stack_profile.render_html(profile)
    html = html.replace('<body>', '<body><p>Diagnostic offline replay only; no qualified CPU shares or pooled cohorts.</p>', 1)
    stack_profile.write_new(directory / 'profile.html', html)
    return dict(export_succeeded=True, diagnostic_only=True, cpu_share_qualified=False,
                qualification=quality, profile_sha256=w.digest(output), app_rooted_samples=app,
                other_ancestry_samples=profile['totals']['samples'] - app, quality=profile['quality'])


def replay_phase(args, root, budget):
    sources = w.source_identity(args.core, args.expected_core, args.expected_suite)
    result = dict(schema='coaptic-windows-replay/1', run_id=RUN_ID, run_attempt=ATTEMPT,
                  artifact_id=ARTIFACT_ID, zip_sha256=ZIP_SHA256, original_core=ORIGINAL_CORE,
                  original_suite=ORIGINAL_SUITE, capture_id=CAPTURE_ID, cohort=COHORT,
                  pinned_inputs={k: dict(bytes=v[0], sha256=v[1]) for k, v in INPUT_PINS.items()},
                  diagnostic_only=True, cpu_share_qualified=False, export_succeeded=False)
    try:
        metadata, data = download(budget, os.environ.get('GITHUB_TOKEN'))
        selected, manifest, build = inspect_zip(data, budget)
        del data
        result.update(artifact_metadata=metadata, input_manifest=manifest, original_build_receipt=build,
                      original_capture_receipt_bytes_utf8=selected[SELECTED[2]].decode('utf-8'),
                      original_capture_receipt_sha256=sha(selected[SELECTED[2]]))
        receipt = receipt_inputs(selected, build, root)
        materialize(root, selected)
        del selected
        budget.check(force=True)
        tool, env, tooling = build_tool(args, root, budget)
        result['replay_tooling'] = tooling
        budget.rss_limit = 1024**3
        result.update(export_only(tool, env, root, budget, receipt))
        verify_materialized(root)
    except BaseException as error:
        result['export_succeeded'] = False
        result['failure'] = dict(error=type(error).__name__, detail=str(error)[:2048],
                                 notes=[str(n)[:1024] for n in getattr(error, '__notes__', ())[:8]])
        raise
    finally:
        try:
            if sources != w.source_identity(args.core, args.expected_core, args.expected_suite):
                raise ValueError('sources changed during offline replay')
        except BaseException as error:
            result['source_check_failure'] = dict(error=type(error).__name__, detail=str(error)[:2048])
            result['export_succeeded'] = False
            raise
        finally:
            diagnostic = root / 'evidence/replay/profile.json.module-diagnostic.json'
            if diagnostic.is_file():
                ordinary_path(diagnostic)
                size = diagnostic.stat().st_size
                result['module_diagnostic'] = dict(path=str(diagnostic), bytes=size,
                                                   sha256=w.digest(diagnostic) if size <= METADATA_LIMIT else None)
            result.update(sampled_owned_build_peak_bytes=budget.peak,
                          sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak)
            w.save(root / 'evidence/replay-receipt.json', result)


def worker(config):
    if sys.stdin.buffer.readline(4) != b'go\n':
        raise ValueError('outer ownership handshake missing')
    w.hosted_preflight()
    args = argparse.Namespace(**w.read_json(config))
    root = ordinary_path(args.output)
    budget = ReplayBudget(root, 830, rss_limit=4 * 1024**3)
    replay_phase(args, root, budget)
    budget.check(force=True)


class ReplayBudget(w.Budget):
    def check(self, *, force=False):
        previous_scan = self.last_scan
        super().check(force=force)
        if force or self.last_scan != previous_scan:
            if w.owned_size(self.root / 'conversion-replay') > 256 * 1024**2:
                raise ValueError('replay conversion workspace exceeds 256 MiB sampled refusal bound')


def execute(args):
    from suite_process import run_worker
    w.hosted_preflight()
    w.source_identity(args.core, args.expected_core, args.expected_suite)
    if shutil.which('agent-resources'):
        raise ValueError('installed resource controller requires an explicitly registered compatible hosted lane')
    root = fresh_root(args.output, os.environ['RUNNER_TEMP'])
    w.save(root / 'evidence/owner.json', dict(project='Coaptic', owner=os.environ.get('GITHUB_RUN_ID'),
           release='Ephemeral hosted VM; evidence retention14days', build_limit=w.BUILD_LIMIT,
           evidence_limit=w.EVIDENCE_LIMIT, mode='offline replay; no ETW session or native execution'))
    config = root / 'replay-task.json'
    w.save(config, vars(args))
    result = None
    stdout = stderr = b''
    try:
        result = run_worker([sys._base_executable, '-B', str(Path(__file__).resolve()), '_worker', str(config)],
                            timeout=900, limit=w.LOG_LIMIT, cwd=w.SUITE,
                            env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path), PYTHONDONTWRITEBYTECODE='1'),
                            settle_build_auxiliaries=True)
        w.save(root / 'evidence/replay-outer.json', dict(passed=True, seconds=result.duration_seconds,
               descendants_settled=True, build_auxiliaries_terminated=result.descendants_settled))
    except BaseException as error:
        stdout, stderr = getattr(error, 'stdout', b''), getattr(error, 'stderr', b'')
        failure = w.outer_failure(error)
        failure.pop('etw_stop_proof', None)
        failure['mode'] = 'offline replay; no ETW session started'
        w.save(root / 'evidence/replay-outer.json', failure)
        raise
    finally:
        if result is not None:
            stdout, stderr = result.stdout, result.stderr
        with (root / 'evidence/replay-outer.log').open('xb') as stream:
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
