"""Bounded hosted-only Windows stack profiling, with a gated native workload."""
import argparse
import ctypes
import json
import os
import re
import sys
import hashlib
from pathlib import Path
import platform
import queue
import shutil
import subprocess
import threading
import time
import uuid

import stack_profile

MODES = ("unprotected", "oscore")
CAPTURES_PER_MODE = 8
EMPTY_GATES = 16
OPERATIONS = 50000
WARMUP = 128
MIN_APP_SAMPLES = 200
HERE = Path(__file__).resolve().parent
SUITE = HERE.parents[1]
BUILD_LIMIT = 8 * 1024**3
EVIDENCE_LIMIT = 256 * 1024**2
LOG_LIMIT = 2 * 1024**2


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    stack_profile.write_new(path, json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2) + '\n')


def source_identity(core, expected_core, expected_suite):
    from development_suite import identity, resolved_core
    result = {'core': identity(core), 'suite': identity(SUITE)}
    if (result['core']['commit'] != expected_sha(expected_core)
            or result['suite']['commit'] != expected_sha(expected_suite)
            or resolved_core() != Path(core).resolve()):
        raise ValueError('exact clean source/dependency identity mismatch')
    return result


def owned_cache_alias(root, path, info):
    """Prune only the Windows INetCache compatibility junction, never traverse it.

    Its backing directory must have an ordinary lexical path under this owned
    root. Inspect every existing component without accepting a reparse chain;
    the regular tree walk counts backing files once at their ordinary path.
    """
    root, path = Path(root).absolute(), Path(path).absolute()
    expected = root / 'user/AppData/Local/Microsoft/Windows/INetCache/Content.IE5'
    if (path != expected or getattr(info, 'st_reparse_tag', 0) != 0xA0000003
            or not getattr(info, 'st_file_attributes', 0) & 0x10):
        return False
    raw = os.readlink(path).replace('\\', '/')
    if raw.startswith('//?/'):
        raw = raw[4:]
    if not re.match(r'^[A-Za-z]:/', raw):
        raise ValueError('INetCache alias target is not an ordinary local drive path')
    target = Path(raw)
    if target != expected.parent / 'IE':
        raise ValueError('INetCache alias target is not its owned IE backing directory')
    component = root
    for part in target.relative_to(root).parts:
        component = component / part
        try:
            state = component.lstat()
        except FileNotFoundError:
            break  # A not-yet-created owned backing directory has no bytes yet.
        if getattr(state, 'st_file_attributes', 0) & 0x400 or component.is_symlink():
            raise ValueError('INetCache alias target contains a reparse entry')
        if not component.is_dir():
            raise ValueError('INetCache alias target contains a non-directory')
    return True


def owned_size(root):
    """Count job-owned backing files; refuse links except the pruned cache alias."""
    total = 0
    def walk_error(error):
        if not isinstance(error, FileNotFoundError):
            raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in dirs + files:
            path = Path(directory) / name
            try:
                stat = path.lstat()
            except FileNotFoundError:
                continue  # Normal compiler/SDK temporary-file churn.
            if path.is_symlink() or getattr(stat, 'st_file_attributes', 0) & 0x400:
                if name in dirs and owned_cache_alias(root, path, stat):
                    dirs.remove(name)  # os.walk must never enter the junction.
                    continue
                # Preserve the refusing entry without following its target. A
                # generic error cannot distinguish SDK output from an escape.
                entry = path.relative_to(root).as_posix()[:512]
                attributes = getattr(stat, 'st_file_attributes', 0)
                tag = getattr(stat, 'st_reparse_tag', 0)
                raise ValueError(f'reparse entry in owned output: {entry!r}; '
                                 f'attributes={attributes:#x}; tag={tag:#x}')
            if name in files:
                total += stat.st_size
    return total


def native_artifact_pair(raw, target):
    """Select the EXE/PDB from one Cargo artifact, without filename guessing."""
    target = Path(target).resolve()
    pair = None
    finished = []
    for line in raw.splitlines():
        if not line.startswith(b'{'):
            continue
        row = json.loads(line)
        if row.get('reason') == 'build-finished':
            finished.append(row.get('success') is True)
        if (row.get('reason') != 'compiler-artifact'
                or row.get('target', {}).get('name') != 'bench-core'
                or 'bin' not in row.get('target', {}).get('kind', [])):
            continue
        executable = row.get('executable')
        filenames = row.get('filenames')
        if not isinstance(executable, str) or not isinstance(filenames, list):
            raise ValueError('native Cargo artifact fields missing')
        pdbs = [x for x in filenames if isinstance(x, str) and Path(x).suffix.lower() == '.pdb']
        if len(pdbs) != 1:
            raise ValueError('native Cargo artifact requires exactly one PDB')
        paths = tuple(Path(x) for x in (executable, pdbs[0]))
        if any(not x.is_absolute() or not x.resolve().is_relative_to(target) for x in paths):
            raise ValueError('native Cargo artifact outside owned target')
        selected = tuple(x.resolve() for x in paths)
        if pair is not None and pair != selected:
            raise ValueError('ambiguous native Cargo artifact pair')
        pair = selected
    if finished != [True] or pair is None:
        raise ValueError('native Cargo artifact/build completion missing')
    return pair


def working_set(process):
    """Windows handle-scoped working set, without PID reopening or image reads."""
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
            'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
            'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage')]
    query = ctypes.WinDLL('kernel32', use_last_error=True).K32GetProcessMemoryInfo
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    query.restype = wintypes.BOOL
    value = Counters()
    value.cb = ctypes.sizeof(value)
    if not query(wintypes.HANDLE(int(process._handle)), ctypes.byref(value), value.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return value.WorkingSetSize


class Budget:
    def __init__(self, root, seconds, *, rss_limit=1024**3):
        self.root = Path(root)
        self.deadline = time.monotonic() + seconds
        self.peak = 0
        self.last_scan = 0
        self.processes = set()
        self.rss_limit = rss_limit
        self.observed_child_working_set_peak = 0

    def check(self, *, force=False):
        now = time.monotonic()
        if now >= self.deadline:
            raise TimeoutError('owned phase deadline')
        # Sample direct children, including the in-process ETL converter. This
        # is a refusal monitor, not a hard memory quota or whole-job peak proof.
        rss = [working_set(p) for p in tuple(self.processes) if p.poll() is None]
        self.observed_child_working_set_peak = max(self.observed_child_working_set_peak, sum(rss))
        if any(n > self.rss_limit for n in rss) or sum(rss) > 2 * self.rss_limit:
            raise ValueError('direct child working-set refusal bound exceeded')
        if force or now - self.last_scan >= 1:
            self.last_scan = now
            evidence = owned_size(self.root / 'evidence')
            build = owned_size(self.root) - evidence
            self.peak = max(self.peak, build)
            if build > BUILD_LIMIT or evidence > EVIDENCE_LIMIT:
                raise ValueError('owned build/evidence budget exceeded')


class Process:
    """Pipe owner inside the outer Job; finite reads and combined output bound."""
    def __init__(self, command, budget, *, env=None, cwd=SUITE):
        self.command, self.budget = list(map(str, command)), budget
        self.events = queue.Queue()
        self.raw = [bytearray(), bytearray()]
        self.error = None
        self.lock = threading.Lock()
        self.p = subprocess.Popen(self.command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.budget.processes.add(self.p)
        self.threads = []
        for index, pipe in enumerate((self.p.stdout, self.p.stderr)):
            thread = threading.Thread(target=self._read, args=(index, pipe), daemon=True)
            thread.start()
            self.threads.append(thread)

    def _read(self, index, pipe):
        pending = bytearray()
        try:
            while block := pipe.read(4096):
                with self.lock:
                    if sum(map(len, self.raw)) + len(block) > LOG_LIMIT:
                        raise ValueError('combined child output exceeds 2 MiB')
                    self.raw[index].extend(block)
                if index == 0:
                    pending.extend(block)
                    while b'\n' in pending:
                        line, _, pending = pending.partition(b'\n')
                        self.events.put(bytes(line) + b'\n')
            if index == 0:
                if pending:
                    self.events.put(bytes(pending))
                self.events.put(None)
        except BaseException as error:
            self.error = error

    def line(self, seconds=30, *, cleanup=False):
        deadline = time.monotonic() + seconds
        while True:
            if not cleanup:
                self.budget.check()
            if self.error:
                raise self.error
            if time.monotonic() >= deadline:
                raise TimeoutError('child event deadline')
            try:
                row = self.events.get(timeout=min(.05, max(0, deadline - time.monotonic())))
                if row is None:
                    raise RuntimeError('unexpected child stdout EOF')
                return parse_event(row)
            except queue.Empty:
                continue

    def send(self, command):
        self.p.stdin.write((command + '\n').encode('ascii'))
        self.p.stdin.flush()

    def finish(self, seconds=30, *, cleanup=False):
        deadline = time.monotonic() + seconds
        while self.p.poll() is None:
            if not cleanup:
                self.budget.check()
            if self.error:
                raise self.error
            if time.monotonic() >= deadline:
                raise TimeoutError('child exit deadline')
            time.sleep(.02)
        for thread in self.threads:
            thread.join(1)
            if thread.is_alive():
                raise RuntimeError('child pipe did not settle')
        if self.error:
            raise self.error
        if self.p.returncode:
            raise RuntimeError('child exited ' + str(self.p.returncode))

    def close(self):
        # A malformed/EOF cleanup event is not permission to preempt the tool's
        # owned-handle ETW stop. Keep its original grace even after read failure.
        deadline = getattr(self, 'etw_cleanup_deadline', 0)
        while (self.p.poll() is None and not getattr(self, 'etw_cleanup_settled', False)
               and time.monotonic() < deadline):
            time.sleep(min(.02, max(0, deadline - time.monotonic())))
        if self.p.poll() is None:
            self.p.kill()  # Windows handle, never a re-used numeric group ID.
        self.p.wait(timeout=5)
        for pipe in (self.p.stdin, self.p.stdout, self.p.stderr):
            pipe.close()
        for thread in self.threads:
            thread.join(1)
            if thread.is_alive():
                raise RuntimeError('child reader cleanup unresolved')
        self.budget.processes.discard(self.p)

    def log(self, path):
        with Path(path).open('xb') as stream:
            stream.write(bytes(self.raw[0]) + b'\n--- stderr ---\n' + bytes(self.raw[1]))


def command(command, budget, log, *, env=None, cwd=SUITE):
    child = Process(command, budget, env=env, cwd=cwd)
    try:
        child.p.stdin.close()
        child.finish(780)
        return bytes(child.raw[0])
    finally:
        child.close()
        child.log(log)


def build_environment(root):
    """Keep SDK/NuGet user caches and temporary output inside the build budget.

    NuGet has independent packages, HTTP and plugin caches. SDK/MSBuild use
    CLI home, user app-data and TEMP; credential plugins may also use app-data.
    This console SDK project has no ASP.NET compilation cache. Redirect the
    user roots too, so inherited plugin/profile settings cannot select defaults
    outside the owned root. No machine-wide SDK installation is performed.
    """
    env = dict(os.environ)
    paths = {
        'CARGO_HOME': 'cargo-home', 'CARGO_TARGET_DIR': 'target',
        'NUGET_PACKAGES': 'nuget', 'NUGET_HTTP_CACHE_PATH': 'nuget-http',
        'NUGET_PLUGINS_CACHE_PATH': 'nuget-plugins',
        'NUGET_SCRATCH': 'nuget-scratch',
        'DOTNET_CLI_HOME': 'dotnet-home', 'DOTNET_BUNDLE_EXTRACT_BASE_DIR': 'dotnet-bundle',
        'MSBUILDDEBUGPATH': 'msbuild-debug',
        'NUGET_CREDENTIALPROVIDER_MSAL_FILECACHE_LOCATION': 'user/local/msal.cache',
        'USERPROFILE': 'user', 'APPDATA': 'user/roaming', 'LOCALAPPDATA': 'user/local',
        'TMP': 'tmp', 'TEMP': 'tmp',
    }
    for key, relative in paths.items():
        path = root / relative
        (path.parent if key == 'NUGET_CREDENTIALPROVIDER_MSAL_FILECACHE_LOCATION'
         else path).mkdir(parents=True, exist_ok=True)
        env[key] = str(path)
    # Credential-provider session/MSAL caches are unnecessary for public feeds.
    # Disable them as well as relocating their default user/app-data roots.
    env.update(NUGET_CREDENTIALPROVIDER_SESSIONTOKENCACHE_ENABLED='false',
               NUGET_CREDENTIALPROVIDER_MSAL_FILECACHE_ENABLED='false',
               DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true')
    return env


def retain_file(root, source, destination, expected=None):
    """Copy one owned artifact without overwrites or unbounded growth.

    Refused/partial evidence is retained on failure; callers never delete it.
    Hash both original observations and the durable copy before accepting it.
    """
    root = Path(root).resolve()
    evidence = root / 'evidence'
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not source.is_relative_to(root) or not destination.is_relative_to(evidence):
        raise ValueError('retained artifact escaped owned root/evidence')
    size = source.stat().st_size
    if size > EVIDENCE_LIMIT - owned_size(evidence):
        raise ValueError('retained artifact exceeds evidence budget')
    source_digest = digest(source)
    if expected is None:
        expected = source_digest
    if source_digest != expected:
        raise ValueError('retained artifact source hash mismatch')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as original, destination.open('xb') as retained:
        remaining = size
        while block := original.read(min(65536, remaining + 1)):
            if len(block) > remaining:
                raise ValueError('retained artifact grew during copy')
            retained.write(block)
            remaining -= len(block)
    if remaining or digest(destination) != expected or digest(source) != expected:
        raise ValueError('retained artifact copy/source hash mismatch')
    return dict(path=str(destination), sha256=expected, bytes=size)


def retain_build_evidence(root, binary, pdb, tool):
    """Keep replay symbols and compact rebuild identities in uploaded evidence."""
    # Windows temporary roots may use an 8.3 alias; compare canonical paths on
    # both sides, as retain_file does for each retained artifact.
    root = Path(root).resolve()
    evidence = root / 'evidence'
    binary, pdb, tool = Path(binary), Path(pdb), Path(tool)
    native = retain_file(root, binary, evidence / 'binaries' / binary.name)
    symbols = retain_file(root, pdb, evidence / 'binaries' / pdb.name)
    package_lock = root / 'tool-packages.lock.json'
    lock = retain_file(root, package_lock, evidence / 'build-inputs/tool-packages.lock.json')
    dependencies = tool.with_suffix('.deps.json')
    deps = retain_file(root, dependencies, evidence / 'build-inputs/tool.deps.json')
    files = []
    for count, path in enumerate(tool.parent.rglob('*'), 1):
        if count > 256:
            raise ValueError('tool dependency manifest entry limit')
        if path.is_file():
            relative = path.relative_to(tool.parent).as_posix()
            if len(relative) > 512 or not path.resolve().is_relative_to(root):
                raise ValueError('tool dependency path escaped/oversized')
            files.append(dict(path=relative, bytes=path.stat().st_size, sha256=digest(path)))
    manifest = evidence / 'build-inputs/tool-files.json'
    value = dict(schema='coaptic-windows-tool-files/1', files=sorted(files, key=lambda row: row['path']),
                 notes='Dependency identity for source-pinned rebuilds; bit-identical rebuilds are not claimed.')
    manifest_bytes = len((json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2) + '\n').encode('utf-8'))
    if manifest_bytes > EVIDENCE_LIMIT - owned_size(evidence):
        raise ValueError('tool dependency manifest exceeds evidence budget')
    save(manifest, value)
    if owned_size(evidence) > EVIDENCE_LIMIT:
        raise ValueError('retained artifacts exceed evidence budget')
    return (dict(path=native['path'], sha256=native['sha256'], bytes=native['bytes'],
                 pdb=symbols['path'], pdb_sha256=symbols['sha256'], pdb_bytes=symbols['bytes']),
            dict(package_lock=lock, dependencies=deps,
                 files_manifest=dict(path=str(manifest), sha256=digest(manifest))))


def selected_dotnet_sdk(dotnet, root, budget, env):
    """Select the exact provisioned SDK from an owned, retained global.json."""
    directory = root / 'evidence/build-inputs'
    directory.mkdir(parents=True, exist_ok=True)
    selection = directory / 'global.json'
    save(selection, dict(sdk=dict(version='8.0.427', rollForward='disable', allowPrerelease=False)))
    version = command([dotnet, '--version'], budget, root / 'evidence/dotnet-version.log',
                      env=env, cwd=directory).decode('utf-8').strip()
    if version != '8.0.427':
        raise ValueError('selected .NET SDK is not the exact provisioned 8.0.427')
    info = command([dotnet, '--info'], budget, root / 'evidence/dotnet-info.log',
                   env=env, cwd=directory).decode('utf-8')
    return directory, info, dict(path=str(selection), sha256=digest(selection), version=version)


def build_phase(args, root, budget):
    from development_suite import cargo_inputs, toolchain
    from native_lock import native_lock
    sources = source_identity(args.core, args.expected_core, args.expected_suite)
    inputs = cargo_inputs()
    compiler, cargo, tools = toolchain()
    env = build_environment(root)
    for name in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTFLAGS'):
        env.pop(name, None)
    env.update(CARGO_HOME=str(root / 'cargo-home'), CARGO_TARGET_DIR=str(root / 'target'),
               CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2', RUSTC=tools['rustc']['path'],
               RUSTFLAGS='-Cforce-frame-pointers=yes', CARGO_PROFILE_RELEASE_DEBUG='2',
               CARGO_PROFILE_RELEASE_STRIP='none', CARGO_PROFILE_RELEASE_LTO='thin',
               CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1',
               DOTNET_CLI_TELEMETRY_OPTOUT='1', MSBUILDDISABLENODEREUSE='1')
    before = time.monotonic()
    projects = list((HERE / 'windows-stack').glob('*.csproj'))
    if len(projects) != 1:
        raise ValueError('exactly one owned C# project required')
    dotnet = shutil.which('dotnet')
    if not dotnet:
        raise ValueError('.NET SDK unavailable')
    sdk_directory, sdk, sdk_selection = selected_dotnet_sdk(dotnet, root, budget, env)
    command([dotnet, 'build', projects[0], '--configuration', 'Release', '--output', root / 'tool',
             '-p:BaseIntermediateOutputPath=' + str(root / 'dotnet-obj') + os.sep,
             '-p:NuGetLockFilePath=' + str(root / 'tool-packages.lock.json'),
             '-p:RestorePackagesWithLockFile=true', '-p:UseSharedCompilation=false', '-nodeReuse:false'], budget,
            root / 'evidence/tool-build.log', env=env, cwd=sdk_directory)
    tool_dlls = [x for x in (root / 'tool').glob('*.runtimeconfig.json')]
    if len(tool_dlls) != 1:
        raise ValueError('tool executable receipt ambiguous')
    tool = tool_dlls[0].with_name(tool_dlls[0].name.removesuffix('.runtimeconfig.json') + '.dll')
    if not tool.is_file():
        raise ValueError('tool DLL missing')
    # Fail the smaller tooling build before spending time on the Rust workload.
    with native_lock(args.core) as lock:
        raw = command([tools['cargo']['path'], 'build', '--release', '--locked',
                       '--target', 'x86_64-pc-windows-msvc', '--manifest-path',
                       HERE / 'native/Cargo.toml', '-p', 'bench-rust-server', '--bin', 'bench-core',
                       '--message-format=json-render-diagnostics'], budget,
                      root / 'evidence/native-build.log', env=env)
        lock = dict(lock)
    binary, pdb = native_artifact_pair(raw, root / 'target')
    if not binary.is_file() or not pdb.is_file():
        raise ValueError('native Cargo executable/PDB missing')
    if sources != source_identity(args.core, args.expected_core, args.expected_suite):
        raise ValueError('source changed during build')
    if any(digest(v['path']) != v['sha256'] for v in tools.values()):
        raise ValueError('compiler changed during build')
    native, tool_evidence = retain_build_evidence(root, binary, pdb, tool)
    tool_evidence['sdk_selection'] = sdk_selection
    record = dict(schema='coaptic-windows-build/1', sources=sources, inputs=inputs,
                  compiler=compiler, cargo=cargo, tools=tools, lock=lock, dotnet=sdk,
                  native=native,
                  tool=dict(path=str(tool), sha256=digest(tool), dotnet=dotnet,
                            package_lock_sha256=tool_evidence['package_lock']['sha256'],
                            retained_evidence=tool_evidence),
                  flags={k: v for k, v in env.items() if k.startswith(('CARGO_', 'RUST'))},
                  duration_seconds=time.monotonic() - before,
                  sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak,
                  platform=platform.platform(), sampled_owned_build_peak_bytes=budget.peak)
    save(root / 'evidence/build.json', record)
    budget.check(force=True)
    return record


def read_json(path):
    return stack_profile.parse_json(stack_profile.read_text(path))


def tool_event(row, status, capture_id):
    if (set(row) != {'status', 'capture_id', 'detail'} or row['status'] != status
            or row['capture_id'] != capture_id or not isinstance(row['detail'], dict)):
        raise ValueError('collector event/identity mismatch')
    return row['detail']


def stopped_receipt(detail, capture_id, receipt_path):
    """Require the expected durable receipt, not a queued status alone."""
    path = Path(detail.get('receipt', '')).resolve()
    if receipt_path is None or path != Path(receipt_path).resolve():
        raise ValueError('collector receipt path mismatch')
    if path.stat().st_size > 65536:
        raise ValueError('collector receipt exceeds limit')
    receipt = read_json(path)
    if (receipt.get('schema') != 'coaptic-windows-stack-capture/1'
            or receipt.get('stopped') is not True
            or receipt.get('config', {}).get('capture_id') != capture_id
            or receipt.get('session_name') != 'CoapticStack-' + capture_id):
        raise ValueError('collector durable stop proof mismatch')


def stop_collector(child, capture_id, *, cleanup=False, receipt_path=None):
    """Settle ETW before any Job deadline; an unproven stop invalidates capture."""
    if cleanup:
        deadline = time.monotonic() + 15
        child.etw_cleanup_deadline = deadline
        child.etw_cleanup_settled = False
        try:
            child.p.stdin.close()  # EOF invokes only the tool's owned handle.
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('collector cleanup deadline')
                row = child.line(remaining, cleanup=True)
                if time.monotonic() >= deadline:
                    raise TimeoutError('collector cleanup deadline')
                status = row.get('status')
                detail = tool_event(row, status, capture_id)
                if status in ('armed', 'ready'):
                    continue
                if status == 'stopped':
                    stopped_receipt(detail, capture_id, receipt_path)
                elif status != 'failed' or detail.get('cleanup_settled') is not True:
                    raise ValueError('collector terminal cleanup proof missing')
                child.etw_cleanup_settled = True
                # Failure exit is expected; use wait, not success-only finish.
                child.p.wait(timeout=5)
                return detail
        except BaseException as error:
            raise RuntimeError('ETW cleanup unresolved; dispose dedicated VM: ' + str(error)) from error
    child.send('stop')
    row = child.line(15)
    detail = tool_event(row, 'stopped', capture_id)
    stopped_receipt(detail, capture_id, receipt_path)
    child.finish(10)
    return detail


def verified_build(args, root):
    root = Path(root).resolve()
    record = read_json(root / 'evidence/build.json')
    if record['sources'] != source_identity(args.core, args.expected_core, args.expected_suite):
        raise ValueError('prepared sources changed')
    native, tool = record['native'], record['tool']
    for path in (native['path'], native['pdb']):
        if not Path(path).resolve().is_relative_to(root / 'evidence/binaries'):
            raise ValueError('prepared replay binary/PDB not retained in evidence')
    for path, expected in ((native['path'], native['sha256']), (native['pdb'], native['pdb_sha256']),
                           (tool['path'], tool['sha256'])):
        if not Path(path).resolve().is_relative_to(root) or digest(path) != expected:
            raise ValueError('prepared executable/PDB changed or escaped output')
    for receipt in tool['retained_evidence'].values():
        path = Path(receipt['path']).resolve()
        if not path.is_relative_to(root / 'evidence') or digest(path) != receipt['sha256']:
            raise ValueError('prepared dependency evidence changed or escaped output')
    return record


def capture_phase(args, root, budget):
    budget.check(force=True)  # Retained EXE/PDB/receipts count before any process.
    record = verified_build(args, root)
    tool = [record['tool']['dotnet'], record['tool']['path']]
    command(tool + ['metadata'], budget, root / 'evidence/tool-metadata.log')
    command(tool + ['selftest'], budget, root / 'evidence/tool-selftest.log')
    cohorts = []
    for mode, kind, index in plan():
        budget.check(force=True)
        name = f'{mode}-{kind}-{index:02d}'
        directory = root / 'evidence' / name
        directory.mkdir()
        events = []
        native = Process([record['native']['path'], str(OPERATIONS), mode, '--batch-cpu'], budget)
        collector = None
        settled = True
        capture_id = str(uuid.uuid4())
        work_started = None
        work_seconds = None
        config_path = directory / 'config.json'
        try:
            # Target identity is acquired by the tool at native precision, never
            # round-tripped through Python's lower precision datetime objects.
            raw_target = command(tool + ['target', '--pid', str(native.p.pid)], budget,
                                 directory / 'target.log')
            target = parse_event(raw_target)
            detail = target.get('detail', target)
            start_utc = detail['process_start_utc']
            tid = detail['main_thread_id']
            if type(tid) is not int or tid <= 0:
                raise ValueError('one native thread must be identified before capture')
            identity = dict(source=json.dumps(record['sources'], sort_keys=True),
                            tool='TraceEvent3.1.21; exporter SHA256 ' + record['tool']['sha256'],
                            workload='64B Default allocated; server App; socket-free; batch50000; ' + mode,
                            capture=capture_id, platform=record['platform'], cohort=name)
            config = dict(capture_id=capture_id, directory=str(directory), pid=native.p.pid, tid=tid,
                          process_start_utc=start_utc, exe=record['native']['path'],
                          exe_sha256=record['native']['sha256'], pdb=record['native']['pdb'],
                          pdb_sha256=record['native']['pdb_sha256'], identity=identity,
                          label='server main; ' + name, max_seconds=60, dedicated_hosted_vm=True)
            save(config_path, config)
            if kind == 'capture':
                command(tool + ['preflight', '--config', config_path], budget, directory / 'preflight.log')
                command(tool + ['symbols', '--config', config_path], budget, directory / 'symbols.log')
            protocol = BatchProtocol(mode)
            native.send('start')
            while protocol.stage != 'done':
                row = native.line(45)
                events.append(row)
                action = protocol.receive(row)
                if action == 'capture_then_run':
                    if kind == 'capture':
                        collector = Process(tool + ['capture', '--config', config_path], budget)
                        settled = False
                        tool_event(collector.line(15), 'armed', capture_id)
                        collector.send('start')
                        tool_event(collector.line(15), 'ready', capture_id)
                    work_started = time.perf_counter()
                    native.send('run')
                elif action == 'stop_then_verify':
                    work_seconds = time.perf_counter() - work_started
                    if collector is not None:
                        stop_collector(collector, capture_id, receipt_path=directory / 'capture.json')
                        settled = True
                        collector.close()
                        collector.log(directory / 'collector.log')
                        collector = None
                    native.send('verify')
                elif action:
                    native.send(action)
            native.finish(10)
            save(directory / 'native.json', dict(events=events, work_gate_wall_seconds=work_seconds,
                                                scope='parent-observed gate interval; includes IPC; no subtraction',
                                                complete=True, etw_cleanup_settled=settled))
            item = dict(name=name, mode=mode, kind=kind, index=index,
                        verified=OPERATIONS + WARMUP, work_gate_wall_seconds=work_seconds)
            if kind == 'capture':
                scratch = root / ('conversion-' + name)
                scratch.mkdir()
                profile_path = directory / 'profile.json'
                export_config = directory / 'export.json'
                save(export_config, dict(capture_receipt=str(directory / 'capture.json'),
                                        output=str(profile_path), scratch_directory=str(scratch),
                                        max_etl_bytes=128 * 1024**2, max_conversion_bytes=256 * 1024**2))
                command(tool + ['export', '--config', export_config], budget, directory / 'export.log')
                profile = stack_profile.load_json(stack_profile.read_text(profile_path))
                if profile['scope']['pid'] != native.p.pid or profile['scope']['tid'] != tid or profile['identity'] != identity:
                    raise ValueError('exported profile scope/identity mismatch')
                app_samples = sum(s['samples'] for s in profile['stacks']
                                  if any('coaptic::app::' in f for f in s['frames']))
                # Unknown unwind completeness remains unknown even after a
                # successful export; no evidence is manufactured from a zero.
                item['quality'] = qualification(profile, app_rooted=app_samples,
                                                pdb_match=True, truncated=None)
                item['profile_sha256'] = digest(profile_path)
                stack_profile.write_new(directory / 'profile.html', stack_profile.render_html(profile))
            cohorts.append(item)
            save(directory / 'result.json', item)
        except BaseException as error:
            if collector is not None and not settled:
                try:
                    stop_collector(collector, capture_id, cleanup=True, receipt_path=directory / 'capture.json')
                    settled = True
                except BaseException as cleanup:
                    error.add_note('ETW cleanup unresolved; dedicated VM must be disposed: ' + str(cleanup))
            save(directory / 'runner-failure.json', dict(error=type(error).__name__, detail=str(error)[:2048],
                                                       notes=getattr(error, '__notes__', []),
                                                       etw_cleanup_settled=settled))
            raise
        finally:
            # ETW cleanup happens before process termination. A forced Job kill
            # has no ETW guarantee and can never turn a failed receipt into pass.
            if collector is not None:
                collector.close()
                collector.log(directory / 'collector.log')
            native.close()
            native.log(directory / 'native.log')
    if record['sources'] != source_identity(args.core, args.expected_core, args.expected_suite):
        raise ValueError('sources changed during capture')
    save(root / 'evidence/results.json', dict(schema='coaptic-windows-profile-results/1',
         functional_pass=True, cohorts=cohorts, cpu_share_qualified=False,
         notes='Separate PID/TID cohorts; no pooled flame graph or CPU improvement claim.',
         sampled_owned_build_peak_bytes=budget.peak,
         sampled_direct_child_working_set_peak_bytes=budget.observed_child_working_set_peak,
         direct_child_working_set_refusal_bytes=budget.rss_limit))


def worker(phase, config):
    if sys.stdin.buffer.readline(4) != b'go\n':
        raise ValueError('outer ownership handshake missing')
    args = argparse.Namespace(**read_json(config))
    hosted_preflight()
    root = Path(args.output).resolve()
    budget = Budget(root, 830 if phase == 'build' else 650,
                    rss_limit=(4 if phase == 'build' else 1) * 1024**3)
    try:
        if phase == 'build':
            build_phase(args, root, budget)
        else:
            capture_phase(args, root, budget)
        budget.check(force=True)
    except BaseException as error:
        save(root / 'evidence' / (phase + '-failure.json'),
             dict(error=type(error).__name__, detail=str(error)[:2048], notes=getattr(error, '__notes__', [])))
        raise


def outer_failure(error):
    """Bounded structured causes from suite_process.WorkerError's contract."""
    def notes(cause):
        return [str(note)[:1024] for note in getattr(cause, '__notes__', ())[:8]]

    def cause_record(cause):
        return dict(error=type(cause).__name__, detail=str(cause)[:2048], notes=notes(cause))

    cleanup = getattr(error, 'cleanup_errors', ())
    return dict(passed=False, error=type(error).__name__, detail=str(error)[:2048],
                primary=cause_record(getattr(error, 'primary_cause', error)),
                cleanup_errors=[cause_record(cause) for cause in cleanup[:16]],
                cleanup_errors_omitted=max(0, len(cleanup) - 16), notes=notes(error),
                cleanup_unresolved=getattr(error, 'cleanup_unresolved', None),
                etw_stop_proof='Consult per-capture receipts; forced Job termination is not ETW cleanup')


def execute(args):
    from suite_process import run_worker
    hosted_preflight()
    root = Path(args.output).resolve()
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    if root.parent != runner_temp or not root.name.startswith('coaptic-stack'):
        raise ValueError('owned output must be a direct coaptic-stack child of RUNNER_TEMP')
    if shutil.which('agent-resources'):
        raise ValueError('installed resource controller requires an explicitly registered compatible hosted lane')
    source_identity(args.core, args.expected_core, args.expected_suite)
    if args.command != 'capture':
        root.mkdir()
        (root / 'evidence').mkdir()
        save(root / 'evidence/owner.json', dict(project='Coaptic', owner=os.environ.get('GITHUB_RUN_ID'),
             release='Ephemeral job output; evidence retention14days', build_limit=BUILD_LIMIT,
             evidence_limit=EVIDENCE_LIMIT, plan=plan()))
    elif not (root / 'evidence/build.json').is_file():
        raise ValueError('capture requires successful prepared build')
    phases = ('build', 'capture') if args.command == 'all' else (args.command,)
    for phase in phases:
        result = None
        failure_stdout = failure_stderr = b''
        config = root / (phase + '-task.json')
        save(config, vars(args))
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path), PYTHONDONTWRITEBYTECODE='1')
        try:
            result = run_worker([sys._base_executable, '-B', str(Path(__file__).resolve()),
                                 '_worker', phase, str(config)], timeout=900, limit=LOG_LIMIT,
                                cwd=SUITE, env=env, settle_build_auxiliaries=phase == 'build')
            save(root / 'evidence' / (phase + '-outer.json'),
                 dict(passed=True, seconds=result.duration_seconds, descendants_settled=True,
                      build_auxiliaries_terminated=result.descendants_settled))
        except BaseException as error:
            failure_stdout = getattr(error, 'stdout', b'')
            failure_stderr = getattr(error, 'stderr', b'')
            save(root / 'evidence' / (phase + '-outer.json'),
                 outer_failure(error))
            raise
        finally:
            stdout = result.stdout if result is not None else failure_stdout
            stderr = result.stderr if result is not None else failure_stderr
            with (root / 'evidence' / (phase + '-outer.log')).open('xb') as stream:
                stream.write(stdout + b'\n--- stderr ---\n' + stderr)


def plan():
    """Fixed serial order; controls and captured workers have fresh processes."""
    return [(mode, "capture", i) for i in range(CAPTURES_PER_MODE) for mode in MODES] + [
        (mode, "control", 0) for mode in MODES]


def expected_sha(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("expected a full lowercase Git SHA-1")
    return value


def hosted_preflight(environment=None, *, platform=None, elevated=None):
    env = os.environ if environment is None else environment
    if (sys.platform if platform is None else platform) != "win32":
        raise ValueError("Windows is required")
    if env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("dedicated GitHub-hosted runner is required")
    if elevated is None:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    if not elevated:
        raise ValueError("elevated hosted runner is required")


def parse_event(data):
    """Decode one bounded UTF-8 event line, rejecting duplicate JSON keys."""
    if not isinstance(data, bytes) or len(data) > 4096 or not data.endswith(b"\n"):
        raise ValueError("invalid or oversized event line")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate event key")
            result[key] = value
        return result
    result = json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if not isinstance(result, dict):
        raise ValueError("event must be an object")
    return result


def check_growth(sizes, limit):
    """Fail closed for missing or invalid bounded file-size observations."""
    if type(limit) is not int or limit < 0 or not isinstance(sizes, (tuple, list)):
        raise ValueError("invalid budget")
    if any(type(size) is not int or size < 0 for size in sizes):
        raise ValueError("invalid file-size observation")
    if sum(sizes) > limit:
        raise ValueError("file growth budget exceeded")
    return sum(sizes)


class BatchProtocol:
    """Validate every native worker event and prescribe the next gate.

    The caller starts capture only on work-ready and must stop and flush it
    before sending verify. No event is accepted out of order.
    """
    def __init__(self, mode):
        if mode not in MODES:
            raise ValueError("invalid security mode")
        self.mode = mode
        self.stage = "fixture"
        self.block = 0
        self.kind = "empty"

    def receive(self, row):
        if not isinstance(row, dict):
            raise ValueError("event must be an object")
        if self.stage == "fixture":
            required = {"event": "fixture", "security": self.mode, "rows": OPERATIONS,
                        "wire_bytes": 25600000, "limit_bytes": 33554432,
                        "capture_datagram_bytes": 256, "app_datagram_bytes": 1472}
            if any(row.get(k) != v or type(row.get(k)) is not type(v) for k, v in required.items()):
                raise ValueError("fixture mismatch")
            for key in ("requested_bytes", "row_bytes", "row_metadata_bytes", "request_ref_bytes",
                        "optional_request_ref_bytes", "app_heap_bytes", "app_inline_bytes",
                        "fixture_inline_bytes", "scratch_allowance_bytes"):
                if type(row.get(key)) is not int or row[key] < 0:
                    raise ValueError("invalid fixture accounting")
            if row["requested_bytes"] > row["limit_bytes"]:
                raise ValueError("fixture exceeds limit")
            self.stage = "ready"
            return None
        if self.stage == "complete":
            required = {"event": "complete", "mode": "server-app-batch-cpu", "security": self.mode,
                        "operations": OPERATIONS, "warmup": WARMUP, "verified": OPERATIONS + WARMUP,
                        "work_batches": 1, "batch_operations": OPERATIONS, "empty_gates": EMPTY_GATES,
                        "internal_datagrams": 100256, "udp_datagrams": 0, "black_box": True}
            if row != required or any(type(row[k]) is not type(v) for k, v in required.items()):
                raise ValueError("completion mismatch")
            self.stage = "done"
            return "exit"
        if self.stage == "done":
            raise ValueError("unexpected event after completion")
        verified = WARMUP + (OPERATIONS if self.kind == "work" and self.stage == "verified" else 0)
        expected = {"event": self.stage, "kind": self.kind, "block": self.block, "verified": verified}
        if row != expected or any(type(row[k]) is not type(v) for k, v in expected.items()):
            raise ValueError("batch protocol mismatch")
        if self.stage == "ready":
            self.stage = "measured"
            return "capture_then_run" if self.kind == "work" else "run"
        if self.stage == "measured":
            self.stage = "verified"
            return "stop_then_verify" if self.kind == "work" else "verify"
        if self.kind == "work":
            self.stage = "complete"
        elif self.block + 1 == EMPTY_GATES:
            self.kind, self.block, self.stage = "work", 0, "ready"
        else:
            self.block += 1
            self.stage = "ready"
        return None


def qualification(profile, *, app_rooted, pdb_match, truncated):
    """Return eligibility; unknown quality is not zero and counts never pool."""
    stack_profile.validate_profile(profile)
    if type(app_rooted) is not int or not 0 <= app_rooted <= profile["totals"]["samples"]:
        raise ValueError("invalid App-rooted sample count")
    if (pdb_match is not None and type(pdb_match) is not bool) or (truncated is not None and type(truncated) is not bool):
        raise ValueError("invalid quality proof")
    reasons = []
    if profile["scope"]["tid"] is None:
        reasons.append("thread scope unknown")
    if app_rooted < MIN_APP_SAMPLES:
        reasons.append("fewer than 200 eligible App-rooted samples")
    for name in ("lost", "unresolved", "refused"):
        if profile["quality"][name] != 0:
            reasons.append(name + " is nonzero or unknown")
    if pdb_match is not True:
        reasons.append("PDB identity mismatch or unknown")
    if truncated is not False:
        reasons.append("truncation present or unknown")
    return {"qualified": not reasons, "reasons": reasons, "app_rooted_samples": app_rooted,
            "sample_denominator": profile["totals"]["samples"]}


def main(argv=None):
    if argv is None and len(sys.argv) == 4 and sys.argv[1] == '_worker':
        worker(sys.argv[2], sys.argv[3])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "capture", "all"))
    parser.add_argument("--core", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-core", required=True, type=expected_sha)
    parser.add_argument("--expected-suite", required=True, type=expected_sha)
    args = parser.parse_args(argv)
    try:
        execute(args)
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(2, 'error: ' + str(error) + '\n')


if __name__ == "__main__":
    main()
