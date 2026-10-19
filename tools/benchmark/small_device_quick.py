"""Finite matched Windows/host sample; not saturation or durable-security qualification."""
import argparse
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

import psutil

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'protected'))
from load import run
from context import SECURITY


def snapshot(process):
    cpu = process.cpu_times()
    return {'cpu_seconds': cpu.user + cpu.system, 'memory': process.memory_info()._asdict()}


def process_tree(process):
    members = [process, *process.children(recursive=True)]
    if len(members) > 8:
        raise ValueError('fixture process tree exceeds eight processes')
    rows = [{'pid': p.pid, 'name': p.name(), **snapshot(p)} for p in members]
    return {'processes': rows, 'cpu_seconds': sum(p['cpu_seconds'] for p in rows),
            'rss_sum_bytes': sum(p['memory']['rss'] for p in rows)}


def host_identity():
    model = platform.processor()
    if sys.platform == 'win32':
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
            model = winreg.QueryValueEx(key, 'ProcessorNameString')[0].strip()
    return {'cpu': model, 'logical_cpus': psutil.cpu_count(),
            'physical_cpus': psutil.cpu_count(logical=False),
            'ram_bytes': psutil.virtual_memory().total,
            'rustc': subprocess.check_output(['rustc', '+1.99.0', '-Vv'], text=True),
            'build_profile': 'release; thin LTO; codegen-units=1; existing registered Cargo lane'}


def driver(port, credentials, protected):
    before = snapshot(psutil.Process())
    report = run(SimpleNamespace(host='127.0.0.1', port=port, bytes=32, concurrency=1,
        operations=200, warmup=20, timeout_ms=1000, mode='con', sequence=0,
        credentials=credentials, security=SECURITY if protected else 'plaintext'))
    after = snapshot(psutil.Process())
    report['security'] = 'volatile-oscore' if protected else 'unprotected'
    report['client_cpu_seconds'] = after['cpu_seconds'] - before['cpu_seconds']
    report['client_memory'] = after['memory']
    print(json.dumps(report))


def identity(root):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
    if git('status', '--porcelain'):
        raise ValueError('source must be committed and clean')
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def measure(server, peer, protected):
    with tempfile.TemporaryDirectory(prefix='coaptic-small-') as temporary:
        credentials = Path(temporary) / 'credentials'
        credentials.write_bytes(secrets.token_bytes(24))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        if peer == 'aiocoap':
            command = [sys.executable, str(HERE / 'protected/aiocoap_server.py'),
                '--host', '127.0.0.1', '--port', str(port), '--bytes', '32']
            if protected:
                command += ['--credentials', str(credentials)]
        else:
            command = [str(server), peer, '127.0.0.1', str(port), '32']
            if peer == 'coaptic-small':
                command += ['1152']
                if protected:
                    command += [str(credentials)]
        with tempfile.TemporaryFile(mode='w+b') as log:
            child = subprocess.Popen(command, stdout=log, stderr=log)
            failure = None
            try:
                for _ in range(200):
                    if child.poll() is not None:
                        raise RuntimeError('server exited before readiness')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        try:
                            probe.bind(('127.0.0.1', port))
                        except OSError:
                            break
                    time.sleep(.01)
                else:
                    raise TimeoutError('server bind deadline')
                process = psutil.Process(child.pid)
                before = process_tree(process)
                started = time.perf_counter_ns()
                result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--driver',
                    str(port), str(credentials), str(int(protected))], capture_output=True, text=True, timeout=15)
                after = process_tree(process)
                wall = time.perf_counter_ns() - started
                result.check_returncode()
                report = json.loads(result.stdout)
                if {p['pid'] for p in before['processes']} != {p['pid'] for p in after['processes']}:
                    raise ValueError('server process tree changed during resource window')
                report.update(peer=peer, server_cpu_seconds=after['cpu_seconds'] - before['cpu_seconds'],
                    server_process_tree=after, resource_window_ns=wall)
                values = sorted(report['latencies_ns'])
                report['summary'] = {name: values[min(len(values)-1, math.ceil(len(values)*q)-1)] / 1000
                    for name, q in [('p50_us', .5), ('p95_us', .95), ('max_us', 1)]} if values else {}
                report['summary']['verified_operations_per_second'] = report['completed'] * 1e9 / report['elapsed_ns']
            except Exception as error:
                failure = error
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
                log.seek(0)
                server_log = log.read(65536).decode(errors='replace')
        if failure is not None:
            raise RuntimeError(str(failure) + '\nserver log:\n' + server_log.replace(str(credentials), '[ephemeral credentials]')) from failure
        report['server_log'] = server_log.replace(str(credentials), '[ephemeral credentials]')
        if peer == 'coaptic-small':
            profile = json.loads(server_log.splitlines()[0])
            if profile['profile'] != 'SmallDevice' or profile['storage'] != 'fixed' or profile['app_including_adapter_bytes'] > 14*1024:
                raise ValueError('SmallDevice profile/independent whole-owner ceiling')
            report['profile'] = profile
        return report


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--driver':
        driver(int(sys.argv[2]), sys.argv[3], bool(int(sys.argv[4])))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = HERE.parents[1]
    sources = {'suite': identity(root), 'core': identity(root / 'coaptic')}
    report = {'schema': 'coaptic-small-quick/1', 'sources': sources, 'platform': platform.platform(),
        'python': sys.version, 'host': host_identity(),
        'native_lock_sha256': digest(HERE / 'native/Cargo.lock'),
        'native_versions': {'coap-rs': '0.28.1', 'coap-lite': '0.13.3'}, 'versions': {n: importlib.metadata.version(n) for n in ['aiocoap','cryptography','psutil']},
        'server_sha256': digest(args.server), 'driver_sha256': digest(HERE / 'protected/load.py'),
        'runner_sha256': digest(__file__), 'cells': [],
        'limits': 'One short serial closed-loop window/cell, 32B complete GET/CON, concurrency1. Python/GIL and independent authentication/byte validation included. No saturation or significance claim. Server scheduling differs: Coaptic spin, coap-rs two Tokio workers, aiocoap asyncio, codec narrower endpoint. CPU is quantized; client resource window includes context/socket setup+warmup, server window also includes driver process startup. Server CPU includes launcher+worker process tree; RSS sum includes shared pages more than once and per-process peak RSS covers lifetime. Client RSS and server tree RSS include runtime/dependencies, not core memory. OSCORE volatile only; no provisioning/persistence. No device involvement.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for peer, protected in [('coaptic-small',False),('coaptic-small',True),('aiocoap',False),('aiocoap',True),('coap-rs',False),('coap-lite-codec',False)]:
        try:
            cell = measure(args.server.resolve(), peer, protected)
        except Exception as error:
            report['failure'] = {'peer': peer, 'security': 'volatile-oscore' if protected else 'unprotected', 'error': str(error)}
            args.output.write_text(json.dumps(report, indent=2)+'\n')
            raise
        report['cells'].append(cell)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'peer':peer,'security':cell['security'],'completed':cell['completed'],'failed':cell['failed'],**cell['summary']}), flush=True)
        if cell['failed'] or cell['warmup_failed'] or cell['completed'] != 200 or cell['verified_bytes'] != 6400:
            raise ValueError('cell failed; preserve receipt and stop')
    if sources != {'suite': identity(root), 'core': identity(root/'coaptic')}:
        raise ValueError('source changed during sample')


if __name__ == '__main__':
    main()
