"""Verify portable hashes and recompute CPU/ESP/host points from full vectors."""
from pathlib import Path
import gzip, hashlib, json, math, statistics, zipfile

P = Path(__file__).resolve().parent
sha = lambda raw: hashlib.sha256(raw).hexdigest()
load = lambda p: json.loads(p.read_text())
point = lambda values: math.exp(statistics.mean(map(math.log, values)))
for name, info in load(P / 'FILES.json').items():
    raw = (P / name).read_bytes()
    assert len(raw) == info['bytes'] and sha(raw) == info['sha256'], name

for name in ['rejected-integration-cpu4', 'rejected-timer-cpu64', 'rejected-guard-cpu4']:
    result = load(P / (name + '.json'))
    means = {}
    total = 0
    with zipfile.ZipFile(P / (name + '-raw.zip')) as archive:
        assert archive.testzip() is None
        for row in result['processes']:
            raw = gzip.decompress(archive.read(row['label'] + '.json.gz'))
            assert len(raw) <= 2 * 1024**2
            value = json.loads(raw)
            cell = row['cell']
            field = 'cycles' if cell[0] == 'retained' else ('latencies_cycles' if cell[1] == 'small-device' else 'server_poll_cpu_cycles_sum')
            cycles = value[field]
            assert cycles and all(type(v) is int and v > 0 for v in cycles)
            assert len(cycles) == row['cycle_count'] and sum(cycles) == row['cycle_sum']
            means[row['label']] = statistics.mean(cycles)
            assert means[row['label']] == row['cycle_mean']
            if row['label'].startswith('measure-'): total += len(cycles)
    assert total == result['measured_operations']
    for row in result['rows']:
        label = 'measure-' + str(row['pair']) + '-' + '-'.join(map(str, row['cell']))
        ratio = means[label + '-B'] / means[label + '-A']
        assert math.isclose(ratio, row['ratio'], rel_tol=1e-12)
    failed = []
    for row in result['summary']:
        ratios = [v['ratio'] for v in result['rows'] if v['cell'] == row['cell']]
        ratio = point(ratios)
        assert math.isclose(ratio, row['ratio'], rel_tol=1e-12)
        if row['upper95'] is not None:
            logs = list(map(math.log, ratios))
            upper = math.exp(statistics.mean(logs) + 1.67 * statistics.stdev(logs) / math.sqrt(len(logs)))
            assert math.isclose(upper, row['upper95'], rel_tol=1e-12)
            if upper > 1.02: failed.append(row['cell'])
        elif ratio > 1.02: failed.append(row['cell'])
    assert failed and not result['continuation_signal']
    print(name, total, 'measured operations;', len(failed), 'failed cell guards')

for cohort in load(P / 'rejected-esp-screens.json'):
    ratios = []
    for cell in cohort['analysis']['cells']:
        samples = {profile: [row['elapsed_ns'] / 1000 for boot in cohort['boots'] if boot['profile'] == profile for row in boot['clients'][cell['client']] if row['path'] == cell['path']] for profile in ['C', 'Rust']}
        assert all(len(v) == 16 for v in samples.values())
        ratio = statistics.mean(samples['Rust']) / statistics.mean(samples['C'])
        assert math.isclose(ratio, cell['latency_ratio'], rel_tol=1e-12)
        ratios.append(ratio)
    assert not (point(ratios) < 1 and max(ratios) <= 1.02)
    print(cohort['name'], 'Rust/C latency', point(ratios), 'gate failed')

with zipfile.ZipFile(P / 'loopback-raw.zip') as archive:
    assert archive.testzip() is None
    rows = [json.loads(archive.read(n)) for n in archive.namelist()]
assert len(rows) == 630
cells = {(r['window'], r['case'], r['peer']): r for r in rows}
peers, cases = sorted({r['peer'] for r in rows}), sorted({r['case'] for r in rows})
assert len(peers) == 7 and len(cases) == 18
for r in rows:
    value = r['sample']
    assert value['failed'] == value['warmup_failed'] == 0
    assert len(value['latencies_ns']) == value['completed']
assert sum(r['sample']['completed'] for r in rows) == 84000
for peer in peers:
    windows = []
    for window in range(5):
        ratios = []
        for case in cases:
            a, b = cells[window, case, peer]['sample'], cells[window, case, 'libcoap']['sample']
            ratios.append((a['completed'] / a['elapsed_ns']) / (b['completed'] / b['elapsed_ns']))
        windows.append(point(ratios))
    print(peer, 'host completion-rate/C', point(windows))
print('Portable vector and hash verification passed')
