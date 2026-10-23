"""Regrade saved receipts only; no sockets, builds, or private credentials."""
import gzip
import json
from pathlib import Path
import statistics

root = Path(__file__).resolve().parent
data = json.loads((root / 'rankings.json').read_text())
groups = {}
attempted = completed = verified = failed = invalid = warmup_failed = 0
with gzip.open(root / 'cells.jsonl.gz', 'rt', encoding='utf-8') as stream:
    for line in stream:
        record = json.loads(line)
        receipt = record['receipt']
        sample = receipt['sample']
        stratum = record['path'].split('/')[0]
        if stratum == 'matched':
            stratum = 'matched-unprotected' if sample['security'] == 'unprotected' else 'oscore'
        key = (stratum, receipt['case'], receipt['peer'])
        groups.setdefault(key, []).append(sample)
        attempted += sample['attempted']
        completed += sample['completed']
        failed += sample['failed']
        warmup_failed += sample['warmup_failed']
        verified += sample['verified_bytes']
        invalid += sample.get('driver_failures', 0)

def quantile(values, probability):
    values = sorted(values)
    point = (len(values) - 1) * probability
    lo = int(point)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (point - lo)

for row in data['rows']:
    samples = groups[(row['stratum'], row['case'], row['peer'])]
    assert len(samples) == 5
    rate = statistics.median(s['completed'] * 1e9 / s['elapsed_ns'] for s in samples)
    assert abs(rate - row['rate']) < max(1e-8, rate * 1e-12)
    latencies = [n for sample in samples for n in sample['latencies_ns']]
    assert abs(quantile(latencies, .5) / 1000 - row['p50_us']) < 1e-7
    assert abs(quantile(latencies, .99) / 1000 - row['p99_us']) < 1e-7

assert len(groups) == 522
assert attempted == completed == data['totals']['completed'] == 348000
assert verified == data['totals']['verified_bytes'] == 1040547840
assert failed == invalid == warmup_failed == 0
print('522 rankings, 2610 cells, 348000 complete operations and latency quantiles verified')
