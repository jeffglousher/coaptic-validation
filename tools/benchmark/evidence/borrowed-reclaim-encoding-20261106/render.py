"""Render only retained results; no builds or new measurements."""
from pathlib import Path
import html
import json
import math

ROOT = Path(__file__).resolve().parent
read = lambda name: json.loads((ROOT / name).read_text())
layout32 = read('layout32-comparison.json')
mem32 = ''
result, memory, owners = read('measurement.json'), read('memory-comparison.json'), read('owners.json')
passed = result['runtime_accepted']
pct = lambda r: f'{(r-1)*100:+.2f}%'

def table(headers, rows):
    return '<div class="scroll"><table><thead><tr>' + ''.join(f'<th>{html.escape(x)}</th>' for x in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{x}</td>' for x in row) + '</tr>' for row in rows) + '</tbody></table></div>'

def cpu_row(label, value):
    ok = value['upper95'] <= 1.02
    return [html.escape(label), pct(value['ratio']), pct(value['upper95']),
            f'<span class="{"good" if ok else "bad"}">{"Within 2%" if ok else "Failed bound"}</span>']

groups = result['groups']
cpu = table(['Server-App CPU cost', 'Change', '95% upper', 'Preservation'], [cpu_row(label, groups[key]) for key, label in [
    ('ordinary-sync','Ordinary / sync'),('ordinary-async','Ordinary / async'),
    ('retained-sync','Retained / sync'),('retained-async','Retained / async'),
    ('all-sync','All / sync'),('all-async','All / async')]])
cells = table(['Kind / profile / security / mode / bytes','Change','95% upper','Preservation'], [cpu_row(' / '.join(map(str,v['cell'])),v) for v in result['summary']])
mem = table(['Memory owner (bytes)','Baseline','Candidate','Change'], [[html.escape(r['owner']),f"{r['baseline']:,}",f"{r['candidate']:,}",f"{r['candidate']-r['baseline']:+,}"] for r in memory['rows']])
mem32 = table(['Thumbv7EM / bytes / unit transport','Baseline','Candidate','Change'], [[html.escape(r['owner']),f"{r['baseline']:,}",f"{r['candidate']:,}",f"{r['candidate']-r['baseline']:+,}"] for r in layout32['rows']])
worst = max(result['summary'], key=lambda x:x['upper95'])
series = [('All sync',groups['all-sync']),('All async',groups['all-async']),('Largest upper bound',worst)]
lo = min(-2,math.floor(min(v['ratio'] for _,v in series)*100-100)-1)
hi = max(3,math.ceil(worst['upper95']*100-100)+1)
x = lambda r: 190 + ((r-1)*100-lo)*500/(hi-lo)
svg = ['<svg viewBox="0 0 720 180" role="img" aria-label="CPU point changes and one-sided upper bounds; lower is better">']
for tick in range(lo,hi+1):
    xx=x(1+tick/100)
    svg.append(f'<path d="M{xx} 10v130" class="grid"/><text x="{xx}" y="164" text-anchor="middle">{tick:+}%</text>')
svg.append(f'<path d="M{x(1.02)} 10v130" class="limit"/>')
for i,(label,v) in enumerate(series):
    y=35+43*i
    color='var(--destructive,#dc2626)' if v['upper95']>1.02 else 'var(--chart-1,#2563eb)'
    svg.append(f'<text x="0" y="{y+5}">{label}</text><path d="M{x(v["ratio"])} {y}H{x(v["upper95"])}" stroke="{color}" stroke-width="3"/><circle cx="{x(v["ratio"])}" cy="{y}" r="5" fill="{color}"/><path d="M{x(v["upper95"])} {y-6}v12" stroke="{color}" stroke-width="2"/>')
svg.append('</svg>')
pool=next(o for o in owners if o['type'].startswith('coaptic::storage::Memory<coaptic::profiles::Service,') and any(f['name']=='.bodies' for f in o['fields']))
bars=''
maximum=max(f['bytes'] for f in pool['fields'])
for f in sorted(pool['fields'],key=lambda f:-f['bytes']):
    bars+=f'<div class="owner"><span>{html.escape(f["name"].lstrip("."))}</span><div><i style="width:{f["bytes"]*100/maximum:.4f}%"></i></div><span>{f["bytes"]:,} B</span></div>'
experiments=[]
for directory,label in [('owner-overlap-20261105','Request phases + replay'),('inbox-borrow-20261105','Borrowed inbox + Option'),('inbox-flat-20261105','Borrowed inbox / flat state'),('shared-dispatch-20261106','Shared dispatch / borrowed inbox'),('replay-scan-index-20261106','Compact replay / scan index'),('replay-chunk-staging-20261106','Replay index / direct chunk initialization'),('deadline-cache-20261106','Replay deadline cache / chunk initialization'),('replay-occupancy-index-20261106','Combined occupancy / message-ID filter'),('owned-replay-reclaim-20261106','Owned reclaim / occupancy fast path'),('borrowed-reclaim-encoding-20261106','Borrowed reclaim encoding')]:
    p=ROOT.parent/directory
    r=json.loads((p/'measurement.json').read_text()); m=json.loads((p/'memory-comparison.json').read_text())
    small=next(v for v in m['rows'] if v['owner']=='SmallDevice App')['candidate']
    experiments.append([label,f'{small:,}',pct(r['groups']['all-sync']['ratio']),pct(r['groups']['all-async']['ratio']),str(len(r['failed_point_guards']))])
history=table(['Experiment','SmallDevice App B','Sync CPU','Async CPU','Failed cells'],experiments)
status='Preservation gate passed' if passed else 'Preservation gate failed; not accepted'
css='''body{margin:0;color:var(--foreground,#171717);font-family:var(--font-sans,system-ui);font-size:14px;line-height:1.5}h2{font-size:17px;margin:22px 0 8px}p{margin:8px 0}.muted,small,th{color:var(--muted-foreground,#6b7280)}.bad{color:var(--destructive,#dc2626)}.good{color:var(--success,#16835b)}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}th,td{padding:7px;text-align:right;border-bottom:1px solid var(--border,#ddd);white-space:nowrap}th:first-child,td:first-child{text-align:left;white-space:normal}svg{width:100%;height:180px;display:block}svg text{fill:var(--foreground,#171717);font-size:12px}.grid{stroke:var(--border,#ddd)}.limit{stroke:var(--destructive,#dc2626);stroke-dasharray:4 4}.owner{display:grid;grid-template-columns:100px 1fr 95px;gap:8px;align-items:center;margin:6px 0;font-size:13px}.owner span:last-child{text-align:right}.owner i{display:block;min-width:1px;height:12px;background:var(--chart-2,#0d9488)}summary{cursor:pointer;font-weight:600;margin:18px 0 8px}code{font-family:var(--font-mono,monospace);font-size:12px}'''
document=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Coaptic borrowed reclaim encoding comparison</title><style>{css}</style></head><body>
<p><strong class="{'good' if passed else 'bad'}">{status}.</strong> {len(result['failed_point_guards'])} workload bounds exceed +2%. Configured capacities are unchanged.</p>
<p class="muted">Pinned baseline <code>bd63199</code> to candidate <code>40e195a</code>. 64 process pairs per cell, 28 workloads, 3,584 timing outputs. Complete server-App thread CPU cycles in memory transport.</p>
<h2>CPU cost: lower is better</h2>{''.join(svg)}
<small>Dot = geometric mean change; segment ends at the one-sided 95% upper bound. Dashed line = +2% preservation limit.</small>
<p class="muted">Largest upper bound: {html.escape(' / '.join(map(str,worst['cell'])))}.</p>{cpu}
<p>The owned reclaim operation removes repeated key searches without adding resident metadata. Memory savings below come from the integrated compact replay and occupancy representation.</p><h2>64-bit host memory: exact owners</h2>{mem}
<p>Full retained chunks now initialize their staging array directly, bypassing the previous 1 KiB clear. Partial chunks retain initialization and every range check. The selected encoder frames match baseline; the inspected encoder instruction sizes are retained in diagnostics.</p><p>Compact replay owners save 16 bytes per row. Occupancy and message-ID filtering share a four-byte state, adding three bytes per slot over the original boolean occupancy. This removes the separate deadline cache. Net row reduction: 13 bytes, before whole-object padding. The unused allocated pin-vector header is also removed.</p>
<p class="muted">The original startup allocation count is preserved; there is no separate deadline-cache allocation. Requested heap excludes allocator bookkeeping and rounding. Future sizes are compiler objects, not peak stack. Do not add nested pool owners twice.</p>
<h2>Selected reclaim frames</h2><table><thead><tr><th>Compiler frame / bytes</th><th>Baseline</th><th>Candidate</th><th>Change</th></tr></thead><tbody><tr><td>SmallDevice</td><td>800</td><td>544</td><td>-256</td></tr><tr><td>Constrained with bodies</td><td>800</td><td>544</td><td>-256</td></tr><tr><td>Service fixed</td><td>784</td><td>544</td><td>-240</td></tr><tr><td>Service allocated</td><td>800</td><td>544</td><td>-256</td></tr></tbody></table><p>Encoding now fills a borrowed 16-byte buffer and returns only its length. Storage constructs the replay row. This removes the preceding candidate's extra 304-byte row-return copy. These selected compiler reservations do not establish peak stack.</p><h2>32-bit layout audit: smaller owners</h2>{mem32}<p>The replay owner shrinks eight bytes on this target while combined occupancy adds three bytes per slot. Whole-object alignment is included in these actual compiler sizes. The allocated App header also shrinks.</p><p class="muted">Installed Thumbv7EM target, actual core types, unit transport. Static sizes only; no device execution or new platform integration. Absolute sizes are not comparable to the transport-inclusive host table.</p><h2>Fixed Service pool owners</h2>{bars}
<p class="muted">{pool['bytes']:,} B total, already inside the fixed App. Most storage pays for independent body and packet capacities; preallocation makes it predictable but does not automatically remove overlapping temporary copies.</p>
<details><summary>All 28 matched workload results</summary>{cells}<p>A failed upper bound can mean unresolved preservation; it is not necessarily a proven regression. No trimming or sample replacement.</p></details>
<details><summary>Preserved experiments against the same pinned source</summary>{history}<p>Separate cohorts, not direct head-to-head comparisons. The first uses 16 pairs; subsequent cohorts use 64. Earlier failures retain their original decisions.</p></details>
<details><summary>Checks, review and limits</summary><p>Exact candidate passes 930 library tests, 11 allocation/failure-injection tests, 27 retained-Q regressions, 13 footprint checks and formatting. General read-only review found no actionable issue in cache coherence, duplicate keys, TX release order, acquired-empty slots or full-width/reversed clocks.</p><p>The preceding owned-reclaim integration failed three fixed-Service 16 KiB CPU bounds and grew its fixed reclaim frame by 32 bytes. Its full-row return boundary introduced an extra emitted 304-byte copy. This candidate replaces that boundary with borrowed encoding and checked length, while retaining the search reduction and immediate-free-cursor acquisition.</p><p>930 library, 11 allocation, 27 retained-transfer and 13 footprint tests pass. General review found no issue. A dedicated regression checks callback invocation count and release-before-encoding; models cover refusal, excessive lengths, zero-length replay, duplicates, failed TX release and slot rotation. One fresh cohort, no replacement samples.</p><p>Sync and actual async progress use immediate-ready memory transport and a pending timer. Client preparation/authentication and verification are outside the server interval. This is not network latency, maximum throughput, peak device RAM or a new libcoap ranking. Baseline layout is an incomplete prefix with complete selected future records; candidate capture is complete.</p></details>
</body></html>'''
(ROOT/'comparison.html').write_text(document,encoding='utf-8')
print(ROOT/'comparison.html')
