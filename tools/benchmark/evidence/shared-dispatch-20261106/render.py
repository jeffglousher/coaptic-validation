"""Render only retained results; no builds or new measurements."""
from pathlib import Path
import html
import json
import math

ROOT = Path(__file__).resolve().parent
read = lambda name: json.loads((ROOT / name).read_text())
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
for directory,label in [('owner-overlap-20261105','Request phases + replay'),('inbox-borrow-20261105','Borrowed inbox + Option'),('inbox-flat-20261105','Borrowed inbox / flat state'),('shared-dispatch-20261106','Shared dispatch / borrowed inbox')]:
    p=ROOT.parent/directory
    r=json.loads((p/'measurement.json').read_text()); m=json.loads((p/'memory-comparison.json').read_text())
    small=next(v for v in m['rows'] if v['owner']=='SmallDevice App')['candidate']
    experiments.append([label,f'{small:,}',pct(r['groups']['all-sync']['ratio']),pct(r['groups']['all-async']['ratio']),str(len(r['failed_point_guards']))])
history=table(['Experiment','SmallDevice App B','Sync CPU','Async CPU','Failed cells'],experiments)
status='Preservation gate passed' if passed else 'Preservation gate failed; not accepted'
css='''body{margin:0;color:var(--foreground,#171717);font-family:var(--font-sans,system-ui);font-size:14px;line-height:1.5}h2{font-size:17px;margin:22px 0 8px}p{margin:8px 0}.muted,small,th{color:var(--muted-foreground,#6b7280)}.bad{color:var(--destructive,#dc2626)}.good{color:var(--success,#16835b)}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}th,td{padding:7px;text-align:right;border-bottom:1px solid var(--border,#ddd);white-space:nowrap}th:first-child,td:first-child{text-align:left;white-space:normal}svg{width:100%;height:180px;display:block}svg text{fill:var(--foreground,#171717);font-size:12px}.grid{stroke:var(--border,#ddd)}.limit{stroke:var(--destructive,#dc2626);stroke-dasharray:4 4}.owner{display:grid;grid-template-columns:100px 1fr 95px;gap:8px;align-items:center;margin:6px 0;font-size:13px}.owner span:last-child{text-align:right}.owner i{display:block;min-width:1px;height:12px;background:var(--chart-2,#0d9488)}summary{cursor:pointer;font-weight:600;margin:18px 0 8px}code{font-family:var(--font-mono,monospace);font-size:12px}'''
document=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Coaptic shared dispatch comparison</title><style>{css}</style></head><body>
<p><strong class="{'good' if passed else 'bad'}">{status}.</strong> {len(result['failed_point_guards'])} workload bounds exceed +2%. Same configured capacities; the inbox hold is removed. Memory savings do not override an adverse CPU bound.</p>
<p class="bad">Source review also found a custom-profile Send/Sync regression. Its separate correctness repair is retained but has no runtime result.</p>
<p class="muted">Pinned baseline <code>bd63199</code> to candidate <code>90e3ef9</code>. 64 process pairs per cell, 28 workloads, 3,584 timing outputs. Complete server-App thread CPU cycles in memory transport.</p>
<h2>CPU cost: lower is better</h2>{''.join(svg)}
<small>Dot = geometric mean change; segment ends at the one-sided 95% upper bound. Dashed line = +2% preservation limit.</small>
<p class="muted">Largest upper bound: {html.escape(' / '.join(map(str,worst['cell'])))}.</p>{cpu}
<h2>Memory: exact owner sizes</h2>{mem}
<p class="muted">Future sizes are compiler objects, not measured peak stack. Do not sum App and nested pool views. Baseline layout capture is an incomplete prefix with the three selected records complete; candidate capture is complete.</p>
<h2>Fixed Service pool owners</h2>{bars}
<p class="muted">{pool['bytes']:,} B total, already inside the fixed App. Pools keep their original capacities. Borrowing removes duplicate metadata; it does not remove the body pools.</p>
<details><summary>All 28 matched workload results</summary>{cells}<p>A failed upper bound can mean unresolved preservation; it is not necessarily a proven regression. No trimming or sample replacement.</p></details>
<details><summary>Preserved experiments against the same pinned source</summary>{history}<p>Separate cohorts, not direct head-to-head comparisons. The first uses 16 pairs, the inbox experiments 64. Earlier failures retain their original decisions.</p></details>
<details><summary>Scope, checks and remaining copies</summary><p>926 library tests, 13 footprint checks and 2 admission checks pass. General review found a custom-profile Send/Sync regression; a separately retained correction passes added regressions but has no runtime result. The offline verifier checks source/fixture and observation hashes, capacities, exact owner changes, selected future sizes and every runtime bound.</p><p>Sync and actual async progress are exercised with immediate-ready memory transport and a pending timer. Client preparation/authentication and verification are outside the measured server interval. This is not network latency, maximum throughput, peak device RAM or a new libcoap ranking.</p><p>Blockwise dispatch reuses collected-body backing. Datagram-only scratch stays on demand. Packet copying and protected plaintext writeback remain. Large custom scratch changes owner variants when collecting a body; startup and collection costs are not measured here.</p></details>
</body></html>'''
(ROOT/'comparison.html').write_text(document,encoding='utf-8')
print(ROOT/'comparison.html')
