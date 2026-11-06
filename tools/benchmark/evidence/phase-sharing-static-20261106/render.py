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
for directory,label in [('owner-overlap-20261105','Request phases + replay'),('inbox-borrow-20261105','Borrowed inbox + Option'),('inbox-flat-20261105','Borrowed inbox / flat state'),('shared-dispatch-20261106','Shared dispatch / borrowed inbox'),('replay-scan-index-20261106','Compact replay / scan index'),('replay-chunk-staging-20261106','Replay index / direct chunk initialization'),('deadline-cache-20261106','Replay deadline cache / chunk initialization'),('replay-occupancy-index-20261106','Combined occupancy / message-ID filter'),('owned-replay-reclaim-20261106','Owned reclaim / occupancy fast path'),('borrowed-reclaim-encoding-20261106','Borrowed reclaim encoding'),('short-inline-replay-20261106','Short replay128'),('replay-row-presence-20261106','Replay row presence'),('replay-shared-dispatch-20261106','Replay + shared dispatch / flat inbox'),('replay-scratch-original-inbox-20261106','Replay + shared scratch / original inbox'),('borrowed-send-chain-20261106','Replay + five borrowed send helpers'),('phase-sharing-static-20261106','Phase sharing / original replay')]:
    p=ROOT.parent/directory
    r=json.loads((p/'measurement.json').read_text()); m=json.loads((p/'memory-comparison.json').read_text())
    small=next(v for v in m['rows'] if v['owner']=='SmallDevice App')['candidate']
    experiments.append([label,f'{small:,}',pct(r['groups']['all-sync']['ratio']),pct(r['groups']['all-async']['ratio']),str(len(r['failed_point_guards']))])
history=table(['Experiment','SmallDevice App B','Sync CPU','Async CPU','Failed cells'],experiments)
status='Preservation gate passed' if passed else 'Preservation gate failed; not accepted'
css='''body{margin:0;color:var(--foreground,#171717);font-family:var(--font-sans,system-ui);font-size:14px;line-height:1.5}h2{font-size:17px;margin:22px 0 8px}p{margin:8px 0}.muted,small,th{color:var(--muted-foreground,#6b7280)}.bad{color:var(--destructive,#dc2626)}.good{color:var(--success,#16835b)}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}th,td{padding:7px;text-align:right;border-bottom:1px solid var(--border,#ddd);white-space:nowrap}th:first-child,td:first-child{text-align:left;white-space:normal}svg{width:100%;height:180px;display:block}svg text{fill:var(--foreground,#171717);font-size:12px}.grid{stroke:var(--border,#ddd)}.limit{stroke:var(--destructive,#dc2626);stroke-dasharray:4 4}.owner{display:grid;grid-template-columns:100px 1fr 95px;gap:8px;align-items:center;margin:6px 0;font-size:13px}.owner span:last-child{text-align:right}.owner i{display:block;min-width:1px;height:12px;background:var(--chart-2,#0d9488)}summary{cursor:pointer;font-weight:600;margin:18px 0 8px}code{font-family:var(--font-mono,monospace);font-size:12px}'''
document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Coaptic phase sharing comparison</title><style>{css}</style></head><body>
<p><strong class="{'good' if passed else 'bad'}">{status}.</strong> {len(result['failed_point_guards'])} workload bounds exceed +2%. All nine final qualification lanes pass; merge is recorded separately.</p>
<p class="muted">Exact native source <code>3e592ad</code> versus pinned <code>bd63199</code>. 64 process pairs per workload, 28 workloads, 3,584 timing outputs. Complete server-App thread CPU cycles in memory transport.</p>
<h2>CPU cost: lower is better</h2>{''.join(svg)}
<small>Dot = geometric mean change; segment ends at one-sided 95% upper bound. Dashed line = +2% preservation limit.</small>
<p class="muted">Largest upper bound: {html.escape(' / '.join(map(str,worst['cell'])))}.</p>{cpu}
<p>The slowest point result is retained fixed OSCORE sync: +0.851%, upper bound +1.299%. It passes the declared 2% tolerance; aggregate gains do not mean every workload gets faster.</p>
<h2>Complete memory owners</h2>{mem}
<p>Both Service progress futures shrink by 1,416 bytes (8.37%). SmallDevice future and all selected resident App/pool owners stay unchanged. Futures and pool fields are nested owners: do not add their sizes twice. Requested heap excludes allocator bookkeeping; these are not peak-RAM or reserved-stack measurements.</p>
<h2>What changed</h2><p>Blockwise dispatch borrows storage used by the collected-response body in a later phase. Five retained-send helpers borrow immutable response metadata from their callers. Resident scratch capacity is a type constant, so the shared owner stores no capacity field. A nonzero encoded body length lets the enum fit the existing storage.</p>
<p>Original replay storage, client inbox ownership and retained-chunk copying are preserved. This cohort measures the integrated lifetime changes together; no gains from separate experiments are added.</p>
<h2>32-bit static layout</h2>{mem32}
<p class="muted">Installed Thumbv7EM target, actual core types with unit transport; no device execution. All selected owners equal baseline. The untimed precursor grew both Service Apps by 8 bytes and is preserved separately.</p>
<details><summary>All 28 matched workloads</summary>{cells}<p>A failed upper bound can reflect unresolved preservation, rather than a proven regression. No trimming or replacement samples.</p></details>
<details><summary>Largest fixed-Service pool owners</summary>{bars}<p>The pool is already inside the App total. Independent packet/body capacities dominate resident storage. Preallocation bounds allocations but does not automatically share temporary owners across phases.</p></details>
<details><summary>Retained prior experiments</summary>{history}<p>Separate cohorts against the same pinned baseline. No causal subtraction, unchanged resampling or reclassification of earlier failures.</p></details>
<details><summary>Checks and tradeoffs</summary><p>926 library, 11 allocation, 27 retained-Q, 13 footprint and 5 scratch-admission tests pass at 9f2c014. Exact 3e592ad adds one rustdoc line only; byte comparison justifies test reuse. Formatting and strict all-target/all-feature Clippy pass at 3e592ad. The original missing-doc lint failure is retained. General static review found no actionable issue. All-feature testing passes 1,681 tests (one explicitly ignored idle microbenchmark); no-default, alloc, oscore and std lanes pass. Both Rust 1.89 feature checks, no-default strict lint and rustdoc pass.</p>
<p>Encoder frames remain 1,280/1,296 bytes and selected reclaim frames do not grow. Custom resident backing types now declare stable writable CAPACITY; admission checks actual readable/writable slices before entropy. Datagram-only temporary scratch is unchanged. Oversized custom scratch switches initialized variants when a body is collected; startup and custom-switch cost are unmeasured. Body release timing and the 4,096-byte collection limit are preserved.</p>
<p>Actual sync and async wait/progress use immediate-ready memory transport and a pending timer. Client preparation, authentication and verification are outside the server clock. No network throughput/latency, executor scheduling, peak memory, hardware qualification or new libcoap ranking is claimed.</p></details>
</body></html>'''
(ROOT/'comparison.html').write_text(document,encoding='utf-8')
print(ROOT/'comparison.html')
