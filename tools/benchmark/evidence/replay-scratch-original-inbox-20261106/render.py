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
for directory,label in [('owner-overlap-20261105','Request phases + replay'),('inbox-borrow-20261105','Borrowed inbox + Option'),('inbox-flat-20261105','Borrowed inbox / flat state'),('shared-dispatch-20261106','Shared dispatch / borrowed inbox'),('replay-scan-index-20261106','Compact replay / scan index'),('replay-chunk-staging-20261106','Replay index / direct chunk initialization'),('deadline-cache-20261106','Replay deadline cache / chunk initialization'),('replay-occupancy-index-20261106','Combined occupancy / message-ID filter'),('owned-replay-reclaim-20261106','Owned reclaim / occupancy fast path'),('borrowed-reclaim-encoding-20261106','Borrowed reclaim encoding'),('short-inline-replay-20261106','Short replay128'),('replay-row-presence-20261106','Replay row presence'),('replay-scratch-original-inbox-20261106','Replay + shared scratch / original inbox')]:
    p=ROOT.parent/directory
    r=json.loads((p/'measurement.json').read_text()); m=json.loads((p/'memory-comparison.json').read_text())
    small=next(v for v in m['rows'] if v['owner']=='SmallDevice App')['candidate']
    experiments.append([label,f'{small:,}',pct(r['groups']['all-sync']['ratio']),pct(r['groups']['all-async']['ratio']),str(len(r['failed_point_guards']))])
history=table(['Experiment','SmallDevice App B','Sync CPU','Async CPU','Failed cells'],experiments)
status='Preservation gate passed' if passed else 'Preservation gate failed; not accepted'
css='''body{margin:0;color:var(--foreground,#171717);font-family:var(--font-sans,system-ui);font-size:14px;line-height:1.5}h2{font-size:17px;margin:22px 0 8px}p{margin:8px 0}.muted,small,th{color:var(--muted-foreground,#6b7280)}.bad{color:var(--destructive,#dc2626)}.good{color:var(--success,#16835b)}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}th,td{padding:7px;text-align:right;border-bottom:1px solid var(--border,#ddd);white-space:nowrap}th:first-child,td:first-child{text-align:left;white-space:normal}svg{width:100%;height:180px;display:block}svg text{fill:var(--foreground,#171717);font-size:12px}.grid{stroke:var(--border,#ddd)}.limit{stroke:var(--destructive,#dc2626);stroke-dasharray:4 4}.owner{display:grid;grid-template-columns:100px 1fr 95px;gap:8px;align-items:center;margin:6px 0;font-size:13px}.owner span:last-child{text-align:right}.owner i{display:block;min-width:1px;height:12px;background:var(--chart-2,#0d9488)}summary{cursor:pointer;font-weight:600;margin:18px 0 8px}code{font-family:var(--font-mono,monospace);font-size:12px}'''
document = f'''<!doctype html><html><head><meta charset="utf-8"><title>Replay and shared scratch with original inbox</title><style>{css}</style></head><body>
<p><strong>{'Runtime preservation passed; qualification and merge are separate' if passed else 'Rejected: runtime preservation not established'}</strong></p>
<p>Exact native source <code>ecf1747</code> versus pinned <code>bd63199</code>. Complete server-App thread CPU cycles,64 paired processes per workload,28 matched workloads. Lower is better.</p>
{''.join(svg)}<p class="muted">Dots: geometric mean change. Lines: one-sided95% upper bound. Dashed line: +2% preservation limit. All28 cell bounds and ordinary/all sync/async aggregates must pass. No trimming or replacement.</p>
{cpu}
<h2>Complete memory owners</h2>{mem}
<p>Host SmallDevice saves56 bytes; fixed Service saves816; allocated Service saves8 inline plus832 requested pool bytes. Both Service progress futures shrink1,416 bytes; SmallDevice's future is unchanged. Nested fields are already included in their owners. These are object/compiler sizes and requested heap, not peak RAM or reserved task stacks.</p>
<h2>What changed</h2><p>Blockwise dispatch borrows the existing collected-body backing. Datagram-only dispatch keeps its temporary owner. The original owned client inbox is restored; independent inbox metadata borrowing is excluded. Replay uses compact exclusive ownership, a short128-byte writer, reduced key-search work and direct row-presence checks. Full retained chunks initialize directly from the body. The final integration is measured together; gains from earlier cohorts are not added.</p>
<h2>32-bit static layout</h2>{mem32}<p>Installed Thumbv7EM target, actual App types with unit transport; no device execution or new platform claim. Capacities are unchanged.</p>
<details><summary>All28 workload comparisons</summary>{cells}</details>
<details><summary>Largest fixed-Service pool owners</summary>{bars}<p>The pool is already inside the App total. Independent body and packet capacities dominate; preallocation alone does not make temporary copies share storage.</p></details>
<details><summary>Retained prior failures</summary>{history}<p>Separate cohorts against the same pinned source. No causal subtraction or unchanged resampling. Previous failed integrations remain failed, including row-presence8fc41ea and scratch90e3ef9.</p></details>
<details><summary>Checks and tradeoffs</summary><p>933 library,11 allocation,27 retained-Q,13 footprint and4 scratch-admission checks pass. Exact ecf1747 passes formatting and strict all-features lint. General integration review found no actionable issue; prior replay review remains valid.</p><p>Selected encoder frames remain1,280/1,296 bytes. Reclaim frames are544 versus baseline784–800. Short replay writes128 payload bytes plus metadata; full256-byte capacity remains. Its helper reserves8 bytes and all eight inspected caller reservations match or shrink. This is not peak-stack evidence.</p><p>The shared owner adds metadata included in App totals. Large custom scratch switches initialized variants when collecting bodies; startup and those custom switch costs are outside this steady-state cohort. Body-slot release timing and4,096-byte collection capacity are preserved. Custom implementations select ResidentRxScratch separately from temporary scratch so temporary Rc markers do not restrict App Send/Sync. Compact replay equality/hash excludes discarded inactive bytes.</p><p>Sync and actual async wait/progress use immediate-ready memory transport and a pending timer. Client preparation, authentication and verification are outside the server clock. No socket latency, maximum throughput, executor scheduling, peak device memory or new libcoap ranking is claimed.</p></details>
</body></html>'''
(ROOT/'comparison.html').write_text(document,encoding='utf-8')
print(ROOT/'comparison.html')
