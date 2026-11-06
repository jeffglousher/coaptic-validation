"""Render the retained comparison, without executing or resampling probes."""
from pathlib import Path
import html
import json

ROOT = Path(__file__).resolve().parent
result = json.loads((ROOT / "measurement.json").read_text())
memory = json.loads((ROOT / "memory-comparison.json").read_text())
owners = json.loads((ROOT / "owners.json").read_text())


def pct(ratio):
    return f"{(ratio - 1) * 100:+.2f}%"


def row(label, value):
    failed = value["upper95"] > 1.02
    return (f'<tr><td>{html.escape(label)}</td><td>{pct(value["ratio"])}</td>'
            f'<td>{pct(value["upper95"])}</td><td class="{"bad" if failed else "good"}">'
            f'{"Unresolved" if failed else "Within 2%"}</td></tr>')


def table(headings, rows):
    return '<div class="scroll"><table><thead><tr>' + ''.join(
        f'<th>{html.escape(h)}</th>' for h in headings
    ) + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'


groups = result["groups"]
cpu = table(["Complete-App workload", "CPU change", "95% upper bound", "Preservation"], [
    row(label, groups[key]) for key, label in [
        ("ordinary-sync", "Ordinary · sync"), ("ordinary-async", "Ordinary · async"),
        ("retained-sync", "Retained · sync"), ("retained-async", "Retained · async"),
        ("all-sync", "All cells · sync"), ("all-async", "All cells · async")]])
cells = table(["Workload / profile / security / mode / bytes", "CPU change", "95% upper", "Preservation"], [
    row(' / '.join(map(str, value["cell"])), value) for value in result["summary"]])
mem = table(["Memory owner (bytes)", "Baseline", "Candidate", "Change"], [
    f'<tr><td>{html.escape(r["owner"])}</td><td>{r["baseline"]:,}</td>'
    f'<td>{r["candidate"]:,}</td><td>{r["candidate"]-r["baseline"]:+,}</td></tr>'
    for r in memory["rows"]])

# The line is point-to-upper-bound, not a two-sided confidence interval.
chart_values = [("All sync", groups["all-sync"]), ("All async", groups["all-async"]),
                ("Small protected async", next(v for v in result["summary"]
                 if v["cell"] == ["ordinary", "small-device", "oscore", "async", 32]))]
def x(r):
    return 220 + ((r - 1) * 100 + 3) * 60
svg = ['<svg viewBox="0 0 720 195" role="img" aria-label="CPU change and one-sided upper bounds, lower is better">']
for tick in [-3, -2, -1, 0, 1, 2, 3, 4, 5]:
    xx = x(1 + tick / 100)
    svg.append(f'<line x1="{xx}" x2="{xx}" y1="20" y2="153" class="grid"/>'
               f'<text x="{xx}" y="178" text-anchor="middle">{tick:+}%</text>')
svg.append(f'<line x1="{x(1.02)}" x2="{x(1.02)}" y1="20" y2="153" class="limit"/>')
for i, (label, value) in enumerate(chart_values):
    y = 44 + i * 44
    color = 'var(--destructive)' if value['upper95'] > 1.02 else 'var(--chart-1)'
    svg.append(f'<text x="0" y="{y+5}">{label}</text><line x1="{x(value["ratio"])}" '
               f'x2="{x(value["upper95"])}" y1="{y}" y2="{y}" stroke="{color}" stroke-width="3"/>'
               f'<circle cx="{x(value["ratio"])}" cy="{y}" r="5" fill="{color}"/>'
               f'<path d="M{x(value["upper95"])} {y-6}v12" stroke="{color}" stroke-width="2"/>')
svg.append('</svg>')

pool = next(o for o in owners if o['type'].startswith('coaptic::storage::Memory<coaptic::profiles::Service,')
            and o['bytes'] == 279624)
bars = ''
for field in sorted(pool['fields'], key=lambda f: -f['bytes']):
    bars += (f'<div class="owner"><span>{html.escape(field["name"].lstrip("."))}</span>'
             f'<div><i style="width:{100*field["bytes"]/136688:.4f}%"></i></div>'
             f'<b>{field["bytes"]:,} B</b></div>')

document = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Coaptic owner-overlap evidence</title>
<style>body{margin:0;color:var(--foreground);font-family:var(--font-sans);font-size:14px;line-height:1.5}
h2{font-size:17px;margin:22px 0 8px}p{margin:8px 0}.muted,small{color:var(--muted-foreground)}
.bad{color:var(--destructive)}.good{color:var(--success)}.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
td,th{padding:7px 8px;text-align:right;border-bottom:1px solid var(--border);white-space:nowrap}
td:first-child,th:first-child{text-align:left;white-space:normal}th{font-weight:600;color:var(--muted-foreground)}
svg{width:100%;height:195px;display:block}svg text{fill:var(--foreground);font-size:13px}
.grid{stroke:var(--border);stroke-width:1}.limit{stroke:var(--destructive);stroke-dasharray:4 4}
.owner{display:grid;grid-template-columns:75px 1fr 95px;gap:10px;align-items:center;margin:7px 0;font-size:13px}
.owner i{display:block;min-width:1px;height:12px;background:var(--chart-2)}.owner b{text-align:right;font-weight:400}
summary{cursor:pointer;font-weight:600;margin:16px 0 8px}code{font-family:var(--font-mono);font-size:12px}
</style></head><body>
<p><strong class="bad">Experimental — not accepted or merged.</strong> Memory shrinks and aggregate CPU improves,
but six of 28 workload upper bounds exceed the prospective +2% preservation limit.</p>
<p class="muted">Pinned baseline <code>bd63199</code> → integrated candidate <code>cc8e20a</code>.
Same capacities; 16 process pairs per cell. Server-App thread cycles, not network latency.</p>
<h2>CPU cost: lower is better</h2>''' + ''.join(svg) + '''
<small>Dot = geometric mean change; segment ends at one-sided 95% upper bound.
Dashed line = +2% limit. A small aggregate gain does not clear a failing cell.</small>''' + cpu + '''
<h2>Memory: exact owner sizes</h2>''' + mem + '''
<p class="muted">App and pool/future rows are different owners or views; do not sum overlapping storage.
Futures are compiler object sizes, not peak stack. Baseline diagnostic prefix is incomplete;
the three selected records are complete and verified. Candidate capture is complete.</p>
<h2>Where fixed Service pool memory goes</h2>''' + bars + '''
<p class="muted">279,624 B total, nested inside the 314,632 B App. Body pools alone use 136,688 B.
These configured capacities were preserved, not reduced to obtain savings.</p>
<details><summary>All 28 matched workload results — including six failed bounds</summary>''' + cells + '''
<p>“Unresolved” means the upper bound exceeds +2%; it does not establish a regression in every case.
SmallDevice protected async has an adverse point estimate of +2.68%.</p></details>
<details><summary>Remaining copies, checks and limitations</summary>
<p>RX packets are still copied into dispatch scratch; protected dispatch writes plaintext back to RX.
The scratch remains live across child sends because parsed views borrow it while Engine is mutated.
Blockwise response collection separately copies into a 4,098 B App hold before releasing the body slot.</p>
<p>Preallocation guarantees bounded capacity. It does not automatically overlay independent scratch or
eliminate future captures. The next target is safe RX borrowing with split Engine access; a response
hold replacement must preserve release timing and capacity.</p>
<p>924 alloc+oscore library tests passed; general independent source review found no actionable defect.
The offline verifier reproduces the failed decision from 896 timing outputs and checks 1,916 archived
members. No unchanged resampling, no changed acceptance rule, no fresh device or libcoap ranking.</p>
</details></body></html>'''
(ROOT / 'comparison.html').write_text(document, encoding='utf-8')
print(ROOT / 'comparison.html')
