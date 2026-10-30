"""Bounded offline stack profiles. No capture or qualification is performed.

Schema coaptic-stack-profile/1: identity strings identify immutable source, tool,
workload, capture, platform and cohort; scope identifies one PID and optional TID.
Each stack has root-to-leaf full symbols, positive weight and sample count. Optional
`event` preserves comm, decimal-second timestamp, period, event name, root-to-leaf
addresses and DSOs. Events must consistently be cpu-clock periods or
Windows SampledProfile samples (period 1), with sampled_cpu measurement metadata.
Unknown loss/unresolved/refused counts are null. Totals are observed denominators,
not estimates of missing data. A profile cannot mix scopes or measurements.

CLI: render INPUT OUTPUT; perf INPUT OUTPUT --identity IDENTITY.json --scope LABEL.
perf produces canonical JSON, render produces standalone interactive HTML. Outputs
must not already exist. The perf importer accepts only the documented cpu-clock
sample and PERF_RECORD_COMM records, refusing all other input.
"""
import argparse
import json
import math
import re
from pathlib import Path

LIMIT = 16 * 1024 * 1024
MAX_NUMBER = 2**53 - 1
MAX_STACKS = 100_000
MAX_TEXT = 4096
SCHEMA = 'coaptic-stack-profile/1'


def _keys(obj, required, optional=()):
    if not isinstance(obj, dict) or set(obj) - set(required) - set(optional) or set(required) - set(obj):
        raise ValueError('unexpected or missing fields')


def _text(value):
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT or any(ord(c) < 32 for c in value):
        raise ValueError('invalid text')
    try: value.encode('utf-8')
    except UnicodeEncodeError as exc: raise ValueError('invalid Unicode text') from exc
    return value


def _count(value, *, nullable=False, positive=False):
    if nullable and value is None:
        return
    if type(value) is not int or value < int(positive) or value > MAX_NUMBER:
        raise ValueError('invalid count')


def _weight(value):
    if type(value) not in (int, float) or value <= 0 or value > MAX_NUMBER or not math.isfinite(value):
        raise ValueError('invalid weight')


def validate_profile(p):
    """Validate a single profile; return it unchanged or raise ValueError."""
    _keys(p, ('schema', 'identity', 'measurement', 'quality', 'scope', 'totals', 'stacks'))
    if p['schema'] != SCHEMA:
        raise ValueError('unsupported schema')
    _keys(p['identity'], ('source', 'tool', 'workload', 'capture', 'platform', 'cohort'))
    for x in p['identity'].values(): _text(x)
    _keys(p['measurement'], ('kind', 'unit'))
    if p['measurement']['kind'] not in ('sampled_cpu', 'elapsed_wall'): raise ValueError('unknown measurement kind')
    _text(p['measurement']['unit'])
    _keys(p['quality'], ('lost', 'unresolved', 'refused', 'notes'))
    for k in ('lost', 'unresolved', 'refused'): _count(p['quality'][k], nullable=True)
    _text(p['quality']['notes'])
    _keys(p['scope'], ('pid', 'tid', 'label', 'cpu_mode'))
    _count(p['scope']['pid']); _count(p['scope']['tid'], nullable=True)
    _text(p['scope']['label'])
    if p['scope']['cpu_mode'] not in ('unknown', 'user', 'kernel', 'mixed'): raise ValueError('invalid CPU mode')
    _keys(p['totals'], ('samples', 'weight'))
    _count(p['totals']['samples'], positive=True); _weight(p['totals']['weight'])
    stacks = p['stacks']
    if not isinstance(stacks, list) or not 1 <= len(stacks) <= MAX_STACKS: raise ValueError('invalid stack count')
    weights = []
    count = 0
    frame_count = 0
    text_bytes = 0
    event_name = None
    for s in stacks:
        _keys(s, ('frames', 'weight', 'samples'), ('event',))
        if not isinstance(s['frames'], list) or not 1 <= len(s['frames']) <= 128: raise ValueError('invalid stack depth')
        frame_count += len(s['frames'])
        if frame_count > 200_000: raise ValueError('too many frames')
        for f in s['frames']:
            _text(f)
            text_bytes += len(f.encode('utf-8'))
            if text_bytes > LIMIT: raise ValueError('frame text too large')
        _weight(s['weight']); _count(s['samples'], positive=True)
        count += s['samples']; weights.append(s['weight'])
        if 'event' in s:
            e = s['event']; _keys(e, ('comm', 'timestamp', 'period', 'name', 'addresses', 'dsos'))
            for k in ('comm', 'timestamp', 'name'): _text(e[k])
            unit = {'cpu-clock': 'cpu-clock period', 'SampledProfile': 'samples'}.get(e['name'])
            if (unit is None or p['measurement'] != {'kind': 'sampled_cpu', 'unit': unit}
                    or (event_name is not None and e['name'] != event_name)):
                raise ValueError('inconsistent event measurement')
            event_name = e['name']
            if not re.fullmatch(r'\d+\.\d+', e['timestamp']): raise ValueError('invalid timestamp')
            _count(e['period'], positive=True)
            if e['name'] == 'SampledProfile' and e['period'] != 1:
                raise ValueError('invalid SampledProfile period')
            for k in ('addresses', 'dsos'):
                if not isinstance(e[k], list) or len(e[k]) != len(s['frames']): raise ValueError('invalid frame metadata')
                for v in e[k]: _text(v)
            if any(not re.fullmatch(r'[0-9a-fA-F]+', a) for a in e['addresses']): raise ValueError('invalid address')
            if s['samples'] != 1 or s['weight'] != e['period']: raise ValueError('inconsistent perf event')
    if count != p['totals']['samples'] or math.fsum(weights) != p['totals']['weight'] or count > MAX_NUMBER:
        raise ValueError('inconsistent totals')
    return p


def aggregate(p):
    """Return per-symbol self and inclusive weights; recursive symbols count once per stack."""
    validate_profile(p)
    table = {}
    for s in p['stacks']:
        for f in set(s['frames']):
            row = table.setdefault(f, [[], []]); row[1].append(s['weight'])
        table[s['frames'][-1]][0].append(s['weight'])
    return {f: {'self': math.fsum(v[0]), 'inclusive': math.fsum(v[1])} for f, v in table.items()}


HEADER = re.compile(r'^\s*(\S+)\s+(\d+)/(\d+)\s+(\d+\.\d+):\s+(\d+)\s+(cpu-clock):\s*$')
COMM = re.compile(r'^\s*\S+\s+\d+/\d+\s+\d+\.\d+:\s+PERF_RECORD_COMM:\s+\S+:\d+/\d+\s*$')
FRAME = re.compile(r'^\t\s*([0-9a-fA-F]+)\s+(.+) \(([^()]*)\)\s*$')


def parse_perf_script(text, identity, scope_label):
    """Parse one PID/TID cpu-clock perf script. Reject unknown records and empty stacks."""
    if not isinstance(text, str) or len(text.encode('utf-8')) > LIMIT: raise ValueError('input too large')
    if text and not text.endswith('\n'): raise ValueError('truncated final line')
    stacks = []; current = None; scope = None
    def finish():
        if current is None: return
        if not current['frames']: raise ValueError('sample without frames')
        for key in ('frames',): current[key].reverse()
        current['event']['addresses'].reverse(); current['event']['dsos'].reverse()
        stacks.append(current)
    for line in text.splitlines():
        if not line.strip():
            finish(); current = None; continue
        if line.startswith('\t'):
            m = FRAME.fullmatch(line)
            if current is None or not m: raise ValueError('malformed frame')
            addr, symbol, dso = m.groups(); _text(symbol); _text(dso)
            current['frames'].append(symbol); current['event']['addresses'].append(addr); current['event']['dsos'].append(dso)
            if len(current['frames']) > 128: raise ValueError('stack too deep')
            continue
        finish(); current = None
        if COMM.fullmatch(line): continue
        m = HEADER.fullmatch(line)
        if not m: raise ValueError('unknown perf record')
        comm, pid, tid, stamp, period, name = m.groups(); pair = (int(pid), int(tid))
        if scope is not None and pair != scope: raise ValueError('mixed PID/thread scope')
        scope = pair; period = int(period)
        current = {'frames': [], 'weight': period, 'samples': 1, 'event': {'comm': comm, 'timestamp': stamp, 'period': period, 'name': name, 'addresses': [], 'dsos': []}}
        if len(stacks) >= MAX_STACKS: raise ValueError('too many stacks')
    finish()
    if not stacks: raise ValueError('no samples')
    p = {'schema': SCHEMA, 'identity': identity, 'measurement': {'kind': 'sampled_cpu', 'unit': 'cpu-clock period'},
         'quality': {'lost': None, 'unresolved': None, 'refused': None, 'notes': 'perf text alone does not establish loss or CPU mode completeness.'},
         'scope': {'pid': scope[0], 'tid': scope[1], 'label': scope_label, 'cpu_mode': 'unknown'},
         'totals': {'samples': len(stacks), 'weight': math.fsum(s['weight'] for s in stacks)}, 'stacks': stacks}
    return validate_profile(p)


def parse_json(text):
    if len(text.encode('utf-8')) > LIMIT: raise ValueError('input too large')
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d: raise ValueError('duplicate JSON field')
            d[k] = v
        return d
    return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def load_json(text):
    return validate_profile(parse_json(text))


def _script_json(obj):
    return json.dumps(obj, ensure_ascii=True, separators=(',', ':'), allow_nan=False).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')


def _flame_tree(p):
    """Build a validated profile's call tree with the same fsum weights as the table.

    Sum original stack weights at each prefix: summing rounded child totals or
    adding weights in JavaScript can lose valid fractional observations.
    """
    root = {'name': 'All observed', 'weights': [], 'children': {}}
    for s in p['stacks']:
        n = root
        n['weights'].append(s['weight'])
        for f in s['frames']:
            n = n['children'].setdefault(f, {'name': f, 'weights': [], 'children': {}})
            n['weights'].append(s['weight'])
    pending = [root]
    while pending:
        n = pending.pop()
        n['weight'] = math.fsum(n.pop('weights'))
        n['children'] = list(n['children'].values())
        pending.extend(n['children'])
    return root


def render_html(p):
    """Render a self-contained interactive flame graph and symbol table."""
    validate_profile(p)
    data = _script_json(_script_json({'profile': p, 'table': aggregate(p), 'tree': _flame_tree(p)}))
    html = HTML.replace('/*PROFILE_DATA*/', data)
    if len(html.encode('utf-8')) > LIMIT: raise ValueError('output too large')
    return html


def read_text(path):
    with open(path, 'rb') as f: data = f.read(LIMIT + 1)
    if len(data) > LIMIT: raise ValueError('input too large')
    return data.decode('utf-8')


def write_new(path, text):
    data = text.encode('utf-8')
    if len(data) > LIMIT: raise ValueError('output too large')
    with open(path, 'xb') as f: f.write(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    a = sub.add_parser('render'); a.add_argument('input'); a.add_argument('output')
    a = sub.add_parser('perf'); a.add_argument('input'); a.add_argument('output'); a.add_argument('--identity', required=True); a.add_argument('--scope', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'render': result = render_html(load_json(read_text(args.input)))
        else:
            identity = parse_json(read_text(args.identity))
            result = json.dumps(parse_perf_script(read_text(args.input), identity, args.scope), ensure_ascii=True, allow_nan=False, indent=2) + '\n'
        write_new(args.output, result)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.exit(2, f'error: {exc}\n')


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"><title>Stack profile</title><style>
body{font:15px system-ui,sans-serif;margin:1.5rem;color:#18202b}h1{margin-bottom:.3rem}.notice{background:#fff2c6;padding:1rem;border-left:4px solid #b76b00}pre{white-space:pre-wrap;overflow-wrap:anywhere}button,input{font:inherit;padding:.35rem}#flame{overflow:auto;border:1px solid #aaa;min-height:3rem}.row{position:relative;height:26px;min-width:800px}.frame{position:absolute;top:0;height:26px;box-sizing:border-box;min-width:0;margin:0;padding:0;border:0;overflow:hidden;background:#ecad65;text-align:left;font-size:12px;cursor:pointer}.frame-label{position:absolute;inset:0;box-sizing:border-box;border:1px solid white;padding:3px;overflow:hidden;white-space:nowrap;pointer-events:none}.frame:hover{background:#e78242}table{border-collapse:collapse;width:100%}td,th{padding:.35rem;border-bottom:1px solid #ddd;text-align:left}td:first-child{overflow-wrap:anywhere}th{cursor:pointer}td:not(:first-child){text-align:right;font-variant-numeric:tabular-nums}</style></head><body>
<h1>Stack profile</h1><p class="notice"><strong>Diagnostic only.</strong> Observed weights are not qualified CPU share. Capture scope, loss, unresolved frames, refusals, sampling bias, privilege coverage and workload representativeness require independent assessment. Unknown is not zero. Self and inclusive values overlap and must not be added.</p>
<pre id="meta"></pre><p><button id="reset">Reset zoom</button> <label>Filter symbols <input id="filter" type="search"></label></p><div id="flame" aria-label="Interactive flame graph"></div><p>Click a frame to zoom into that call path. Width is observed weight in the selected path.</p><h2>Symbols</h2><p>Inclusive counts each stack once per symbol, including recursive frames. Click a heading to sort.</p><table><thead><tr><th data-key="name">Symbol</th><th data-key="self">Self</th><th data-key="inclusive">Inclusive</th></tr></thead><tbody id="table"></tbody></table>
<script>"use strict";const data=JSON.parse(/*PROFILE_DATA*/);const p=data.profile;const meta=document.getElementById('meta');meta.textContent=JSON.stringify({identity:p.identity,measurement:p.measurement,scope:p.scope,totals:p.totals,quality:p.quality},null,2);
const root=data.tree;
let selected=root;function draw(){const box=document.getElementById('flame');box.replaceChildren();let layer=[[selected,0,1]];while(layer.length){const row=document.createElement('div');row.className='row';let next=[];for(const [n,x,w] of layer){const b=document.createElement('button');b.className='frame';b.style.left=(x*100)+'%';b.style.width=(w*100)+'%';const label=document.createElement('span');label.className='frame-label';label.textContent=n.name;b.append(label);b.title=n.name+' - '+n.weight+' '+p.measurement.unit;b.onclick=()=>{selected=n;draw()};row.append(b);let pos=x;for(const child of n.children){const cw=w*(child.weight/n.weight);next.push([child,pos,cw]);pos+=cw}}box.append(row);layer=next}}document.getElementById('reset').onclick=()=>{selected=root;draw()};draw();
let sort='inclusive';function table(){let rows=Object.entries(data.table).map(([name,v])=>({name,...v}));const q=document.getElementById('filter').value.toLocaleLowerCase();rows=rows.filter(r=>r.name.toLocaleLowerCase().includes(q));rows.sort((a,b)=>sort==='name'?a.name.localeCompare(b.name):b[sort]-a[sort]||a.name.localeCompare(b.name));const body=document.getElementById('table');body.replaceChildren();for(const r of rows){const tr=document.createElement('tr');for(const v of [r.name,r.self,r.inclusive]){const td=document.createElement('td');td.textContent=String(v);tr.append(td)}body.append(tr)}}document.getElementById('filter').oninput=table;document.querySelectorAll('th').forEach(th=>th.onclick=()=>{sort=th.dataset.key;table()});table();</script></body></html>'''

if __name__ == '__main__': main()

