"""Grade the finite device CPU ledger against authenticated host read records.

Wall, scheduled task CPU (including attributed ISR/stall time), blocked time and
ready-but-unscheduled time are distinct. Readiness begins at worker select
return, not earliest lwIP enqueue. Instrumentation overhead is included.
"""
import re


def delta(start, end):
    values = {name: end[name]-start[name] for name in ('w','c','b','r')}
    if min(values.values()) < 0 or abs(values['w']-values['c']-values['b']-values['r']) > 4:
        raise ValueError('inconsistent scheduler accounting')
    return dict(wall_us=values['w'], task_cpu_us=values['c'], blocked_us=values['b'], ready_unscheduled_us=values['r'])


def grade(lines, host, run_id):
    if not re.fullmatch('[0-9a-f]{32}', run_id):
        raise ValueError('run identity')
    rows=[];ends=[];resources=[]
    for line in lines:
        if 'COAPTIC_CPU' not in line:
            continue
        fields=dict(re.findall(r'([a-z_]+)=([^ ]+)',line))
        if fields.get('run') != run_id:
            raise ValueError('foreign diagnostic run')
        if 'COAPTIC_CPU_END ' in line:
            ends.append(fields)
        elif 'COAPTIC_CPU_RESOURCE ' in line:
            resources.append({k:int(v) for k,v in fields.items() if k!='run'})
        elif 'COAPTIC_CPU ' in line:
            row={k:(v if k=='tok' else int(v)) for k,v in fields.items() if k!='run'}
            if not re.fullmatch('[0-9a-f]{16}',row['tok']) or row['k'] not in range(1,10):
                raise ValueError('diagnostic row')
            rows.append(row)
    if len(ends)!=1 or ends[0]['overflow']!='false' or int(ends[0]['count'])!=len(rows) or not 0<len(rows)<=512:
        raise ValueError('missing, incomplete or overflowing ledger')
    if [r['i'] for r in rows] != list(range(len(rows))):
        raise ValueError('ledger ordering')
    for first,last in zip(rows,rows[1:]):
        delta(first,last)
    if (not host or not host[-1].get('passed') or host[-1].get('security')!='durable-oscore'
            or host[-1].get('case')!='timing_campaign' or host[-1].get('completed')!=24 or host[-1].get('run_id')!=run_id):
        raise ValueError('host campaign failed')
    operations=[x for x in host if x.get('case')=='complete_operation']
    expected=[(iteration,path) for iteration in range(8) for path in ('identity','test','large')]
    if [(x['iteration'],x['path']) for x in operations]!=expected or any(not x.get('passed') for x in operations):
        raise ValueError('incomplete matched read cohort')
    if not any(x.get('run_id')==run_id for x in host):
        raise ValueError('host identity')
    exchanges=[];ready=None;receives={};sends={}
    for row in rows:
        key=(row['mid'],row['tok'])
        if row['k']==9:
            ready=row
        elif row['k']==1:
            if key in receives:
                raise ValueError('duplicate request in measurement cohort')
            receives[key]=(row,ready);ready=None
        elif row['k']==2:
            if key not in receives or key in sends:
                raise ValueError('unmatched or duplicate send')
            received,readiness=receives[key]
            start=readiness or received
            sends[key]=(row,dict(mid=row['mid'],token=row['tok'],receive_us=received['w'],send_us=row['w'],
                readiness_boundary='worker_select_return' if readiness else 'receive_return',
                ready_to_send=delta(start,row), receive_to_send=delta(received,row),
                sample_start={key:start[key] for key in ('w','c','b','r')}))
        elif row['k']==3:
            if key not in sends:
                raise ValueError('send completion lacks entry')
            start,exchange=sends.pop(key)
            exchange['send_call']=delta(start,row)
            exchange['send_complete_us']=row['w']
            exchange['sample_end']={key:row[key] for key in ('w','c','b','r')}
            exchanges.append(exchange)
    if sends:
        raise ValueError('incomplete sends')
    if set(receives)!={(x['mid'],x['token']) for x in exchanges}:
        raise ValueError('unmatched receive in cohort')
    by_mid={x['mid']:x for x in exchanges}
    if len(by_mid)!=len(exchanges):
        raise ValueError('ambiguous MID')
    selected=[];used=set()
    for operation in operations:
        mids=[event[4] for event in operation['events'] if event[0]==2]
        expected=2 if operation['path']=='large' else 1
        if len(mids)!=expected or any(mid not in by_mid or mid in used for mid in mids):
            raise ValueError('host/device exchange mismatch')
        used.update(mids)
        device=[by_mid[mid] for mid in mids]
        selected.append(dict(device_service=delta(device[0]['sample_start'],device[-1]['sample_end']),path=operation['path'],iteration=operation['iteration'],host_elapsed_ns=operation['elapsed_ns'],
                             exchanges=[by_mid[mid] for mid in mids]))
    if len(used)!=len(exchanges) or len(exchanges)!=32:
        raise ValueError('unexpected traffic in cohort')
    first_receive=min(pair[0]['w'] for pair in receives.values())
    final_send=max(x['send_complete_us'] for x in exchanges)
    traffic_resources=[x for x in resources if 0<x['tx']<=x['rx']<32 and first_receive<=x['at']<=final_send]
    if not traffic_resources:
        raise ValueError('no protected traffic-period resource sample')
    state_spans=[];pending={}
    for row in rows:
        if row['k'] in (4,6): pending[row['k']]=row
        elif row['k'] in (5,7):
            start=pending.pop(row['k']-1,None)
            if start is None: raise ValueError('unpaired state span')
            state_spans.append(dict(kind='read' if row['k']==5 else 'commit',**delta(start,row)))
    if pending: raise ValueError('unfinished state span')
    return dict(passed=True,run_id=run_id,operations=selected,state_spans=state_spans,resources=resources,
                ledger_rows=len(rows),ledger_bytes=int(ends[0]['rows_bytes']),
                scope='instrumented scheduled-task CPU includes attributed ISR/stall time; readiness is worker observed; no performance gain comparison')
