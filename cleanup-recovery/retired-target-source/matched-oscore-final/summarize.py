import json
from pathlib import Path
import statistics
import sys

root=Path(__file__).resolve().parents[2]
here=Path(__file__).resolve().parent
sys.path.insert(0,str(root/'tools/benchmark'))
import campaign

reports={key:campaign.read(here/file) for key,file in {
    'plaintext':'matched-coaptic-report.json',
    'oscore':'matched-coaptic-oscore-report.json',
    'regression':'regression-coaptic-5039-report.json'}.items()}
plans={name:campaign.read(here/name/'plan.json') for name in ('matched','regression')}
cells={}
totals={}
for name in ('matched','regression'):
    windows=list((here/name).glob('window-*.json'))
    assert len(windows)==10
    records=[campaign.read(path) for path in (here/name).glob('window-*/*.json')]
    assert len(records)==sum(len(x) for x in plans[name]['schedule'])
    cells[name]={(r['case'],r['peer'],r['window']):r for r in records}
    totals[name]=dict(sessions=10,cells=len(records),attempted=sum(r.get('sample',{}).get('attempted',0) for r in records),
                      completed=sum(r.get('sample',{}).get('completed',0) for r in records),
                      failed=sum(r.get('sample',{}).get('failed',0) for r in records),
                      warmup_failed=sum(r.get('sample',{}).get('warmup_failed',0) for r in records),
                      invalid_cells=sum('sample' not in r for r in records),
                      driver_failures=sum(r.get('sample',{}).get('driver_failures',0) for r in records))

rows=[r for r in reports['plaintext']['summary'] if r['security']=='plaintext'] + [r for r in reports['oscore']['summary'] if r['security'].startswith('OSCORE')]
case_lookup={c['id']:c for c in plans['matched']['cases']}
for row in rows:
    row['workload']=case_lookup[row['case']]
    cpu=[]
    for window in range(10):
        cell=cells['matched'][(row['case'],row['peer'],window)]
        accounting=cell.get('server_cpu',{})
        before,after=accounting.get('before'),accounting.get('after')
        sample=cell.get('sample',{})
        if before and after and sample.get('completed'):
            delta=sum(after[k]-before[k] for k in ('user_seconds','system_seconds'))
            cpu.append(delta*1e6/sample['completed'])
    row['median_scoped_server_cpu_us_per_completion']=statistics.median(cpu) if cpu else None

overhead=[]
for implementation in ('coaptic','aiocoap'):
    for case in plans['matched']['cases']:
        if case['security']!='plaintext':
            continue
        secure=next(c for c in plans['matched']['cases'] if c['security'].startswith('OSCORE') and all(c[k]==case[k] for k in ('bytes','concurrency','mode')))
        ratios=[]
        failures=0
        for window in range(10):
            plain=cells['matched'][(case['id'],implementation,window)].get('sample')
            protected=cells['matched'][(secure['id'],implementation+'-oscore',window)].get('sample')
            if not plain or not protected or any(s['failed'] or s['warmup_failed'] for s in (plain,protected)):
                failures+=1
                continue
            ratios.append((protected['completed']/protected['elapsed_ns'])/(plain['completed']/plain['elapsed_ns']))
        overhead.append(dict(implementation=implementation,bytes=case['bytes'],mode=case['mode'],concurrency=case['concurrency'],
                             protected_completed_rate_vs_plaintext=campaign.paired_interval(ratios),
                             excluded_pairs=failures,comparison_eligible=failures==0 and len(ratios)==10,
                             interpretation='end-to-end security profile cost includes both driver and server, shared sender sequencing and byte validation'))

busy=[]
available=[]
for cell in cells['matched'].values():
    for field in ('noise_before','noise_after'):
        value=cell[field].get('memory_available_bytes')
        if value is not None:
            available.append(value)
    before=cell['noise_before'].get('system_cpu_times')
    after=cell['noise_after'].get('system_cpu_times')
    if before and after:
        user=after['user']-before['user']; system=after['system']-before['system']; idle=after['idle']-before['idle']
        total=user+system+idle
        if total>0:
            busy.append(100*(user+system)/total)

regression=[]
for row in reports['regression']['summary']:
    row['workload']=case_lookup[row['case']]
    interval=row['completed_rate_vs_reference']['confidence_95']
    row['interpretation']='descriptive'
    if row['comparison_eligible'] and interval:
        row['interpretation']='inconclusive'
        if interval[0]>1:
            row['interpretation']='higher rate in this cell'
        elif interval[1]<1:
            row['interpretation']='lower rate in this cell'
    regression.append(row)

result=dict(schema='coaptic-performance-summary/1',sources=plans['matched']['manifest']['sources'],
            regression_provenance=campaign.read(here/'regression-provenance.json'),
            host=dict(platform=plans['matched']['host']['platform'],processor='AMD Ryzen 7 5800X3D',physical_cores=8,logical_cpus=16,
                      memory_total_bytes=34266349568,python=plans['matched']['host']['python'],
                      host_busy_percent=campaign.descriptive(busy),available_memory_bytes=campaign.descriptive(available),
                      host_busy_method='per-cell Windows CPU counter delta: (user+system)/(user+system+idle); includes all colocated work'),
            time_range=dict(start=reports['plaintext']['sessions'][0]['started'],end=reports['plaintext']['sessions'][-1]['finished']),
            totals=totals,matched=rows,regression=regression,security_overhead=overhead,
            coverage=plans['matched']['manifest']['unsupported'],
            pilot=dict(source='68bed08603eda8ee36b9b30108e28cf7668022f3',complete_matched_sessions=6,complete_regression_sessions=6,
                       additional_partial_matched_cells=27,measured_failures=3,warmup_failures=1,
                       limitation='128-entry independent replay window versus native 32; shared sender dispatch unsequenced; resource sampler absent; retained separately from final inference'),
            limits=['Preliminary shared Windows host, IPv4 loopback, fixed profiles and no global quiet fence.',
                    'Closed-loop concurrency without retransmission; complete authenticated byte validation included; no offered-load/saturation or corrected-tail claim.',
                    'Python/GIL driver and both crypto implementations contribute to protected end-to-end results. Native source comparison is a separate driver stratum.',
                    'One process-lifetime OSCORE identity, AES-CCM-16-64-128/HKDF-SHA-256, replay window 32; fresh per-cell secret/salt; no enrollment, persistence or handshake timing.',
                    'Server CPU scope includes driver startup, warmup, requests and exit; OS accounting granularity applies. Host available RAM is not SUT allocation/RSS or a device ceiling.',
                    'Latency quantiles cover successful requests; failed attempts and wall time remain reported. Sparse 64 KiB request p99 samples are not a tail SLO.',
                    'Seeded session bootstrap intervals are marginal/exploratory; no adjustment across the 18 source-comparison cells. Host noise and systematic biases remain.',
                    'DTLS, protected libcoap fixture, impairment, HTTP/3, routed/hardware execution, durability and independent driver-capacity/diagnostic-overhead qualification remain separate.'])
campaign.write_new(here/'summary.json',result)
print(json.dumps(dict(totals=totals,source_interpretations={label:sum(r['interpretation']==label for r in regression if r['peer']=='coaptic') for label in ('inconclusive','higher rate in this cell','lower rate in this cell','descriptive')})))
