"""Check diagnostic evidence without building or executing native probes."""
from pathlib import Path
import hashlib, json, math, statistics, zipfile
r=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
result=read(r/'result.json'); method=read(r/'METHOD.json')
assert result['status']=='complete' and result['acceptance_claim'] is False
with zipfile.ZipFile(r/'diagnostic.zip') as z:
    hashes=read(r/'sha256.json'); assert set(z.namelist())==set(hashes)
    for n,h in hashes.items(): assert hashlib.sha256(z.read(n)).hexdigest()==h,n
    assert json.loads(z.read('result.json'))==result
    assert json.loads(z.read('METHOD.json'))==method
    assert len(result['process_exits'])==128
    assert all(x['exit_code']==0 for x in result['process_exits'])
    for row in result['rows']:
        pair,mode,size=row['pair'],row['mode'],row['payload']
        n=(1024+128)*(size//1024)
        for arm in ['A','B']:
            label=f'{pair}-{mode}-{size}-{arm}'
            x=json.loads(z.read(label+'.json'))
            assert x['operations']==1024 and x['warmup']==128 and x['verified']==1152
            assert x['payload_bytes']==size and x['security']=='unprotected'
            assert x['server_capacities']['dedup']==64
            assert z.read(label+'.stderr')==b''
            for i,phase in enumerate(['store','expiry','lookup']):
                cycles,calls=x['phase_cost_including_warmup'][i]
                assert calls==[n,n-1,3*n-62][i]
                assert row['phases'][phase]['calls']==calls
                assert row['phases'][phase][arm+'_cycles_per_call']==cycles/calls
            assert row['empty_interval_cycles'][arm]==x['phase_empty_4096_cycles']/4096
            assert row['instrumented_App_mean_cycles'][arm]==statistics.mean(x['server_poll_cpu_cycles_sum'])
    for s in result['summary']:
        rows=[x['phases'][s['phase']] for x in result['rows'] if x['mode']==s['mode'] and x['payload']==s['payload']]
        assert len(rows)==16
        for arm in ['A','B']:
            assert s[arm+'_mean_cycles_per_call']==statistics.mean(x[arm+'_cycles_per_call'] for x in rows)
        ratio=math.exp(statistics.mean(math.log(x['B_cycles_per_call']/x['A_cycles_per_call']) for x in rows))
        assert math.isclose(ratio,s['paired_geomean_ratio'],rel_tol=1e-14)
print('Diagnostic hashes,128 process exits, phase counts and summaries verified; no acceptance claim.')
