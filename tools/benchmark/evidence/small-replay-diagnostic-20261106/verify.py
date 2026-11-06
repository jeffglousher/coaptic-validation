from pathlib import Path
import hashlib,json,math,statistics,zipfile
r=Path(__file__).resolve().parent
with zipfile.ZipFile(r/'diagnostic.zip') as z:
 hashes=json.loads((r/'sha256.json').read_text());assert set(z.namelist())==set(hashes)
 for n,h in hashes.items():assert hashlib.sha256(z.read(n)).hexdigest()==h,n
 read=lambda n:json.loads(z.read(n))
 method=read('METHOD.json');result=read('result.json')
 assert method==json.loads((r/'METHOD.json').read_text()) and result==json.loads((r/'result.json').read_text())
 assert result['status']=='complete' and result['acceptance_claim'] is False
 assert len(result['rows'])==64 and len(result['process_exits'])==128
 assert len({v['label'] for v in result['process_exits']})==128 and all(v['exit_code']==0 for v in result['process_exits'])
 assert all(v['exit_code']==0 for v in read('build-results.json'))
 for arm in 'AB':
  assert hashlib.sha256(z.read(arm+'/dispatch-probe.exe')).hexdigest()==method['binaries'][arm]
  assert read(arm+'/source.json')['source']==method['sources'][arm]
 for row in result['rows']:
  for arm in 'AB':
   raw=read(f"{row['pair']}-{row['mode']}-{row['security']}-{arm}.json")
   assert raw['operations']==1024 and raw['verified']==1152 and raw['dedup']==4
   assert raw['wire_lengths_min_max_count']==[55 if row['security']=='unprotected' else 66]*2+[1152]
   assert row['wire_lengths_min_max_count'][arm]==raw['wire_lengths_min_max_count']
   assert row['empty_interval_cycles'][arm]==raw['phase_empty_4096_cycles']/4096
   assert row['instrumented_App_mean_cycles'][arm]==statistics.mean(raw['latencies_cycles'])
   for index,phase in enumerate(method['phases']):
    cycles,calls=raw['phase_cost_including_warmup'][index]
    assert calls==(2300 if phase=='lookup' else 1152)
    assert row['phases'][phase][arm+'_calls']==calls
    assert row['phases'][phase][arm+'_cycles_per_call']==cycles/calls
  for phase in method['phases']:
   v=row['phases'][phase];assert v['ratio']==v['B_cycles_per_call']/v['A_cycles_per_call']
 for item in result['summary']:
  selected=[v for v in result['rows'] if v['mode']==item['mode'] and v['security']==item['security']]
  phase=item['phase']
  for arm in 'AB':
   assert item[arm+'_mean_cycles_per_call']==statistics.mean(v['phases'][phase][arm+'_cycles_per_call'] for v in selected)
   assert item[arm+'_call_counts']==sorted({v['phases'][phase][arm+'_calls'] for v in selected})
  assert item['paired_geomean_ratio']==math.exp(statistics.mean(math.log(v['phases'][phase]['ratio']) for v in selected))
 print({'verified_members':len(hashes),'processes':128,'lookups_per_process':2300,'operations_including_warmup':1152,'wire_bytes':{'unprotected':55,'oscore':66},'acceptance_claim':False})
