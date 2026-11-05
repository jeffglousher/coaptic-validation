from pathlib import Path
import subprocess,json,hashlib,statistics,math,time,psutil
ROOT=Path(__file__).resolve().parent
CELLS=[('ordinary',p,s,m,b) for p in ['small-device','service-fixed','service-allocated'] for s in ['unprotected','oscore'] for m in ['sync','async'] for b in ([32] if p=='small-device' else [1024,16384])]
CELLS += [('retained',p,s,m,11264) for p in ['fixed','allocated'] for s in ['unprotected','oscore'] for m in ['sync','async']]
BIN={('A','ordinary'):ROOT.parent/'A/dispatch-probe.exe',('A','retained'):ROOT.parent/'retained-body/A/retained-probe.exe',('B','ordinary'):ROOT/'B/dispatch-probe.exe',('B','retained'):ROOT/'B/retained-probe.exe'}
def run(arm,cell,count,label):
 kind,p,s,m,size=cell
 env=dict(__import__('os').environ);env.pop('COAPTIC_DISPATCH_ASYNC',None);env['COAPTIC_EXPIRY_PROBE']='steady'
 if m=='async':env['COAPTIC_DISPATCH_ASYNC']='1'
 if kind=='ordinary':cmd=[str(BIN[arm,kind]),str(count),s,'--'+p]+([] if p=='small-device' else [str(size)])
 else:cmd=[str(BIN[arm,kind]),str(count),s,m,p]
 r=subprocess.run(cmd,env=env,capture_output=True,timeout=15)
 (ROOT/(label+'.json')).write_bytes(r.stdout);(ROOT/(label+'.stderr')).write_bytes(r.stderr)
 assert r.returncode==0,(label,r.stderr.decode())
 x=json.loads(r.stdout);assert x['operations']==count and x['security']==s and x['payload_bytes']==size
 if kind=='retained':
  assert x['mode']==m and x['storage']==p and x['verified']==count+128 and x['requests_per_operation']==2 and x['data_packets_per_operation']==11
  values=x['cycles']
 elif p=='small-device':
  assert x['black_box'] and x['dedup']==4;values=x['latencies_cycles']
 else:
  assert x['black_box'] and x['verified']==count+128 and x['server_poll_counts']==[(size+1023)//1024]*count and x['expiry_probe']=='steady'
  assert x['server_capacities']['dedup']==64;values=x['server_poll_cpu_cycles_sum']
 assert len(values)==count and all(type(v)==int and v>0 for v in values)
 return statistics.mean(values),x
def name(cell):return '-'.join(map(str,cell))
assert not (ROOT/'measurement.json').exists(),'Never replace an observed cohort'
method={'baseline':'dcf82cbb75d903bd9ab44ccd64ba3e6584bd6f93','candidate':'d2d4484cc5c6beb66856511e6d86ce75ce3cefd2','cells':CELLS,'operations':'8192 ordinary32/1024;1024 ordinary16384 and retained11264','warmup':128,'process_pairs':4,'orders':['AB','BA','BA','AB'],'cpu':0,'binaries':{a+'-'+k:hashlib.sha256(v.read_bytes()).hexdigest() for (a,k),v in BIN.items()},'primary':'Equal weight complete-App process-mean ratios; separate original20 ordinary controls and all28 groups. Both sync/async upper95 must be below1 in original20 AND all28; every cell point ratio<=1.02. RetainedQ groups reported separately. Matched memory reduction required independently.','limits':'In-memory complete server App CPU work, actual sync poll and native async wait+progress; client preparation/authentication/verification outside clock. Not sockets, executor latency, peak memory or hardware. All previous failed cohorts retained.','interval':'Student-t df3 one-sided95 percent on four paired log ratios; geometric means, no trimming or discarded measured samples.'}
(ROOT/'METHOD.json').write_text(json.dumps(method,indent=2),encoding='utf-8')
process=psutil.Process();affinity=process.cpu_affinity();process.cpu_affinity([0]);rows=[];start=time.monotonic()
try:
 for cell in CELLS:
  _,a=run('A',cell,8,'qualify-A-'+name(cell));_,b=run('B',cell,8,'qualify-B-'+name(cell))
  for key in ['server_capacities','client_capacities','memory','routes','calls','deferred','security_requests','associations','app_inline_bytes']:
   if key in a:assert a[key]==b[key],(cell,key)
 for pair,order in enumerate(method['orders']):
  for cell in CELLS:
   means={}
   for arm in order:
    assert time.monotonic()-start<180
    means[arm],_=run(arm,cell,8192 if cell[4] in [32,1024] else 1024,f'measure-{pair}-'+name(cell)+'-'+arm)
   rows.append(dict(pair=pair,cell=cell,means=means,ratio=means['B']/means['A']))
 def interval(values):
  logs=list(map(math.log,values));mean=statistics.mean(logs)
  return dict(ratio=math.exp(mean),upper95=math.exp(mean+2.3533634348*statistics.stdev(logs)/math.sqrt(len(logs))))
 summary=[dict(cell=cell,**interval([r['ratio'] for r in rows if r['cell']==cell])) for cell in CELLS]
 groups={}
 for kind in ['ordinary','retained','all']:
  for mode in ['sync','async','all']:
   groups[kind+'-'+mode]=interval([math.exp(statistics.mean(math.log(r['ratio']) for r in rows if r['pair']==pair and (kind=='all' or r['cell'][0]==kind) and (mode=='all' or r['cell'][3]==mode))) for pair in range(4)])
 failed=[r for r in summary if r['ratio']>1.02]
 accepted=not failed and all(groups[k+'-'+m]['upper95']<1 for k in ['ordinary','all'] for m in ['sync','async'])
 result=dict(status='complete',runtime_accepted=accepted,rows=rows,summary=summary,groups=groups,failed_point_guards=failed,seconds=time.monotonic()-start)
 (ROOT/'measurement.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
 print(json.dumps(dict(runtime_accepted=accepted,groups=groups,failed_point_guards=failed),indent=2))
except BaseException as e:
 (ROOT/'measurement.json').write_text(json.dumps(dict(status='failed',error=str(e),rows=rows),indent=2),encoding='utf-8');raise
finally:process.cpu_affinity(affinity)
