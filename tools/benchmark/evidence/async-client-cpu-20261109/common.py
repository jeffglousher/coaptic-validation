"""Full-vector regrade of one four-pair complete-App CPU development refusal."""
import gzip,hashlib,io,json,math,re,statistics
from pathlib import Path,PurePosixPath
BUDGET=1024*1024
MAX_EXPANDED=16*1024*1024
BASE='a85c51e689607051e36e450567fe051f8f85dc2b'
PRODUCTION='84a785f075cb86bf805d0e1fe8a1eabcaae3218f'
TESTED='4f434952ba86df35245fa9736f8a5a341de88bf0'
RAW_KEYS='app_inline_bytes associations black_box blockwise calibration_samples calls client_capacities clock_calibration_cycles concurrency cycles data_packets_per_operation dedup deferred expiry_probe latencies_cycles measurement memory message_type metadata mode observe operations payload_bytes pools populated_routes profile requests_per_operation routes rx_body_slots rx_datagram_bytes rx_slots scope security security_requests sends server_capacities server_poll_counts server_poll_cpu_cycles_sum storage tx_body_slots tx_datagram_bytes tx_slots verified warmup'.split()
MEMORY_KEYS='app_including_transport_inline_bytes client_app_including_transport_inline_bytes client_pool_payload_nested_bytes client_pool_requested_heap_bytes client_transport_nested_bytes clock_inline_bytes each_transport_input_nested_bytes each_transport_output_nested_bytes fixed_pool_heap_bytes packet_buffers_nested_count remaining separate_calibration_requested_bytes separate_latency_requested_bytes separate_optional_client_context_inline_bytes separate_pending_inline_bytes separate_poll_counts_requested_bytes separate_representation_static_bytes separate_static_representation_bytes separate_timing_requested_bytes separate_timing_vec_headers_bytes separate_vec_headers_bytes separate_verification_buffer_bytes separate_verification_requested_bytes server_app_including_transport_inline_bytes server_pool_payload_nested_bytes server_pool_requested_heap_bytes server_transport_nested_bytes transport_input_nested_bytes transport_nested_in_app_inline_bytes transport_output_nested_bytes'.split()
CAP_KEYS='associations blockwise body_bytes calls datagram_bytes dedup deferred observe populated_routes routes rx_body_bytes rx_body_slots rx_slots security_requests tx_body_bytes tx_body_slots tx_slots'.split()
VECTORS=['latencies_cycles','clock_calibration_cycles','server_poll_cpu_cycles_sum','server_poll_counts','cycles']
CLAIMS={'confidence_qualification':False,'adopted':False,'goal_complete':False,'libcoap_comparison':False,'WiFi_or_MCU_speed':False,'regression_acceptance':False}

def need(x,s):
 if not x:raise ValueError(s)
def enc(x):return (json.dumps(x,separators=(',',':'),sort_keys=True,allow_nan=False)+'\n').encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def keys(x,k,n,optional=False):need(type(x)is dict and (set(x)<=set(k) if optional else set(x)==set(k)),n+' allowlist differs')
def point(x):return math.exp(statistics.mean(map(math.log,x)))
def same(x,y):
 if type(y) in [int,float]:need(type(x)in[int,float] and math.isclose(x,y,rel_tol=1e-12,abs_tol=1e-9),'numeric differs')
 elif type(y)is dict:
  keys(x,y,'result')
  for k,v in y.items():same(x[k],v)
 elif type(y)is list:
  need(type(x)is list and len(x)==len(y),'length differs')
  for a,b in zip(x,y):same(a,b)
 else:need(type(x)is type(y) and x==y,'value differs')
def private(raw):
 t=raw.decode('utf-8-sig');p=[r'(?<![a-z])[a-z]:[\\/]',('/'+'Users/|/'+'home/'),r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',r'\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b',r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b',('noise_'+'psk|t3-'+'thread://')]
 return any(re.search(x,t,re.I) for x in p)
def relative(n):
 p=PurePosixPath(n);need(not p.is_absolute() and '..'not in p.parts and ':'not in n and '\\'not in n and str(p)==n,'unsafe path')
def unpack(b,m):
 need(len(b)==m['bytes'] and sha(b)==m['sha256'],'packed digest differs')
 with gzip.GzipFile(fileobj=io.BytesIO(b))as f:r=f.read(MAX_EXPANDED+1)
 need(len(r)==m['raw_bytes']<=MAX_EXPANDED and sha(r)==m['raw_sha256'],'raw digest differs');return r
def continuation(summary,groups):return all(x['ratio']<=1.02 for x in summary) and all(groups['all-'+m]['ratio']<=.995 for m in ['sync','async'])
CELLS=([['ordinary','small-device',security,mode,32]for security in ['unprotected','oscore']for mode in ['sync','async']]
 +[['ordinary','service-'+storage,security,mode,body]for storage in ['fixed','allocated']for security in ['unprotected','oscore']for mode in ['sync','async']for body in [1024,16384]]
 +[['retained',storage,security,mode,11264]for storage in ['fixed','allocated']for security in ['unprotected','oscore']for mode in ['sync','async']])
FIXTURES_SHA256='406e9335cb211fae983516fdaa111a528dcd91105a826079668604eab483917f'
SOURCE_FILES=[{'after_sha256': '5bb16fba1b3a0ea2a5cc66538ce5799d7f28c194d56c12ab5fec72ce2939de6b', 'before_sha256': 'aa1d4c8ddfc8d674270714f9dada67720380b8f07df8e8822cae0c42ce1da592', 'path': 'crates/coaptic-io/src/lib.rs'}, {'after_sha256': '46ebd68d1381b34a7f047d14c1b71d23faa5152de9b1f47d378a7ef3ad3cef50', 'before_sha256': None, 'path': 'crates/coaptic-io/tests/conditional_outline.rs'}, {'after_sha256': 'f560d195d31e5cca19cff9915e33c377062bc153bccabebfb2cead49736520d1', 'before_sha256': 'a134a89dcfbcb8be632b3f8bf255ac6dae03fcfa5f6fc24577b7f4665efd2192', 'path': 'src/app/async_server_tests.rs'}, {'after_sha256': '8e0ab0f823057604c381c30a837224ae7892ad597dde9682fd3c6fa57b83711e', 'before_sha256': '633c8c90c8ed6c1a4e28c7d4924ffd8be27ef9585c8aafdf6e7f54fbcda3362c', 'path': 'src/app/client.rs'}, {'after_sha256': 'eb778e9988b70d6e24d1cf7d69627f7cae515b9a601be5d1e7d97f2accdf325e', 'before_sha256': '3f8538ac791feae54118a6c740d336e2e20a1de92bf92a065c18cd38df13abaa', 'path': 'src/app/client_async.rs'}, {'after_sha256': '6071395022582179ed0b3eaef47a97388fb50dbec6f2447a4ac51bad81ddbfc5', 'before_sha256': '75418156ebdc7c9708fa35935e302fa039a41f105fb85baa2b6181a4d9c33bd2', 'path': 'src/app/mod.rs'}]
SOURCE_PATHS=[x['path']for x in SOURCE_FILES]
PATCH_SHA256='43ce4af65716094e14069e1f7544df8054dd8ab0d8d809cbc5d1059141c1f3c8'
SCOPE_CLAIMS={'vector_arithmetic': 'independently_regraded', 'eligibility_capacity_and_resident_ledgers': 'frozen producer records; required exact inventories', 'ordinary_mode_selection': 'producer label and compiled-runner attestation; ordinary raw record has no mode field', 'retained_mode_selection': 'raw mode field and producer label', 'compiler_fixture_binary_join': 'private producer attestation', 'target_static_findings': 'retained producer attestation; not independently compiled by this verifier', 'independent_source_or_firmware_build': False, 'independent_target_static_build': False}

def fixture_inventory():
 packed=(Path(__file__).resolve().parent/'fixtures.json.gz').read_bytes()
 with gzip.GzipFile(fileobj=io.BytesIO(packed))as f:raw=f.read(192*1024+1)
 need(len(raw)<=192*1024 and sha(raw)==FIXTURES_SHA256,'frozen fixture inventories differ')
 rows=json.loads(raw)
 expected=[(tuple(c),n)for ncase in ['qualify','measure']for c in CELLS for n in [8 if ncase=='qualify'else 8192 if c[4]in [32,1024]else 1024]]
 need([(tuple(x['cell']),x['operations'])for x in rows]==expected,'fixture grid/order differs')
 return {(tuple(x['cell']),x['operations']):x for x in rows}

def validate_provenance(p,patch):
 keys(p,['build_environment', 'compiler_files', 'compiler_version_verbose', 'corrected_screen_sha256', 'fixture_count', 'fixture_input_plan_sha256', 'independent_numeric_audit_sha256', 'measurement_sha256', 'normalized_build_argv', 'original_build_argv_sha256', 'original_runner_sha256', 'plan_sha256', 'production_commit', 'schema', 'scope', 'scope_claims', 'source_files', 'source_patch_sha256', 'source_with_corrected_test', 'static_findings', 'static_findings_sha256', 'test_only_difference', 'wrapper_refusal'],'provenance')
 need(p['schema']=='coaptic-four-pair-CPU-provenance/1'and p['production_commit']==PRODUCTION and p['source_with_corrected_test']==TESTED and p['test_only_difference']==['src/app/async_server_tests.rs'],'source/test pins differ')
 need(p['source_files']==SOURCE_FILES and len({x['path']for x in p['source_files']})==6,'exact unique six-file source inventory differs')
 need(sha(patch)==p['source_patch_sha256']==PATCH_SHA256,'exact final source patch digest differs')
 text=patch.decode('utf-8');headers=re.findall(r'^diff --git a/(.+) b/(.+)$',text,re.M)
 need(headers==[(x,x)for x in SOURCE_PATHS],'patch header inventory differs')
 before=re.findall(r'^--- (.+)$',text,re.M);after=re.findall(r'^\+\+\+ (.+)$',text,re.M)
 need(before==['/dev/null'if x['before_sha256']is None else'a/'+x['path']for x in SOURCE_FILES]and after==['b/'+x for x in SOURCE_PATHS],'patch old/new path inventory differs')
 keys(p['scope_claims'],SCOPE_CLAIMS,'provenance scope claims');need(enc(p['scope_claims'])==enc(SCOPE_CLAIMS),'provenance build/scope overclaim')
 need(p['fixture_count']==683 and p['measurement_sha256']=='241373173268c997068484f8843fede7397fa98c53d646e07aed6e22ebb2e93d','producer commitments differ')

def grade(d):
 keys(d,['schema','claims','method','processes'],'CPU dataset');need(d['schema']=='coaptic-four-pair-CPU-vectors/1','schema differs');same(d['claims'],CLAIMS)
 m=d['method'];keys(m,['baseline','production','source_with_corrected_test','cells','orders','warmup','preflight_operations','cpu_affinity','parent_clocks_released'],'method')
 need((m['baseline'],m['production'],m['source_with_corrected_test'])==(BASE,PRODUCTION,TESTED),'source pins differ');need(m['orders']==['AB','BA','BA','AB'] and m['warmup']==128 and m['preflight_operations']==8 and m['cpu_affinity']==0 and m['parent_clocks_released'] is True,'four-pair method differs')
 cells=m['cells'];need(enc(cells)==enc(CELLS),'exact 28-cell grid differs');fixtures=fixture_inventory()
 expected=['qualify-'+arm+'-'+'-'.join(map(str,c)) for c in cells for arm in 'AB']
 expected += ['measure-'+str(i)+'-'+'-'.join(map(str,c))+'-'+arm for i,order in enumerate(m['orders'])for c in cells for arm in order]
 need([p['label']for p in d['processes']]==expected and len(expected)==280,'process order/coverage differs')
 descriptors=[('qualify-'+arm+'-'+'-'.join(map(str,c)),arm,c)for c in cells for arm in 'AB']
 descriptors += [('measure-'+str(i)+'-'+'-'.join(map(str,c))+'-'+arm,arm,c)for i,order in enumerate(m['orders'])for c in cells for arm in order]
 processes=[];aux=0
 for p,(label,arm,cell) in zip(d['processes'],descriptors):
  keys(p,['label','arm','cell','vector_field','cycle_sum','cycle_count','cycle_mean','raw','original_packed_sha256','original_raw_sha256','original_stderr_packed_sha256','original_stderr_raw_sha256','original_stderr_bytes'],'process')
  c=p['cell'];v=p['raw'];need((p['label'],p['arm'],c)==(label,arm,cell),'process label/arm/cell binding differs')
  need(c in cells and p['arm']in'AB','process identity differs');n=8 if p['label'].startswith('qualify-')else 8192 if c[4]in[32,1024]else 1024
  f=fixtures[(tuple(c),n)];keys(v,f['raw_keys'],'required exact fixture raw inventory')
  need(enc({k:v[k]for k in v if k not in VECTORS})==enc(f['non_vector_fields']),'immutable fixture identity/capacity/memory ledger differs')
  need(v['operations']==n and v['warmup']==128 and v['verified']==n+128 and v['security']==c[2] and v['payload_bytes']==c[4],'complete operation eligibility differs')
  field='cycles'if c[0]=='retained'else'latencies_cycles'if c[1]=='small-device'else'server_poll_cpu_cycles_sum';need(p['vector_field']==field,'primary CPU boundary differs')
  for k in VECTORS:
   if k in v:
    need(type(v[k])is list and len(v[k])==(4096 if k=='clock_calibration_cycles'else n),'vector length differs')
    need(all(type(x)is int and x>=(0 if k=='clock_calibration_cycles'else 1)for x in v[k]),'nonpositive CPU/count vector')
    if k=='clock_calibration_cycles':aux+=len(v[k])
  a=v[field];need(sum(a)==p['cycle_sum'] and len(a)==p['cycle_count'] and sum(a)/len(a)==p['cycle_mean'],'per-process full-vector sum/count differs')
  need(p['original_stderr_bytes']==0,'nonempty stderr');need(all(re.fullmatch('[0-9a-f]{64}',p[k])for k in ['original_packed_sha256','original_raw_sha256','original_stderr_packed_sha256','original_stderr_raw_sha256']),'raw commitment format differs')
  for key,allow in [('memory',MEMORY_KEYS),('server_capacities',CAP_KEYS),('client_capacities',CAP_KEYS),('sends',['client','server','combined','combined_limit','per_port_limit'])]:
   if key in v:keys(v[key],allow,key,True)
  if c[0]=='ordinary':need(v['black_box']is True and v['concurrency']==1 and v['message_type']=='CON' and v['calibration_samples']==4096,'ordinary eligibility differs')
  else:need(v['mode']==c[3] and v['requests_per_operation']==2 and v['data_packets_per_operation']==11,'retained eligibility differs')
  # Exact frozen non-vector ledgers above bind identities, capacities and all resident owners.
  processes.append({k:p[k]for k in ['label','arm','cell','vector_field','cycle_sum','cycle_count','cycle_mean']})
 rows=[]
 for pair in range(4):
  for c in cells:
   ps={a:next(p for p in processes if p['label']=='measure-'+str(pair)+'-'+'-'.join(map(str,c))+'-'+a)for a in'AB'}
   means={a:ps[a]['cycle_mean']for a in'AB'};rows.append({'pair':pair,'cell':c,'means':means,'ratio':means['B']/means['A'],'raw':{a:{k:ps[a][k]for k in['cycle_sum','cycle_count']}for a in'AB'}})
 summary=[{'cell':c,'ratio':point([r['ratio']for r in rows if r['cell']==c])}for c in cells];groups={}
 for kind in ['ordinary','retained','all']:
  for mode in ['sync','async','all']:
   pairs=[point([r['ratio']for r in rows if r['pair']==pair and(kind=='all'or r['cell'][0]==kind)and(mode=='all'or r['cell'][3]==mode)])for pair in range(4)]
   selected=[p for p in processes if p['label'].startswith('measure-')and(kind=='all'or p['cell'][0]==kind)and(mode=='all'or p['cell'][3]==mode)]
   groups[kind+'-'+mode]={'ratio':point(pairs),'pair_point_ratios':pairs,'raw':{a:{'cycle_sum':sum(p['cycle_sum']for p in selected if p['arm']==a),'cycle_count':sum(p['cycle_count']for p in selected if p['arm']==a)}for a in'AB'}}
 measured=sum(p['cycle_count']for p in processes if p['label'].startswith('measure-'));qual=sum(p['cycle_count']for p in processes if p['label'].startswith('qualify-'));need(measured==917504 and qual==448,'used sample count differs')
 return {'status':'complete','development_only':True,'continuation_signal':continuation(summary,groups),'qualified':False,'adopted':False,'rows':rows,'summary':summary,'groups':groups,'failed_cell_point_guards':[x for x in summary if x['ratio']>1.02],'processes':processes,'measured_processes':224,'preflight_processes':56,'measured_operations':measured,'qualification_operations':qual,'all_used_cycle_samples':measured+qual,'calibration_samples_retained':aux,'claims':d['claims']}
