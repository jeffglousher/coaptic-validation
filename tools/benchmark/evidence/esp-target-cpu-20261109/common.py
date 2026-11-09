"""Narrow full-vector target screen regrade; follows exact-H whitelist helpers."""
from collections import Counter, defaultdict
import gzip
import hashlib
import io
import json
import math
from pathlib import PurePosixPath
import re
import statistics as st

BUDGET=1024*1024
MAX_EXPANDED=2*1024*1024
CORE='c0151713fc187a4a2b8ed3cba1eb0b12df597d00'
BASE='a85c51e689607051e36e450567fe051f8f85dc2b'
RUNTIME='32f8fcac22fc16b1957c35f4f145df6be3a72532'
C_PIN='libcoap-pin-full-iram-cache32-server'
C_FLOAT='libcoap-floating-full-iram-cache32-server'
OWN_SYNC='pipeline-O3Thin-cache32-sync-iram-server'
OWN_ASYNC='hot-packet-OsFat-cache32-async-iram-server'
SYNC='target-cpu-O3Thin-core1-sync-server'
ASYNC='target-cpu-O3Thin-core1-async-server'
NAMES=[C_PIN,OWN_SYNC,ASYNC,C_FLOAT,SYNC,OWN_ASYNC]
C_NAMES=[C_PIN,C_FLOAT]
CANDIDATES=[SYNC,ASYNC]
CELLS=[(c,p) for c in ['sync','async'] for p in ['identity','test','large']]
CLAIMS={'task_CPU':False,'cache_miss':False,'isolated_affinity_cause':False,'peak_RAM':False,
        'new_host_measurement':False,'adopted':False,'goal_complete':False}
CAPACITIES={'routes':8,'populated_routes':7,'Calls':4,'deferred':0,'rx_slots':2,'tx_slots':2,
            'packet_bytes':1152,'rx_body_slots':1,'tx_body_slots':1,'body_bytes':4096,
            'dedup':4,'Observe':2,'token_bytes':8}
OP_KEYS=['passed','iteration','path','bytes','elapsed_ns','prepare_ns','poll_ns','checkpoint_ns',
         'take_ns','verify_ns','sleep_ns','request_send_attempts','distinct_request_sends','repeated_request_send_attempts']
POLICY_KEYS=['available','records','compiled_core','compiled_priority','observed_core','observed_cores',
             'observed_requested_core','observed_priority','observed_stack_reserved_bytes','runtime_policy_qualified']
HEAP_KEYS=['phase','caps','total_bytes','allocated_bytes','free_bytes','region_min_free_sum_bytes',
           'largest_free_block_bytes','coaptic_task_stack_reserved_bytes','sdk_snapshot_bytes']
NETWORK_KEYS=['rx','tx','dropped','stack_high_water_bytes','stack_capacity_bytes','polls','idle_waits','scheduler_yields','wait_errors']
CLEANUP_KEYS=['free_before_b','free_after_b','min_b','stack_free_b','stack_b']
TERMINAL_KEYS=['passed','calls','refused','polls','error']
CLASS_KEYS=['before_bytes','after_bytes','delta_bytes','before_align','after_align','whole_object_ceiling_bytes','object_sha256']
STORAGE_KEYS=['runtime_bytes','future_bytes','runtime_ceiling_bytes','future_ceiling_bytes','raw_archive_witness_reused']
SDK_KEYS=['ESP32S3_DATA_CACHE_16KB','ESP32S3_DATA_CACHE_32KB','ESP32S3_DATA_CACHE_4WAYS','ESP32S3_DATA_CACHE_64KB',
          'ESP32S3_DATA_CACHE_8WAYS','ESP32S3_DATA_CACHE_LINE_16B','ESP32S3_DATA_CACHE_LINE_32B','ESP32S3_DATA_CACHE_LINE_64B',
          'ESP32S3_DATA_CACHE_LINE_SIZE','ESP32S3_DATA_CACHE_SIZE','ESP32S3_DCACHE_ASSOCIATED_WAYS',
          'ESP32S3_ICACHE_ASSOCIATED_WAYS','ESP32S3_INSTRUCTION_CACHE_16KB','ESP32S3_INSTRUCTION_CACHE_32KB',
          'ESP32S3_INSTRUCTION_CACHE_4WAYS','ESP32S3_INSTRUCTION_CACHE_8WAYS','ESP32S3_INSTRUCTION_CACHE_LINE_16B',
          'ESP32S3_INSTRUCTION_CACHE_LINE_32B','ESP32S3_INSTRUCTION_CACHE_LINE_SIZE','ESP32S3_INSTRUCTION_CACHE_SIZE',
          'ESPTOOLPY_FLASHFREQ','ESPTOOLPY_FLASHMODE','ESP_DEFAULT_CPU_FREQ_MHZ','FREERTOS_HZ','FREERTOS_UNICORE',
          'PM_ENABLE','SPIRAM','VFS_SUPPORT_SELECT']
BUILD_KEYS=['core','runtime','task_core','task_priority','task_stack_reserved_bytes','sdk','hashes',
            'resource_qualification','SDK_build_only','startup_qualified','class_layout','async_storage']
BUILD_HASHES=['ota_sha256','archive_sha256','source_archive_sha256','compiled_cpp_sha256','compiled_header_sha256',
              'source_config_sha256','build_config_sha256','schema_source_sha256','elf_sha256','baseline_image_sha256']


def require(value,message):
    if not value: raise ValueError(message)


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def sha(raw):return hashlib.sha256(raw).hexdigest()


def pick(value,allowed,required=True):
    return {k:value[k] for k in allowed if required or k in value}


def keys(value,allowed,name,optional=False):
    require(type(value) is dict and (set(value)<=set(allowed) if optional else set(value)==set(allowed)),name+' field allowlist differs')


def natural(v):
    require(type(v) is int and v>=0,'nonnegative integer required')
    return v


def exact(a,b,name):require(encoded(a)==encoded(b),name+' differs')


def same(a,b,name='regrade'):
    if type(b) in [int,float]:require(type(a) in [int,float] and math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-9),name+' numeric differs')
    elif type(b) is dict:
        keys(a,b,name)
        for k,v in b.items():same(a[k],v,name+'.'+k)
    elif type(b) is list:
        require(type(a) is list and len(a)==len(b),name+' length differs')
        for x,y in zip(a,b):same(x,y,name)
    else:require(type(a) is type(b) and a==b,name+' differs')


def private(raw):
    text=raw.decode('utf-8')
    patterns=[r'(?<![a-z])[a-z]:[\\/]',('/'+'Users/|/'+'home/'),
              r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',r'\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b',
              r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b',
              ('noise_'+'psk|private-'+'checkpoints|t3-'+'thread://')]
    return any(re.search(pattern,text,re.I) for pattern in patterns)


def relative(name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and ':' not in name and '\\' not in name and str(p)==name,'unsafe relative name')
    return name


def unpack(packed,metadata):
    require(len(packed)==metadata['bytes'] and sha(packed)==metadata['sha256'],'gzip hash/length differs')
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as f: raw=f.read(MAX_EXPANDED+1)
    require(len(raw)==metadata['raw_bytes']<=MAX_EXPANDED and sha(raw)==metadata['raw_sha256'],'expanded hash/length differs')
    return raw


def q(values,p):
    values=sorted(values);at=(len(values)-1)*p;a,b=math.floor(at),math.ceil(at)
    return values[a]+(values[b]-values[a])*(at-a)


def decision(name,controls,lookup,eligible):
    strict=[]
    for client,path in CELLS:
        a=lookup[name,client,path];cs=[lookup[c,client,path] for c in controls];best=min(cs,key=lambda z:z['median_ms'])
        strict.append({'client':client,'path':path,'best_C':best['name'],'median_ratio':a['median_ms']/best['median_ms'],
                       'boot_best_C_ratios':[a['boot_medians_ms'][i]/min(z['boot_medians_ms'][i] for z in cs) for i in [0,1]]})
    geom=st.geometric_mean(z['median_ratio'] for z in strict)
    boots={c:[st.geometric_mean(lookup[name,client,path]['boot_medians_ms'][i]/lookup[c,client,path]['boot_medians_ms'][i] for client,path in CELLS) for i in [0,1]] for c in controls}
    allcells=all(z['median_ratio']<1 for z in strict);bootpass=all(v<1 for vs in boots.values() for v in vs)
    return {'name':name,'promising':bool(eligible and allcells and geom<=.97 and bootpass),
            'strict_best_C_geometric_median_ratio':geom,'all_six_cell_medians_below_best_C':allcells,
            'boot_best_C_geometric_ratios':[st.geometric_mean(z['boot_best_C_ratios'][i] for z in strict) for i in [0,1]],
            'boot_pairwise_C_geometric_ratios':boots,'all_boot_pairwise_geomeans_below_one':bootpass,'cells':strict}


def grade(value):
    keys(value,['schema','status','claims','method','boots','commitments','proof_attestations'],'dataset')
    require(value['schema']=='coaptic-target-cpu-speed-portable/1','schema differs')
    exact(value['claims'],CLAIMS,'claim boundaries')
    status=value['status'];exact(status,{'collection_complete':True,'passed':True,'restore_verified':True,
                                        'parent_clocks_released':True,'parent_normal_restored':True,
                                        'startup_contiguous_floor_qualified':False,'startup_qualification_open':True},'completion/qualification scope')
    m=value['method'];keys(m,['core','baseline','runtime','names','C_names','candidate_names','order','control_pairs','post_ota_settle_s',
                            'post_ready_settle_s','clients_per_boot','client_process_timeout_s','c_service_window_ms',
                            'capacities','read_timeout_s','sequential_concurrency','no_interoperation_gap','candidate_opt_level','candidate_lto'], 'method')
    require(m['core']==CORE and m['baseline']==BASE and m['runtime']==RUNTIME,'source pins differ')
    exact(m['names'],NAMES,'profile names');exact(m['C_names'],C_NAMES,'C controls');exact(m['candidate_names'],CANDIDATES,'candidates')
    exact(m['order'],[list(range(6)),list(reversed(range(6)))],'opposite boot order');exact(m['capacities'],CAPACITIES,'configured capacities')
    require(m['post_ota_settle_s']==30 and m['post_ready_settle_s']==.5 and m['clients_per_boot']==4 and
            m['client_process_timeout_s']==14 and m['c_service_window_ms']==120000 and m['read_timeout_s']==5 and
            m['sequential_concurrency']==1 and m['no_interoperation_gap'] is True and
            m['candidate_opt_level']=='3' and m['candidate_lto']=='thin','finite method/profile differs')
    exact(m['control_pairs'],[[SYNC,OWN_SYNC],[ASYNC,OWN_ASYNC]],'own controls')
    require(len(value['boots'])==12,'must retain all twelve boots')
    groups=defaultdict(list);processes=[];stable=True;signals=[]
    for index,b in enumerate(value['boots']):
        keys(b,['name','round','slot','mode','configuration','connections','unexpected_disconnects','connect_refusals','network','heap',
                'image_bytes','settle_seconds','timing_start_utc','timing_end_utc','linked_iram_added_bytes','task_policy',
                'instruction_cache_bytes','physical_net_static_ram_added_bytes','stack_reserved_bytes','stack_observed_used_bytes',
                'C_cleanup','C_terminal','application_dropped','wait_errors','wifi_signal_dbm','uptime_seconds','clients'],'boot')
        rn,slot=index//6+1,index%6;name=NAMES[m['order'][rn-1][slot]]
        require(b['name']==name and b['round']==rn and b['slot']==slot+1,'boot/process mapping differs')
        expected_mode='C' if name in C_NAMES else 'async' if name in [ASYNC,OWN_ASYNC] else 'sync'
        require(b['mode']==expected_mode,'actual server mode differs');cfg=b['configuration'];keys(cfg,BUILD_KEYS,'configuration')
        for k in ['task_core','task_priority','task_stack_reserved_bytes']:require(type(cfg[k]) is int,'compiled task integer missing')
        stack=16384 if expected_mode=='C' else 196608 if expected_mode=='async' else 98304
        require(cfg['task_stack_reserved_bytes']==b['stack_reserved_bytes']==stack and cfg['task_priority']==1,'original worker reservation differs')
        require(cfg['task_core']==(1 if name in [C_PIN,SYNC,ASYNC] else -1),'compiled task core differs')
        keys(cfg['sdk'],SDK_KEYS,'SDK',True)
        for k,v in {'ESP_DEFAULT_CPU_FREQ_MHZ':240,'ESP32S3_INSTRUCTION_CACHE_SIZE':32768,'ESP32S3_ICACHE_ASSOCIATED_WAYS':8,'ESP32S3_INSTRUCTION_CACHE_LINE_SIZE':32}.items():
            require(type(cfg['sdk'].get(k)) is int and cfg['sdk'][k]==v,'attested CPU/instruction-cache geometry differs')
        if name in CANDIDATES:
            require(cfg['core']==CORE and cfg['runtime']==RUNTIME and cfg['resource_qualification'] is True and cfg['SDK_build_only'] is True and cfg['startup_qualified'] is False,'candidate identity/qualification differs')
            for k,v in {'ESP32S3_DATA_CACHE_SIZE':32768,'ESP32S3_DCACHE_ASSOCIATED_WAYS':8,'ESP32S3_DATA_CACHE_LINE_SIZE':32,'FREERTOS_HZ':1000,'FREERTOS_UNICORE':False}.items():
                require(type(cfg['sdk'].get(k)) is type(v) and cfg['sdk'][k]==v,'candidate actual data-cache/tick/core SDK differs')
        else:
            require('ESP32S3_DATA_CACHE_SIZE' not in cfg['sdk'] and 'FREERTOS_HZ' not in cfg['sdk'],'old controls gained unrecorded D-cache/tick attestations')
        keys(cfg['hashes'],BUILD_HASHES,'image/source hashes',True)
        require(all(v is None or (type(v) is str and re.fullmatch('[0-9a-f]{64}',v)) for v in cfg['hashes'].values()),'image/source digest format differs')
        require(type(cfg['hashes'].get('ota_sha256')) is str and type(cfg['hashes'].get('archive_sha256')) is str,'required image/archive digest missing')
        if cfg['class_layout'] is not None:
            layout=cfg['class_layout'];keys(layout,CLASS_KEYS,'class layout')
            require(type(layout['delta_bytes']) is int and layout['after_bytes']-layout['before_bytes']==layout['delta_bytes'] and
                    natural(layout['after_bytes'])<=layout['whole_object_ceiling_bytes'] and re.fullmatch('[0-9a-f]{64}',layout['object_sha256']),'selected class owner accounting differs')
        if cfg['async_storage'] is not None:
            storage=cfg['async_storage'];keys(storage,STORAGE_KEYS,'async selected storage')
            require(natural(storage['runtime_bytes'])<=storage['runtime_ceiling_bytes'] and natural(storage['future_bytes'])<=storage['future_ceiling_bytes'],'selected runtime/future owner bound differs')
        policy=b['task_policy'];keys(policy,POLICY_KEYS,'task-policy witness')
        require(policy['compiled_core']==cfg['task_core'] and policy['compiled_priority']==1,'compiled-policy witness join differs')
        if expected_mode=='C':require(policy['available'] is True and policy['observed_core']==1 and policy['runtime_policy_qualified'] is True,'C startup policy observation differs')
        else:require(policy['available'] is False and policy['records']==0 and policy['observed_core'] is None and policy['runtime_policy_qualified'] is False,'invented actual Rust task-core observation')
        require(b['settle_seconds']>=30 and b['connections']>0,'settle/API connection guard fails')
        stable &= b['unexpected_disconnects']==b['connect_refusals']==0 and b['application_dropped'] in [None,0] and b['wait_errors'] in [None,0]
        require(b['instruction_cache_bytes']==32768 and 0<=b['stack_observed_used_bytes']<=stack,'cache/stack witness differs')
        natural(b['image_bytes']);natural(b['linked_iram_added_bytes']);natural(b['physical_net_static_ram_added_bytes'])
        require(b['physical_net_static_ram_added_bytes'] <= (9984 if name==ASYNC else 61440 if name==SYNC else 65536 if name==OWN_SYNC else 12288 if expected_mode=='async' else 98304),'static memory bound fails')
        require(b['linked_iram_added_bytes'] <= (12288 if expected_mode=='async' else 65536 if name in [SYNC,OWN_SYNC] else 98304),'IRAM bound fails')
        for z in b['network']:
            keys(z,NETWORK_KEYS,'network counters')
            for v in z.values():natural(v)
        for heap in b['heap']:
            keys(heap,HEAP_KEYS,'heap',True)
            for k,v in heap.items():
                if k not in ['phase','caps'] and v is not None:natural(v)
        if expected_mode=='C':
            require(b['heap']==[] and b['network']==[] and b['application_dropped'] is None and b['wait_errors'] is None,'C unavailable running metrics fabricated')
            keys(b['C_cleanup'],CLEANUP_KEYS,'C terminal cleanup');keys(b['C_terminal'],TERMINAL_KEYS,'C terminal')
            require(b['C_terminal']['passed'] is True and all(type(b['C_cleanup'][k]) is int and b['C_cleanup'][k]>0 for k in ['free_before_b','free_after_b','min_b']),'C terminal cleanup failed')
            require(b['C_cleanup']['stack_b']==stack and b['C_cleanup']['stack_b']-b['C_cleanup']['stack_free_b']==b['stack_observed_used_bytes'],'C cleanup stack owner join differs')
        else:
            require(b['C_cleanup'] is None and b['C_terminal'] is None and b['network'],'Rust/C phase scope differs')
            running=[z for z in b['heap'] if z.get('phase')=='running' and z.get('caps')=='all_8bit'];require(running,'running heap witnesses missing')
            require(all(8192<=h['free_bytes']<=h['total_bytes'] and h['largest_free_block_bytes']>=8192 and h['region_min_free_sum_bytes']>=12288 for h in running),'running heap guard fails')
            require(max(z['stack_capacity_bytes'] for z in b['network'])==stack and max(z['stack_high_water_bytes'] for z in b['network'])==b['stack_observed_used_bytes'],'network/stack owner join differs')
            require(max(z['dropped'] for z in b['network'])==b['application_dropped'] and max(z['wait_errors'] for z in b['network'])==b['wait_errors'],'operational network counter join differs')
        require(all(type(v) in [int,float] and math.isfinite(v) for v in b['wifi_signal_dbm']+b['uptime_seconds']),'non-numeric metrics')
        signals.extend(b['wifi_signal_dbm'])
        order=['sync','async','async','sync'] if rn==1 else ['async','sync','sync','async'];require(len(b['clients'])==4,'client processes missing')
        for ordinal,(client,mode) in enumerate(zip(b['clients'],order),1):
            keys(client,['mode','ordinal','passed','completed','original_report_sha256','operations'],'client')
            require(client['mode']==mode and client['ordinal']==ordinal and client['passed'] is True and client['completed']==24 and len(client['operations'])==24,'client completion/order differs')
            require(re.fullmatch('[0-9a-f]{64}',client['original_report_sha256']),'client raw commitment malformed')
            expected=[(i,p,n) for i in range(8) for p,n in [('identity',32),('test',7),('large',2000)]]
            for op,identity in zip(client['operations'],expected):
                keys(op,OP_KEYS,'operation');require(op['passed'] is True and (op['iteration'],op['path'],op['bytes'])==identity,'operation identity/order differs')
                require(type(op['elapsed_ns']) is int and 0<op['elapsed_ns']<5000000000,'operation elapsed bound fails')
                stages=[op[k] for k in ['prepare_ns','poll_ns','checkpoint_ns','take_ns','verify_ns','sleep_ns']]
                require(all(type(v) is int and v>=0 for v in stages) and sum(stages)<=op['elapsed_ns'],'stage/accounting bound fails')
                for k in ['request_send_attempts','distinct_request_sends','repeated_request_send_attempts']:natural(op[k])
                require(op['request_send_attempts']-op['distinct_request_sends']==op['repeated_request_send_attempts'],'send/repeat accounting differs')
                stable &= op['repeated_request_send_attempts']==0
                groups[name,mode,op['path']].append((rn,op['elapsed_ns']/1e6,op['repeated_request_send_attempts']))
            processes.append({'name':name,'client':mode,'round':rn,'ordinal':ordinal,'completed':24})
    require(len(processes)==48 and sum(len(g) for g in groups.values())==1152 and len(groups)==36,'full cohort coverage differs')
    summary=[]
    for (name,client,path),rows in sorted(groups.items()):
        require(len(rows)==32,'cell lacks all 32 reads');v=[x for _,x,_ in rows]
        summary.append({'name':name,'client':client,'path':path,'n':32,'median_ms':st.median(v),'p95_ms':q(v,.95),'p99_ms':q(v,.99),'max_ms':max(v),
                        'boot_medians_ms':[st.median(x for rn,x,_ in rows if rn==i) for i in [1,2]],'repeated_request_send_attempts':sum(n for _,_,n in rows)})
    lookup={(z['name'],z['client'],z['path']):z for z in summary};comparisons=[]
    pairs=m['control_pairs']+[[a,b] for a in NAMES if a not in C_NAMES for b in C_NAMES]
    for left,right in pairs:
        cells=[]
        for client,path in CELLS:
            a,b=lookup[left,client,path],lookup[right,client,path]
            cells.append({'client':client,'path':path,'median_ratio':a['median_ms']/b['median_ms'],'p95_ratio':a['p95_ms']/b['p95_ms'],'p99_ratio':a['p99_ms']/b['p99_ms'],
                          'boot_median_ratios':[v/w for v,w in zip(a['boot_medians_ms'],b['boot_medians_ms'])]})
        comparisons.append({'left':left,'right':right,'geometric_median_ratio':st.geometric_mean(z['median_ratio'] for z in cells),'worst_median_ratio':max(z['median_ratio'] for z in cells),
                            'boot_geometric_median_ratios':[st.geometric_mean(z['boot_median_ratios'][i] for z in cells) for i in [0,1]],'cells':cells})
    memory=[]
    for name in NAMES:
        bs=[b for b in value['boots'] if b['name']==name];require(len(bs)==2,'memory replication differs')
        require(all(bs[0][k]==bs[1][k] for k in ['image_bytes','linked_iram_added_bytes','physical_net_static_ram_added_bytes','configuration']),'profile image/source changed between boots')
        memory.append({'name':name,'task_stack_reserved_bytes':bs[0]['stack_reserved_bytes'],'max_observed_lifetime_stack_bytes':max(b['stack_observed_used_bytes'] for b in bs),
                       'per_boot_observed_used_bytes':[b['stack_observed_used_bytes'] for b in bs],'image_bytes':bs[0]['image_bytes'],'linked_iram_added_bytes':bs[0]['linked_iram_added_bytes'],
                       'physical_net_static_ram_added_bytes':bs[0]['physical_net_static_ram_added_bytes'],'instruction_cache_bytes':bs[0]['instruction_cache_bytes'],
                       'observed_total_heap_bytes':sorted({h['total_bytes'] for b in bs for h in b['heap'] if h.get('caps')=='all_8bit'}),
                       'per_boot_running_free_bytes':[min((h['free_bytes'] for h in b['heap'] if h.get('phase')=='running' and h.get('caps')=='all_8bit'),default=None) for b in bs],
                       'per_boot_running_region_min_free_sum_bytes':[min((h['region_min_free_sum_bytes'] for h in b['heap'] if h.get('phase')=='running' and h.get('caps')=='all_8bit'),default=None) for b in bs]})
    keys(value['proof_attestations'],['controller_checks_passed','private_identity_source_binary_API_joins','independent_firmware_rebuild','rerun_for_export'],'producer proof scope')
    exact(value['proof_attestations'],{'controller_checks_passed':39,'private_identity_source_binary_API_joins':True,'independent_firmware_rebuild':False,'rerun_for_export':False},'retained producer proof scope')
    for c in value['commitments']:
        keys(c,['role','bytes','sha256'],'raw commitment');natural(c['bytes']);require(re.fullmatch('[A-Za-z0-9_-]+',c['role']) and re.fullmatch('[0-9a-f]{64}',c['sha256']),'unsafe raw commitment')
    return {'verified_complete':True,'operations':1152,'boots':12,'processes':processes,'stability_passed':bool(stable),'restore_verified':True,
            'startup_contiguous_floor_qualified':False,'startup_qualification_open':True,
            'summary':summary,'comparisons':comparisons,'screen_decisions':[decision(name,C_NAMES,lookup,stable) for name in CANDIDATES],
            'memory':memory,'RSSI_dbm':{'min':min(signals),'max':max(signals),'range':max(signals)-min(signals)},'claims':value['claims']}
