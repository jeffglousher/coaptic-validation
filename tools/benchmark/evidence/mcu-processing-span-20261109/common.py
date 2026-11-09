"""Narrow positive allowlists and arithmetic for the frozen MCU V2 evidence.

Uses the hash/privacy/whitelist pattern of esp-idle-observe-20261109. No network,
firmware build, packet reconstruction or performance-clock operations occur here.
"""
import ast
import gzip
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import statistics as st

BUDGET = 2 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024
TESTNET = '192.0.2.1'
CORE = 'de9230aa22dab0c67604ea4b040a1c1daa59a41e'
RUNTIME = '32f8fcac22fc16b1957c35f4f145df6be3a72532'
PROFILES = ['Hsync', 'Hasync', 'Cpin', 'Cfloat']
PATHS = ['identity', 'test', 'large']
CLAIMS = {'task_CPU': False, 'clean_RTT': False, 'speed_gain': False,
          'adopted': False, 'goal_complete': False, 'performance_operations': 0}
CAPACITIES = {'routes': 8, 'populated_routes': 7, 'Calls': 4, 'deferred': 0,
              'rx_slots': 2, 'tx_slots': 2, 'packet_bytes': 1152,
              'rx_body_slots': 1, 'tx_body_slots': 1, 'body_bytes': 4096,
              'dedup': 4, 'Observe': 2, 'token_bytes': 8}
BOUNDS = {'C_service_ms': 120000, 'C_terminal_seconds': 128, 'capture_seconds': 240,
          'client_seconds': 14, 'post_ota_settle_seconds': 30,
          'post_ready_settle_seconds': .5, 'publication_seconds': 40, 'readiness_seconds': 48}
SDK = {'ESP32S3_DATA_CACHE_16KB': False, 'ESP32S3_DATA_CACHE_32KB': True,
       'ESP32S3_DATA_CACHE_4WAYS': False, 'ESP32S3_DATA_CACHE_64KB': False,
       'ESP32S3_DATA_CACHE_8WAYS': True, 'ESP32S3_DATA_CACHE_LINE_16B': False,
       'ESP32S3_DATA_CACHE_LINE_32B': True, 'ESP32S3_DATA_CACHE_LINE_64B': False,
       'ESP32S3_DATA_CACHE_LINE_SIZE': 32, 'ESP32S3_DATA_CACHE_SIZE': 32768,
       'ESP32S3_DCACHE_ASSOCIATED_WAYS': 8, 'ESP32S3_ICACHE_ASSOCIATED_WAYS': 8,
       'ESP32S3_INSTRUCTION_CACHE_16KB': False, 'ESP32S3_INSTRUCTION_CACHE_32KB': True,
       'ESP32S3_INSTRUCTION_CACHE_4WAYS': False, 'ESP32S3_INSTRUCTION_CACHE_8WAYS': True,
       'ESP32S3_INSTRUCTION_CACHE_LINE_16B': False, 'ESP32S3_INSTRUCTION_CACHE_LINE_32B': True,
       'ESP32S3_INSTRUCTION_CACHE_LINE_SIZE': 32, 'ESP32S3_INSTRUCTION_CACHE_SIZE': 32768,
       'ESPTOOLPY_FLASHFREQ': '80m', 'ESPTOOLPY_FLASHMODE': 'dio',
       'ESP_DEFAULT_CPU_FREQ_MHZ': 240, 'FREERTOS_HZ': 1000, 'FREERTOS_UNICORE': False,
       'PM_ENABLE': False, 'SPIRAM': False, 'VFS_SUPPORT_SELECT': False}
SPAN_KEYS = ['index', 'path', 'block', 'receive_return_to_send_entry_wall_us',
             'receive_call_wall_us', 'send_call_wall_us', 'send_return_us',
             'native_select_calls', 'native_select_call_wall_us', 'native_delay_calls',
             'native_delay_call_wall_us', 'nested_native_select_calls',
             'nested_native_delay_calls', 'residual_wall_us']
OP_KEYS = ['path', 'receive_return_to_send_entry_sum_wall_us', 'datagrams',
           'native_select_call_sum_wall_us', 'native_delay_call_sum_wall_us', 'residual_sum_wall_us']
NATIVE_KEYS = ['native_select_calls', 'native_select_call_wall_us', 'native_delay_calls',
               'native_delay_call_wall_us', 'nested_native_select_calls', 'nested_native_delay_calls']
HEAP_KEYS = ['phase','caps','free_bytes','total_bytes','largest_free_block_bytes','region_min_free_sum_bytes']
STARTUP_KEYS = ['stack_reserved_bytes','largest_internal_before_task','largest_all8bit_before_task',
                'free_all8bit_before_task','worker_entered']
MEMORY_KEYS = ['worker_reserved_bytes','observed_lifetime_stack_used_before_clients_bytes',
               'observed_lifetime_stack_used_after_capture_bytes','before_task_largest_internal_bytes',
               'required_before_task_largest_internal_bytes','observer_context_stack_bytes',
               'observer_global_bytes','observer_storage_bytes','observer_requested_heap_bytes',
               'main_sram_static_bytes','clean_main_sram_static_bytes',
               'observer_main_sram_static_delta_bytes','observer_row_encoder_stack_bound_bytes']
HASH_KEYS = ['archive_sha256','source_archive_sha256','source_cpp_sha256','compiled_cpp_sha256',
             'compiled_header_sha256','ota_sha256','observer_source_sha256',
             'observer_manifest_sha256','observer_protocol_sha256']
COUNTER_KEYS = {'rx':['rx','would_block','peek_calls','rx_error','rx_refused','rx_replaced','rx_abandoned'],
                'tx':['tx','success','failed','partial','unmatched','refused'],
                'observer':['rows','rows_refused','bind_conflict','fd_reuse','native_refused','saturated']}


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def keys(value, expected, name):
    require(type(value) is dict and set(value)==set(expected),name+' field allowlist differs')


def pick(value, allowed):
    return {key:value[key] for key in allowed}


def natural(value):
    require(type(value) is int and value>=0,'nonnegative integer required')
    return value


def exact(actual, expected, name):
    require(encoded(actual)==encoded(expected),name+' differs')


def relative(name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and ':' not in name and '\\' not in name and str(p)==name,'unsafe relative filename')
    return name


def private(raw):
    text=raw.decode('utf-8')
    ips=re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',text)
    if any(ip!=TESTNET for ip in ips): return True
    patterns=[r'(?<![a-z])[a-z]:[\\/]',('/'+'Users/|/'+'home/'),
              r'\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b',
              r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b',
              ('noise_'+'psk|private-'+'checkpoints|t3-'+'thread://')]
    return any(re.search(p,text,re.I) for p in patterns)


def normalized_matcher(raw, replace=False):
    text=raw.decode('utf-8');tree=ast.parse(text)
    nodes=[n for n in tree.body if isinstance(n,ast.Assign) and
           any(isinstance(t,ast.Name) and t.id=='EXPECTED_IP' for t in n.targets)]
    require(len(nodes)==1 and type(nodes[0].value) is ast.Constant and type(nodes[0].value.value) in [str,int],'matcher expected-IP assignment differs')
    node=nodes[0].value
    replacement=TESTNET if type(node.value) is str else int.from_bytes(bytes(map(int,TESTNET.split('.'))),'big')
    if replace:
        lines=text.splitlines(keepends=True)
        require(node.lineno==node.end_lineno,'matcher address literal spans lines')
        line=lines[node.lineno-1]
        lines[node.lineno-1]=line[:node.col_offset]+repr(replacement)+line[node.end_col_offset:]
        public=''.join(lines).encode()
    else:
        require(node.value==replacement,'matcher address is not TEST-NET')
        public=raw
    node.value='__EXPECTED_IP_REDACTED__'
    normalized=sha(ast.dump(tree,include_attributes=False).encode())
    if replace:
        same_raw,public_ast=normalized_matcher(public)
        require(normalized==public_ast,'matcher changes exceed address constant')
        require(same_raw==public,'matcher normalization is unstable')
    return public,normalized


def unpack(packed, metadata):
    require(sha(packed)==metadata['sha256'] and len(packed)==metadata['bytes'],'compressed digest/length differs')
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream: raw=stream.read(MAX_EXPANDED+1)
    require(len(raw)==metadata['raw_bytes']<=MAX_EXPANDED and sha(raw)==metadata['raw_sha256'],'raw digest/length differs')
    return raw


def operations(spans):
    require(len(spans)==64,'exactly 64 packet rows required')
    out=[]
    for cycle in range(16):
        batch=spans[cycle*4:cycle*4+4]
        require([(s['path'],s['block']) for s in batch]==[('identity',None),('test',None),('large',0),('large',1)],'packet path/Block2 order differs')
        for i,s in enumerate(batch):
            keys(s,SPAN_KEYS,'packet')
            require(s['block'] is None or (type(s['block']) is int and s['block'] in [0,1]),'block integer type differs')
            require(s['index']==cycle*4+i and type(s['index']) is int,'packet index missing/reordered')
            for k in SPAN_KEYS:
                if k not in ['path','block']: natural(s[k])
            require(s['receive_return_to_send_entry_wall_us']==s['residual_wall_us']+
                    s['native_select_call_wall_us']+s['native_delay_call_wall_us'],
                    'native union/residual does not reconcile; do not double-count nested calls')
        for group in (batch[:1],batch[1:2],batch[2:]):
            out.append({'path':group[0]['path'],'datagrams':len(group),
                        'receive_return_to_send_entry_sum_wall_us':sum(s['receive_return_to_send_entry_wall_us'] for s in group),
                        'native_select_call_sum_wall_us':sum(s['native_select_call_wall_us'] for s in group),
                        'native_delay_call_sum_wall_us':sum(s['native_delay_call_wall_us'] for s in group),
                        'residual_sum_wall_us':sum(s['residual_wall_us'] for s in group)})
    return out


def statistics(values):
    require(bool(values),'empty statistic group')
    return {'n':len(values),'sum_us':sum(values),'median_us':st.median(values),
            'mean_us':st.mean(values),'min_us':min(values),'max_us':max(values)}


def grade(data):
    keys(data,['schema','source_pins','claims','release_attestation','method','profiles','failures','proof_attestations','commitments'],'dataset')
    require(data['schema']=='coaptic-mcu-span-v2-portable/1','schema differs')
    exact(data['source_pins'],{'core':CORE,'runtime':RUNTIME},'measured source pins')
    exact(data['claims'],CLAIMS,'diagnostic claims')
    exact(data['release_attestation'],{'parent_clocks_released':True,'normal_restored_verified':True},'release/restoration attestation')
    method=data['method'];keys(method,['bounds','capacities','client_order','reads_per_client','datagrams_per_client',
                                      'reads_per_profile','datagrams_per_profile','boots_per_profile','total_boots',
                                      'expected_datagrams','maximum_logged_attempts','packet_bytes','quiet_us',
                                      'read_timeout_seconds','capture_limit_bytes','normal_capture_limit_bytes',
                                      'runtime_budget_bytes','running_free_floor_bytes','running_largest_floor_bytes',
                                      'running_regional_lowwater_floor_bytes','contiguous_margin_bytes','diagnostic_only'], 'method')
    exact(method,{'bounds':BOUNDS,'capacities':CAPACITIES,'client_order':['sync','async'],
                  'reads_per_client':24,'datagrams_per_client':32,'reads_per_profile':48,'datagrams_per_profile':64,
                  'boots_per_profile':1,'total_boots':4,'expected_datagrams':64,'maximum_logged_attempts':96,
                  'packet_bytes':1152,'quiet_us':15000000,'read_timeout_seconds':5,'capture_limit_bytes':524288,
                  'normal_capture_limit_bytes':262144,'runtime_budget_bytes':8388608,
                  'running_free_floor_bytes':8192,'running_largest_floor_bytes':8192,
                  'running_regional_lowwater_floor_bytes':12288,'contiguous_margin_bytes':4096,
                  'diagnostic_only':True},'frozen finite method')
    require([p['profile'] for p in data['profiles']]==PROFILES,'profile set/order differs')
    summary=[];all_native={k:0 for k in NATIVE_KEYS+['processing_wall_sum_us','residual_wall_sum_us']}
    for p in data['profiles']:
        keys(p,['profile','status','clients','source_hashes','codegen','task_policy','startup','memory',
                'heap_before_clients','heap_after_capture','sdk','counters','spans','operations'],'profile')
        name=p['profile'];stack=98304 if name=='Hsync' else 196608 if name=='Hasync' else 16384
        exact(p['status'],{'passed':True,'startup_guard_passed':True,'reads_verified':48,'datagrams_matched':64,'boots':1},'profile status')
        for c,mode in zip(p['clients'],['sync','async']):
            exact(c,{'mode':mode,'passed':True,'reads_verified':24,'datagrams_matched':32},'client completion')
        require(len(p['clients'])==2,'client replication differs')
        keys(p['source_hashes'],HASH_KEYS,'source commitments')
        require(all(re.fullmatch('[0-9a-f]{64}',h) for h in p['source_hashes'].values()),'source digest format differs')
        expected_codegen={'opt_level':'3','lto':'thin'} if name=='Hsync' else {'opt_level':'s','lto':'fat'} if name=='Hasync' else {'compiler':'unchanged pinned libcoap archive'}
        exact(p['codegen'],expected_codegen,'integrated codegen profile')
        keys(p['task_policy'],['actual_available','compiled_core','compiled_priority','startup_core_observed','records'],'task policy')
        rust=name.startswith('H');core=1 if name=='Cpin' else -1
        exact(p['task_policy'],{'actual_available':not rust,'compiled_core':core,'compiled_priority':1,
                                'startup_core_observed':None if rust else 1,'records':0 if rust else 1},'observed/compiled task policy')
        startup=p['startup'];keys(startup,STARTUP_KEYS,'startup')
        require(startup['worker_entered'] is True and startup['stack_reserved_bytes']==stack and
                natural(startup['largest_internal_before_task'])>=stack+4096,'startup contiguous guard fails')
        for k in STARTUP_KEYS:
            if k!='worker_entered':natural(startup[k])
        memory=p['memory'];keys(memory,MEMORY_KEYS,'memory')
        for v in memory.values():natural(v)
        require(memory['worker_reserved_bytes']==stack and memory['required_before_task_largest_internal_bytes']==stack+4096 and
                memory['before_task_largest_internal_bytes']==startup['largest_internal_before_task'],'memory/startup owner join differs')
        require(0<=memory['observed_lifetime_stack_used_before_clients_bytes']<=
                memory['observed_lifetime_stack_used_after_capture_bytes']<=stack,'stack watermark/reservation differs')
        require(memory['observer_context_stack_bytes']==2512 and memory['observer_global_bytes']==28 and
                memory['observer_storage_bytes']==2540 and memory['observer_requested_heap_bytes']==0 and
                memory['observer_row_encoder_stack_bound_bytes']==256,'observer nested storage differs')
        require(memory['main_sram_static_bytes']-memory['clean_main_sram_static_bytes']==
                memory['observer_main_sram_static_delta_bytes']==(32 if name=='Hasync' else 24),'observer static delta differs')
        for heap in [p['heap_before_clients'],p['heap_after_capture']]:
            keys(heap,HEAP_KEYS,'heap')
            require(heap['phase']=='running' and heap['caps']=='all_8bit','heap scope differs')
            for k in HEAP_KEYS[2:]:natural(heap[k])
            require(8192<=heap['free_bytes']<=heap['total_bytes'] and heap['largest_free_block_bytes']>=8192 and
                    heap['region_min_free_sum_bytes']>=12288,'running heap floor fails')
        exact(p['sdk'],{**SDK,'VFS_SUPPORT_SELECT':name=='Hasync'},'actual per-image SDK facts')
        counters=p['counters'];keys(counters,COUNTER_KEYS,'counter groups')
        for group,allowed in COUNTER_KEYS.items():
            keys(counters[group],allowed,'counter '+group)
            for k,v in counters[group].items():
                if k=='saturated': require(v is False,'observer saturated')
                else:natural(v)
        require(counters['rx']['rx']==counters['tx']['tx']==counters['tx']['success']==counters['observer']['rows']==64,'RX/TX/observer count differs')
        for group,names in {'rx':['rx_error','rx_refused','rx_replaced','rx_abandoned'],
                            'tx':['failed','partial','unmatched','refused'],
                            'observer':['rows_refused','bind_conflict','fd_reuse','native_refused']}.items():
            require(all(counters[group][key]==0 for key in names),'packet/observer failure retained')
        ops=operations(p['spans']);require(len(p['operations'])==48,'operation rows missing')
        for o in p['operations']:keys(o,OP_KEYS,'operation')
        exact(ops,p['operations'],'independent two-block operation reconstruction')
        native={k:sum(s[k] for s in p['spans']) for k in NATIVE_KEYS}
        native['processing_wall_sum_us']=sum(s['receive_return_to_send_entry_wall_us'] for s in p['spans'])
        native['residual_wall_sum_us']=sum(s['residual_wall_us'] for s in p['spans'])
        require(native['native_select_calls']==native['native_select_call_wall_us']==0,'frozen select total differs')
        require((native['native_delay_calls'],native['native_delay_call_wall_us'])==((2,1139) if name=='Hasync' else (0,0)),'frozen nonzero Hasync delay evidence lost')
        for k in all_native:all_native[k]+=native[k]
        groups=[{'path':path,**statistics([o['receive_return_to_send_entry_sum_wall_us'] for o in ops if o['path']==path])} for path in PATHS]
        packets=[{'path':path,'block':block,**statistics([s['receive_return_to_send_entry_wall_us'] for s in p['spans'] if s['path']==path and s['block']==block])} for path,block in [('identity',None),('test',None),('large',0),('large',1)]]
        clients=[{'mode':mode,'operations':[{'path':path,**statistics([o['receive_return_to_send_entry_sum_wall_us'] for o in ops[i*24:(i+1)*24] if o['path']==path])} for path in PATHS]} for i,mode in enumerate(['sync','async'])]
        summary.append({'profile':name,'operations':groups,'packet_groups':packets,'clients':clients,'native':native})
    failures=data['failures'];require(len(failures)==2,'preserved failure set differs')
    exact(failures[0],{'attempt':'V1 capture','passed':False,'status':'incomplete','normal_restore_verified':True,
                       'verified_client_reads':48,'full_packet_publication_complete':False},'V1 failure')
    exact(failures[1],{'attempt':'V2 original Cpin SDK/component pipeline','passed':False,
                       'source_assertions_passed':True,'immutable_archive_refused':True,
                       'staging_restored':True,'fixture_unchanged':True,'cleanup_unresolved':False,
                       'guarded_controls_inventory_is_separate':True},'V2 original pipeline failure')
    exact(data['proof_attestations'],{'codec_checks_passed':14,'actual_source_Cpp_host_mock_passed':True,
                                     'controller_checks_passed':28,'full_target_guards_passed':True,
                                     'private_packet_body_identity_OTA_API_joins':True,
                                     'rerun_for_export':False,'independent_firmware_rebuild':False},'retained producer proof scope')
    require(bool(data['commitments']),'private input commitments missing')
    roles=[]
    for c in data['commitments']:
        keys(c,['role','bytes','sha256'],'private commitment');natural(c['bytes']);roles.append(c['role'])
        require(re.fullmatch('[a-zA-Z0-9_-]+',c['role']) and re.fullmatch('[0-9a-f]{64}',c['sha256']),'unsafe commitment label/digest')
    require(len(roles)==len(set(roles)),'duplicate private input role')
    return {'schema':'coaptic-mcu-span-v2-regrade/1','arithmetic_verified':True,'reads':192,'datagrams':256,
            'boots':4,'profiles':summary,'native_totals':all_native,'claims':data['claims'],
            'scope':'Numeric regrade plus retained private producer attestations; no CPU, clean RTT, speed, adoption or completed-goal claim.'}
