"""Export the completed fresh TargetCPU screen after explicit parent release."""
import argparse
from collections import Counter
import gzip
import json
from pathlib import Path, PureWindowsPath
from common import *

ANALYSIS_SHA='65d4c98c408d4079765b399b068cef52794d768784eb1f8a09fcbff9a62c9bc0'
METHOD_HASH_KEYS=['capture_script_sha256','final_build_manifest_sha256','script_sha256','analyzer_sha256',
                  'source_manifest_sha256','producer_inventory_sha256','joined_plan_sha256','raw_SDK_inventory_sha256',
                  'source_SDK_plan_sha256','preflight_preparation_sha256','safety_checks_sha256',
                  'comparison_helper_proof_sha256','parent_review_sha256']
COMPARISON_KEYS=['left','right','geometric_median_ratio','worst_median_ratio','boot_geometric_median_ratios','cells']
DECISION_KEYS=['name','promising','strict_best_C_geometric_median_ratio','all_six_cell_medians_below_best_C',
               'boot_best_C_geometric_ratios','boot_pairwise_C_geometric_ratios','all_boot_pairwise_geomeans_below_one','cells']


def operation(value):
    out=pick(value,[k for k in OP_KEYS if k not in ['request_send_attempts','distinct_request_sends','repeated_request_send_attempts']])
    sends=Counter(e[4] for e in value['events'] if e[0]==2 and e[3]>4)
    out.update(request_send_attempts=sum(sends.values()),distinct_request_sends=len(sends),
               repeated_request_send_attempts=sum(n-1 for n in sends.values()))
    return out


def export(root,here,clocks_released=False,normal_restored=False):
    require(clocks_released and normal_restored,'explicit parent clocks-released and normal-restored flags required')
    root=Path(root);here=Path(here);destination=here/'package'
    require(not destination.exists(),'refuse existing package; preserve prior output')
    commitments=[]
    def raw(rel,role,expected=None):
        b=(root/rel).read_bytes();digest=sha(b);require(expected is None or digest==expected,'private digest mismatch: '+role)
        commitments.append({'role':role,'bytes':len(b),'sha256':digest});return b
    def load(rel,role,expected=None):return json.loads(raw(rel,role,expected))
    analysis=load('target-cpu-speed-analysis.json','original_analysis',ANALYSIS_SHA)
    result=load('target-cpu-speed-comparison/result.json','original_result',analysis['inputs']['raw_sha256'])
    method=load('target-cpu-speed-controller/METHOD-BEFORE.json','frozen_method',analysis['inputs']['method_sha256'])
    load('target-cpu-speed-controller/firmware-inventory.json','frozen_controller_inventory',analysis['inputs']['manifest_sha256'])
    raw('target-cpu-speed-controller/analyze_target_cpu_speed.py','original_private_analyzer',analysis['inputs']['script_sha256'])
    raw('target-cpu-speed-controller/run_target_cpu_speed.py','original_private_controller',method['script_sha256'])
    source=load('target-cpu-affinity-source/manifest.json','affinity_manifest')
    plan=load('target-cpu-codegen-prep/plan.json','codegen_plan')
    codegen=load('target-cpu-codegen-prep/provenance.json','codegen_provenance')
    require(result['status']!='running' and result['collection_complete'] is True and result['passed'] is True and
            result['restore_verified'] is True and analysis['verified_complete'] is True and analysis['restore_verified'] is True,
            'terminal campaign incomplete or normal restoration unverified')
    require(analysis['startup_contiguous_floor_qualified'] is False and analysis['startup_qualification_open'] is True,'startup qualification scope changed')
    require(method['total_focused_check_count']==39,'reused controller check count differs')
    require(plan['candidate']==CORE and plan['baseline']==BASE and plan['runtime']==RUNTIME and codegen['passed'] is True,'codegen/source provenance differs')
    require(method['core']==CORE and method['baseline']==BASE and method['runtime']==RUNTIME and source['runtime']==RUNTIME,'measured source pins differ')
    require(len(result['cohorts'])==len(analysis['boots'])==12,'complete boot grid missing')
    boots=[];private_ids=[]
    for index,(row,ab) in enumerate(zip(result['cohorts'],analysis['boots'])):
        rn,slot=index//6+1,index%6;name=NAMES[method['order'][rn-1][slot]];build=row['build'];private_ids.append(row['run_id'])
        require(row['name']==name+'-boot-'+str(rn) and row['boot_round']==ab['round']==rn and ab['name']==name and row['slot']==slot+1,'original boot mapping differs')
        require(row['passed'] is True and row['ota_sha256']==build['ota_sha256'],'producer image/completion join differs')
        api=raw('target-cpu-speed-comparison/'+row['name']+'-api.jsonl','boot%02d_API'%(index+1),row['api_sha256'])
        require(analysis['inputs']['raw_reports_sha256'][row['name']+'-api.jsonl']==sha(api),'analysis/API commitment differs')
        api_rows=[json.loads(line) for line in api.splitlines()]
        require(api_rows[-1]['kind']=='capture_complete' and api_rows[-1]['overflow'] is False and api_rows[-1]['connections']>0,'API capture incomplete/overflow')
        exact(row['task_policy_witness'],ab['task_policy'],'private task-policy producer join')
        cfg={'core':build.get('core'),'runtime':build.get('runtime'),'task_core':build['task_core'],'task_priority':build['task_priority'],
             'task_stack_reserved_bytes':build['task_stack_reserved_bytes'],'sdk':pick(build['sdk'],SDK_KEYS,False),
             'hashes':pick(build,BUILD_HASHES,False),'resource_qualification':build.get('resource_qualification'),
             'SDK_build_only':build.get('SDK_build_only'),'startup_qualified':build.get('startup_qualified'),
             'class_layout':pick(build['class_layout'],CLASS_KEYS) if build.get('class_layout') else None,
             'async_storage':pick(build['async_storage'],STORAGE_KEYS) if build.get('async_storage') else None}
        clients=[]
        for client in row['clients']:
            label=PureWindowsPath(client['report_path']).name
            blob=raw('target-cpu-speed-comparison/'+label,'boot%02d_client%02d'%(index+1,client['ordinal']),client['source_report_sha256'])
            require(analysis['inputs']['raw_reports_sha256'][label]==sha(blob),'analysis/client commitment differs')
            report=[json.loads(line) for line in blob.splitlines()];final=report[-1]
            require(final['case']=='timing_campaign' and final['passed'] is True and final['completed']==24 and
                    final['io_mode']==client['mode'] and final['security']=='unprotected' and final['run_id']==row['run_id'],
                    'original client/body/identity attestation differs')
            clients.append({'mode':client['mode'],'ordinal':client['ordinal'],'passed':client['passed'],
                            'completed':client['operations'],'original_report_sha256':sha(blob),
                            'operations':[operation(v) for v in report if v.get('case')=='complete_operation']})
        boot={k:ab[k] for k in ['name','round','mode','connections','unexpected_disconnects','connect_refusals','image_bytes','settle_seconds',
                                'timing_start_utc','timing_end_utc','linked_iram_added_bytes','instruction_cache_bytes',
                                'physical_net_static_ram_added_bytes','stack_reserved_bytes','stack_observed_used_bytes',
                                'application_dropped','wait_errors','wifi_signal_dbm']}
        boot.update(slot=slot+1,configuration=cfg,network=[pick(v,NETWORK_KEYS) for v in ab['network']],
                    heap=[pick(v,HEAP_KEYS,False) for v in ab['heap']],task_policy=pick(ab['task_policy'],POLICY_KEYS),
                    C_cleanup=pick(ab['C_cleanup'],CLEANUP_KEYS) if ab.get('C_cleanup') is not None else None,
                    C_terminal=pick(ab['C_terminal'],TERMINAL_KEYS) if ab.get('C_terminal') is not None else None,
                    uptime_seconds=ab['last_reported_uptime_seconds'],clients=clients)
        boots.append(boot)
    data={'schema':'coaptic-target-cpu-speed-portable/1',
          'status':{'collection_complete':result['collection_complete'],'passed':result['passed'],'restore_verified':result['restore_verified'],
                    'parent_clocks_released':clocks_released,'parent_normal_restored':normal_restored,
                    'startup_contiguous_floor_qualified':analysis['startup_contiguous_floor_qualified'],
                    'startup_qualification_open':analysis['startup_qualification_open']},
          'claims':CLAIMS,'method':{'core':method['core'],'baseline':method['baseline'],'runtime':method['runtime'],
          'names':method['names'],'C_names':method['C_names'],'candidate_names':method['candidate_names'],'order':method['order'],
          'control_pairs':[[p[0],p[1]] for p in method['control_pairs']],'post_ota_settle_s':method['post_ota_settle_s'],
          'post_ready_settle_s':.5,'clients_per_boot':method['clients_per_boot'],'client_process_timeout_s':method['client_process_timeout_s'],
          'c_service_window_ms':method['c_service_window_ms'],'capacities':CAPACITIES,'read_timeout_s':5,
          'sequential_concurrency':1,'no_interoperation_gap':True,'candidate_opt_level':plan['profile_flags']['opt_level'],
          'candidate_lto':plan['profile_flags']['lto']},'boots':boots,'commitments':commitments,
          'proof_attestations':{'controller_checks_passed':method['total_focused_check_count'],
                                'private_identity_source_binary_API_joins':True,'independent_firmware_rebuild':False,'rerun_for_export':False}}
    result_grade=grade(data)
    same(result_grade['summary'],analysis['summary'],'original cell/tail summaries')
    same(result_grade['comparisons'],[pick(v,COMPARISON_KEYS) for v in analysis['comparisons']],'original comparisons')
    same(result_grade['screen_decisions'],[pick(v,DECISION_KEYS) for v in analysis['screen_decisions']],'original actual decisions')
    same(result_grade['memory'],analysis['memory'],'original memory ledger')
    same(result_grade['processes'],analysis['processes'],'original process/boot mapping')
    require(result_grade['stability_passed']==analysis['stability_passed'],'original stability outcome differs')
    patch_specs=[('target-cpu-affinity-source/task-core.patch','sources/task-core.patch',source['patch_sha256']),
                 ('target-cpu-codegen-prep/accepted-to-c015-target-annotations.patch','sources/accepted-to-c015-target-annotations.patch',codegen['source_attribute_patch_sha256'])]
    patches={}
    for original,published,digest in patch_specs:
        content=(root/original).read_bytes();require(sha(content)==digest,'original source patch hash differs');patches[published]=content
    provenance={'schema':'coaptic-target-cpu-speed-provenance/1','original_analysis_sha256':ANALYSIS_SHA,
                'original_result_sha256':analysis['inputs']['raw_sha256'],'original_method_sha256':analysis['inputs']['method_sha256'],
                'original_controller_inventory_sha256':analysis['inputs']['manifest_sha256'],
                'method_hash_commitments':pick(method,METHOD_HASH_KEYS),
                'client_binary_sha256':result['client_sha256'],'patches':{name:sha(content) for name,content in patches.items()},
                'candidate_profile_flags':pick(plan['profile_flags'],['toolchain','target','opt_level','lto','codegen_units','panic','debug','incremental','build_jobs','features','offline','locked','future_whole_ceiling_bytes']),
                'affinity_manifest_sha256':sha((root/'target-cpu-affinity-source/manifest.json').read_bytes()),
                'affinity_patch_base':source['companion_base'],'affinity_file_joins':[pick(v,['path','before_sha256','after_sha256']) for v in source['files']],
                'codegen_plan_sha256':sha((root/'target-cpu-codegen-prep/plan.json').read_bytes()),
                'codegen_provenance_sha256':sha((root/'target-cpu-codegen-prep/provenance.json').read_bytes()),
                'scope':'Original identity, source/binary, role/security and API producer joins remain private attestations. No independent firmware rebuild or packet reconstruction kit.'}
    # commit list is complete before serialization; no raw filenames or identities enter it.
    plain=encoded(data);packed=gzip.compress(plain,compresslevel=9,mtime=0)
    files={'screen.json.gz':packed,'results.json':encoded(result_grade),'provenance.json':encoded(provenance),**patches}
    for name in ['README.md','common.py','export.py','verify.py','test_export.py']:files[name]=(here/name).read_bytes()
    for name,content in files.items():
        relative(name);visible=plain if name=='screen.json.gz' else content
        require(not private(visible),'privacy refused '+name)
        require(not any(v and v.encode() in visible for v in private_ids),'private run identity survived whitelist')
    manifest={'schema':'coaptic-target-cpu-speed-manifest/1','files':{name:{'bytes':len(content),'sha256':sha(content)} for name,content in sorted(files.items())}}
    manifest['files']['screen.json.gz'].update(raw_bytes=len(plain),raw_sha256=sha(plain))
    files['manifest.json']=encoded(manifest)
    current=sum(f.stat().st_size for f in here.rglob('*') if f.is_file())
    require(current+sum(map(len,files.values()))<=BUDGET,'combined private preparation/package exceeds 1 MiB')
    destination.mkdir()
    for name,content in files.items():
        p=destination/name;p.parent.mkdir(exist_ok=True,parents=True)
        with p.open('xb') as f:f.write(content)
    return {'package_bytes':sum(map(len,files.values())),'combined_bytes':current+sum(map(len,files.values())),
            'manifest_sha256':sha(files['manifest.json']),'operations':1152,'boots':12,'client_processes':48,
            'decisions':[{'name':v['name'],'promising':v['promising'],'ratio':v['strict_best_C_geometric_median_ratio']} for v in result_grade['screen_decisions']]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-root',type=Path,required=True)
    p.add_argument('--parent-clocks-released',action='store_true');p.add_argument('--normal-restored-verified',action='store_true');a=p.parse_args()
    print(json.dumps(export(a.native_root,Path(__file__).resolve().parent,a.parent_clocks_released,a.normal_restored_verified),sort_keys=True))
