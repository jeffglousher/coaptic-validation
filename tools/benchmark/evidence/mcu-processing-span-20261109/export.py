"""Export frozen private MCU V2 records using positive field allowlists only."""
import argparse
import ast
import gzip
import json
from pathlib import Path, PureWindowsPath
import re
from common import *

RESULT_SHA='c8f13be3569998e36bcf75bfcd338723a25e75be3ac40cc458d54298358c66ae'
METHOD_SHA='2580b76d803d18edb7d9eb6c1493bad51e26a7eab513f55348e87b3d845559fa'
INVENTORY_SHA='ec58dfc5584bd666e84e5e53ef2911858ab8203a0d333ceb245cb8baf7b93622'
SOURCE_SHA='9b0aade931d49ee4f3c85495d675e8929c9be53b79d56035d7602d933a27129f'
PROTOCOL_SHA='b0e64a3763e5aeda480f37ffd6622a965593b8093ac4293dcfff53d6d180daf9'
MATCHER_SHA='174782047bf366887c683f1f6c3ea29c9ee4404bef61a99796e8a1f013bb0757'
METHOD_HASHES=['controller_sha256','diagnostic_capture_sha256','helper_proof_sha256',
               'inventory_sha256','matcher_sha256','normal_capture_sha256','normal_image_sha256','transport_sha256']


def selected_span(raw):
    return pick(raw,SPAN_KEYS)


def export(native_root, here, clocks_released=False, normal_restored=False):
    require(clocks_released and normal_restored,'explicit parent clock release and verified normal restoration are required')
    native_root=Path(native_root);here=Path(here);destination=here/'package'
    require(not destination.exists(),'refuse existing package; preserve earlier output')
    commitments=[]
    def raw(rel,role,expected=None):
        content=(native_root/rel).read_bytes();digest=sha(content)
        require(expected is None or digest==expected,'private source hash differs: '+role)
        commitments.append({'role':role,'bytes':len(content),'sha256':digest})
        return content
    def load(rel,role,expected=None):
        return json.loads(raw(rel,role,expected))
    result=load('mcu-processing-span-device-v2/result.json','terminal_result',RESULT_SHA)
    method=load('mcu-processing-span-controller-v2/METHOD-BEFORE.json','frozen_method',METHOD_SHA)
    inventory=load('mcu-processing-span-firmware-v2/server-firmware.controls.json','guarded_controls_inventory',INVENTORY_SHA)
    source=load('mcu-processing-span-source-v2/manifest.json','original_source_manifest',SOURCE_SHA)
    load('mcu-processing-span-source-v2/protocol.json','original_observer_protocol',PROTOCOL_SHA)
    private_matcher=raw('mcu_processing_span_v2.py','original_private_matcher',MATCHER_SHA)
    require(result['status']=='complete' and result['collection_complete'] is True and
            result['measurements_passed'] is True and result['passed'] is True and result['restore_verified'] is True,
            'terminal device result is not complete/restored')
    require(result['diagnostic_only'] is True and result['performance_comparison_operations']==0 and
            result['task_CPU_claim'] is False,'private result diagnostic scope differs')
    exact(result['method'],method,'terminal/frozen method')
    require(result['method_sha256']==METHOD_SHA and method['inventory_sha256']==INVENTORY_SHA and
            method['matcher_sha256']==MATCHER_SHA,'private method join differs')
    require(inventory['passed'] is True and inventory['fixture_unchanged'] is True and
            inventory['staging_restored'] is True and inventory['original_pipeline_passed'] is False,
            'guarded inventory/failed-original scope differs')
    require(source['core']==CORE and source['runtime']==RUNTIME and source['focused_checks']==14 and
            source['host_mock_passed'] is True,'source pin/proof attestation differs')
    require([c['profile'] for c in result['cohorts']]==[c['profile'] for c in inventory['cohorts']]==PROFILES,
            'private profile order differs')
    profiles=[];secrets=[]
    for row,image in zip(result['cohorts'],inventory['cohorts']):
        name=row['profile'];b=row['build'];exact(b,image,'image/result join')
        if name.startswith('H'): require(b['core']==CORE and b['runtime']==RUNTIME,'Rust measured source differs')
        require(b['observer_manifest_sha256']==SOURCE_SHA and b['observer_protocol_sha256']==PROTOCOL_SHA,
                'target/source observer join differs')
        secrets.append(row['run_id'])
        matched=load('mcu-processing-span-device-v2/'+name+'-matched.json',name+'_full_matched',row['matched_result_sha256'])
        require(matched['run_id']==row['run_id'] and matched['verified_complete'] is True,'private matcher identity/completion differs')
        api=[json.loads(line) for line in raw('mcu-processing-span-device-v2/'+name+'-api.jsonl',name+'_raw_API',row['api_sha256']).splitlines()]
        require(api[-1]['kind']=='capture_complete' and api[-1]['overflow'] is False and
                not any(a.get('kind')=='disconnected' and a.get('expected') is False for a in api),
                'private API capture incomplete/overflowed/disconnected')
        observed=[]
        for a in api:
            line=a.get('line','')
            if row['run_id'] in line and ('COAPTIC_TASK_POLICY ' in line or 'LIBCOAP_TASK_POLICY ' in line):
                match=re.search(r' core=(\d+) priority=(\d+) pinned_core=(-?\d+)',line)
                require(match is not None,'task-policy witness format differs')
                observed.append(tuple(map(int,match.groups())))
        require(len(observed)==row['task_policy_witness']['records'],'task-policy count differs')
        require(all(o==(1,1,b['task_core']) for o in observed),'C startup observation differs')
        require(bool(observed)==row['task_policy_witness']['available'],'task-policy availability differs')
        clients=[]
        for c in row['clients']:
            rel='mcu-processing-span-device-v2/'+PureWindowsPath(c['report_path']).name
            raw(rel,name+'_'+c['mode']+'_client',c['source_report_sha256'])
            clients.append({'mode':c['mode'],'passed':c['passed'],'reads_verified':c['operations'],'datagrams_matched':method['datagrams_per_client']})
        pre=row['pre_client_metadata'];post=row['post_capture_metadata'];startup=pick(matched['startup'],STARTUP_KEYS)
        require(pre['MCU_SPAN_STARTUP']==post['MCU_SPAN_STARTUP']==matched['startup'],'private startup metadata join differs')
        memory={'worker_reserved_bytes':b['task_stack_reserved_bytes'],
                'observed_lifetime_stack_used_before_clients_bytes':pre['MCU_SPAN_STACK']['stack_observed_used_bytes'],
                'observed_lifetime_stack_used_after_capture_bytes':post['MCU_SPAN_STACK']['stack_observed_used_bytes'],
                'before_task_largest_internal_bytes':startup['largest_internal_before_task'],
                'required_before_task_largest_internal_bytes':b['minimum_before_task_largest_bytes'],
                'observer_context_stack_bytes':b['observer_context_stack_bytes'],
                'observer_global_bytes':b['observer_global_bytes'],
                'observer_storage_bytes':b['observer_storage_bytes'],
                'observer_requested_heap_bytes':b['observer_heap_requested_bytes'],
                'main_sram_static_bytes':b['main_sram_static_bytes'],
                'clean_main_sram_static_bytes':b['clean_main_sram_static_bytes'],
                'observer_main_sram_static_delta_bytes':b['observer_static_added_bytes'],
                'observer_row_encoder_stack_bound_bytes':b['observer_row_encoder_stack_bound_bytes']}
        archive=PureWindowsPath(b['source_archive']).name
        require(archive=={'Hsync':'O3Thin-sync.a','Hasync':'OsFat-async.a','Cpin':'C-original.a','Cfloat':'C-original.a'}[name],
                'integrated codegen archive provenance differs')
        profiles.append({'profile':name,
                         'status':{'passed':row['passed'],'startup_guard_passed':row['startup_guard_passed'],
                                   'reads_verified':row['diagnostic_reads_verified'],'datagrams_matched':row['diagnostic_datagrams_verified'],'boots':1},
                         'clients':clients,'source_hashes':pick(b,HASH_KEYS),
                         'codegen':{'opt_level':'3','lto':'thin'} if name=='Hsync' else {'opt_level':'s','lto':'fat'} if name=='Hasync' else {'compiler':'unchanged pinned libcoap archive'},
                         'task_policy':{'actual_available':bool(observed),'compiled_core':b['task_core'],
                                        'compiled_priority':b['task_priority'],'startup_core_observed':observed[0][0] if observed else None,'records':len(observed)},
                         'startup':startup,'memory':memory,'heap_before_clients':pick(pre['running_heap'],HEAP_KEYS),
                         'heap_after_capture':pick(post['running_heap'],HEAP_KEYS),'sdk':pick(b['sdk'],SDK),
                         'counters':{g:pick(matched['counters'][g],ks) for g,ks in COUNTER_KEYS.items()},
                         'spans':[selected_span(s) for s in matched['spans']],
                         'operations':[pick(o,OP_KEYS) for o in matched['operations']]})
    begins=[pick(c['pre_client_metadata']['MCU_SPAN_BEGIN'],['expected_datagrams','max_rows','packet_bytes','quiet_us']) for c in result['cohorts']]
    require(all(begin==begins[0] for begin in begins),'common observer metadata differs by profile')
    v1=load('mcu-processing-span-device/result.json','failed_V1_device_result')
    failed=load('mcu-processing-span-firmware-v2/server-firmware.json','failed_V2_original_inventory',inventory['original_failed_inventory_sha256'])
    load('mcu-processing-span-firmware-v2/unqualified-Cpin-sdk-component-v2-regeneration/archive-manifest.json',
         'failed_Cpin_archive_preservation','e32e096cd9dbf6bc967b634511950b83d48609c9eb0700758cc53f1be4c410cc')
    require(v1['passed'] is False and v1['status']=='incomplete' and v1['restore_verified'] is True,'V1 failure no longer preserved')
    require(failed['passed'] is False and failed['error']['reason']=='Immutable library archive was rebuilt; preserve refusal and stop',
            'original V2 immutable archive refusal differs')
    data={'schema':'coaptic-mcu-span-v2-portable/1','source_pins':{'core':CORE,'runtime':RUNTIME},'claims':CLAIMS,
          'release_attestation':{'parent_clocks_released':clocks_released,'normal_restored_verified':normal_restored and result['restore_verified']},
          'method':{'bounds':pick(method['bounds'],BOUNDS),'capacities':CAPACITIES,'client_order':method['client_order'],
                    'reads_per_client':method['reads_per_client'],'datagrams_per_client':method['datagrams_per_client'],
                    'reads_per_profile':method['reads_per_profile'],'datagrams_per_profile':method['datagrams_per_profile'],
                    'boots_per_profile':1,'total_boots':4,'expected_datagrams':begins[0]['expected_datagrams'],
                    'maximum_logged_attempts':begins[0]['max_rows'],'packet_bytes':begins[0]['packet_bytes'],
                    'quiet_us':begins[0]['quiet_us'],'read_timeout_seconds':5,
                    'capture_limit_bytes':method['diagnostic_capture_limit_bytes'],
                    'normal_capture_limit_bytes':method['normal_capture_limit_bytes'],
                    'runtime_budget_bytes':method['capture_budget_bytes'],'running_free_floor_bytes':8192,
                    'running_largest_floor_bytes':8192,'running_regional_lowwater_floor_bytes':12288,
                    'contiguous_margin_bytes':4096,'diagnostic_only':method['diagnostic_only']},
          'profiles':profiles,
          'failures':[{'attempt':'V1 capture','passed':v1['passed'],'status':v1['status'],
                       'normal_restore_verified':v1['restore_verified'],
                       'verified_client_reads':sum(c['operations'] for p in v1['cohorts'] for c in p['clients'] if c['passed'] is True),
                       'full_packet_publication_complete':False},
                      {'attempt':'V2 original Cpin SDK/component pipeline','passed':failed['passed'],
                       'source_assertions_passed':True,'immutable_archive_refused':True,
                       'staging_restored':failed['staging_restored'],'fixture_unchanged':failed['fixture_unchanged'],
                       'cleanup_unresolved':failed['cleanup_unresolved'],'guarded_controls_inventory_is_separate':True}],
          'proof_attestations':{'codec_checks_passed':source['focused_checks'],'actual_source_Cpp_host_mock_passed':source['host_mock_passed'],
                                'controller_checks_passed':28,'full_target_guards_passed':result['passed'],
                                'private_packet_body_identity_OTA_API_joins':True,'rerun_for_export':False,'independent_firmware_rebuild':False},
          'commitments':commitments}
    summary=grade(data)
    generic={}
    for name,key in [('mcu_processing_span.cpp','common_cpp_sha256'),('mcu_processing_span.h','common_header_sha256'),('CMakeLists.txt','cmake_sha256')]:
        content=(native_root/'mcu-processing-span-source-v2'/name).read_bytes()
        require(sha(content)==source[key],'generic observer source hash differs')
        generic['sources/'+name]=content
    public_matcher,normalized_ast=normalized_matcher(private_matcher,True)
    original_ast=ast.parse(private_matcher.decode())
    original_ip=next(n.value.value for n in original_ast.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='EXPECTED_IP' for t in n.targets))
    secrets.append(original_ip if type(original_ip) is str else '.'.join(map(str,original_ip.to_bytes(4,'big'))))
    generic['sources/mcu_processing_span_v2.py']=public_matcher
    Crows=[row['build'] for row in result['cohorts'] if row['profile'] in ['Cpin','Cfloat']]
    libcoap={'version':Crows[0]['libcoap_version'],'component_archive_sha256':Crows[0]['libcoap_component_archive_sha256'],
             'component_receipt_sha256':Crows[0]['libcoap_component_receipt_sha256'],
             'source_archive_sha256':Crows[0]['source_archive_sha256'],'placed_archive_sha256':Crows[0]['archive_sha256']}
    require(all(row['libcoap_version']==libcoap['version'] and row['libcoap_component_archive_sha256']==libcoap['component_archive_sha256'] and
                row['libcoap_component_receipt_sha256']==libcoap['component_receipt_sha256'] for row in Crows),'C component provenance differs')
    provenance={'schema':'coaptic-mcu-span-v2-provenance/1','libcoap_source':libcoap,
                'original_result_sha256':RESULT_SHA,'original_method_sha256':METHOD_SHA,
                'original_controls_inventory_sha256':INVENTORY_SHA,'original_source_manifest_sha256':SOURCE_SHA,
                'original_protocol_sha256':PROTOCOL_SHA,'method_hash_commitments':pick(method,METHOD_HASHES),
                'matcher_normalization':{'private_source_sha256':MATCHER_SHA,'published_source_sha256':sha(public_matcher),
                                          'allowed_assignment':'EXPECTED_IP','published_default':TESTNET,
                                          'normalized_AST_sha256':normalized_ast,'only_constant_changed_attestation':True},
                'exact_generic_sources':{name:sha(content) for name,content in generic.items() if name!='sources/mcu_processing_span_v2.py'},
                'already_public_H_sources':'https://github.com/jeffglousher/coaptic-validation/tree/021b691ed34167e488bde6915561613c98ae9455/tools/benchmark/evidence/esp-idle-observe-20261109/sources',
                'scope':'Private packet/body/identity/OTA/API/producer joins remain attestations. Generic observer inspection and numeric regrade only; not an independent firmware or packet rebuild kit.'}
    plain=encoded(data);packed=gzip.compress(plain,compresslevel=9,mtime=0)
    files={'records.json.gz':packed,'summary.json':encoded(summary),'provenance.json':encoded(provenance),**generic}
    for name in ['README.md','common.py','export.py','verify.py','test_export.py']:
        files[name]=(here/name).read_bytes()
    for name,content in files.items():
        relative(name);visible=plain if name=='records.json.gz' else content
        require(not private(visible),'privacy scan refused '+name)
        require(not any(secret and secret.encode() in visible for secret in secrets),'private identifier survived whitelist: '+name)
    manifest={'schema':'coaptic-mcu-span-v2-manifest/1','files':{name:{'bytes':len(content),'sha256':sha(content)} for name,content in sorted(files.items())}}
    manifest['files']['records.json.gz'].update(raw_bytes=len(plain),raw_sha256=sha(plain))
    files['manifest.json']=encoded(manifest)
    used=sum(p.stat().st_size for p in here.rglob('*') if p.is_file())
    require(used+sum(map(len,files.values()))<=BUDGET,'private prep plus package budget exceeds 2 MiB')
    destination.mkdir()
    for name,content in files.items():
        path=destination/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(content)
    return {'package_bytes':sum(map(len,files.values())),'prep_plus_package_bytes':used+sum(map(len,files.values())),
            'manifest_sha256':sha(files['manifest.json']),'reads':summary['reads'],'datagrams':summary['datagrams'],
            'native_totals':summary['native_totals'],'claims':summary['claims']}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-root',type=Path,required=True)
    p.add_argument('--parent-clocks-released',action='store_true')
    p.add_argument('--normal-restored-verified',action='store_true')
    a=p.parse_args()
    print(json.dumps(export(a.native_root,Path(__file__).resolve().parent,a.parent_clocks_released,a.normal_restored_verified),sort_keys=True))
