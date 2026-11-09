"""Standalone hash/privacy/source-commitment and full-vector speed verifier."""
import json
from pathlib import Path
from common import *

FILES={'README.md','common.py','export.py','verify.py','test_export.py','screen.json.gz','results.json','provenance.json',
       'sources/task-core.patch','sources/accepted-to-c015-target-annotations.patch'}
METHOD_HASH_KEYS=['capture_script_sha256','final_build_manifest_sha256','script_sha256','analyzer_sha256',
                  'source_manifest_sha256','producer_inventory_sha256','joined_plan_sha256','raw_SDK_inventory_sha256',
                  'source_SDK_plan_sha256','preflight_preparation_sha256','safety_checks_sha256',
                  'comparison_helper_proof_sha256','parent_review_sha256']


def verify(root):
    root=Path(root);m=json.loads((root/'manifest.json').read_bytes());keys(m,['schema','files'],'manifest')
    require(m['schema']=='coaptic-target-cpu-speed-manifest/1' and set(m['files'])==FILES,'manifest file grid differs')
    require({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}==FILES|{'manifest.json'},'missing/unsealed extra file')
    require(sum(p.stat().st_size for p in root.rglob('*') if p.is_file())<=BUDGET,'package exceeds 1 MiB')
    content={}
    for name,metadata in m['files'].items():
        relative(name);b=(root/name).read_bytes();require(len(b)==metadata['bytes'] and sha(b)==metadata['sha256'],'file hash/length differs: '+name)
        keys(metadata,['bytes','sha256','raw_bytes','raw_sha256'] if name.endswith('.gz') else ['bytes','sha256'],'file metadata')
        content[name]=unpack(b,metadata) if name.endswith('.gz') else b
        require(not private(content[name]),'private content refused: '+name)
    require(not private((root/'manifest.json').read_bytes()),'private manifest')
    provenance=json.loads(content['provenance.json'])
    keys(provenance,['schema','original_analysis_sha256','original_result_sha256','original_method_sha256',
                     'original_controller_inventory_sha256','method_hash_commitments','client_binary_sha256','patches',
                     'candidate_profile_flags','affinity_manifest_sha256','codegen_plan_sha256','codegen_provenance_sha256',
                     'affinity_patch_base','affinity_file_joins','scope'],'provenance')
    require(provenance['schema']=='coaptic-target-cpu-speed-provenance/1','provenance schema differs')
    keys(provenance['method_hash_commitments'],METHOD_HASH_KEYS,'method source commitments')
    require(all(re.fullmatch('[0-9a-f]{64}',v) for v in provenance['method_hash_commitments'].values()),'invalid method source digest')
    require(set(provenance['patches'])=={'sources/task-core.patch','sources/accepted-to-c015-target-annotations.patch'},'source patch grid differs')
    for name,digest in provenance['patches'].items():
        require(sha(content[name])==digest,'source patch hash differs')
        for line in content[name].decode().splitlines():
            if line.startswith(('--- ','+++ ')):
                filename=line[4:].split('\t')[0]
                if filename!='/dev/null':relative(filename)
    require(re.fullmatch('[0-9a-f]{40}',provenance['affinity_patch_base']),'affinity base commit differs')
    for row in provenance['affinity_file_joins']:
        keys(row,['path','before_sha256','after_sha256'],'source byte join');relative(row['path'])
        require(re.fullmatch('[0-9a-f]{64}',row['before_sha256']) and re.fullmatch('[0-9a-f]{64}',row['after_sha256']),'source byte digest differs')
    flags=provenance['candidate_profile_flags']
    keys(flags,['toolchain','target','opt_level','lto','codegen_units','panic','debug','incremental','build_jobs','features','offline','locked','future_whole_ceiling_bytes'],'compiler profile')
    require(flags['opt_level']=='3' and flags['lto']=='thin' and flags['codegen_units']==1 and flags['panic']=='abort' and
            flags['incremental'] is False and flags['offline'] is True and flags['locked'] is True,'frozen compiler flags differ')
    data=json.loads(content['screen.json.gz']);results=grade(data);same(results,json.loads(content['results.json']),'published full numeric regrade')
    commits={v['role']:v['sha256'] for v in data['commitments']}
    require(len(commits)==len(data['commitments']),'duplicate raw commitment role')
    for key,role in [('original_analysis_sha256','original_analysis'),('original_result_sha256','original_result'),
                     ('original_method_sha256','frozen_method'),('original_controller_inventory_sha256','frozen_controller_inventory'),
                     ('affinity_manifest_sha256','affinity_manifest'),('codegen_plan_sha256','codegen_plan'),('codegen_provenance_sha256','codegen_provenance')]:
        require(provenance[key]==commits[role],'private commitment join differs')
    require(provenance['method_hash_commitments']['analyzer_sha256']==commits['original_private_analyzer'] and
            provenance['method_hash_commitments']['script_sha256']==commits['original_private_controller'],'original controller/analyzer commitment differs')
    for index,b in enumerate(data['boots'],1):
        require('boot%02d_API'%index in commits,'private API commitment missing')
        for client in b['clients']:
            require(client['original_report_sha256']==commits['boot%02d_client%02d'%(index,client['ordinal'])],'raw client/boot mapping commitment differs')
    return {'full_vector_regrade_verified':True,'operations':results['operations'],'boots':results['boots'],'client_processes':len(results['processes']),
            'RSSI_dbm':results['RSSI_dbm'],'decisions':[{'name':d['name'],'promising':d['promising'],'ratio':d['strict_best_C_geometric_median_ratio'],
            'cell_ratios':[c['median_ratio'] for c in d['cells']],'boot_ratios':d['boot_best_C_geometric_ratios']} for d in results['screen_decisions']],
            'startup_qualification_open':results['startup_qualification_open'],'claims':results['claims'],'manifest_sha256':sha((root/'manifest.json').read_bytes()),
            'producer_identity_source_binary_API_proofs':'retained private attestations; no independent firmware rebuild'}


if __name__=='__main__':print(json.dumps(verify(Path(__file__).resolve().parent),sort_keys=True))
