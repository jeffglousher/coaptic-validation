"""Offline public whitelist, hash, source-normalization and numeric verifier."""
import json
from pathlib import Path
from common import *

EXPECTED_FILES={'README.md','common.py','export.py','verify.py','test_export.py',
                'records.json.gz','summary.json','provenance.json','sources/mcu_processing_span.cpp',
                'sources/mcu_processing_span.h','sources/CMakeLists.txt','sources/mcu_processing_span_v2.py'}


def verify(root):
    root=Path(root);manifest=json.loads((root/'manifest.json').read_bytes())
    keys(manifest,['schema','files'],'manifest')
    require(manifest['schema']=='coaptic-mcu-span-v2-manifest/1','manifest schema differs')
    require(set(manifest['files'])==EXPECTED_FILES,'unexpected/missing published files')
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    require(actual==EXPECTED_FILES|{'manifest.json'},'unsealed extra file or missing file')
    require(sum(p.stat().st_size for p in root.rglob('*') if p.is_file())<=BUDGET,'package exceeds budget')
    blobs={}
    for name,metadata in manifest['files'].items():
        relative(name);blob=(root/name).read_bytes()
        require(len(blob)==metadata['bytes'] and sha(blob)==metadata['sha256'],'file hash/length differs: '+name)
        keys(metadata,['bytes','sha256','raw_bytes','raw_sha256'] if name.endswith('.gz') else ['bytes','sha256'],'file metadata')
        blobs[name]=unpack(blob,metadata) if name.endswith('.gz') else blob
        require(not private(blobs[name]),'private content refused: '+name)
    require(not private((root/'manifest.json').read_bytes()),'private manifest content')
    provenance=json.loads(blobs['provenance.json'])
    keys(provenance,['schema','libcoap_source','original_result_sha256','original_method_sha256','original_controls_inventory_sha256',
                     'original_source_manifest_sha256','original_protocol_sha256','method_hash_commitments',
                     'matcher_normalization','exact_generic_sources','already_public_H_sources','scope'],'provenance')
    require(provenance['schema']=='coaptic-mcu-span-v2-provenance/1','provenance schema differs')
    keys(provenance['method_hash_commitments'],['controller_sha256','diagnostic_capture_sha256','helper_proof_sha256',
                                               'inventory_sha256','matcher_sha256','normal_capture_sha256',
                                               'normal_image_sha256','transport_sha256'],'method source commitments')
    require(all(re.fullmatch('[0-9a-f]{64}',v) for v in provenance['method_hash_commitments'].values()),'method source digest format differs')
    libcoap=provenance['libcoap_source']
    keys(libcoap,['version','component_archive_sha256','component_receipt_sha256','source_archive_sha256','placed_archive_sha256'],'C source provenance')
    require(libcoap['version']=='4.3.5~8' and libcoap['component_archive_sha256']=='82b6412afff7dc30edff3a82cfe56fb186bb5c29c72acae5ed78cbbb6c655f48','C version/component pin differs')
    require(all(re.fullmatch('[0-9a-f]{64}',v) for k,v in libcoap.items() if k!='version'),'C source digest format differs')
    normalization=provenance['matcher_normalization']
    keys(normalization,['private_source_sha256','published_source_sha256','allowed_assignment','published_default',
                        'normalized_AST_sha256','only_constant_changed_attestation'],'normalization')
    require(normalization['allowed_assignment']=='EXPECTED_IP' and normalization['published_default']==TESTNET and
            normalization['only_constant_changed_attestation'] is True,'matcher allowed change differs')
    matcher=blobs['sources/mcu_processing_span_v2.py'];_,ast_hash=normalized_matcher(matcher)
    require(sha(matcher)==normalization['published_source_sha256'] and ast_hash==normalization['normalized_AST_sha256'],'matcher AST/source proof differs')
    require(set(provenance['exact_generic_sources'])=={'sources/mcu_processing_span.cpp','sources/mcu_processing_span.h','sources/CMakeLists.txt'},'generic source set differs')
    for name,digest in provenance['exact_generic_sources'].items():
        require(sha(blobs[name])==digest,'exact generic source changed')
    data=json.loads(blobs['records.json.gz']);summary=grade(data)
    for profile in data['profiles'][2:]:
        require(profile['source_hashes']['archive_sha256']==libcoap['placed_archive_sha256'] and
                profile['source_hashes']['source_archive_sha256']==libcoap['source_archive_sha256'],'C archive/source provenance join differs')
    exact(summary,json.loads(blobs['summary.json']),'published arithmetic summary')
    commits={c['role']:c['sha256'] for c in data['commitments']}
    for key,role in [('original_result_sha256','terminal_result'),('original_method_sha256','frozen_method'),
                     ('original_controls_inventory_sha256','guarded_controls_inventory'),
                     ('original_source_manifest_sha256','original_source_manifest'),('original_protocol_sha256','original_observer_protocol')]:
        require(provenance[key]==commits[role],'private raw commitment join differs')
    require(normalization['private_source_sha256']==commits['original_private_matcher'],'private matcher commitment differs')
    require(provenance['method_hash_commitments']['inventory_sha256']==provenance['original_controls_inventory_sha256'] and
            provenance['method_hash_commitments']['matcher_sha256']==normalization['private_source_sha256'],'frozen method source joins differ')
    for profile in data['profiles']:
        hashes=profile['source_hashes']
        require(hashes['observer_source_sha256']==sha(blobs['sources/mcu_processing_span.cpp']) and
                hashes['observer_manifest_sha256']==provenance['original_source_manifest_sha256'] and
                hashes['observer_protocol_sha256']==provenance['original_protocol_sha256'] and
                hashes['compiled_cpp_sha256']==hashes['source_cpp_sha256'],'per-image observer/source commitment joins differ')
    return {'arithmetic_verified':True,'reads':summary['reads'],'datagrams':summary['datagrams'],'boots':summary['boots'],
            'medians_us':{p['profile']:[s['median_us'] for s in p['operations']] for p in summary['profiles']},
            'native_totals':summary['native_totals'],'claims':summary['claims'],
            'packet_identity_firmware_API_proof':'retained private producer attestations, not independently rebuilt',
            'manifest_sha256':sha((root/'manifest.json').read_bytes())}


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent),sort_keys=True))
