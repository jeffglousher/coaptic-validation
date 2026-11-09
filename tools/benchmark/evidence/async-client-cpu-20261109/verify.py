"""Standalone full-vector arithmetic, eligibility, hash and privacy regrade."""
import json
from pathlib import Path
from common import *
FILES={'cpu.json.gz','results.json','provenance.json','sources/a85-to-4f-rust.patch.gz','common.py','export.py','verify.py','test_export.py','README.md','fixtures.json.gz'}
def verify(root):
 root=Path(root);b=(root/'manifest.json').read_bytes();m=json.loads(b);keys(m,['schema','files'],'manifest');need(m['schema']=='coaptic-four-pair-CPU-manifest/1'and set(m['files'])==FILES,'file inventory differs')
 need({p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()}==FILES|{'manifest.json'},'unsealed extra/missing file')
 content={}
 for name,meta in m['files'].items():
  relative(name);packed=(root/name).read_bytes();need(len(packed)==meta['bytes']and sha(packed)==meta['sha256'],'file hash differs');content[name]=unpack(packed,meta)if name.endswith('.gz')else packed;need(not private(content[name]),'private content')
 need(not private(b),'private manifest');data=json.loads(content['cpu.json.gz']);result=grade(data);same(result,json.loads(content['results.json']))
 p=json.loads(content['provenance.json']);validate_provenance(p,content['sources/a85-to-4f-rust.patch.gz'])
 need(result['continuation_signal']is False and len(result['failed_cell_point_guards'])==3,'retained development refusal differs')
 return {'manifest_sha256':sha(b),'full_vectors_regraded':True,'processes':280,'pairs':112,'cells':28,'measured_operations':result['measured_operations'],
         'qualification_operations':result['qualification_operations'],'calibration_samples_also_retained':result['calibration_samples_retained'],
         'sync_ratio':result['groups']['all-sync']['ratio'],'async_ratio':result['groups']['all-async']['ratio'],
         'failed_cells':result['failed_cell_point_guards'],'continuation_signal':result['continuation_signal'],'qualified':False,'adopted':False,'claims':result['claims']}
if __name__=='__main__':print(json.dumps(verify(Path(__file__).resolve().parent),sort_keys=True))
