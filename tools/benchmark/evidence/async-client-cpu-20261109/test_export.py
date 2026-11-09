"""Focused missing-data, eligibility, continuation and privacy counterexamples."""
import copy,json
from pathlib import Path
from common import *
def refuse(fn):
 try:fn()
 except ValueError:return
 raise AssertionError('counterexample accepted')
def main():
 root=Path(__file__).resolve().parent;m=json.loads((root/'manifest.json').read_bytes());d=json.loads(unpack((root/'cpu.json.gz').read_bytes(),m['files']['cpu.json.gz']));checks=0
 def bad(fn):
  nonlocal checks
  v=copy.deepcopy(d);fn(v);refuse(lambda:grade(v));checks+=1
 bad(lambda v:v['processes'].pop())
 bad(lambda v:v['processes'][0]['raw'][v['processes'][0]['vector_field']].pop())
 bad(lambda v:v['processes'][0].__setitem__('cycle_sum',0))
 bad(lambda v:v['processes'][0]['raw'].__setitem__('verified',0))
 bad(lambda v:v['processes'][0]['raw'].__setitem__('private_token','withheld'))
 for k in ['confidence_qualification','adopted','libcoap_comparison']:bad(lambda v,k=k:v['claims'].__setitem__(k,True))
 # Missing or changed ledgers must refuse even when both arms change together.
 bad(lambda v:[p['raw'].pop('memory',None)for p in v['processes']])
 bad(lambda v:[p['raw'].pop('server_capacities',None)for p in v['processes']])
 bad(lambda v:v['processes'][0]['raw']['memory'].pop('app_including_transport_inline_bytes'))
 bad(lambda v:[p['raw']['server_capacities'].__setitem__('routes',16)for p in v['processes']if 'server_capacities'in p['raw']])
 bad(lambda v:[p['raw'].__setitem__('profile','OtherService')for p in v['processes']if p['cell'][0]=='ordinary'])
 bad(lambda v:[p['raw'].__setitem__('storage','allocated')for p in v['processes']if p['cell'][0]=='ordinary'])
 bad(lambda v:[p['raw'].__setitem__('scope','isolated CPU and whole memory')for p in v['processes']if p['cell'][0]=='ordinary'])
 bad(lambda v:v['processes'][0]['raw'].__setitem__('mode','sync'))
 bad(lambda v:v['processes'][0]['raw'].pop('clock_calibration_cycles'))
 bad(lambda v:v['processes'][0].__setitem__('arm','B'))
 def relabel(v):
  for c in v['method']['cells']:
   if c[1]=='small-device':c[1]='service-other'
  for p in v['processes']:
   if p['cell'][1]=='small-device':p['cell'][1]='service-other'
   p['label']=p['label'].replace('small-device','service-other')
 bad(relabel)
 provenance=json.loads((root/'provenance.json').read_bytes());patch=unpack((root/'sources/a85-to-4f-rust.patch.gz').read_bytes(),m['files']['sources/a85-to-4f-rust.patch.gz'])
 def bad_provenance(fn):
  nonlocal checks
  v=copy.deepcopy(provenance);fn(v);refuse(lambda:validate_provenance(v,patch));checks+=1
 bad_provenance(lambda v:v['source_files'].__setitem__(1,copy.deepcopy(v['source_files'][0])))
 bad_provenance(lambda v:v['source_files'][0].__setitem__('path','src/app/other.rs'))
 bad_provenance(lambda v:v['scope_claims'].__setitem__('independent_target_static_build',True))
 bad_provenance(lambda v:v['scope_claims'].__setitem__('independent_source_or_firmware_build',True))
 bad_provenance(lambda v:v['scope_claims'].__setitem__('ordinary_mode_selection','raw-observed'))
 refuse(lambda:validate_provenance(provenance,patch.replace(b'b/src/app/mod.rs',b'b/src/app/other.rs',1)));checks+=1
 s=[{'ratio':1.0}for _ in range(28)];g={'all-sync':{'ratio':.99},'all-async':{'ratio':.99}}
 need(continuation(s,g),'positive predicate hardcoded false');checks+=1
 s[0]['ratio']=1.021;need(not continuation(s,g),'failed cell overridden');checks+=1
 s[0]['ratio']=1.0;g['all-async']['ratio']=1.001;need(not continuation(s,g),'async mode failure overridden');checks+=1
 need(private('.'.join(['10','0','0','1']).encode()),'private address not found');checks+=1
 print(json.dumps({'focused_counterexamples_passed':checks,'no_build_or_clock':True},sort_keys=True))
if __name__=='__main__':main()
