"""Meaningful gate/privacy/qualification counterexamples; no hardware or clocks."""
import copy
import json
from pathlib import Path
from common import *
from export import operation,export


def refused(fn):
    try:fn()
    except ValueError:return
    raise AssertionError('counterexample accepted')


def main():
    here=Path(__file__).resolve().parent;root=here if (here/'screen.json.gz').exists() else here/'package'
    m=json.loads((root/'manifest.json').read_bytes());data=json.loads(unpack((root/'screen.json.gz').read_bytes(),m['files']['screen.json.gz']))
    grade(data);checks=0
    def bad(change):
        nonlocal checks
        d=copy.deepcopy(data);change(d);refused(lambda:grade(d));checks+=1
    bad(lambda d:d['boots'][0]['clients'].pop())
    bad(lambda d:d['boots'][0]['clients'][0]['operations'].pop())
    bad(lambda d:d['boots'][0].__setitem__('round',2))
    bad(lambda d:d['boots'][2]['task_policy'].__setitem__('observed_core',1))
    bad(lambda d:d['status'].__setitem__('startup_contiguous_floor_qualified',True))
    bad(lambda d:d['boots'][0]['heap'].append({'phase':'running','caps':'all_8bit','free_bytes':0}))
    bad(lambda d:d['boots'][0]['clients'][0]['operations'][0].__setitem__('mid',42))
    for claim in ['task_CPU','new_host_measurement','adopted','goal_complete']:
        bad(lambda d,c=claim:d['claims'].__setitem__(c,True))
    lookup={}
    for name,median in [('A',.8),('C1',1.0),('C2',1.1)]:
        for client,path in CELLS:lookup[name,client,path]={'name':name,'median_ms':median,'boot_medians_ms':[median,median]}
    require(decision('A',['C1','C2'],lookup,True)['promising'] is True,'success path was hardcoded false');checks+=1
    one=copy.deepcopy(lookup);one['A','sync','test']['median_ms']=1.01
    require(decision('A',['C1','C2'],one,True)['promising'] is False,'aggregate overrode failed cell');checks+=1
    boot=copy.deepcopy(lookup)
    for client,path in CELLS:boot['A',client,path]['boot_medians_ms']=[1.2,.4]
    require(decision('A',['C1','C2'],boot,True)['promising'] is False,'pooled aggregate overrode failed boot');checks+=1
    require(decision('A',['C1','C2'],lookup,False)['promising'] is False,'eligibility ignored');checks+=1
    sample={k:0 for k in OP_KEYS if k not in ['request_send_attempts','distinct_request_sends','repeated_request_send_attempts']};sample['events']=[[2,0,0,12,41],[2,0,0,12,41]];sample.update(run_id='withheld',token='withheld',mid=41)
    out=operation(sample);require(set(out)==set(OP_KEYS) and out['repeated_request_send_attempts']==1,'identity stripping lost repeat count');checks+=1
    for text in ['.'.join(['10','0','0','1']),':'.join(['aa']*6),'C'+':'+chr(92)+'Users'+chr(92)+'someone']:
        require(private(text.encode()),'private value accepted');checks+=1
    for clocks,restored in [(False,True),(True,False)]:refused(lambda c=clocks,r=restored:export(Path('.'),here,c,r));checks+=1
    print(json.dumps({'focused_counterexamples_passed':checks,'controller_target_producer_checks_rerun':False},sort_keys=True))


if __name__=='__main__':main()
