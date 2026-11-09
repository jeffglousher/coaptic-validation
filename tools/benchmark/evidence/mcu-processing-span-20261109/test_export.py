"""Small synthetic export/privacy/decision counterexamples; no target reruns."""
import copy
import json
from pathlib import Path
from common import *
from export import export, selected_span


def refused(fn):
    try:fn()
    except ValueError:return
    raise AssertionError('counterexample was accepted')


def main():
    here=Path(__file__).resolve().parent
    root=here if (here/'records.json.gz').is_file() else here/'package'
    m=json.loads((root/'manifest.json').read_bytes())
    data=json.loads(unpack((root/'records.json.gz').read_bytes(),m['files']['records.json.gz']))
    grade(data)
    checks=0
    def bad(mutate):
        nonlocal checks
        d=copy.deepcopy(data);mutate(d);refused(lambda:grade(d));checks+=1
    bad(lambda d:d['profiles'][0]['spans'].pop())
    bad(lambda d:d['profiles'][0]['spans'].__setitem__(3,copy.deepcopy(d['profiles'][0]['spans'][2])))
    bad(lambda d:d['profiles'][0]['operations'][2].__setitem__('receive_return_to_send_entry_sum_wall_us',1))
    bad(lambda d:d['profiles'][1]['spans'][0].__setitem__('residual_wall_us',d['profiles'][1]['spans'][0]['residual_wall_us']+1))
    def lose_delay(d):
        for s in d['profiles'][1]['spans']:
            s['residual_wall_us']+=s['native_delay_call_wall_us'];s['native_delay_calls']=s['native_delay_call_wall_us']=0
        d['profiles'][1]['operations']=operations(d['profiles'][1]['spans'])
    bad(lose_delay)
    for claim in ['task_CPU','clean_RTT','speed_gain','adopted','goal_complete']:
        bad(lambda d,c=claim:d['claims'].__setitem__(c,True))
    bad(lambda d:d['profiles'][0]['spans'][0].__setitem__('mid',42))
    bad(lambda d:d['profiles'][0]['status'].__setitem__('boots',2))
    bad(lambda d:d['failures'][0].__setitem__('passed',True))
    bad(lambda d:d['profiles'][1]['sdk'].__setitem__('FREERTOS_HZ',999))
    sample={**data['profiles'][0]['spans'][0],'peer_ip':'withheld','token_hex':'withheld','mid':42}
    require(set(selected_span(sample))==set(SPAN_KEYS),'positive whitelist retained protocol identity');checks+=1
    address='.'.join(['10','0','0','1'])
    for raw in [address,':'.join(['aa']*6),'-'.join(['12345678','abcd','abcd','abcd','123456789abc']),'C'+':'+chr(92)+'Users'+chr(92)+'someone']:
        require(private(raw.encode()),'privacy counterexample not detected');checks+=1
    require(not private(TESTNET.encode()),'documentation-only address rejected');checks+=1
    fake=('EXPECTED_IP = '+repr(address)+'\ndef tiny():\n    return 1\n').encode()
    public,proof=normalized_matcher(fake,True)
    require(address.encode() not in public and TESTNET.encode() in public and normalized_matcher(public)[1]==proof,'single-constant AST proof failed');checks+=1
    integer_source=('EXPECTED_IP = '+repr(int.from_bytes(bytes([10,0,0,1]),'big'))+'\n').encode()
    integer_public,integer_proof=normalized_matcher(integer_source,True)
    require(normalized_matcher(integer_public)[1]==integer_proof,'integer address representation proof failed');checks+=1
    tampered=public.replace(b'return 1',b'return 2')
    require(normalized_matcher(tampered)[1]!=proof,'nonconstant AST mutation not detected');checks+=1
    for clocks,restored in [(False,True),(True,False)]:
        refused(lambda c=clocks,r=restored:export(Path('.'),here,c,r));checks+=1
    print(json.dumps({'focused_counterexamples_passed':checks,'target_codec_controller_checks_rerun':False},sort_keys=True))


if __name__=='__main__':main()
