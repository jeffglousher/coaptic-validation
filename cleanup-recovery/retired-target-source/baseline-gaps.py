import json
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'tools/interop'))
from oscore_observe_tests import record, exchange
from oscore_observe import exchange_grade, campaign_review
from oscore_qblock1 import FixtureContext,request_plain
from oscore_qblock2_tests import protected,ENDPOINTS
from run import coap_message

writer = exchange(1,b'2',200,0)
old_back = writer['endpoints']['back']
front = writer['endpoints']['front']
writer['endpoints']['back'] = front
for row in writer['trace']:
    for field in ('source','destination','relay'):
        if row[field] == old_back: row[field] = front
owner_proof = exchange_grade(writer,1,b'2',tuple(ENDPOINTS['server']))
r = record()
w = r['sessions'][0]['writes'][0]
req = bytes.fromhex(w['trace'][0]['hex'])
_,binding = request_plain(req)
wire = protected(FixtureContext(server=True,sequence=1000),coap_message(68,60,b'w',[],b''),binding,True)
w['trace'][2].update(hex=wire.hex(),forwarded_hex=wire.hex())
nonce_proof = campaign_review(r,{'patch_sha256':'patch'})
report = dict(source='488ae624d2980c215acbc584a60a81f60fa262bf',
              overlapping_relay_owners_false_pass=owner_proof,
              notification_writer_explicit_piv_reuse_false_pass=nonce_proof,
              scope='Authenticated synthetic evidence-oracle counterexamples; no actual peer/security attribution.')
(root/'target/baseline-gaps.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
