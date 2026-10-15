import hashlib
import json
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'tools/interop'))
from oscore_observe import campaign_review
from oscore_observe_cancel import review
for directory in sys.argv[1:]:
    for family,name,grader in (
        ('ipv4','oscore-observe-campaign.json',campaign_review),('ipv6','oscore-observe-ipv6-campaign.json',campaign_review),
        ('ipv4','oscore-observe-cancellation.json',review),('ipv6','oscore-observe-cancellation-ipv6.json',review)):
        paths=list((root/'target'/directory/'artifact').rglob(name));assert len(paths)==1
        report=json.loads(paths[0].read_text(encoding='utf-8'))
        proof=grader(report['campaign'],report['libcoap_patch'],family=family)
        assert report['qualification_complete'] and proof==report['campaign']['proof']
        print(json.dumps(dict(directory=directory,name=name,proof=proof,source=report['source'],suite_source=report['suite_source'],sha256=hashlib.sha256(paths[0].read_bytes()).hexdigest())))
