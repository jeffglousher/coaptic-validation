import json
import subprocess
from pathlib import Path
root=Path(__file__).parent
core=Path('D:/codex-work/coaptic-observe-evidence-wave-pin')
for label,num,repo,worktree in (('suite',64,'jeffglousher/coaptic-validation',root.parent),('core',510,'jeffglousher/coaptic',core)):
    config=json.loads((root/(label+'-audit-config.json')).read_text(encoding='utf-8'))
    reports=list((root/('hosted-'+label+'-final/artifact')).rglob('oscore-observe-ipv6-campaign.json'));assert len(reports)==1
    report=json.loads(reports[0].read_text(encoding='utf-8'))
    tree=subprocess.check_output(['git','rev-parse',config['head']+'^{tree}'],cwd=worktree,text=True).strip()
    payload=dict(repo=repo,number=num,worktree=str(worktree),evidence=str(core/'target'/(label+'-merge')),
                 head=config['head'],tree=tree,hosted=report['suite_source' if label=='suite' else 'source'],checks=config['checks'],
                 dependencies=[] if label=='suite' else [['jeffglousher/coaptic-validation',64]])
    (core/'target'/(label+'-merge-config.json')).write_text(json.dumps(payload,indent=2),encoding='utf-8')
    print(json.dumps(payload))
