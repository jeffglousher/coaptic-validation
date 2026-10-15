import json
from pathlib import Path
root=Path(__file__).parent
locks=json.loads((root/'prepare.json').read_text(encoding='utf-8'))['suite_locks']
for label,repo,num,run,head,core_head,count in (
    ('suite','jeffglousher/coaptic-validation',64,38240914898,'93e34bba8154b1f841d39570cc4a02db44f58673','b953240c9e5cdabe5a889868ac4aeb18456c7bb6',26),
    ('core','jeffglousher/coaptic',510,38240962954,'9be672091168393ffb2b3129542dc20f46cb4c14','9be672091168393ffb2b3129542dc20f46cb4c14',31)):
    config=dict(repo=repo,pr=num,run=run,head=head,core_head=core_head,checks=count,suite_head='93e34bba8154b1f841d39570cc4a02db44f58673',
                locks=locks,core_worktree='D:/codex-work/coaptic-observe-evidence-wave-pin',output=str(root/('hosted-'+label+'-final')))
    (root/(label+'-audit-config.json')).write_text(json.dumps(config,indent=2),encoding='utf-8')
