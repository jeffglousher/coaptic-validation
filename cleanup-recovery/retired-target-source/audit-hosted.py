"""Audit changed Observe campaigns and exact candidate source provenance."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'tools/interop'))
from oscore_observe import campaign_review
from oscore_observe_cancel import review as cancellation_review
config=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
out=Path(config['output']);out.mkdir(parents=True,exist_ok=True)
def gh(*args):return json.loads(subprocess.check_output(['gh',*map(str,args)]))
pr=gh('pr','view',config['pr'],'-R',config['repo'],'--json','headRefOid,statusCheckRollup')
assert pr['headRefOid']==config['head']
checks=pr['statusCheckRollup']
assert len(checks)==config['checks'] and all(c['conclusion']=='SUCCESS' for c in checks)
run=gh('run','view',config['run'],'-R',config['repo'],'--json','headSha,status,conclusion,jobs')
assert run['headSha']==config['head'] and run['status']=='completed' and run['conclusion']=='success'
job=next(j for j in run['jobs'] if 'independent process interop' in j['name'])
for step in ('Authenticated protected Observe ownership and IPv6 oracle tests',
             'Authenticated protected Observe duplicate oracle tests','Authenticated protected Observe cancellation oracle tests',
             'Protected Observe duplicate refusal and fresh recovery','Protected IPv6 Observe duplicate refusal and fresh recovery',
             'Protected Observe explicit cancellation and fresh registration','Protected IPv6 Observe explicit cancellation and fresh registration'):
    assert any(s['name']==step and s['conclusion']=='success' for s in job['steps'])
if not (out/'artifact').exists():
    subprocess.run(['gh','run','download',str(config['run']),'-R',config['repo'],'-n','process-interop','-D',str(out/'artifact')],check=True)
patch=json.loads((root/'tools/interop/libcoap/patches/oscore-qblock2-continuation.json').read_text(encoding='utf-8'))
reports={};trees={}
for label,family,name,grader,schema in (
    ('observe-ipv4','ipv4','oscore-observe-campaign.json',campaign_review,'coaptic-protected-observe/1'),
    ('observe-ipv6','ipv6','oscore-observe-ipv6-campaign.json',campaign_review,'coaptic-protected-observe/1'),
    ('cancel-ipv4','ipv4','oscore-observe-cancellation.json',cancellation_review,'coaptic-protected-observe-cancellation/1'),
    ('cancel-ipv6','ipv6','oscore-observe-cancellation-ipv6.json',cancellation_review,'coaptic-protected-observe-cancellation/1')):
    paths=list((out/'artifact').rglob(name));assert len(paths)==1
    path=paths[0];report=json.loads(path.read_text(encoding='utf-8'))
    assert report['schema']==schema and report['qualification_complete'] and report['campaign']['complete']
    assert report['dirty'] is False and report['suite_dirty'] is False
    assert report['family']==family and report['campaign']['family']==family
    assert report['libcoap_source']=='851533c3cf63d16984d370ce39d586ecb3694971'
    assert report['libcoap_patch']==patch and report['suite_locks']==config['locks']
    assert all(len(row['sha256'])==64 for row in report['executables'].values())
    proof=grader(report['campaign'],patch,family=family);assert proof==report['campaign']['proof']
    for kind,worktree,sha,head in (('suite',root,report['suite_source'],config['suite_head']),
                                  ('core',Path(config['core_worktree']),report['source'],config['core_head'])):
        subprocess.run(['git','fetch','origin',sha],cwd=worktree,capture_output=True,check=True)
        tree=lambda rev:subprocess.check_output(['git','rev-parse',rev+'^{tree}'],cwd=worktree,text=True).strip()
        assert tree(sha)==tree(head)
        identity=dict(hosted=sha,head=head,tree=tree(sha))
        assert kind not in trees or trees[kind]==identity
        trees[kind]=identity
    reports[label]=dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),proof=proof,executables=report['executables'])
assert all(r['executables']==reports['observe-ipv4']['executables'] for r in reports.values())
result=dict(complete=True,repo=config['repo'],run=config['run'],pr=config['pr'],checks=len(checks),trees=trees,reports=reports)
(out/'verified-summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
(out/'checks.json').write_text(json.dumps(pr,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result))
