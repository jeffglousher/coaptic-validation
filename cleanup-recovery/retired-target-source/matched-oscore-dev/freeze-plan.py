import hashlib
import json
from pathlib import Path
import shutil
import sys

root = Path(__file__).resolve().parents[2]
here = Path(__file__).resolve().parent
sys.path.insert(0,str(root/'tools/benchmark'))
import campaign
import prepare

manifest = campaign.read(here/'full-manifest.json')
binary_root = here/'bin'
binary_root.mkdir(exist_ok=True)
origins = []
for peer in manifest['peers']:
    for field in ('server','driver'):
        source = Path(peer[field][0])
        if source.name in ('bench-rust-server.exe','bench-load.exe','bench-go.exe','bench-libcoap.exe'):
            destination = binary_root/source.name
            # Native binaries were frozen before the baseline rebuild.
            if not destination.exists():
                shutil.copy2(source,destination)
            peer[field][0] = str(destination.resolve())
            origins.append(dict(original=str(source),frozen=str(destination),sha256=campaign.digest(destination)))
manifest['sources']['suite'] = prepare.source_identity(root)
manifest['binary_snapshots'] = origins
campaign.write_new(here/'matched-manifest.json',manifest)
campaign.write_new(here/'matched/plan.json',campaign.create_plan(manifest,10,20261013))

regression = dict(manifest)
current = next(p for p in manifest['peers'] if p['id']=='coaptic')
driver = [str(binary_root/'bench-load.exe'),'{host}','{port}','{bytes}','{concurrency}','{operations}','{warmup}','{timeout_ms}','{mode}']
current = dict(current,driver=driver)
baseline = dict(current,id='coaptic-5039',server=[str(binary_root/'bench-rust-server-5039.exe'),'coaptic','{host}','{port}','{bytes}','1472'])
baseline['identity'] = dict(current['identity'],implementation='coaptic-5039',source='5039b5af791bdc95327992caeef798b2740731c8')
for peer in (current,baseline):
    peer['identity'] = dict(peer['identity'])
    peer['identity'].pop('driver_crypto',None)
    peer['identity']['driver_scope']='native Rust driver; no crypto/library dependencies; plaintext closed-loop'
    peer.pop('dependency_trees',None)
    peer.pop('dependency_files',None)
regression['peers']=[current,baseline]
regression['cases']=[c for c in manifest['cases'] if c['security']=='plaintext']
regression['sources']['baseline']=campaign.read(here/'regression-provenance.json')
regression['scope']='matched current/5039 plaintext regression; identical current fixture source and driver; features std,alloc,oscore enabled in both servers; baseline dependency versions retained'
campaign.write_new(here/'regression-manifest.json',regression)
campaign.write_new(here/'regression/plan.json',campaign.create_plan(regression,10,20261013))
print(json.dumps(dict(peers=len(manifest['peers']),cases=len(manifest['cases']),cells_per_session=len(campaign.read(here/'matched/plan.json')['schedule'][0]),sources=manifest['sources'])))
