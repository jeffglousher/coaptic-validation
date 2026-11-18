"""Export finite recovery receipts without private configs, keys or host paths."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
from recovery_grading import grade_reconnect
from device_cpu_grading import grade as grade_cpu


def sha(data):
    return hashlib.sha256(data).hexdigest()


def export(root, core):
    read=lambda name:json.loads((root/name).read_text())
    rows=lambda name:[json.loads(x) for x in (root/name).read_text().splitlines()]
    sources={p.relative_to(core).as_posix():sha(p.read_bytes()) for p in (core/'src').rglob('*.rs')}
    def restoration(name):
        capture=rows(name)
        assert capture[-1]['kind']=='capture_complete' and not capture[-1]['overflow']
        assert any('5092e00212e5465f8903bcf1eb1e4d7b' in x.get('line','') for x in capture)
        return dict(verified=True,capture_sha256=sha((root/name).read_bytes()))
    cells=[]
    definitions=[
        ('async','durable-oscore','async-oscore-clock','async-oscore-clock','async-oscore-complete-q2'),
        ('async','unprotected','async-unprotected-complete','async-unprotected-complete','async-unprotected-complete-controls'),
        ('sync','unprotected','sync-unprotected-complete','sync-unprotected-complete','sync-unprotected-complete'),
        ('sync','durable-oscore','sync-oscore-complete','sync-oscore-complete','sync-oscore-complete'),
    ]
    for mode,security,image,wifi,controls in definitions:
        build=read(image+'/firmware-build.json');w=read('trial-'+wifi+'.json');c=read('trial-'+controls+'.json')
        assert build['passed'] and build['staging_restored'] and build['compiled_runtime_verified']
        assert build['security']==security and build['mode']==mode and build['provision_only'] is False
        assert build['generated_security_setter_verified'] and build['generated_wifi_interruption_verified']
        assert build['archive_features']==[('async-network' if mode=='async' else 'network'),'oscore','standalone']
        assert {k.replace('\\','/'):v for k,v in build['source_sha256'].items()}==sources
        assert sha((root/image/'candidate.ota.bin').read_bytes())==build['image_sha256']
        assert sha(gzip.decompress((root/image/'candidate.elf.gz').read_bytes()))==build['elf_sha256']
        assert sha((root/('async-final.a' if mode=='async' else 'sync-final.a')).read_bytes())==build['archive_sha256']
        assert w['wifi_call_passed'] and c['passed'] and w['restore_verified'] and c['restore_verified']
        assert w['run_id']==c['run_id']==build['run_id']
        reconnect=rows(wifi+'-trial/reconnect.jsonl')
        grade=grade_reconnect(w['wifi_receipt']+' '+w['clock_receipt'],reconnect,build['run_id'])
        if security=='durable-oscore':
            control=(w.get('protected_controls') or c.get('controls'))
            assert control['passed'] and control['cached_reply_confirmed'] and control['duplicated_wire']
            assert control['refused_and_reused'] and control['unresolved_relations']==0
            assert (control['after']-control['before'])%2**32==1
            effects=dict(before=control['before'],after=control['after'],exact_duplicate_cached_reply=True)
        else:
            control=c['controls'];assert all(x['passed'] for x in control.values())
            effects=control['duplicate-effects']['observations']
            assert (effects['after']-effects['before'])%2**32==1 and effects['identical_requests']==2
            pool=control['observe-capacity']['observations']
            assert pool['capacity']==2 and pool['third_registration_refused'] and pool['released_slot_reused']
        q=c['qblock_suffix']
        assert q['passed'] and q['run_id']==build['run_id'] and q['security']==security
        assert q['first_size2_2000'] and q['dropped_final_976'] and q['suffix_repair_sent']
        normal=['normal-after-'+controls+'.jsonl']
        if wifi!=controls:normal.append('normal-after-'+wifi+'.jsonl')
        if wifi=='async-oscore-clock':normal[-1]='normal-after-drained-async-protected-verified.jsonl'
        cells.append(dict(mode=mode,security=security,run_id=build['run_id'],image_sha256=build['image_sha256'],
            elf_sha256=build['elf_sha256'],archive_sha256=build['archive_sha256'],archive_features=build['archive_features'],
            source_head=build['source_head'],suite_recorded_at_build_completion=build['suite_source'],
            client_sha256=c['client_sha256'],duplicate_effects=effects,observe_capacity=2,observe_refused_and_reused=True,
            qblock_suffix=q,wifi=grade,delayed_call_elapsed_us=next(x['elapsed_us'] for x in reconnect if x.get('index')==grade['delayed_call']),
            restorations=[restoration(x) for x in dict.fromkeys(normal)]))
    cpu=read('trial-async-oscore-cpu.json');b=read('async-oscore-cpu/firmware-build.json')
    assert cpu['passed'] and cpu['restore_verified'] and b['diagnostic_only']
    assert sha((root/'async-oscore-cpu/candidate.ota.bin').read_bytes())==b['image_sha256']
    assert sha(gzip.decompress((root/'async-oscore-cpu/candidate.elf.gz').read_bytes()))==b['elf_sha256']
    assert cpu['run_id']==b['run_id']
    g=grade_cpu([x.get('line','') for x in rows('async-oscore-cpu-trial/api.jsonl')],rows('async-oscore-cpu-trial/host-timing.jsonl'),cpu['run_id'])
    performance=dict(mode='async',security='durable-oscore',run_id=cpu['run_id'],image_sha256=b['image_sha256'],elf_sha256=b['elf_sha256'],
        kernel_original_sha256=b['kernel_original_sha256'],kernel_copy_sha256=b['kernel_copy_sha256'],
        restoration=restoration('normal-after-async-oscore-cpu.jsonl'),**{key:value for key,value in g.items() if key!='run_id'})
    return dict(schema='coaptic-finite-device-recovery/1',production_core='b8750885f8bd10d2f5dd73c92807df00c7f2f0a8',
        core_source_inventory_sha256=sha(json.dumps(sources,sort_keys=True).encode()),cells=cells,performance=performance,
        capacities=dict(rx_datagrams=2,tx_datagrams=2,datagram_bytes=1152,body_bytes_each_direction=4096,dedup=4,observe=2,calls=4,security_bindings=4,associations=1,deferred=0,routes=8),
        limits=['QBlock2 loss is host receive/device response reissue, not MCU-client recovery',
                'Call initiated during outage; pre-existing-at-disable Call unproven','Only Observe pool exhaustion selected',
                'CPU is one instrumented async OSCORE diagnostic, includes attributed ISR/stall time; no gain comparison',
                'Resource samples and startup-inclusive minima do not establish normal firmware traffic peaks',
                'Physical power333, deferred credential touch365 and scoped inbound reverse-LAN remain unexecuted'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root',type=Path,required=True)
    parser.add_argument('--core-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=export(args.evidence_root,args.core_root)
    with args.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
