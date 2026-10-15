from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=root/'tools/interop/oscore_observe.py'
s=p.read_text(encoding='utf-8')
for old,new in [
 ('front,back,server=(loopback_endpoint(endpoints[k],family) for k in ("front","back","server"))\n    req=None', 'front,back,server=(loopback_endpoint(endpoints[k],family) for k in ("front","back","server"))\n    require(len({client,front,back,server})==4,"overlapping writer/readback owners")\n    req=None'),
 ('def campaign_review(record,patch):', 'def campaign_review(record,patch,*,family="ipv4"):\n    require(family in ("ipv4","ipv6") and record.get("family","ipv4")==family,"campaign family mismatch")'),
 ('server=loopback_endpoint(("127.0.0.1",ready["port"]),"ipv4")', 'server=loopback_endpoint(("::1",ready["port"],0,0) if family=="ipv6" else ("127.0.0.1",ready["port"]),family)'),
 ('index*2,index==1)', 'index*2,index==1,family=family)'),
 ('exchange_grade(write,2,b"",server)', 'exchange_grade(write,2,b"",server,family=family)'),
 ('exchange_grade(case["readback"],1,str(index*2+2).encode(),server)', 'exchange_grade(case["readback"],1,str(index*2+2).encode(),server,family=family)'),
 ('require(not response_pivs.intersection(proof["response_pivs"]),"server notification nonce reused")\n        response_pivs.update(proof["response_pivs"])', 'for trace in [case["trace"],*(w["trace"] for w in case["writes"]),case["readback"]["trace"]]:\n            for piv in explicit_server_pivs(trace):\n                require(piv not in response_pivs,"server response PIV reused across campaign")\n                response_pivs.add(piv)'),
 ('"scope":"finite IPv4 loopback fixture,', '"scope":f"finite {\'IPv6\' if family==\'ipv6\' else \'IPv4\'} loopback fixture,'),
 ('def campaign(client,server,record,patch):\n    record["sessions"]=[]\n    with Server(server,"oscore") as service:', 'def campaign(client,server,record,patch,*,family="ipv4"):\n    require(family in ("ipv4","ipv6"),"unsupported protected address family")\n    record.update(family=family,sessions=[])\n    with Server(server,"oscore",family=family) as service:'),
 ('sequence=0,path="counter")', 'sequence=0,path="counter",family=family)'),
 ('relay=ObserveRelay(service.number)', 'relay=ObserveRelay(service.number,family=family)'),
 ('r=Proxy(service.number,"pass")', 'r=Proxy(service.number,"pass",family=family)'),
 ('relay_endpoints(r,"ipv4")', 'relay_endpoints(r,family)'),
 ('method=method,sequence=sequence)', 'method=method,sequence=sequence,family=family)'),
 ('relay_endpoints(relay,"ipv4")', 'relay_endpoints(relay,family)'),
 ('timeout=15000,observe=True)', 'timeout=15000,observe=True,family=family)'),
 ('campaign_review(record,patch);', 'campaign_review(record,patch,family=family);'),
 ('args=parser.parse_args();', 'parser.add_argument("--family",choices=("ipv4","ipv6"),default="ipv4")\n    args=parser.parse_args();'),
 ('"qualification_complete":False,"campaign":{}}', '"family":args.family,"qualification_complete":False,"campaign":{}}'),
 ('report["campaign"],patch);', 'report["campaign"],patch,family=args.family);'),
]:
    assert old in s,old
    s=s.replace(old,new)
p.write_text(s,encoding='utf-8',newline='\n')
p=root/'.github/workflows/ci.yml'
s=p.read_text(encoding='utf-8').replace('f245d97e7e2bcffd568ed8d1f94379c18fcc6bc6','b953240c9e5cdabe5a889868ac4aeb18456c7bb6')
p.write_text(s,encoding='utf-8',newline='\n')
