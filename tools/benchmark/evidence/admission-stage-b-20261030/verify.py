"""Standalone, stdlib, data-only verification. Run python -B verify.py.

No network, subprocess, imports of producer modules, native execution or writes.
Pure schema functions are explicitly reused by AST extraction from exact retained
c656045 source; runtime/compiler assertions remain collector/producer evidence.
Bootstrap arithmetic below is independently implemented from all raw samples.
Reproducing 13 failed gates and the frozen STOP vector is verification SUCCESS.
"""
import ast,base64,copy,gzip,hashlib,json,lzma,math,random,re,sys,zlib
from pathlib import Path,PurePosixPath
from types import SimpleNamespace

SUITE='c65604510749424bc3efc2b54157bef08c036c42'
TREE='901553be75877c3c59e309d4252028d8abb8ba55'
H='161b7fd033cd7c2cc37b203f878b4307de913e2da2b651bacdbe9e84c186a83c'
COLLECTORS={
 'collector-41151191502.json':(24395,'f393110575fd493727ad01fba1eb53eaef5c53b2f3f4fc2ddbe2d2c32c4381e6'),
 'collector-41152630644.json':(32397,'4a698384e84dd29234652cfdfba74dcff7a3e34a2b47b6f063ae299ecaea6d99'),
 'collector-timing-41154445351.json':(77438,'00051d3be2caa2d6af25dbdeccf7dc9c808180512e65fc23f26fc46a814e013f')}
STOP=[False,False,True,True,False,True,False,False,False,False,False,False,True,False,True,False,False,True,True,True,True,False,True,True,True,True,True,True,True,True,True,True,True,True,True,True]
sha=lambda b:hashlib.sha256(b).hexdigest()
def require(ok,label):
    if not ok:raise ValueError(label)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def exact(a,b,label):require(encoded(a)==encoded(b),label)
def read_json(raw):
    require(len(raw)<=16*1024**2,'bounded JSON')
    def pairs(items):
        result={}
        for k,v in items:
            require(k not in result,'duplicate JSON key');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
def safe_name(name):
    require(type(name) is str and name==str(PurePosixPath(name)) and not PurePosixPath(name).is_absolute() and '\\' not in name and ':' not in name and all(p not in ('','..','.') for p in name.split('/')),'safe unique relative name')
def gunzip(raw):
    decoder=zlib.decompressobj(31);plain=decoder.decompress(raw,16*1024**2+1)
    require(len(plain)<=16*1024**2 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'bounded single gzip stream')
    return plain
def unpack(raw):
    require(len(raw)<=700000 and raw[4:8]==bytes(4),'deterministic bounded gzip')
    data=read_json(gunzip(raw));exact(data['codec'],'concatenated-utf8-xz-base64/1','codec')
    decoder=lzma.LZMADecompressor(memlimit=128*1024**2)
    p=decoder.decompress(base64.b64decode(data['payload_base64'],validate=True),max_length=16*1024**2+1)
    require(len(p)<=16*1024**2 and decoder.eof and not decoder.unused_data,'bounded single XZ stream')
    require(len(p)==data['payload_bytes']<=16*1024**2 and sha(p)==data['payload_sha256'],'pack payload')
    files={};off=0
    for name,s in data['members'].items():
        safe_name(name);require(s['offset']==off and type(s['bytes']) is int and s['bytes']>=0,'contiguous offsets')
        b=p[off:off+s['bytes']];off+=s['bytes']
        require((len(b),sha(b),zlib.crc32(b)&0xffffffff)==(s['bytes'],s['sha256'],s['crc32']),'member integrity '+name)
        require(b.decode('utf8','strict').encode('utf8')==b,'UTF8 roundtrip');files[name]=b
    require(off==len(p),'no dropped trailing bytes')
    return files

def pure_api(parents):
    """Attribute exact source reuse; select only pure functions and literal constants."""
    source=parents['frozen-source/tools/benchmark/admission_stage_b.py']
    require(sha(source)=='acfabe3b3f9b33bf0cdecfa4c0f2226de7b4e38494039fb166147e075352cd6f','immutable adapter source')
    raw=parents['frozen-source/tools/benchmark/admission_stage_b_contract.json'];c=read_json(raw)
    require(raw==encoded(c)+b'\n' and sha(encoded(c))==H,'frozen canonical contract')
    constants={'HASH','ID','ROOT','QUAL_SCHEMA','METRICS','SETTLED','MEMORY','NATIVE_KEYS'}
    functions={'encoded','equal','binding','check','bound','schedule','uint','keys','array','test_cell','validate_native','parse_result','validate_listing'}
    namespace={'math':math,'json':json,'re':re,'contract':lambda:c}
    selected=[];found=set()
    for n in ast.parse(source).body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in constants:
            name=n.targets[0].id;namespace[name]=ast.literal_eval(n.value);found.add(name)
        elif isinstance(n,ast.FunctionDef) and n.name in functions:
            require(not n.decorator_list,'no decorators');selected.append(n);found.add(n.name)
    exact(sorted(found),sorted(constants|functions),'pure definition census')
    exec(compile(ast.Module(body=selected,type_ignores=[]),'<retained-pure-c656045>','exec'),namespace)
    return SimpleNamespace(**{k:namespace[k] for k in constants|functions}),c

def independent_compare(a,b):
    """Twenty consecutive means; reset RNG; A20 then B20 even for BA order."""
    for values in (a,b):
        require(type(values) is list and len(values)==1000 and all(type(x) is int and 0<=x<=30_000_000_000 for x in values),'independent sample bounds')
    aa=[math.fsum(a[i:i+50])/50 for i in range(0,1000,50)]
    bb=[math.fsum(b[i:i+50])/50 for i in range(0,1000,50)]
    require(all(math.isfinite(x) and x>0 for x in aa+bb),'positive block means')
    rng=random.Random(20261030);rep=[]
    for _ in range(10000):
        av=math.fsum(rng.choices(aa,k=20))/20
        bv=math.fsum(rng.choices(bb,k=20))/20
        rep.append(bv/av)
    rep.sort();position=(len(rep)-1)*.95;lo=int(position);fraction=position-lo
    upper=rep[lo]*(1-fraction)+rep[min(lo+1,len(rep)-1)]*fraction
    return dict(mean_ratio=math.fsum(b)/math.fsum(a),upper95=upper,passed=math.isfinite(upper) and upper<=1.02,orientation='B/A')

def verify(blobs=None):
    root=Path(__file__).resolve().parent
    read=lambda name:blobs[name] if blobs is not None else (root/name).read_bytes()
    index=read_json(read('index.json'))
    exact(sorted(index['files']),sorted(['README.md','checks.json','data.json.gz','collectors.json.gz','parent-records.json.gz','verify.py','screen.html']),'bundle census')
    for name,s in index['files'].items():
        raw=read(name);require((len(raw),sha(raw))==(s['bytes'],s['sha256']),'bundle file integrity '+name)
        require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==s['git_blob_sha1'],'Git blob '+name)
        if name.endswith('.gz'):
            b=gunzip(raw);require((len(b),sha(b))==(s['payload_bytes'],s['payload_sha256']),'gzip payload '+name)
    require(len(read('index.json'))+sum(x['bytes'] for x in index['files'].values())+index['attributes_delta_bytes']<=700000,'publication ceiling')
    files=unpack(read('data.json.gz'));parents=unpack(read('parent-records.json.gz'));collectors=unpack(read('collectors.json.gz'))
    exact(sorted(collectors),sorted(COLLECTORS),'collector set')
    for n,(size,h) in COLLECTORS.items():require((len(collectors[n]),sha(collectors[n]))==(size,h),'sealed collector '+n)
    c=read_json(collectors['collector-timing-41154445351.json'])
    exact([c['head'],c['tree'],c['run_id'],c['attempt'],c['status'],c['decision']],[SUITE,TREE,41154445351,1,'completed','STOP'],'run identity')
    require(c['artifact']['id']==13024269755 and c['artifact']['sha256']=='9a41a3511034bb316c82cd4c662043b7b074677f6ce40ffad174385a4fab5b70' and c['artifact']['size']==5090445,'ZIP identity')
    exact(c['artifact']['api_digest'],'sha256:'+c['artifact']['sha256'],'API ZIP digest')
    manifest={m['path']:m for m in c['artifact']['manifest']}
    require(len(manifest)==274 and sum(m['size'] for m in manifest.values())==15287649 and len(files)==270,'artifact census/expanded bytes')
    excluded={v['path'] for v in c['verification']['exe_pdb_actual']};exact(sorted(set(manifest)-set(files)),sorted(excluded),'exactly four binary exclusions')
    require(len(excluded)==4,'binary pair count')
    for name,b in files.items():
        safe_name(name);s=manifest[name];require((len(b),zlib.crc32(b)&0xffffffff,sha(b))==(s['size'],s['crc32'],s['sha256']),'original bytes '+name)
    for m in c['verification']['exe_pdb_actual']:
        x=manifest[m['path']];exact([m['size'],m['sha256']],[x['size'],x['sha256']],'excluded binary hash/size')
    for n,s in index['parent_records'].items():require(n in parents and (len(parents[n]),sha(parents[n]))==(s['bytes'],s['sha256']),'parent snapshot '+n)
    exact(sorted(parents),sorted(index['parent_records']),'no dropped parent records')
    for n,s in c['prior_files'].items():
        b=collectors.get(n,parents.get(n));require(b is not None and (len(b),sha(b))==(s['size'],s['sha256']),'prior bytes '+n)
    api,contract=pure_api(parents);load=lambda n:read_json(files[n]);parse_api=SimpleNamespace(read_json=read_json)
    exact(c['cores'],contract['cores'],'core contract bindings')
    build=load('build.json');owner=load('owner.json');result=load('result.json')
    for obj in [build,owner]:api.check(obj,'stage-b-regression');exact(obj['contract'],contract,'complete frozen contract')
    exact(build['owner'],owner,'owner/build identity');exact(owner['expected_suite'],SUITE,'expected suite');exact([owner['owner'],owner['attempt']],['41154445351','1'],'owner run')
    exact(owner['schema'],contract['owner_schema'],'owner schema');exact(build['flags'],c['verification']['flags'],'build flags');exact(owner['flags'],build['flags'],'owner flags')
    exact([build['suite']['identity'][k] for k in ['commit','tree']],[SUITE,TREE],'suite identity')
    exact(sha(encoded(build['suite'])),c['verification']['source_snapshots']['suite_sha256'],'suite snapshot')
    for arm in 'AB':
        record=build['records'][arm];source=record['source'];ident=source['identity']
        exact({k:ident[k] for k in ['commit','tree']},contract['cores'][arm],'source identity')
        exact(sha(encoded(source)),c['verification']['source_snapshots'][arm+'_sha256'],'source snapshot')
        exact(record['restoration'],'verified clean initial source','restoration attestation');exact(record['cleanup_unresolved'],False,'unresolved source cleanup')
        for kind,pair in build['artifacts'][arm].items():
            api.check(pair,'stage-b-regression');m=next(m for m in c['verification']['exe_pdb_actual'] if m['arm']==arm and m['kind']==kind)
            exact([pair['bytes'],pair['sha256']],[m['size'],m['sha256']],'build binary pair')
            require(pair['path'].replace('\\','/').endswith('/evidence/'+m['path']),'binary path binding')
        cargo=load(arm+'-cargo.json');api.check(cargo,'stage-b-regression')
        exact(cargo['artifacts'],build['artifacts'][arm],'cargo retained pair');exact(cargo['native_tests'],contract['native_validation_tests'],'qualification declaration');exact(cargo['timing_tests'],contract['native_timing_tests'],'timing declaration')
        cargo_lines=[read_json(x) for x in files[arm+'-build.stdout'].splitlines()]
        exact([x.get('success') for x in cargo_lines if x.get('reason')=='build-finished'],[True],'successful Cargo build')
        targets=[x for x in cargo_lines if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')=='admission-stage-b']
        require(len(targets)==1,'single integration test artifact');t=targets[0]
        require(t['target']['kind']==['test'] and t['profile']['test'] is True and str(t['profile']['opt_level'])=='3','release optimized integration test')
        require(t['executable'].replace('\\','/').endswith('/'+m['path'].split('/')[-1].replace('.pdb','.exe')),'Cargo executable name')
    exact(build['compiler'],c['verification']['compiler'],'compiler attestation');exact(build['cargo'],c['verification']['cargo'],'cargo attestation');exact(build['inputs'],c['verification']['inputs'],'input bindings');exact(build['tools'],c['verification']['tool_snapshots'],'tool metadata')
    for name,h in c['verification']['prepared_owner_build_actual_hashes'].items():require(sha(files[name])==h,'prepared owner/build actual bytes')
    binding_count=0
    def bindings(v):
        nonlocal binding_count
        if type(v) is dict:
            if 'contract_id' in v:api.check(v,'stage-b-regression');binding_count+=1
            for x in v.values():bindings(x)
        elif type(v) is list:
            for x in v:bindings(x)
    for n,b in files.items():
        if n.endswith('.json'):bindings(read_json(b))
    # This scan counts retained JSON occurrences once; the collector counted
    # 137 binding checks across its verification operations, a different census.
    require(binding_count==114 and c['verification']['counts']['binding_objects']==137,'retained binding occurrence / collector check census')
    maps=[build['suite']['files']]+[build['records'][a]['source']['files'] for a in 'AB']
    require(sum(len(m) for m in maps)==1505,'all retained source map entries')
    for mapping in maps:
        for name,h in mapping.items():safe_name(name);require(re.fullmatch('[0-9a-f]{64}',h) is not None,'source map hash syntax')
    def process(stem,command):
        p=load(stem+'-process.json');exact(p,dict(cleanup=[],command=command,passed=True,primary=None,returncode=0),'process command/result '+stem)
        require(files[stem+'.stderr']==b'','empty native stderr '+stem)
        return p
    for arm in 'AB':
        exe=build['artifacts'][arm]['exe']['path']
        for prefix,key in [('qualification','native_validation_tests'),('timing','native_timing_tests')]:
            stem=arm+'-'+prefix+'-list';command=[exe]+([] if prefix=='qualification' else ['--ignored'])+['stage_b_validation::' if prefix=='qualification' else 'stage_b::','--list']
            process(stem,command);api.validate_listing(files[stem+'.stdout'],contract[key])
        for i,name in enumerate(contract['native_validation_tests']):
            stem=arm+'-qualification-'+str(i);command=[exe,'--exact',name,'--test-threads=1','--nocapture','--format=terse','--color=never']
            p=process(stem,command);api.parse_result(parse_api,files[stem+'.stdout'],name,True,stderr=files[stem+'.stderr'],returncode=p['returncode'])
    rows=api.schedule();require(len(rows)==40,'40 frozen rows');values={};latencies=calibrations=0
    exact(result['completed'],rows,'all completed rows');exact(result['attempted'],rows,'all attempted rows');exact(result['not_run'],[],'no not-run');exact(result['failed_or_incomplete'],[],'no incomplete')
    exact(result['scope'],contract['measurement_scope'],'measurement scope');exact(result['passed'],False,'producer STOP')
    require(len(c['array_manifest'])==40,'all array manifests')
    for row,m in zip(rows,c['array_manifest']):
        stem='sample-'+str(row['index']).zfill(2);name='stage_b::'+row['case']+'_'+row['security'];exe=build['artifacts'][row['arm']]['exe']
        command=[exe['path'],'--ignored','--exact',name,'--test-threads=1','--nocapture','--format=terse','--color=never'];p=process(stem,command)
        v=api.parse_result(parse_api,files[stem+'.stdout'],name,stderr=files[stem+'.stderr'],returncode=p['returncode'])
        exact(load(stem+'.json'),api.bound(dict(selection=row,artifact=exe,raw_sha256=sha(files[stem+'.stdout']),passed=True),'stage-b-regression'),'sample binding')
        exact(m['selection'],row,'array selection');exact(m['stdout'],stem+'.stdout','array stdout')
        exact(sorted(m['latencies']),sorted(v['latencies_ns']),'latency labels')
        for label,a in v['latencies_ns'].items():
            exact(m['latencies'][label],dict(count=len(a),sha256_canonical_json=sha(encoded(a))),'all latency bytes');latencies+=len(a)
        a=v['calibration_ns'];exact(m['calibration'],dict(count=len(a),sha256_canonical_json=sha(encoded(a))),'all calibration bytes');calibrations+=len(a)
        values[(row['case'],row['security'],row['order'],row['arm'])]=v
    comparisons=[]
    for case in contract['cases']:
        for mode in contract['modes']:
            for order in contract['rounds']:
                for label in case['labels']:
                    pair=[values[(case['id'],mode,order,a)]['latencies_ns'][label] for a in 'AB']
                    comparisons.append(dict(independent_compare(*pair),case=case['id'],security=mode,order=order,label=label))
    exact(comparisons,result['comparisons'],'independent all36 vs producer');exact(comparisons,c['comparisons'],'independent all36 vs sealed collector')
    exact([x['passed'] for x in comparisons],STOP,'frozen STOP vector');exact([latencies,calibrations],[72000,163840],'all raw values retained')
    exact(c['stop_vector'],dict(failed_gates=13,incomplete=0,inconclusive_gates=0,invalid_native=0,missing_gates=0,not_run=0,passed_gates=23),'sealed stop counts')
    exact(result['failure']['primary'],c['underlying_error'],'underlying gate failure');exact(result['failure']['passed'],False,'gate failure receipt')
    outer=load('measure-outer.json');failure=load('failure.json')
    require(outer['error']==failure['error']=='WorkerError' and outer['passed'] is False and failure['passed'] is False,'retained wrapper failure')
    require(b'Stage B gate failed; STOP' in files['measure-outer.stderr'],'outer failure retained')
    screen=read('screen.html').decode('utf8');match=re.search(r'<script type="application/json" id="comparisons">(.*?)</script>',screen,re.S)
    require(match is not None,'screen data present');exact(read_json(match.group(1).encode()),comparisons,'all exact screen comparisons')
    print('PASS: 270 exact artifact texts; 3 sealed collectors; complete parent snapshot; 40 schemas/commands; 24 qualification + 4 listings; 72000 latencies/163840 calibrations; 36 exact independent comparisons; STOP 13 FAIL/23 PASS.')
    return dict(files=files,parents=parents,collectors=collectors,api=api,contract=contract,values=values,comparisons=comparisons,binding_count=binding_count)
def self_test(data):
    """Meaningful RAM-only refusal/roundtrip checks; no workloads or files written."""
    passed=[]
    def refuse(label,operation):
        try:operation()
        except (ValueError,KeyError,UnicodeError):passed.append(label);return
        raise ValueError('refusal test accepted: '+label)
    api=data['api'];first=next(iter(data['values'].values()))
    refuse('strict duplicate JSON',lambda:read_json(b'{"a":1,"a":2}'))
    refuse('nonfinite JSON',lambda:read_json(b'{"a":NaN}'))
    refuse('boolean unsigned',lambda:api.uint(True))
    refuse('negative unsigned',lambda:api.uint(-1))
    refuse('missing sample',lambda:independent_compare([1]*999,[1]*1000))
    refuse('boolean sample',lambda:independent_compare([True]*1000,[1]*1000))
    refuse('zero arithmetic denominator',lambda:independent_compare([0]*1000,[1]*1000))
    row={'case':first['case'],'security':first['security']}
    for label,mutate in [
      ('counter mismatch',lambda v:v['metrics'].__setitem__('admission_rx_refused',0)),
      ('unsettled state',lambda v:v['settled'].__setitem__('rx_empty',False)),
      ('memory accounting',lambda v:v['memory'].__setitem__('fixture_total_requested_bytes',0)),
      ('calibration dropped',lambda v:v['calibration_ns'].pop()),
      ('latency bound',lambda v:next(iter(v['latencies_ns'].values())).__setitem__(0,30_000_000_001))]:
        v=copy.deepcopy(first);mutate(v);refuse(label,lambda v=v:api.validate_native(v,row))
    protected=next(v for v in data['values'].values() if v['security']=='oscore');v=copy.deepcopy(protected);v['sender_sequences']['max_piv_bytes']=3
    refuse('PIV bound',lambda:api.validate_native(v,{'case':v['case'],'security':'oscore'}))
    original=data['files']['sample-00.stdout'];name='stage_b::rx_unprotected'
    refuse('duplicate output marker',lambda:api.parse_result(SimpleNamespace(read_json=read_json),original+original,name))
    exact(independent_compare([100]*1000,[102]*1000),dict(mean_ratio=1.02,upper95=1.02,passed=True,orientation='B/A'),'inclusive 1.02 arithmetic mock')
    exact(independent_compare([100]*1000,[103]*1000),dict(mean_ratio=1.03,upper95=1.03,passed=False,orientation='B/A'),'over-limit arithmetic mock')
    passed+=['inclusive arithmetic boundary','over-limit arithmetic boundary']
    root=Path(__file__).resolve().parent;blobs={p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}
    altered=dict(blobs);b=bytearray(altered['data.json.gz']);b[-1]^=1;altered['data.json.gz']=bytes(b)
    refuse('bundle byte tamper',lambda:verify(altered))
    d=read_json(gunzip(blobs['data.json.gz']));next(iter(d['members'].values()))['offset']=1
    refuse('pack offset tamper',lambda:unpack(gzip.compress(encoded(d),mtime=0)))
    for name in ['data.json.gz','collectors.json.gz','parent-records.json.gz']:
        raw=gunzip(blobs[name]);require(gunzip(gzip.compress(raw,mtime=0))==raw,'gzip RAM roundtrip')
        unpack(blobs[name])
    passed.append('all packs gzip/XZ/member roundtrip')
    patterns={
      'GitHub token':rb'gh[pousr]_[A-Za-z0-9]{20,}',
      'AWS access key':rb'(?:AKIA|ASIA)[A-Z0-9]{16}',
      'private key header':rb'-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----',
      'bearer token':rb'(?i)authorization\s*[:=]\s*["\x27]?bearer\s+[A-Za-z0-9._~-]{16,}',
      'OpenAI style key':rb'sk-(?:proj-)?[A-Za-z0-9_-]{32,}'}
    payloads={}
    for group in ['files','parents','collectors']:
        payloads.update({group+'/'+n:b for n,b in data[group].items()})
    payloads.update({n:b for n,b in blobs.items() if not n.endswith('.gz')})
    findings=[]
    for n,b in payloads.items():
        if b.startswith((b'MZ',b'\x7fELF',b'Microsoft C/C++ MSF')) or b'\x00' in b:findings.append((n,'binary signature/NUL'))
        for label,pattern in patterns.items():
            if re.search(pattern,b):findings.append((n,label))
    require(not findings,'security heuristic findings: '+repr(findings))
    output=dict(refusal_and_roundtrip_checks=passed,security_scan=dict(payloads=len(payloads),findings=0,scope='all reconstructed artifact texts, sealed collectors, parent/source records and uncompressed publication files',limits='common credential patterns and binary signatures/NUL only; not a complete secret or malware audit'))
    print(json.dumps(output,sort_keys=True))
    return output
if __name__=='__main__':
    result=verify()
    if '--self-test' in sys.argv[1:]:self_test(result)
