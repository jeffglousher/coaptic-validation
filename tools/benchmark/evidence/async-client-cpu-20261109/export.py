"""Export the closed four-pair CPU development screen; no new measurements."""
import argparse,gzip,json,subprocess
from pathlib import Path
from common import *
MEASUREMENT_SHA='241373173268c997068484f8843fede7397fa98c53d646e07aed6e22ebb2e93d'
ENV_KEYS='RUSTUP_TOOLCHAIN CARGO_INCREMENTAL CARGO_BUILD_JOBS CARGO_PROFILE_TEST_DEBUG CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_RELEASE_DEBUG CARGO_PROFILE_RELEASE_OPT_LEVEL CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_CODEGEN_UNITS RUSTFLAGS PYTHONDONTWRITEBYTECODE'.split()
RESULT_KEYS='status development_only continuation_signal qualified adopted rows summary groups failed_cell_point_guards processes measured_processes preflight_processes measured_operations'.split()
def export(root,core,here,released=False):
 need(released,'explicit parent clock release required');root=Path(root);here=Path(here);dest=here/'package';need(not dest.exists(),'existing package refused')
 p=root/'async-client-cpu-screen/cpu-corrected';original=(p/'measurement.json').read_bytes();need(sha(original)==MEASUREMENT_SHA,'measurement changed');m=json.loads(original)
 need(m['status']=='complete' and m['development_only']is True and m['qualified']is False and m['adopted']is False,'development scope changed')
 plan_bytes=(root/'async-client-cpu-screen-prep/plan.json').read_bytes();plan=json.loads(plan_bytes)
 need(plan['candidate']==PRODUCTION and plan['live_test_only_head']==TESTED and plan['baseline']==BASE,'production/test source pins changed')
 records=[]
 for process in m['processes']:
  label=process['label'];packed=(p/(label+'.json.gz')).read_bytes();stdout=gzip.decompress(packed);raw=json.loads(stdout);keys(raw,RAW_KEYS,'producer raw CPU record',True)
  err=(p/(label+'.stderr.gz')).read_bytes();stderr=gzip.decompress(err)
  record={**process,'raw':{k:raw[k]for k in RAW_KEYS if k in raw},'original_packed_sha256':sha(packed),'original_raw_sha256':sha(stdout),
          'original_stderr_packed_sha256':sha(err),'original_stderr_raw_sha256':sha(stderr),'original_stderr_bytes':len(stderr)};records.append(record)
 method=plan['screen_method']
 data={'schema':'coaptic-four-pair-CPU-vectors/1','claims':CLAIMS,
       'method':{'baseline':BASE,'production':PRODUCTION,'source_with_corrected_test':TESTED,'cells':plan['cells'],'orders':method['orders'],
                 'warmup':method['warmup'],'preflight_operations':method['preflight_operations'],'cpu_affinity':method['cpu'],'parent_clocks_released':released},'processes':records}
 result=grade(data);same({k:result[k]for k in RESULT_KEYS},{k:m[k]for k in RESULT_KEYS})
 def git(*a):return subprocess.run(['git','-c','safe.directory='+str(core),'-C',str(core),*a],capture_output=True,check=True).stdout
 files=git('diff','--name-only',BASE,TESTED,'--','*.rs').decode().splitlines();need(files==SOURCE_PATHS,'exact six-file final source patch differs')
 onlytest=git('diff','--name-only',PRODUCTION,TESTED).decode().splitlines();need(onlytest==['src/app/async_server_tests.rs'],'production/test-only separation differs')
 patch=git('diff','--no-ext-diff',BASE,TESTED,'--',*files)
 source_files=[]
 for name in files:
  added=git('diff','--diff-filter=A','--name-only',BASE,TESTED,'--',name).decode().strip()==name
  before=None if added else git('show',BASE+':'+name);after=git('show',TESTED+':'+name);source_files.append({'path':name,'before_sha256':None if added else sha(before),'after_sha256':sha(after)})
 findings_bytes=(root/'async-client-codegen-analysis/integrated-findings.json').read_bytes();findings=json.loads(findings_bytes)
 correction_bytes=(root/'async-client-cpu-screen-prep/parent-clock-correction-seal.json').read_bytes();correction=json.loads(correction_bytes)['execution_correction']
 audit_bytes=(root/'async-client-cpu-numeric-review/receipt.json').read_bytes();need(sha(audit_bytes)=='266d15fb526add269d02029c032d22a1b10f1e5fb841bb0496118e8dfdf7f673','independent numeric audit changed')
 compiler_files=[{'basename':Path(k).name,'sha256':v}for k,v in plan['compiler_files_sha256'].items()]
 provenance={'schema':'coaptic-four-pair-CPU-provenance/1','measurement_sha256':MEASUREMENT_SHA,'plan_sha256':sha(plan_bytes),
  'production_commit':PRODUCTION,'source_with_corrected_test':TESTED,'test_only_difference':onlytest,'source_files':source_files,'source_patch_sha256':sha(patch),
  'compiler_version_verbose':plan['compiler_version_verbose'],'compiler_files':compiler_files,'build_environment':{k:plan['build_environment'][k]for k in ENV_KEYS},
  'normalized_build_argv':['cargo','+stable','build','--offline','--locked','--release','--manifest-path','FIXTURE/probe/Cargo.toml','--bins','--features','oscore,alloc'],
  'original_build_argv_sha256':sha(enc(plan['build_command'])),'fixture_count':plan['fixture_file_count'],'fixture_input_plan_sha256':sha(enc({'baseline_inputs':plan['baseline_inputs'],'candidate_inputs':plan['candidate_inputs']})),
  'original_runner_sha256':plan['old_runner_sha256'],'corrected_screen_sha256':correction['corrected_script_sha256'],
  'wrapper_refusal':{'original_failure_sha256':correction['original_failure_sha256'],'no_benchmark_process_started':correction['no_benchmark_process_was_started'],'original_failure_preserved':correction['failed_output_preserved']},
  'static_findings_sha256':sha(findings_bytes),'static_findings':{k:findings[k]for k in ['gains','tradeoffs','constructor_hypothesis','conclusion']},
  'independent_numeric_audit_sha256':sha(audit_bytes),'scope_claims':SCOPE_CLAIMS,'scope':'Full-vector arithmetic/eligibility reproduction. Four process pairs only; no full-confidence, regression, adoption or libcoap claim. Compiler/fixture/binary joins are retained producer attestations; not an independent build kit.'}
 validate_provenance(provenance,patch)
 plain=enc(data);z=gzip.compress(plain,9,mtime=0);contents={'cpu.json.gz':z,'results.json':enc(result),'provenance.json':enc(provenance),'sources/a85-to-4f-rust.patch.gz':gzip.compress(patch,9,mtime=0)}
 for name in ['common.py','export.py','verify.py','test_export.py','README.md','fixtures.json.gz']:contents[name]=(here/name).read_bytes()
 for name,b in contents.items():
  visible=gzip.decompress(b)if name.endswith('.gz')else b;need(not private(visible),'privacy refused '+name);relative(name)
 manifest={'schema':'coaptic-four-pair-CPU-manifest/1','files':{name:{'bytes':len(b),'sha256':sha(b)}for name,b in sorted(contents.items())}}
 for name,b in contents.items():
  if name.endswith('.gz'):
   expanded=gzip.decompress(b);manifest['files'][name].update(raw_bytes=len(expanded),raw_sha256=sha(expanded))
 contents['manifest.json']=enc(manifest);used=sum(f.stat().st_size for f in here.rglob('*')if f.is_file())
 need(used+sum(map(len,contents.values()))<=BUDGET,'combined one MiB cap exceeded; no cap enlargement permitted')
 dest.mkdir()
 for name,b in contents.items():
  f=dest/name;f.parent.mkdir(parents=True,exist_ok=True)
  with f.open('xb')as out:out.write(b)
 return {'manifest_sha256':sha(contents['manifest.json']),'package_bytes':sum(map(len,contents.values())),'combined_bytes':used+sum(map(len,contents.values())),
         'full_used_samples':result['all_used_cycle_samples'],'calibration_samples_also_retained':result['calibration_samples_retained'],'continuation_signal':result['continuation_signal']}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--core-repo',type=Path,required=True);p.add_argument('--parent-clocks-released',action='store_true');a=p.parse_args()
 print(json.dumps(export(a.native_root,a.core_repo,Path(__file__).resolve().parent,a.parent_clocks_released),sort_keys=True))
