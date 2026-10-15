import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[2]
here = Path(__file__).resolve().parent
variant = here / 'regression-source'
variant.mkdir(exist_ok=True)
if not (variant/'coaptic/.git').exists():
    subprocess.run(['git', 'clone', '--shared', '--no-checkout', str(root/'coaptic'), str(variant/'coaptic')],check=True)
subprocess.run(['git','-C',str(variant/'coaptic'),'checkout','--detach','5039b5af791bdc95327992caeef798b2740731c8'],check=True)
native = variant/'tools/benchmark/native'
if not native.exists():
    shutil.copytree(root/'tools/benchmark/native',native,ignore=shutil.ignore_patterns('target'))
binary_root = here/'bin'
binary_root.mkdir(exist_ok=True)
current = Path('D:/coaptic-batch-interop-target/release/bench-rust-server.exe')
for name in ('bench-rust-server.exe','bench-load.exe'):
    destination = binary_root/name
    if not destination.exists():
        shutil.copy2(current.with_name(name),destination)
env = dict(os.environ,CARGO_TARGET_DIR='D:/coaptic-batch-interop-target',CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0')
subprocess.run(['cargo','build','--release','--manifest-path',str(native/'Cargo.toml'),'-p','bench-rust-server'],env=env,check=True)
destination = binary_root/'bench-rust-server-5039.exe'
if destination.exists():
    raise FileExistsError(destination)
shutil.copy2(current,destination)
def git(directory,*args):
    return subprocess.check_output(['git','-C',str(directory),*args],text=True).strip()
def sha(p):
    with p.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()
report=dict(baseline=git(variant/'coaptic','rev-parse','HEAD'),baseline_tree=git(variant/'coaptic','rev-parse','HEAD^{tree}'),baseline_status=git(variant/'coaptic','status','--porcelain'),
            current=git(root/'coaptic','rev-parse','HEAD'),current_tree=git(root/'coaptic','rev-parse','HEAD^{tree}'),current_status=git(root/'coaptic','status','--porcelain'),
            suite=git(root,'rev-parse','HEAD'),baseline_lock_sha256=sha(native/'Cargo.lock'),current_lock_sha256=sha(root/'tools/benchmark/native/Cargo.lock'),
            server_fixture_sha256=sha(native/'servers/src/main.rs'),current_server_fixture_sha256=sha(root/'tools/benchmark/native/servers/src/main.rs'),
            features=['std','alloc','oscore'],compiler=subprocess.check_output(['rustc','-vV'],text=True),
            build=dict(profile='release',lto='thin',codegen_units=1,jobs=1,incremental=0,baseline_lock_resolution='derived from committed current-suite lock against baseline dependencies; derived lock retained'),
            binaries={p.name:sha(p) for p in binary_root.glob('*.exe')})
(here/'regression-provenance.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
