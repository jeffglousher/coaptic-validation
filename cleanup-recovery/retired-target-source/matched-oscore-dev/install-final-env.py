import os
from pathlib import Path
import subprocess
import sys

root=Path('D:/CoapticCurrent/matched-benchmark-20261013-venv')
scratch=Path('D:/codex-work/coaptic-validation-observe-evidence-wave/target/matched-oscore-final-install')
scratch.mkdir(exist_ok=True)
env=dict(os.environ,TEMP=str(scratch),TMP=str(scratch),PIP_CACHE_DIR='D:/coaptic-tools/benchmark-pip-cache')
if not (root/'Scripts/python.exe').exists():
    subprocess.run([sys.executable,'-m','venv',str(root)],env=env,check=True)
subprocess.run([str(root/'Scripts/python.exe'),'-m','pip','install','-r','tools/benchmark/protected/requirements.txt'],env=env,check=True)
