import json
from pathlib import Path
import subprocess
import uuid

root=Path(__file__).resolve().parent
event=json.loads((root/'board-benchmark-storage-send.json').read_text())['event']
ref=dict(id=event['id'],source=event['source'])
def invoke(request):
    result=subprocess.run(['C:/Users/jeffg/.cargo/bin/agent-board.exe','mailbox','request','--json'],input=json.dumps(request),text=True,capture_output=True,check=True)
    print(result.stdout)
    return json.loads(result.stdout)
read=invoke(dict(operation='get',mailbox='58cdc9b1-5474-41b1-b06d-d0cceaa66c7d',session='c0fe7fc3-5f99-4eb1-aeb3-1a5d4063249c',message=ref))
assert read['event']['id']==ref['id']
ack=root/'board-benchmark-storage-ack.json'
if not ack.exists():
    ack.write_text(json.dumps(dict(operation='acknowledge',mailbox='58cdc9b1-5474-41b1-b06d-d0cceaa66c7d',actor=event['data']['actor'],message=ref,receiptid=str(uuid.uuid4()),stage='acknowledged',detail='Read own shared-host storage and benchmark coordination notice; preserve other work and retain contention in report.'),indent=2))
invoke(json.loads(ack.read_text()))
