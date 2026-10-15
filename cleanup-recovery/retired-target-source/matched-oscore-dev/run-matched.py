import json
import datetime
from pathlib import Path
import sys
import time

root = Path(__file__).resolve().parents[2]
here = Path(__file__).resolve().parent
sys.path.insert(0,str(root/'tools/benchmark'))
import campaign

for window in range(10):
    for name in ('matched','regression'):
        if (here/name/f'window-{window}.json').exists():
            continue
        if window:
            previous=campaign.read(here/name/f'window-{window-1}.json')
            due=datetime.datetime.fromisoformat(previous['finished'])+datetime.timedelta(seconds=65)
            while (remaining:=(due-datetime.datetime.now(datetime.timezone.utc)).total_seconds()) > 0:
                time.sleep(min(remaining,10))
        campaign.run_window(here/name,window)
        print(json.dumps(dict(campaign=name,window=window,completed=True,utc=campaign.utc())),flush=True)
for name,reference in (('matched','coaptic'),('matched','coaptic-oscore'),('regression','coaptic-5039')):
    result=campaign.analyze(here/name,reference)
    campaign.write_new(here/(name+'-'+reference+'-report.json'),result)
    print(json.dumps(dict(campaign=name,reference=reference,report_written=True)),flush=True)
