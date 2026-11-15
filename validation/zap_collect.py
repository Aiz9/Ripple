#!/usr/bin/env python3
"""Capture custom requests and run only two ZAP checks against localhost."""
import urllib.request,urllib.parse,json,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE='http://127.0.0.1:18090';TARGET='http://127.0.0.1:18091'
def api(path,**params):
 with urllib.request.urlopen(BASE+path+'?'+urllib.parse.urlencode(params),timeout=30) as r:return json.load(r)
x=api('/JSON/core/view/messages/',baseurl=TARGET,start=0,count=500)
# Keep only the custom runner's four original requests, not previous ZAP scans.
x['messages']=[m for m in x['messages'] if 'User-Agent: AndroidLab-API-Security/1.0' in m['requestHeader'] and '/fixture' in m['requestHeader'].splitlines()[0]][:4]
if len(x['messages'])!=4:raise SystemExit('Need exactly four original custom fixture requests; start a fresh ZAP session')
(ROOT/'results/zap-original-messages.json').write_text(json.dumps(x,indent=2))
api('/JSON/ascan/action/disableAllScanners/')
api('/JSON/ascan/action/enableScanners/',ids='40012,40018')
for id in [40012,40018]:api('/JSON/ascan/action/setScannerAttackStrength/',id=id,attackStrength='LOW')
scan=api('/JSON/ascan/action/scan/',url=TARGET+'/fixture?q=baseline',recurse='false',inScopeOnly='false')['scan']
for _ in range(60):
 if api('/JSON/ascan/view/status/',scanId=scan)['status']=='100':break
 time.sleep(1)
else:raise SystemExit('ZAP scan did not complete within one minute')
(ROOT/'results/zap-active-alerts.json').write_text(json.dumps(api('/JSON/core/view/alerts/',baseurl=TARGET,start=0,count=500),indent=2))
print('Local scan complete; original exchanges and alerts saved')
