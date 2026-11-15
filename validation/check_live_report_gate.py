#!/usr/bin/env python3
from pathlib import Path
import json,time,base64,hmac,hashlib,urllib.request,urllib.error
ROOT=Path(__file__).resolve().parent
enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=')
u=enc(b'{"alg":"HS256","typ":"JWT"}')+b'.'+enc(json.dumps({'sub':'ARTEX','exp':int(time.time())+120}).encode());key=(ROOT.parent/'identity/jwt.key').read_bytes().strip();token=(u+b'.'+enc(hmac.new(key,u,hashlib.sha256).digest())).decode()
base='http://127.0.0.1:8797/api/android/assessments/6cea5264-a3be-46ea-aa96-f7bb4749c4e4'
def fetch(path):
 try:r=urllib.request.urlopen(urllib.request.Request(base+path,headers={'Authorization':'Bearer '+token}),timeout=10)
 except urllib.error.HTTPError as e:r=e
 return r.status,r.read().decode(),r.headers
status,body,_=fetch('/report');assert status==409,(status,body)
ds,draft,headers=fetch('/report?draft=1');assert ds==200 and draft.startswith('# DRAFT') and 'draft-assessment-' in headers['Content-Disposition']
_,body,_=fetch('');d=json.loads(body);finding=next(f for f in d['findings'] if f['id']=='a403e2490e711822beee2476');assert finding['validation_status']=='validated'
pending=sum(f['validation_status'] not in ['validated','false_positive','remediated'] for f in d['findings'])
result={'final_report_status':status,'draft_report_status':ds,'draft_labeled':True,'firebase_finding_status':finding['validation_status'],'remaining_unresolved_findings':pending}
(ROOT/'results/live-report-gate.json').write_text(json.dumps(result,indent=2)+'\n');(ROOT.parent/'data/allsafe-validation-draft.md').write_text(draft)
print(json.dumps(result,indent=2))
