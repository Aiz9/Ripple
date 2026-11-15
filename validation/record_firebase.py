#!/usr/bin/env python3
"""Record an actually performed raw HTTP validation through existing assessment APIs."""
from pathlib import Path
import json,time,base64,hmac,hashlib,urllib.request,urllib.error
ROOT=Path(__file__).resolve().parent;BASE='http://127.0.0.1:8797/api/android/assessments/6cea5264-a3be-46ea-aa96-f7bb4749c4e4'
def enc(b):return base64.urlsafe_b64encode(b).rstrip(b'=')
key=(ROOT.parent/'identity/jwt.key').read_bytes();header=enc(b'{"alg":"HS256","typ":"JWT"}');claims=enc(json.dumps({'sub':'ARTEX','exp':int(time.time())+600,'iat':int(time.time())}).encode());unsigned=header+b'.'+claims;token=(unsigned+b'.'+enc(hmac.new(key,unsigned,hashlib.sha256).digest())).decode()
def api(path='',data=None):
 req=urllib.request.Request(BASE+path,data=json.dumps(data).encode() if data is not None else None,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
 try:
  with urllib.request.urlopen(req) as r:return json.load(r)
 except urllib.error.HTTPError as e:raise RuntimeError(str(e.code)+' '+e.read().decode())
x=api();d=x.get('assessment',x)
f=next(f for f in d['findings'] if 'Firebase backend permits' in f['title'])
proof=json.loads((ROOT/'results/firebase-validation.json').read_text())
if not (proof['anonymous'] and proof['status']==200 and proof['real_values_returned'] and not proof['truncated']):raise SystemExit('No conclusive proof; do not promote')
if f['validation_status']=='validated':print('Already validated');raise SystemExit()
observation=('Independent anonymous raw HTTP validation: GET '+proof['url']+' returned HTTP 200, application/json, 43 bytes with a concrete 32-character string at the challenge flag key. No Authorization, Cookie, auth parameter, or app credential was sent. This proves anonymous access to actual training-app data, not only metadata. Body SHA-256 '+proof['sha256']+'. Exact raw request/response retained in '+proof['raw_exchange']+' with mode 0600. No writes, further traversal, or other data requests were made. Intended challenge context: Allsafe FirebaseDatabase screen reads the flag. This supports the existing metadata finding and broader read exposure; it does not establish production-user data exposure.')
e={'subject_id':f['subject_ids'][0],'objective':f['objective'],'role':f['role'],'parameters':f.get('parameters',[]),'environment':d['environment'],'revision':d['revision'],'outcome':'vulnerable','observation':observation,'observed_at':proof['observed_at']}
y=api('/evidence',{'performed':True,'evidence':e});d=y.get('assessment',y);eid=d['evidence'][-1]['id']
y=api('/findings/'+f['id']+'/validate',{'status':'validated','rationale':'Confirmed exploitable anonymous read of the Allsafe challenge flag by an independent, bounded raw HTTP request. Real data returned without credentials; evidence hash and restricted raw exchange retained. This is a training-app vulnerability, not evidence of sensitive production data exposure.','role':f['role'],'evidence_ids':[eid]});d=y.get('assessment',y);updated=next(v for v in d['findings'] if v['id']==f['id'])
result={'assessment_id':d['id'],'finding_id':f['id'],'evidence_id':eid,'status':updated['validation_status'],'confidence':updated['confidence'],'anonymous_read_confirmed':True}
(ROOT/'results/firebase-persisted-validation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
