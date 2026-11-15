#!/usr/bin/env python3
"""One bounded anonymous read of the user-selected Allsafe training backend."""
import urllib.request,urllib.error,json,hashlib,os,datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parent
url='https://allsafe-8cef0.firebaseio.com/.json?orderBy=%22%24key%22&limitToFirst=1&timeout=5s'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
req=urllib.request.Request(url,headers={'User-Agent':'AndroidLab-Validation/1.0','Accept':'application/json'})
opener=urllib.request.build_opener(NoRedirect,urllib.request.ProxyHandler({}))
try:r=opener.open(req,timeout=12)
except urllib.error.HTTPError as e:r=e
body=r.read(4097);truncated=len(body)>4096;body=body[:4096]
raw=('GET '+req.selector+' HTTP/1.1\r\nHost: allsafe-8cef0.firebaseio.com\r\nAccept: application/json\r\n\r\nHTTP/1.1 '+str(r.status)+'\r\n'+str(r.headers)+'\r\n').encode()+body
private=ROOT.parent/'data/validation-private/firebase-raw.http'
fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'wb') as f:f.write(raw)
summary={'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'url':url,'status':r.status,'anonymous':True,'bytes_retained':len(body),'truncated':truncated,'sha256':hashlib.sha256(body).hexdigest(),'raw_exchange':'Android/data/validation-private/firebase-raw.http'}
try:
 data=json.loads(body)
 def structure(obj,depth=0):
  if isinstance(obj,dict):return {k:structure(v,depth+1) for k,v in obj.items()} if depth<3 else {'type':'object','count':len(obj)}
  if isinstance(obj,list):return {'type':'list','count':len(obj)}
  return {'type':type(obj).__name__,'length':len(obj) if isinstance(obj,str) else None}
 summary['structure_without_values']=structure(data)
 summary['real_values_returned']=any(v is not None and not isinstance(v,bool) for v in data.values()) if isinstance(data,dict) else data is not None
except Exception:summary['parseable_json']=False
(ROOT/'results/firebase-validation.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
