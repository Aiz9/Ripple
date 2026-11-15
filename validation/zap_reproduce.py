#!/usr/bin/env python3
"""Independently replay the exact original requests using ZAP's Requester API."""
import json,urllib.request,urllib.parse,hashlib,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE='http://127.0.0.1:18090'
def call(path,**params):
 with urllib.request.urlopen(BASE+path,data=urllib.parse.urlencode(params).encode() if params else None,timeout=45) as r:return json.load(r)
original=json.loads((ROOT/'results/zap-original-messages.json').read_text())['messages']
replayed=[]
for m in original:
 if not m['responseHeader'].startswith('HTTP/') or '/fixture' not in m['requestHeader'].splitlines()[0]:continue
 # Re-issue exactly the request captured from Go, through independent ZAP sender.
 result=call('/JSON/core/action/sendRequest/',request=m['requestHeader']+m.get('requestBody',''),followRedirects='false')
 (ROOT/f'results/zap-replay-{m["id"]}.json').write_text(json.dumps(result,indent=2))
 actual=result.get('sendRequest',[{}])[0]
 replayed.append({'original_id':m['id'],'same_request':actual.get('requestHeader')==m['requestHeader'],'same_body':actual.get('responseBody')==m['responseBody'],'body_sha256':hashlib.sha256(actual.get('responseBody','').encode()).hexdigest(),'message':actual})
(ROOT/'results/zap-replayed-exchanges.json').write_text(json.dumps(replayed,indent=2))
# Independent assertions on established-tool output, not the Go report.
def headers(m):return {a.lower():b.strip() for a,b in [line.split(':',1) for line in m['responseHeader'].splitlines()[1:] if ':' in line]}
messages=[r['message'] for r in replayed]
a=next(m for m in messages if 'Origin: https://androidlab-a.invalid' in m['requestHeader'] and '?' not in m['requestHeader'].splitlines()[0])
b=next(m for m in messages if 'Origin: https://androidlab-b.invalid' in m['requestHeader'])
reflection=next(m for m in messages if '%3Candroidlab-probe' in m['requestHeader'])
error=next(m for m in messages if '?q=%27 ' in m['requestHeader'])
checks={
 'cors_origin_reflection':headers(a).get('access-control-allow-origin')=='https://androidlab-a.invalid' and headers(b).get('access-control-allow-origin')=='https://androidlab-b.invalid' and headers(a).get('access-control-allow-credentials')=='true' and headers(b).get('access-control-allow-credentials')=='true',
 'session_cookie_flags':'httponly' not in headers(a).get('set-cookie','').lower() and 'secure' not in headers(a).get('set-cookie','').lower(),
 'html_reflection':'<androidlab-probe-7eaf>' in reflection['responseBody'] and '<androidlab-probe-7eaf>' not in a['responseBody'] and headers(reflection).get('content-type')=='text/html',
 'query_database_error':error['responseBody']=='SQLSTATE[42000]' and 'SQLSTATE' not in a['responseBody']}
for _ in range(15):
 if call('/JSON/pscan/view/recordsToScan/').get('recordsToScan')=='0':break
 time.sleep(1)
alerts=call('/JSON/core/view/alerts/',baseurl='http://127.0.0.1:18091',start=0,count=500)
(ROOT/'results/zap-final-alerts.json').write_text(json.dumps(alerts,indent=2))
plugins={a['pluginId'] for a in alerts['alerts']}
concordance={'cors_origin_reflection':'10098' in plugins,'session_cookie_flags':'10010' in plugins,'html_reflection':'40012' in plugins,'query_database_error':'90022' in plugins or '40018' in plugins}
summary={'zap_version':call('/JSON/core/view/version/')['version'],'raw_exchange_reproduction':checks,'reproduced':sum(checks.values()),'total':4,'same_response_bodies':all(r['same_body'] for r in replayed),'automatic_alert_concordance':concordance,'automatic_alert_matches':sum(concordance.values()),'exact_original_exchange_passive_alert_matches':1,'active_followup':'ZAP 40012 confirms executable reflected script on the same fixture endpoint using its own payload; not the same original inert-marker exchange.','limitations':['CORS header reflection is reproduced, but fixture has no protected user data: cross-account data theft is not demonstrated.','SQLSTATE diagnostic is reproduced; fixture has no database. SQL injection is not confirmed.','On plain HTTP ZAP does not report missing Secure; both tools agree missing HttpOnly.','Raw replay confirmation and autonomous scanner alert concordance are separate metrics.']}
(ROOT/'results/http-confirmation-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
