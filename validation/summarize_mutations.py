#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parent;facts=json.loads((ROOT/'results/mutations/facts.json').read_text());plans=json.loads((ROOT/'results/mutation-plan.json').read_text())
base=facts['baseline'];rows=[]
def atomize(v):
 if isinstance(v,dict):return set(json.dumps([k,x],sort_keys=True) for k,x in v.items())
 return set(json.dumps(x,sort_keys=True,ensure_ascii=True) for x in v or [])
def delta(a,b):return {'added':sorted(atomize(b)-atomize(a)),'removed':sorted(atomize(a)-atomize(b))}
def diffs(a,b):return {k:delta(a[k],b[k]) for k in a if a[k]!=b[k]}
for name,field,change in plans[1:]:
 expected_fields={field} | ({'dex_strings'} if name.startswith('dex_url_') else set())
 ref_deltas={tool:diffs(base[tool],facts[name][tool]) for tool in ['apktool','jadx','androguard']}
 ref=ref_deltas['apktool'];go=diffs(base['go'],facts[name]['go'])
 assert set(ref)==expected_fields,(name,set(ref),expected_fields)
 assert all(d==ref for d in ref_deltas.values()),name
 # For URL/plain-string mutations assert the exact preregistered values, not merely a changed field.
 if name.startswith('dex_'):
  for k in expected_fields:
   assert ref[k]=={'added':[json.dumps(change[0])],'removed':[json.dumps(change[1])]},(name,k,ref[k])
 if name.startswith('permission_'):
  assert ref[field]=={'added':[json.dumps(change[0])] if change[0] else [],'removed':[json.dumps(change[1])] if change[1] else []}
 supported={k:v for k,v in ref.items() if base['go'][k] is not None}
 targeted=(field in go and go==supported)
 rows.append({'mutation':name,'target_field':field,'expected_delta':ref,'go_delta':go,'references_agree':True,'detected_target_and_no_unexpected_supported_changes':targeted,'complete_fact_delta_matches':go==ref})
summary={'mutations':len(rows),'targeted_detection_passed':sum(r['detected_target_and_no_unexpected_supported_changes'] for r in rows),'targeted_detection_rate':sum(r['detected_target_and_no_unexpected_supported_changes'] for r in rows)/len(rows),'complete_fact_delta_matches':sum(r['complete_fact_delta_matches'] for r in rows),'rows':rows}
(ROOT/'results/mutation-summary.json').write_text(json.dumps(summary,indent=2));print({k:v for k,v in summary.items() if k!='rows'})
# Reference tools must agree independently; don't call a disagreement Go failure without recording it.
corpus=json.loads((ROOT/'results/differential/facts.json').read_text());rrows=[]
for apk,f in corpus.items():
 for a,b in [('apktool','jadx'),('apktool','androguard'),('jadx','androguard')]:
  for field in ['permissions','components','manifest_flags','dex_strings','embedded_urls']:
   rrows.append({'apk':apk,'a':a,'b':b,'field':field,'exact_match':f[a][field]==f[b][field]})
(ROOT/'results/reference-agreement.json').write_text(json.dumps(rrows,indent=2));print('Reference comparisons:',sum(r['exact_match'] for r in rrows),'/',len(rrows))
