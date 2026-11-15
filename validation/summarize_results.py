#!/usr/bin/env python3
"""Aggregate measured denominators; never turn a missing result into a pass."""
from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parent
read=lambda f:json.loads((ROOT/'results'/f).read_text())
p=read('differential/summary.json');s=read('skip-summary.json');m=read('mutation-summary.json');h=read('http-confirmation-summary.json');f=read('firebase-persisted-validation.json')
result={'parser':{'corpus_apks':p['apks'],'exact_field_group_agreement':p['exact_field_agreement'],'matches':p['exact_matches'],'comparisons':p['field_comparisons'],'by_reference':p['by_reference'],'unsupported_fields_count_as_failures':True},'skip_selection':s,'mutations':{k:v for k,v in m.items() if k!='rows'},'finding_confirmation':{'live_allsafe':{'confirmed':int(f['status']=='validated'),'candidates':1,'rate':int(f['status']=='validated')/1},'controlled_fixture_raw_reproduction':{'confirmed':h['reproduced'],'cases':4,'rate':h['reproduced']/4},'controlled_fixture_zap_automatic_alert_concordance':{'matched':h['automatic_alert_matches'],'cases':4,'rate':h['automatic_alert_matches']/4},'controlled_fixture_same_exchange_passive_alert_concordance':{'matched':h['exact_original_exchange_passive_alert_matches'],'cases':4,'rate':h['exact_original_exchange_passive_alert_matches']/4},'combined_strict_independent_confirmation':{'confirmed':h['automatic_alert_matches']+int(f['status']=='validated'),'cases':5,'rate':(h['automatic_alert_matches']+int(f['status']=='validated'))/5,'caution':'Mixed live/fixture population, includes an active XSS follow-up; not a production precision estimate. Prefer separate denominators.'}},'acceptance':'NOT READY: full DEX string extraction unsupported; relevant app API references discarded; one mutation target not detected; automatic ZAP agreement incomplete.'}
(ROOT/'results/metrics.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ['skip_selection','parser']},indent=2))
if '--require-full-agreement' in sys.argv:
 if p['exact_field_agreement']<1 or s['selection_recall']<1 or m['targeted_detection_rate']<1 or h['automatic_alert_matches']<4:sys.exit(2)
