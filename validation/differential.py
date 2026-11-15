#!/usr/bin/env python3
"""Run four actual parsers, normalize semantic fields, retain every disagreement."""
import os,sys,json,re,subprocess,hashlib,zipfile,collections,time,shutil
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode
from xml.etree import ElementTree as ET
from loguru import logger
logger.remove()
from androguard.core.apk import APK
from androguard.core.dex import DEX
ROOT=Path(__file__).resolve().parent
CORPUS=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT/'corpus'
OUT=Path(sys.argv[2]).resolve() if len(sys.argv)>2 else ROOT/'results/differential'
OUT.mkdir(parents=True,exist_ok=True)
# Build the DexStrings classpath portably: locate jadx's and apktool's jars from
# the installed tools instead of hardcoding one machine's home directory. Order:
# explicit env override, then the tool resolved on PATH, then common install dirs.
def _jadx_lib():
 v=os.environ.get('JADX_LIB_DIR')
 if v:return v
 exe=shutil.which('jadx')
 if exe:
  lib=Path(exe).resolve().parent.parent/'lib'   # <dist>/bin/jadx -> <dist>/lib
  if lib.is_dir():return str(lib)
 for c in (Path.home()/'.local/share/jadx/lib',Path('/usr/share/jadx/lib'),Path('/opt/jadx/lib')):
  if c.is_dir():return str(c)
 return None
def _apktool_home():
 v=os.environ.get('APKTOOL_LIB_DIR')
 if v:return v
 for c in (Path('/usr/share/apktool'),Path('/usr/local/share/apktool')):
  if c.is_dir():return str(c)
 exe=shutil.which('apktool')
 if exe:
  try:
   m=re.search(r'APP_HOME="?([^"\n]+)"?',Path(exe).read_text(errors='replace'))
   if m and Path(m.group(1)).is_dir():return m.group(1)
  except OSError:pass
 return None
_cp=[str(ROOT)]
_jl=_jadx_lib()
if _jl:_cp.append(os.path.join(_jl,'*'))
_ah=_apktool_home()
if _ah:_cp.append(os.path.join(_ah,'*'))
CP=os.pathsep.join(_cp)
NS='{http://schemas.android.com/apk/res/android}'
FLAGS=['debuggable','allowBackup','usesCleartextTraffic','testOnly','extractNativeLibs','supportsRtl']
PAT=re.compile(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%{}-]{4,1000}')
def run(cmd,log):
 t=time.monotonic()
 with open(log,'w') as f:p=subprocess.run(list(map(str,cmd)),stdout=f,stderr=subprocess.STDOUT,timeout=300,env={**os.environ,'JAVA_OPTS':'-Xmx2g'})
 return dict(command=list(map(str,cmd)),exit_code=p.returncode,seconds=round(time.monotonic()-t,2))
def urls(values):
 out=set()
 for v in values:
  for raw in PAT.findall(v):
   raw=raw.rstrip('.,;)}]')
   try:
    u=urlsplit(raw)
    if not u.hostname or u.username or u.hostname in ['schemas.android.com','www.w3.org']:continue
    query=urlencode(sorted(set((k,'') for k,v in parse_qsl(u.query,keep_blank_values=True))))
    out.add(urlunsplit((u.scheme,u.netloc,u.path,query,'')))
   except ValueError:pass
 return sorted(out)
def manifest(xml):
 root=ET.fromstring(xml);pkg=root.get('package','');app=root.find('application')
 sdk=root.find('uses-sdk');target=int(sdk.get(NS+'targetSdkVersion',sdk.get(NS+'minSdkVersion','1'))) if sdk is not None else 1
 permissions=sorted(set(e.get(NS+'name','') for e in root if e.tag in ['uses-permission','uses-permission-sdk-23']))
 components=[]
 if app is not None:
  for e in app:
   if e.tag not in ['activity','activity-alias','service','receiver','provider']:continue
   name=e.get(NS+'name','');name=pkg+name if name.startswith('.') else pkg+'.'+name if name and '.' not in name else name
   exported=e.get(NS+'exported')
   if exported is None:
    exported='false (default)'
    if e.tag=='provider' and target<17:exported='true (legacy default)'
    elif e.tag!='provider' and e.find('intent-filter') is not None:exported='missing (explicit value required for target 31+)' if target>=31 else 'true (legacy intent-filter default)'
   components.append(dict(kind=e.tag,name=name,exported=exported,permission=e.get(NS+'permission',app.get(NS+'permission',''))))
 return dict(permissions=permissions,components=sorted(components,key=lambda x:(x['kind'],x['name'])),manifest_flags={f:app.get(NS+f,'') if app is not None else '' for f in FLAGS})
def xml_strings(path):
 vals=[]
 for f in path.rglob('*.xml'):
  try:
   root=ET.parse(f).getroot()
   for e in root.iter():vals.extend(e.attrib.values());vals.extend([e.text or '',e.tail or ''])
  except (ET.ParseError,UnicodeError):pass
 # copied asset content, distinct from decoded manifest/resources
 for f in path.rglob('*'):
  if f.is_file() and f.suffix in ['.json','.js','.properties','.txt','.html']:vals.append(f.read_text(errors='replace'))
 return vals
runs=[];comparisons=[];disagreements=[];facts={}
p=subprocess.run(['go','test','./androidapk','-run','^TestDifferentialExport$','-count=1'],cwd=ROOT.parent,env={**os.environ,'APK_DIFFERENTIAL_INPUT':str(CORPUS),'APK_DIFFERENTIAL_OUTPUT':str(OUT/'go')},capture_output=True,text=True)
(OUT/'go.log').write_text(p.stdout+p.stderr)
if p.returncode:raise RuntimeError(p.stdout+p.stderr)
for apk in sorted(CORPUS.glob('*.apk')):
 name=apk.stem;work=OUT/name;work.mkdir(exist_ok=True);facts[name]={}
 print('Parsing '+name,flush=True)
 custom=json.loads((OUT/'go'/f'{apk.name}.json').read_text())
 if 'error' in custom:facts[name]['go']={'error':custom['error']}
 else:
  rep=custom['report'];facts[name]['go']={k:sorted(rep[k],key=lambda x:(x['kind'],x['name'])) if k=='components' else sorted(set(rep[k])) for k in ['permissions','components']}
  facts[name]['go'].update(manifest_flags=custom['manifest_flags'],dex_strings=None,embedded_urls=sorted(set(v['url'] for v in custom['urls'])))
 for tool in ['apktool','jadx','androguard']:
  dest=work/tool;dest.mkdir(exist_ok=True)
  try:
   if tool=='androguard':
    a=APK(str(apk));m=a.get_android_manifest_xml();ET.ElementTree(ET.fromstring(__import__('lxml.etree',fromlist=['tostring']).tostring(m))).write(dest/'AndroidManifest.xml',encoding='unicode')
    strings={n:list(DEX(a.get_file(n)).get_strings()) for n in a.get_dex_names()}
    vals=[]
    arsc=a.get_android_resources()
    if arsc:
     for p in arsc.get_packages_names():
      for loc in arsc.get_locales(p):
       try:
        r=ET.fromstring(arsc.get_string_resources(p,loc));vals.extend(e.text or '' for e in r.iter())
       except Exception:pass
    with zipfile.ZipFile(apk) as z:
     for n in z.namelist():
      if n.endswith(('.json','.js','.properties','.txt','.html')):vals.append(z.read(n).decode(errors='replace'))
    vals.extend(xml_strings(dest))
   else:
    if tool=='apktool':cmd=['apktool','d','-f','-p',ROOT/'work/framework','-o',dest,apk]
    else:cmd=['jadx','-s','-j','2','--log-level','warn','-d',dest,apk]
    outcome=run(cmd,work/f'{tool}.log');runs.append(outcome)
    # Some JADX resources may be emitted despite unrelated resource warnings.
    candidates=list(dest.rglob('AndroidManifest.xml'))
    if not candidates:raise RuntimeError('No decoded manifest; see tool log')
    r=run(['java','-Xmx2g','-cp',CP,'DexStrings',tool,apk,work/f'{tool}-strings.json'],work/f'{tool}-strings.log');runs.append(r)
    if r['exit_code']:raise RuntimeError('DEX decoder failure; see log')
    strings=json.loads((work/f'{tool}-strings.json').read_text());vals=xml_strings(dest)
   flat=sorted(set(s for ss in strings.values() for s in ss))
   f=manifest((dest/'AndroidManifest.xml').read_bytes() if tool=='androguard' else candidates[0].read_bytes())
   f.update(dex_strings=flat,embedded_urls=urls(flat+vals));facts[name][tool]=f
   (work/f'{tool}-facts.json').write_text(json.dumps(f,ensure_ascii=True,indent=2))
  except Exception as e:
   facts[name][tool]={'error':str(e)}
 # Compare each field separately; null/unsupported counts as a failure.
 for reference in ['apktool','jadx','androguard']:
  for field in ['permissions','components','manifest_flags','dex_strings','embedded_urls']:
   actual=facts[name]['go'].get(field);expected=facts[name][reference].get(field)
   supported=actual is not None and expected is not None
   def atomize(v):
    if isinstance(v,dict):return set(json.dumps([k,x],sort_keys=True) for k,x in v.items())
    return set(json.dumps(x,sort_keys=True,ensure_ascii=True) for x in v or [])
   ga,rf=atomize(actual),atomize(expected);intersection=len(ga&rf);union=len(ga|rf)
   row=dict(apk=name,reference=reference,field=field,exact_match=supported and actual==expected,supported=supported,matched=intersection,union=union,reference_facts=len(rf),go_facts=len(ga),jaccard=intersection/union if union else (1 if supported else 0))
   comparisons.append(row)
   for direction,values in [('missing_in_go',rf-ga),('extra_in_go',ga-rf)]:
    for value in sorted(values):disagreements.append(dict(apk=name,reference=reference,field=field,direction=direction,value=json.loads(value)))
   if not supported:disagreements.append(dict(apk=name,reference=reference,field=field,direction='unsupported_or_error',go_error=facts[name]['go'].get('error','field unsupported'),reference_error=facts[name][reference].get('error')))
(OUT/'facts.json').write_text(json.dumps(facts,ensure_ascii=True,indent=2))
(OUT/'comparisons.json').write_text(json.dumps(comparisons,indent=2))
with open(OUT/'disagreements.jsonl','w') as f:
 for row in disagreements:f.write(json.dumps(row,ensure_ascii=True)+'\n')
(OUT/'commands.json').write_text(json.dumps(runs,indent=2))
summary={'apks':len(facts),'field_comparisons':len(comparisons),'exact_matches':sum(c['exact_match'] for c in comparisons),'exact_field_agreement':sum(c['exact_match'] for c in comparisons)/len(comparisons),'by_reference':{},'by_field':{},'disagreement_rows':len(disagreements)}
for group,key in [('by_reference','reference'),('by_field','field')]:
 for value in sorted(set(c[key] for c in comparisons)):
  rows=[c for c in comparisons if c[key]==value];summary[group][value]={'exact_matches':sum(c['exact_match'] for c in rows),'comparisons':len(rows),'mean_fact_jaccard':sum(c['jaccard'] for c in rows)/len(rows)}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
