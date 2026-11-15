#!/usr/bin/env python3
"""Controlled valid manifest/DEX mutations with preregistered expected fact deltas."""
from pathlib import Path
import subprocess,zipfile,json,shutil,os
ROOT=Path(__file__).resolve().parent;W=ROOT/'work/mutations';C=W/'corpus';C.mkdir(parents=True,exist_ok=True)
manifest=(ROOT/'work/AndroidManifest.xml').read_text()
base=(ROOT/'work/smali1/Routes.smali').read_text()+'''
.method public static marker()Ljava/lang/String;
 .registers 1
 const-string v0, "clean-marker"
 return-object v0
.end method
'''
plans=[('baseline',None,None),('permission_add','permissions',('android.permission.CAMERA',None)),('permission_remove','permissions',(None,'android.permission.INTERNET')),('debug_flag','manifest_flags',('true','false')),('exported_component','components',('true','false')),('receiver_add','components',('.Added',None)),('dex_url_primary','embedded_urls',('https://smali.validation.test/changed','https://smali.validation.test/dex1')),('dex_url_secondary','embedded_urls',('https://smali.validation.test/secondary','https://smali.validation.test/dex2')),('dex_plain_string','dex_strings',('changed-marker','clean-marker'))]
def run(cmd):
 p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True)
 if p.returncode:raise RuntimeError(p.stdout+p.stderr)
for name,field,delta in plans:
 d=W/name;d.mkdir(exist_ok=True);xml=manifest;s1=base;s2=(ROOT/'work/smali2/Routes.smali').read_text()
 if name=='permission_add':xml=xml.replace('<application','<uses-permission android:name="android.permission.CAMERA"/><application')
 if name=='permission_remove':xml=xml.replace('<uses-permission android:name="android.permission.INTERNET"/>','')
 if name=='debug_flag':xml=xml.replace('android:debuggable="false"','android:debuggable="true"')
 if name=='exported_component':xml=xml.replace('android:name=".MainActivity" android:exported="false"','android:name=".MainActivity" android:exported="true"')
 if name=='receiver_add':xml=xml.replace('</application>','<receiver android:name=".Added" android:exported="false"/></application>')
 if name=='dex_url_primary':s1=s1.replace(delta[1],delta[0])
 if name=='dex_url_secondary':s2=s2.replace(delta[1],delta[0])
 if name=='dex_plain_string':s1=s1.replace(delta[1],delta[0])
 (d/'AndroidManifest.xml').write_text(xml)
 run(['aapt','package','-f','-M',d/'AndroidManifest.xml','-S',ROOT/'work/res','-I','/usr/share/android-framework-res/framework-res.apk','-F',d/'manifest.apk'])
 for i,s in [(1,s1),(2,s2)]:
  sd=d/f'smali{i}';sd.mkdir(exist_ok=True);(sd/'Routes.smali').write_text(s);run(['smali','assemble',sd,'-o',d/f'classes{i}.dex'])
 with zipfile.ZipFile(d/'manifest.apk') as z,zipfile.ZipFile(C/f'{name}.apk','w',zipfile.ZIP_DEFLATED) as out:
  for n in z.namelist():out.writestr(n,z.read(n))
  out.write(d/'classes1.dex','classes.dex');out.write(d/'classes2.dex','classes2.dex')
(ROOT/'results/mutation-plan.json').write_text(json.dumps(plans,indent=2))
print('Built baseline + 8 single-fact mutants',flush=True)
