#!/usr/bin/env python3
"""Build deterministic parser fixtures; never install or execute an APK."""
from pathlib import Path
import subprocess, zipfile, json, hashlib, shutil, os
ROOT=Path(__file__).resolve().parent
WORK=ROOT/'work'; CORPUS=ROOT/'corpus'
WORK.mkdir(exist_ok=True); CORPUS.mkdir(exist_ok=True)
JAVA=shutil.which('java'); JAVAC=str(Path(JAVA).resolve().with_name('javac'))
FRAMEWORK='/usr/share/android-framework-res/framework-res.apk'
def run(cmd):
 p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True)
 if p.returncode: raise RuntimeError(p.stdout+p.stderr)
 return p.stdout
manifest='''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="lab.validation" android:versionCode="1" android:versionName="1.0"><uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28"/><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="false" android:allowBackup="false" android:usesCleartextTraffic="false" android:testOnly="false" android:supportsRtl="true"><activity android:name=".MainActivity" android:exported="false"/><service android:name="SyncService" android:exported="false"/><receiver android:name=".Notice" android:exported="true" android:permission="android.permission.BROADCAST_SMS"/><provider android:name=".Store" android:authorities="lab.validation.store" android:exported="false"/></application></manifest>'''
res=WORK/'res/values';res.mkdir(parents=True,exist_ok=True)
(res/'strings.xml').write_text('<resources><string name="api_base">https://resource.validation.test/v1</string><string name="unicode">नमस्ते</string></resources>')
(WORK/'AndroidManifest.xml').write_text(manifest)
run(['aapt','package','-f','-M',WORK/'AndroidManifest.xml','-S',WORK/'res','-I',FRAMEWORK,'-F',WORK/'aapt1.apk'])
run(['aapt2','compile','--dir',WORK/'res','-o',WORK/'res.zip'])
run(['aapt2','link','--manifest',WORK/'AndroidManifest.xml','-I',FRAMEWORK,'--min-sdk-version','21','--target-sdk-version','28','-o',WORK/'aapt2.apk',WORK/'res.zip'])
src=WORK/'java/lab/validation';src.mkdir(parents=True,exist_ok=True)
(src/'EndpointStrings.java').write_text('''package lab.validation; public class EndpointStrings { public static String endpoint(){return "https://api.validation.test/v1/orders?q=fixture";} public static String message(){return "नमस्ते\\u0000🙂";} public static String marker(){return "clean-marker";} }''')
classes=WORK/'classes';classes.mkdir(exist_ok=True)
run([JAVAC,'--release','8','-encoding','UTF-8','-d',classes,src/'EndpointStrings.java'])
with zipfile.ZipFile(WORK/'input.jar','w') as z:
 for f in classes.rglob('*.class'):z.write(f,f.relative_to(classes).as_posix())
for kind in ['d8','r8']:
 d=WORK/kind;d.mkdir(exist_ok=True)
 cmd=[JAVA,'-cp',ROOT/'tools/r8.jar','com.android.tools.r8.'+kind.upper(),'--min-api','21','--output',d]
 if kind=='r8':
  (WORK/'rules.pro').write_text('-dontwarn **\n-dontshrink\n-dontoptimize\n-keep,allowobfuscation class lab.validation.** { *; }\n-printmapping '+str(WORK/'mapping.txt')+'\n')
  cmd+=['--pg-conf',WORK/'rules.pro']
 run(cmd+[WORK/'input.jar'])
def pack(base,dexs,out):
 with zipfile.ZipFile(base) as src,zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as dst:
  for n in src.namelist():dst.writestr(n,src.read(n))
  for name,path in dexs:dst.write(path,name)
pack(WORK/'aapt2.apk',[('classes.dex',WORK/'d8/classes.dex')],CORPUS/'aapt2-d8-unobfuscated.apk')
pack(WORK/'aapt2.apk',[('classes.dex',WORK/'r8/classes.dex')],CORPUS/'aapt2-r8-obfuscated.apk')
for idx in [1,2]:
 sm=WORK/f'smali{idx}';sm.mkdir(exist_ok=True)
 (sm/'Routes.smali').write_text(f'''.class public Llab/validation/Routes{idx};
.super Ljava/lang/Object;
.method public static endpoint()Ljava/lang/String;
 .registers 1
 const-string v0, "https://smali.validation.test/dex{idx}"
 return-object v0
.end method
''')
 run(['smali','assemble',sm,'-o',WORK/f'classes{idx}.dex'])
pack(WORK/'aapt1.apk',[('classes.dex',WORK/'classes1.dex'),('classes2.dex',WORK/'classes2.dex')],CORPUS/'aapt1-smali-multidex.apk')
shutil.copyfile('/tmp/androidlab-allsafe.apk',CORPUS/'allsafe.apk')
items=[]
for p in sorted(CORPUS.glob('*.apk')):
 with zipfile.ZipFile(p) as z:dexs=[n for n in z.namelist() if n.endswith('.dex')]
 items.append(dict(name=p.stem,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),dex_files=dexs,provenance='user-approved Allsafe training APK; build provenance unverified' if p.stem=='allsafe' else 'locally generated parser fixture; build scripts and R8 mapping retained',obfuscation=('R8 confirmed by mapping.txt' if 'r8-' in p.stem else 'off' if p.stem!='allsafe' else 'unknown')))
(ROOT/'results/corpus.json').write_text(json.dumps(items,indent=2)+'\n')
print(json.dumps(items,indent=2))
