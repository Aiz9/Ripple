// Run only against a disposable backend/database. Seeds a synthetic APK via API;
// then exercises the real UI, without mocking requests or Android hardware.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {chromium} from 'playwright-core';
if (process.env.ENGINE_BROWSER_DISPOSABLE !== '1') throw new Error('Set ENGINE_BROWSER_DISPOSABLE=1 for an isolated test deployment');
const api = process.env.ENGINE_API_URL || 'http://127.0.0.1:18797';
const ui = process.env.ENGINE_UI_URL || 'http://127.0.0.1:3001';
const password = process.env.ENGINE_TEST_PASSWORD || 'Browser-fixture-only-123!';
let auth = await fetch(`${api}/api/auth/init`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
if (auth.status === 403) auth = await fetch(`${api}/api/auth/login`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
assert.equal(auth.status,200);
const {token} = await auth.json();
async function call(path, options={}) {
  const response = await fetch(`${api}${path}`, {...options,headers:{Authorization:`Bearer ${token}`,...options.headers}});
  assert.ok(response.ok, `${path}: ${response.status} ${response.ok?'':await response.text()}`);
  return response.json();
}
const form = new FormData();
form.set('file',new Blob([await readFile(process.env.ENGINE_TEST_APK)],{type:'application/vnd.android.package-archive'}),'browser-fixture.apk');
const app = await call('/api/android/apps',{method:'POST',body:form});
const doc = await call('/api/android/assessments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'Browser execution fixture',environment:'controlled-fixture',revision:'browser-1',assets:[{type:'android',name:'Fixture APK',apk_id:app.id}]})});
const browser = await chromium.launch({executablePath:process.env.CHROME_PATH || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
try {
  const context = await browser.newContext();
  await context.addCookies([{name:'android_lab_token',value:token,url:ui}]);
  await context.addInitScript(value => localStorage.setItem('android_lab_token',value),token);
  const page = await context.newPage();
  page.setDefaultTimeout(30000);
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto(`${ui}/android/assessments/?id=${doc.id}`);
  await page.getByRole('button',{name:'Add APK account',exact:true}).click();
  await page.getByLabel('Username / email / phone').fill('browser-fixture-user');
  await page.getByLabel('App password',{exact:true}).fill('never-render-this-fixture-secret');
  await page.getByRole('button',{name:'Save APK account',exact:true}).click();
  await page.getByText('Username and password saved · encrypted and hidden').waitFor();
  assert.ok(!(await page.locator('body').innerText()).includes('never-render-this-fixture-secret'));
  await page.getByRole('tab',{name:'Assessment engine',exact:true}).click();
  await page.getByRole('button',{name:'Start engine',exact:true}).click();
  let result;
  for (let n=0;n<60;n++) {
    result=await call(`/api/android/assessments/${doc.id}`);
    if(result.engine?.traces?.length && result.engine?.report)break;
    await new Promise(resolve=>setTimeout(resolve,1000));
  }
  assert.ok(result.engine?.report,'engine did not produce draft');
  assert.ok(result.engine.traces.length>0,'no real worker traces');
  await page.getByText('Part of:',{exact:false}).first().waitFor();
  await page.getByText('Asset and exploration graphs',{exact:true}).click();
  await page.getByLabel('Graph',{exact:true}).selectOption('exploration');
  await page.getByText('Worker traces',{exact:true}).click();
  await page.getByRole('tab',{name:'Security checklist',exact:true}).click();
  assert.match(await page.locator('body').innerText(),/91/);
  await page.getByRole('tab',{name:'Report',exact:true}).click();
  await page.getByRole('button',{name:'Preview draft',exact:true}).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button',{name:'Download Markdown',exact:true}).click();
  const file=await download;
  const markdown=await readFile(await file.path(),'utf8');
  assert.match(markdown,/# DRAFT/);
  assert.ok(!markdown.includes('never-render-this-fixture-secret'));
  await page.getByRole('tab',{name:'Assessment engine',exact:true}).click();
  await page.getByRole('button',{name:'Cancel assessment',exact:true}).click();
  await page.getByText('Assessment engine: cancelled',{exact:true}).waitFor();
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({status:'PASS',assessment:doc.id,sha256:app.id,traces:result.engine.traces.length,checks:['APK account save and hidden secret','engine execution','goal hierarchy','graph view','trace view','91-procedure checklist','draft download','cancellation'],liveAndroid:false}));
} finally { await browser.close(); }
