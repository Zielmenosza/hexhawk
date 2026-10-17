import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const [exeArg, sampleArg, evidenceArg, scratchArg] = process.argv.slice(2);
if (![exeArg, sampleArg, evidenceArg, scratchArg].every(Boolean)) throw new Error('Usage: node native_completion_probe.mjs <exe> <safe-sample> <evidence> <scratch>');
const exe = resolve(exeArg), sample = resolve(sampleArg), evidence = resolve(evidenceArg), scratch = resolve(scratchArg);
mkdirSync(evidence, { recursive: true }); mkdirSync(scratch, { recursive: true });
const sha = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const freePort = () => new Promise((resolvePort, reject) => { const s = createServer(); s.once('error', reject); s.listen(0, '127.0.0.1', () => { const port = s.address().port; s.close(e => e ? reject(e) : resolvePort(port)); }); });
class Cdp {
  constructor(url) { this.ws = new WebSocket(url); this.pending = new Map(); this.id = 0; this.events = []; }
  async open() {
    await new Promise((r,j) => { this.ws.addEventListener('open',r,{once:true}); this.ws.addEventListener('error',j,{once:true}); });
    this.ws.addEventListener('message', ev => { const m=JSON.parse(ev.data); if (!m.id) { if (['Runtime.exceptionThrown','Log.entryAdded'].includes(m.method)) this.events.push(m); return; } const p=this.pending.get(m.id); if(!p)return; this.pending.delete(m.id); clearTimeout(p.timer); if(m.error)p.reject(new Error(JSON.stringify(m.error))); else p.resolve(m.result); });
  }
  send(method, params={}) { const id=++this.id; return new Promise((resolveCall,reject) => { const timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('CDP timeout: '+method));},20000); this.pending.set(id,{resolve:resolveCall,reject,timer});this.ws.send(JSON.stringify({id,method,params})); }); }
  async eval(expression) { const r=await this.send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value; }
  close() { this.ws.close(); }
}
const report={schema:'hexhawk.native_completion_probe.v1',created_utc:new Date().toISOString(),exe:{path:exe,sha256:sha(exe)},sample:{path:sample,sha256:sha(sample)},installer_executed:false,host_install_state_mutated:false,entitlement_bypass:false,cold_starts:[],checks:[],blockers:[]};
const check=(name,ok,detail)=>{report.checks.push({name,ok,detail});if(!ok)report.blockers.push(name);};
for(let attempt=0;attempt<3;attempt++) {
  const port=await freePort(), profile=join(scratch,'cold-'+attempt), appdata=join(profile,'appdata'), local=join(profile,'local');
  mkdirSync(appdata,{recursive:true});mkdirSync(local,{recursive:true});
  const env={...process.env,WEBVIEW2_USER_DATA_FOLDER:join(profile,'webview'),WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS:`--remote-debugging-port=${port} --remote-allow-origins=http://localhost`,APPDATA:appdata,LOCALAPPDATA:local};
  const child=spawn(exe,[],{cwd:resolve(exe,'..'),env,stdio:['ignore','pipe','pipe'],windowsHide:false});
  let stdout='',stderr='',cdp;
  child.stdout.on('data',b=>{stdout=(stdout+b).slice(-16000);});child.stderr.on('data',b=>{stderr=(stderr+b).slice(-16000);});
  const cold={attempt,pid:child.pid,profile,manual_refresh:false};report.cold_starts.push(cold);
  try {
    let page;const start=Date.now();
    while(Date.now()-start<45000) { if(child.exitCode!==null)throw new Error('Native executable exited '+child.exitCode); try { const response=await fetch(`http://127.0.0.1:${port}/json/list`,{signal:AbortSignal.timeout(1000)});const pages=await response.json();page=pages.find(p=>p.type==='page' && /tauri|HexHawk/i.test(p.url+' '+p.title));if(page)break; }catch{}await sleep(200); }
    if(!page)throw new Error('Native CDP target not available');
    cdp=new Cdp(page.webSocketDebuggerUrl);await cdp.open();await cdp.send('Runtime.enable');await cdp.send('Log.enable');await cdp.send('Page.enable');
    let state;
    while(Date.now()-start<60000){state=await cdp.eval(`({url:location.href,ready:document.readyState,native:!!window.__TAURI_INTERNALS__,rootChildren:document.querySelector('#root')?.children.length||0,textLength:document.body.innerText.length})`);if(state.native&&state.rootChildren>0&&state.textLength>100)break;await sleep(200);}
    cold.startup=state;check('cold-start-'+attempt,!!(state?.native&&state.rootChildren>0&&state.textLength>100&&/^http:\/\/tauri.localhost/.test(state.url)),state);
    const windowEvidence=execFileSync('powershell.exe',['-NoProfile','-Command',`$p=Get-Process -Id ${child.pid}; [pscustomobject]@{Id=$p.Id;Path=$p.Path;MainWindowHandle=$p.MainWindowHandle.ToInt64();MainWindowTitle=$p.MainWindowTitle}|ConvertTo-Json -Compress`],{encoding:'utf8',timeout:10000});cold.window=JSON.parse(windowEvidence);check('visible-native-window-'+attempt,cold.window.MainWindowHandle!==0,cold.window);
    const shot=await cdp.send('Page.captureScreenshot',{format:'png'});writeFileSync(join(evidence,`cold-${attempt}.png`),Buffer.from(shot.data,'base64'));
    if(attempt===0){
      await cdp.eval(`(()=>{const skip=Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Skip intro');if(skip)skip.click();return !!skip;})()`);await sleep(200);
      const click=async(testid)=>{const result=await cdp.eval(`(()=>{const b=document.querySelector('[data-testid="${testid}"]');if(!b)return 'missing';if(b.disabled)return 'disabled';b.click();return 'clicked';})()`);check('click-'+testid,result==='clicked',result);return result;};
      await click('nav-load');await sleep(200);
      const applied=await cdp.eval(`(()=>{const e=document.querySelector('[data-testid="load-path-input"]');if(!e)return false;Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(sample)});e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);check('draft-path-entry',applied,{});await sleep(100);await click('load-apply-path');await sleep(200);
      await click('nav-inspect');
      let inspected=false;for(let i=0;i<150;i++){const text=await cdp.eval('document.body.innerText');if(text.includes(report.sample.sha256)&&text.includes('File inspection completed')){inspected=true;break;}await sleep(200);}
      check('native-GUI-input-sha',inspected,{expected:report.sample.sha256});
      const nativeIdentity=await cdp.eval(`window.__TAURI_INTERNALS__.invoke('inspect_file_metadata',{path:${JSON.stringify(sample)}})`);check('backend-independent-sha',nativeIdentity.sha256===report.sample.sha256,{sha256:nativeIdentity.sha256,file_type:nativeIdentity.file_type,architecture:nativeIdentity.architecture,file_size:nativeIdentity.file_size});
      await click('nav-strings');await sleep(800);await click('nav-disassembly');await sleep(1200);await click('nav-verdict');await sleep(300);await click('nav-report');await sleep(400);
      const text=await cdp.eval('document.body.innerText');writeFileSync(join(evidence,'journey-dom.txt'),text);
      const hasGate=/upgrade|requires pro|pro tier|unlock.*pro/i.test(text)&&!(await cdp.eval(`Array.from(document.querySelectorAll('.report-actions button')).some(b=>/JSON/.test(b.textContent)&&!b.disabled)`));
      if(hasGate){report.blockers.push('Fresh-profile report/verdict requires legitimate entitlement or release-owner-approved evaluation policy; no tier switch or key bypass used.');report.journey_result='ENTITLEMENT_BLOCKED';}
      else {
        await cdp.eval(`(()=>{window.__completionExports=[];const original=URL.createObjectURL.bind(URL);URL.createObjectURL=b=>{if(b.size>2000000)throw new Error('Probe export-size limit');b.text().then(text=>window.__completionExports.push({type:b.type,size:b.size,text}));return original(b);};HTMLAnchorElement.prototype.click=function(){};})()`);
        for(const label of ['JSON','Markdown']){
          const state=await cdp.eval(`(()=>{const b=Array.from(document.querySelectorAll('.report-actions button')).find(b=>b.textContent.includes(${JSON.stringify(label)}));if(!b)return 'missing';if(b.disabled)return 'disabled';b.click();return 'clicked';})()`);check('report-'+label,state==='clicked',state);await sleep(500);
        }
        const exports=await cdp.eval('window.__completionExports||[]');report.generated_exports=exports.map((e,i)=>{const path=join(evidence,`export-${i}.${e.type.includes('json')?'json':'md'}`);writeFileSync(path,e.text);return {path,type:e.type,bytes:e.size,sha256:sha(path)};});
        const jsonExport=exports.find(e=>e.type.includes('json'));if(jsonExport){const data=JSON.parse(jsonExport.text);check('export-identity-sha',data.binary?.sha256===report.sample.sha256&&data.crest_evidence_bundle?.file_identity?.sha256===report.sample.sha256,{binary:data.binary?.sha256,crest:data.crest_evidence_bundle?.file_identity?.sha256});check('GYRE-export-authority',data.final_verdict_snapshot?.source_engine==='gyre'&&data.authority_doctrine?.gyre_is_sole_verdict_source===true,{});check('actual-receipt-replay',data.evidence_replay_manifest?.replayable===true&&data.evidence_replay_manifest.entries.every(e=>e.timestamp!==data.generatedAt),{});}
        else check('JSON-export-produced',false,{});
        report.OS_save_dialog_tested=false;report.journey_result=report.checks.every(c=>c.ok)?'DIRECT_NATIVE_GENERATION_PASSED':'FAILED';
      }
    }
    cold.exceptions=cdp.events.filter(e=>e.method==='Runtime.exceptionThrown');check('no-frontend-exceptions-'+attempt,cold.exceptions.length===0,cold.exceptions);
  }catch(error){cold.error=String(error);report.blockers.push(cold.error);}
  finally{if(cdp)cdp.close();writeFileSync(join(evidence,`native-${attempt}-stdout.log`),stdout);writeFileSync(join(evidence,`native-${attempt}-stderr.log`),stderr);if(child.exitCode===null){execFileSync('taskkill.exe',['/PID',String(child.pid),'/T','/F'],{timeout:10000,stdio:'ignore'});}cold.stopped=true;}
}
report.release_ready=false;report.proof_limits=['Direct uninstalled production-binary smoke is not installer qualification.','Export Blob interception proves generated report bytes, not Windows save-dialog or installed-app export behavior.','No entitlement, tier, signing, installer, updater or publication bypass is permitted.'];
writeFileSync(join(evidence,'native-probe.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));if(report.blockers.length)process.exitCode=1;
