const {chromium}=require('playwright');
const {spawn}=require('node:child_process');
const assert=require('node:assert/strict'),net=require('node:net'),path=require('node:path');
async function main(){
  const port=await new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
  const python=spawn(process.env.TEST_PYTHON||'python3',[path.join(__dirname,'policies_browser_fixture.py'),String(port)],{stdio:['ignore','pipe','pipe']});
  let log='',browser;python.stderr.on('data',x=>log+=x);
  try{
    const url='http://127.0.0.1:'+port;
    for(let i=0;i<100;i++){try{if((await fetch(url)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));if(i===99)throw Error(log);}
    browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
    const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(url);
    const open=async kind=>{await page.evaluate(k=>renderPolicyWorkspace(document.getElementById('content-area'),k),kind);await page.locator('#pw-add:enabled').waitFor();};
    for(const kind of ['qos','decryption']){
      await page.evaluate(k=>renderPolicyProfiles(document.getElementById('content-area'),k),kind);
      await page.locator('#pp-add:enabled').waitFor();await page.locator('#pp-add').click();
      await page.locator('#pp-form [name=name]').fill('cancelled');await page.locator('#pp-cancel').click();
      assert.equal((await (await fetch(url+'/api/config/policy-profiles/'+kind)).json()).entries.length,0);
      await page.locator('#pp-add').click();await page.locator('#pp-form [name=name]').fill('browser-'+kind);
      if(kind==='qos'){
        await page.locator('#pp-form [name="max-mbps"]').fill('10');
        await page.locator('#pp-form [name="class1.guaranteed-mbps"]').fill('20');
        await page.locator('#pp-form [name="class1.priority"]').selectOption('real-time');
      }else{
        await page.locator('#pp-form [name="min-version"]').selectOption('tls1-3');
        await page.locator('#pp-form [name="max-version"]').selectOption('tls1-2');
      }
      await page.locator('#pp-form [type=submit]').click();await page.waitForFunction(()=>document.getElementById('pp-message')?.textContent.length>0);
      if(kind==='qos')await page.locator('#pp-form [name="max-mbps"]').fill('100');
      else await page.locator('#pp-form [name="max-version"]').selectOption('tls1-3');
      await page.locator('#pp-form [type=submit]').click();await page.locator('#pp-editor').waitFor({state:'hidden'});
      await page.locator('#pp-list [data-edit]').click();
      assert.equal(await page.locator('#pp-form [name=name]').inputValue(),'browser-'+kind);
      await page.locator('#pp-cancel').click();await page.locator('#pp-source').selectOption('running');
      await page.waitForFunction(()=>document.getElementById('pp-list')?.textContent.includes('No profiles configured'));
      assert(await page.locator('#pp-add').isDisabled());
    }
    const fields={
      nat:{'Source Translation':'dynamic-ip-and-port','Source Interface Address':'ethernet1/1','Translated Destination Address':'192.0.2.10','Translated Destination Port':'443'},
      pbf:{Action:'forward','Egress Interface':'ethernet1/1','Next Hop':'192.0.2.1'},
      'application-override':{Ports:'443',Application:'custom-app'},
      authentication:{'Authentication Enforcement':'auth-profile'},
      sdwan:{'Path Quality Profile':'quality','Traffic Distribution Profile':'distribution'}
    };
    for(const kind of ['security','nat','qos','pbf','decryption','tunnel-inspect','application-override','authentication','dos','sdwan']){
      if(['nat','qos','pbf','decryption'].includes(kind)){
        await open(kind);await page.locator('#pw-plan').click();
        await page.waitForFunction(()=>document.getElementById('pw-plan-result')?.textContent.includes('Compilation passed'));
        assert.match(await page.locator('#pw-plan-result').innerText(),/does not authorize traffic/);
        await page.locator('#object-close').click();
        await page.locator('#pw-test').click();
        for(const [name,value] of Object.entries({source:'192.0.2.10',destination:'198.51.100.10',destination_port:'443'}))await page.locator('#pw-test-form [name='+name+']').fill(value);
        await page.locator('#pw-test-form [name=from_zone]').selectOption('trust');
        await page.locator('#pw-test-form [name=to_zone]').selectOption('untrust');
        await page.getByRole('button',{name:'Test Match',exact:true}).click();
        await page.waitForFunction(()=>document.getElementById('pw-plan-result')?.textContent.includes('No matching enabled rule'));
        await page.locator('#pw-test-close').click();
      }
      if(kind==='nat'){
        await open(kind);await page.locator('#pw-nat-preview').click();
        await page.waitForFunction(()=>document.getElementById('nat-preview')?.textContent.includes('Compilation passed'));
        assert.match(await page.locator('#nat-preview').innerText(),/NAT activation is not commissioned/);
        await page.locator('#object-close').click();
      }
      await open(kind);await page.locator('#pw-add').click();await page.locator('[name=rule-name]').fill(kind+' rule');
      // Tab changes must retain match values and edit controls.
      for(const [label,value] of Object.entries(fields[kind]||{})){
        if(kind==='nat'&&label==='Source Interface Address')await page.locator('#pw-nat-method').selectOption('interface');
        const el=page.locator('#pw-form label').filter({hasText:label}).filter({has:page.locator('input,select')}).first();
        const panel=await el.evaluate(e=>e.closest('[data-panel]').dataset.panel);await page.locator('[data-tab="'+panel+'"]').click();
        const control=el.locator('input,select').first();if(await control.evaluate(e=>e.tagName)==='SELECT')await control.selectOption(value);else await control.fill(value);
      }
      await page.locator('#pw-form [type=submit]').click();await page.locator('#pw-editor').waitFor({state:'hidden'});
      await page.locator('#pw-list [data-rule-edit]').first().waitFor();
      assert.match(await page.locator('#pw-list').innerText(),new RegExp(kind+' rule'));
      await page.locator('[data-rule-edit]').click();assert.equal(await page.locator('[name=rule-name]').inputValue(),kind+' rule');
      await page.locator('[name=rule-description]').fill('edited');await page.locator('#pw-form [type=submit]').click();await page.locator('#pw-editor').waitFor({state:'hidden'});
      await page.locator('[data-rule-clone]').click();assert.equal(await page.locator('[name=rule-enabled]').inputValue(),'false');await page.locator('[name=rule-name]').fill(kind+' clone');await page.locator('#pw-form [type=submit]').click();await page.locator('#pw-editor').waitFor({state:'hidden'});
      await page.locator('[data-rule-op=up][data-index="1"]').click();await page.waitForFunction(k=>document.querySelector('#pw-list tbody tr')?.textContent.includes(k+' clone'),kind);
      await page.locator('[data-rule-op=toggle][data-index="0"]').click();await page.waitForFunction(()=>document.getElementById('pw-status').textContent.includes('block activation'));
      await page.locator('#pw-validate').click();await page.waitForFunction(k=>document.getElementById('pw-validation').textContent.includes(k==='nat'?'Layer 3':'No commissioned runtime provider'),kind);await page.locator('#object-close').click();
      await page.locator('[data-rule-op=toggle][data-index="0"]').click();await page.waitForFunction(()=>document.getElementById('pw-status').textContent.includes('No enabled XML'));
      await page.locator('#pw-search').fill('not found');assert.equal(await page.locator('#pw-list tbody tr').count(),0);
      await page.locator('#pw-source').selectOption('running');await page.waitForFunction(()=>document.getElementById('pw-count').textContent==='0 of 0 rules');assert(await page.locator('#pw-add').isDisabled());
    }
    await open('decryption');await page.locator('#pw-scope').selectOption('vsys2');
    await page.locator('#pw-profiles').click();await page.locator('#pp-add:enabled').waitFor();
    assert.match(await page.locator('#pp-status').innerText(),/vsys2/);
    await page.locator('#pp-back').click();await page.locator('#pw-add:enabled').waitFor();
    assert.equal(await page.locator('#pw-scope').inputValue(),'vsys2');
    await open('security');await page.locator('[data-rule-edit="0"]').click();
    const reveal=async key=>{
      const control=page.locator('[name="pf-'+key+'"]');
      const panel=await control.evaluate(e=>e.closest('[data-panel]').dataset.panel);
      await page.locator('[data-tab="'+panel+'"]').click();return control;
    };
    await (await reveal('profile-mode')).selectOption('group');
    await page.locator('[name=pf-profile-group]').selectOption('inspection');
    assert(await page.locator('[name=pf-antivirus]').isHidden());
    await page.locator('[name=pf-profile-mode]').selectOption('profiles');
    assert(await page.locator('[name=pf-profile-group]').isHidden());
    for(const key of ['antivirus','vulnerability','anti-spyware','url-filtering','file-blocking','data-filtering','crucible-analysis'])await page.locator('[name=pf-'+key+']').selectOption('inspect-'+key);
    await page.locator('[name=pf-profile-mode]').selectOption('group');
    assert.equal(await page.locator('[name=pf-profile-group]').inputValue(),'inspection');
    await page.locator('[name=pf-profile-mode]').selectOption('profiles');
    await (await reveal('source-device')).fill('workstation');
    await (await reveal('destination-device')).fill('workstation');
    await (await reveal('source-user')).fill('EXAMPLE\\alice');
    await (await reveal('action')).selectOption('reset-both');
    await page.locator('[name=pf-icmp-unreachable]').selectOption('yes');
    await (await reveal('log-setting')).selectOption('central-logs');
    await page.locator('[name=pf-log-start]').selectOption('yes');
    await page.getByRole('tab',{name:'Rule Usage',exact:true}).click();
    assert.match(await page.locator('.policy-panel:not([hidden])').innerText(),/Hit Count.*Unavailable.*Last Hit.*Unavailable.*First Hit.*Unavailable/s);
    assert.equal(await page.locator('.policy-panel:not([hidden]) input').count(),0);
    await page.locator('#pw-form [type=submit]').click();await page.locator('#pw-editor').waitFor({state:'hidden'});
    await page.locator('[data-rule-edit="0"]').waitFor();
    const snapshot=await (await fetch(url+'/api/config/policies/security')).json(),saved=snapshot.entries[0].settings;
    assert.equal(saved['profile-mode'],'profiles');assert.equal(saved['profile-group'],'');
    assert.equal(saved['crucible-analysis'],'inspect-crucible-analysis');assert.equal(saved['source-device'][0],'workstation');
    assert.equal(saved['destination-device'][0],'workstation');assert.equal(saved['log-setting'],'central-logs');
    for(const label of ['Source User','Source Device','Destination Device','Hit Count','Last Hit','First Hit'])assert(await page.getByRole('columnheader',{name:label,exact:true}).count());
    await page.locator('[data-rule-edit="0"]').click();
    await (await reveal('profile-mode')).selectOption('none');
    await page.locator('#pw-cancel').click();
    assert.equal((await (await fetch(url+'/api/config/policies/security')).json()).revision,snapshot.revision,'Cancel must not stage edits');
    await page.locator('[data-rule-edit="0"]').click();
    await (await reveal('profile-mode')).selectOption('none');
    await page.locator('#pw-form [type=submit]').click();await page.locator('#pw-editor').waitFor({state:'hidden'});
    await page.locator('[data-rule-edit="0"]').waitFor();
    const cleared=(await (await fetch(url+'/api/config/policies/security')).json()).entries[0].settings;
    assert.equal(cleared['profile-mode'],'none');assert.equal(cleared.antivirus,'');assert.equal(cleared['profile-group'],'');
    await page.locator('[data-rule-edit="0"]').click();
    if(process.env.TEST_SCREENSHOT)await page.screenshot({path:process.env.TEST_SCREENSHOT,fullPage:true});
    assert.deepEqual(errors,[]);console.log('All ten policy editors, tabs, create/edit/clone, move, enable/disable, controller validation and running views passed.');
  }finally{if(browser)await browser.close();python.kill();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
