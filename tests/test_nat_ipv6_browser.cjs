const {chromium}=require('playwright');
const {spawn}=require('node:child_process');
const assert=require('node:assert/strict'),net=require('node:net'),path=require('node:path');
async function main(){
  const port=await new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
  const server=spawn(process.env.TEST_PYTHON||'python3',[path.join(__dirname,'policies_browser_fixture.py'),String(port)],{stdio:['ignore','pipe','pipe']});
  let log='',browser;server.stderr.on('data',x=>log+=x);
  try{
    const url='http://127.0.0.1:'+port;
    for(let i=0;i<100;i++){try{if((await fetch(url)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));if(i===99)throw Error(log);}
    browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
    const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(url);
    await page.evaluate(()=>renderPolicyWorkspace(document.getElementById('content-area'),'nat'));
    const snapshot=async source=>(await (await fetch(url+'/api/config/policies/nat?source='+source)).json());
    const before=await snapshot('running');
    const values={nat64:{'nat64-prefix':'2001:db8:64::/96'},nptv6:{'nptv6-internal-prefix':'fd01:203:405::/48','nptv6-external-prefix':'2001:db8:1::/48'}};
    for(const kind of ['nat64','nptv6']){
      await page.locator('#pw-add:enabled').click();await page.locator('[name=rule-name]').fill(kind);
      await page.locator('[name=pf-nat-type]').selectOption(kind);
      await page.getByRole('tab',{name:'Translated Packet',exact:true}).click();
      for(const [key,value] of Object.entries(values[kind])){
        const label=page.locator('[name="pf-'+key+'"]').locator('..');
        await label.locator('select').selectOption('__literal__');await label.locator('[data-reference-literal]').fill(value);
      }
      assert(await page.locator('[name=pf-source-type]').isHidden());
      assert(await page.locator('[name=pf-destination-type]').isHidden());
      if(kind==='nat64'){
        const label=page.locator('[name=pf-nat64-pool]').locator('..');
        await label.locator('.policy-literal input').fill('192.0.2.10');await label.locator('[data-literal-add]').click();
        assert(await page.locator('[name=pf-nptv6-internal-prefix]').locator('..').isHidden());
      }else assert(await page.locator('[name=pf-nat64-pool]').locator('..').isHidden());
      await page.locator('#pw-form [type=submit]').click();await page.locator('#pw-editor').waitFor({state:'hidden'});
      const saved=(await snapshot('candidate')).entries.find(r=>r.name===kind);
      assert.equal(saved.enabled,false);assert.equal(saved.settings['nat-type'],kind);
      for(const [key,value] of Object.entries(values[kind]))assert.equal(saved.settings[key],value);
    }
    assert.equal((await snapshot('running')).revision,before.revision);
    const candidate=await snapshot('candidate');await page.locator('[data-rule-edit="1"]').first().click();
    await page.getByRole('tab',{name:'Translated Packet',exact:true}).click();
    if(process.env.TEST_SCREENSHOT)await page.screenshot({path:process.env.TEST_SCREENSHOT,fullPage:true});
    await page.locator('#pw-cancel').click();assert.equal((await snapshot('candidate')).revision,candidate.revision);
    assert.deepEqual(errors,[]);console.log('NAT64/NPTv6 editor visibility, literals, candidate staging, Cancel and running isolation passed');
  }finally{if(browser)await browser.close();server.kill();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
