const {chromium}=require('playwright');
const {spawn}=require('node:child_process');
const assert=require('node:assert/strict'),net=require('node:net'),path=require('node:path');
async function main(){
  const port=await new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
  const server=spawn(process.env.TEST_PYTHON||'python3',[path.join(__dirname,'vrrp_browser_fixture.py'),String(port)],{stdio:['ignore','pipe','pipe']});
  let log='',browser;server.stderr.on('data',x=>log+=x);
  try{
    const url='http://127.0.0.1:'+port;
    for(let i=0;i<100;i++){try{if((await fetch(url)).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));if(i===99)throw Error(log);}
    browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
    const page=await browser.newPage({viewport:{width:1280,height:900}}),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(url);
    await page.evaluate(()=>renderNetworkVRRP(document.getElementById('content-area')));
    const snapshot=async source=>await (await fetch(url+'/api/config/network/vrrp?source='+source)).json();
    const running=await snapshot('running');
    await page.locator('#vrrp-add:enabled').click();
    await page.locator('[name=name]').fill('isp-gateway');
    await page.locator('[name=interface]').selectOption('ethernet1/1');
    await page.locator('[name=virtual_addresses]').selectOption('shared-gateway');
    assert.equal(await page.locator('[name=enabled]').inputValue(),'no');
    assert.equal(await page.locator('[name=interface] option').allTextContents().then(v=>v.includes('ethernet1/4')),false);
    await page.locator('#vrrp-form [type=submit]').click();await page.locator('#vrrp-editor').waitFor({state:'hidden'});
    let saved=await snapshot('candidate');assert.deepEqual(saved.entries[0].virtual_addresses,['shared-gateway']);assert.equal(saved.entries[0].enabled,false);
    await page.locator('#vrrp-add:enabled').click();await page.locator('[name=name]').fill('isp-bridge');
    await page.locator('[name=mode]').selectOption('passthrough');
    assert.equal(await page.locator('[name=interface]').count(),0);
    await page.locator('[name=domain]').selectOption('isp-segment');
    await page.locator('#vrrp-form [type=submit]').click();await page.locator('#vrrp-editor').waitFor({state:'hidden'});
    saved=await snapshot('candidate');assert.equal(saved.entries.length,2);assert.equal(saved.entries[1].mode,'passthrough');
    await page.locator('[data-edit="0"]').click();await page.locator('[name=priority]').fill('200');await page.locator('#vrrp-cancel').click();
    assert.equal((await snapshot('candidate')).revision,saved.revision);
    await page.locator('[data-edit="0"]').click();await page.locator('#vrrp-literal').fill('198.51.100.1/24');await page.locator('#vrrp-add-address').click();
    await page.locator('#vrrp-form [type=submit]').click();await page.getByText('Virtual address prefix must match a configured interface subnet',{exact:true}).waitFor();
    assert.equal((await snapshot('candidate')).revision,saved.revision);
    await page.locator('#vrrp-cancel').click();
    await page.locator('#vrrp-source').selectOption('running');await page.getByText('No VRRP entries configured.').waitFor();
    assert(await page.locator('#vrrp-add').isDisabled());assert.equal((await snapshot('running')).revision,running.revision);
    assert.deepEqual(errors,[]);console.log('VRRP browser: both modes, dynamic choices, object references, validation, Cancel, candidate staging and running isolation passed');
  }finally{if(browser)await browser.close();server.kill();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
