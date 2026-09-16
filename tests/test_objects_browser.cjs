// Requires Playwright and the Python test dependencies. Uses only a local fixture.
const {chromium}=require('playwright');
const {spawn}=require('node:child_process');
const assert=require('node:assert/strict');
const net=require('node:net');
const path=require('node:path');
const fs=require('node:fs');
async function main(){
  const port=await new Promise(resolve=>{const server=net.createServer();server.listen(0,'127.0.0.1',()=>{const p=server.address().port;server.close(()=>resolve(p));});});
  const processPython=spawn(process.env.TEST_PYTHON||'python3',[path.join(__dirname,'objects_browser_fixture.py'),String(port)],{stdio:['ignore','pipe','pipe']});
  let log='';processPython.stderr.on('data',x=>log+=x);
  let browser;
  try{
    const url='http://127.0.0.1:'+port;
    for(let i=0;i<100;i++){try{const r=await fetch(url);if(r.ok)break;}catch{}await new Promise(r=>setTimeout(r,100));if(i===99)throw Error(log);}
    browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
    const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(url);
    const open=async kind=>{await page.evaluate(k=>renderConfigObjects(document.getElementById('content-area'),k),kind);await page.locator('#object-add:enabled').waitFor();};
    const definitions=[
      ['tag','tag',{color:'color1'}], ['address','ip-netmask',{value:'192.0.2.1/24'}],
      ['address-group','static',{members:['address fixture']}],
      ['region','region',{addresses:'192.0.2.0/24',latitude:'12',longitude:'42'}],
      ['dynamic-user-group','dynamic',{filter:"'tag fixture'"}],
      ['application','custom',{category:'business',subcategory:'general',technology:'client-server',risk:'3',ports:'tcp/443'}],
      ['application-group','static',{members:['application fixture']}],
      ['application-filter','filter',{risk:'3\n4',category:'business'}],
      ['service','tcp',{value:'443'}],['service-group','static',{members:['service fixture']}],
      ['device','device',{vendor:'Example',model:'Router'}],
      ['external-list','ip',{url:'https://example.com/feed.txt',interval:'daily',time:'12:30',exceptions:'192.0.2.5'}]
    ];
    for(const [kind,type,fields] of definitions){
      await open(kind);await page.locator('#object-add').click();
      await page.locator('#object-form [name=name]').fill(kind+' fixture');
      await page.locator('#object-form [name=type]').selectOption(type);
      for(const [key,value] of Object.entries(fields)){
        const el=page.locator('#object-form [name="'+(['value','members'].includes(key)?key:'setting-'+key)+'"]');
        if(await el.evaluate(e=>e.tagName)==='SELECT')await el.selectOption(value);else await el.fill(value);
      }
      await page.locator('#object-form [name=description]').fill('Objects browser regression');
      await page.locator('#object-form [type=submit]').click();
      await page.locator('#object-editor').waitFor({state:'hidden'});
      assert(await page.locator('#object-list').innerText().then(t=>t.includes(kind+' fixture')),kind+' did not save');
      await page.locator('#object-list [data-edit]').click();
      assert.equal(await page.locator('#object-form [name=name]').inputValue(),kind+' fixture');
      await page.locator('#object-form [name=description]').fill('Edited description');
      await page.locator('#object-form [type=submit]').click();await page.locator('#object-editor').waitFor({state:'hidden'});
      await page.locator('#object-search').fill('no matching objects');assert.equal(await page.locator('#object-list tbody tr').count(),0);
      await page.locator('#object-search').fill('');
      await page.locator('#object-source').selectOption('running');await page.waitForFunction(()=>document.getElementById('object-count').textContent==='0 of 0 items');
      assert(await page.locator('#object-add').isDisabled());
    }
    await open('address');await page.locator('[data-clone]').click();
    assert.equal(await page.locator('#object-form [name=name]').inputValue(),'');
    await page.locator('#object-form [name=name]').fill('cloned address');await page.locator('#object-form [type=submit]').click();await page.locator('#object-editor').waitFor({state:'hidden'});
    assert.equal(await page.locator('#object-list tbody tr').count(),2);
    // Referenced object deletion is rejected, displayed, and leaves its row intact.
    page.on('dialog',d=>d.accept());await page.locator('[data-delete="0"]').click();await page.locator('#object-error').waitFor();
    assert.match(await page.locator('#object-error').innerText(),/referenced/i);
    await page.locator('#object-close').click();
    await page.locator('[data-delete="1"]').click();await page.waitForFunction(()=>document.querySelectorAll('#object-list tbody tr').length===1);
    await open('address-group');await page.locator('#object-add').click();await page.locator('#object-form [name=name]').fill('dynamic addresses');
    await page.locator('#object-form [name=type]').selectOption('dynamic');assert(await page.locator('#object-members').isHidden());
    await page.locator('#object-form [name=value]').fill("'tag fixture'");await page.locator('#object-form [type=submit]').click();await page.locator('#object-editor').waitFor({state:'hidden'});
    if(process.env.TEST_SCREENSHOT){await page.screenshot({path:process.env.TEST_SCREENSHOT,fullPage:true});}
    assert.deepEqual(errors,[]);console.log('All 12 Objects pages: create, edit, search, running view; clone, references, delete protection and dynamic groups passed.');
  }finally{if(browser)await browser.close();processPython.kill();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
