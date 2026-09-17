// Real browser coverage for the combined Security inventory and immutable defaults.
const {chromium}=require('playwright');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
  const root=path.resolve(__dirname,'..'),writes=[],errors=[];
  const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
  try {
    let failure='', reads=0;
    const rules=[
      {id:1,name:'management',kind:'lab-mgmt',immutable:1},
      {id:6,name:'legacy-mp',kind:'mgmt',immutable:1},
      {id:2,name:'shared-name',kind:'user',vsys:1},
      {id:3,name:'intrazone-default',kind:'intrazone-default',hidden:1,immutable:1},
      {id:4,name:'interzone-default',kind:'interzone-default',immutable:1},
      {id:5,name:'other-tenant',kind:'user',vsys:2}
    ].map((r,i)=>({position:i,enabled:1,src_ip:'0.0.0.0/0',dst_ip:'0.0.0.0/0',proto:'any',action:'permit',description:'original',...r}));
    const entry={name:'shared-name',position:1,enabled:false,editable:true,state:'Disabled',settings:{from:['any'],to:['any'],source:['any'],destination:['any'],application:['any'],service:['any'],action:'allow'}};
    const page=await browser.newPage({viewport:{width:1500,height:1050}});
    page.on('pageerror',e=>errors.push(e.message));
    await page.route('**/*',async route=>{
      const url=new URL(route.request().url()),p=url.pathname,method=route.request().method();
      if(url.hostname!=='console.test')return route.fulfill({body:'',contentType:'application/javascript'});
      if(p.startsWith('/api/')){
        if(method!=='GET'){
          const body=route.request().postDataJSON();writes.push({p,method,body});
          if(p==='/api/policy/rules/2')Object.assign(rules[1],body);
          return route.fulfill({json:{status:'updated'}});
        }
        if(p==='/api/policy/rules'){
          reads++;assert.equal(url.searchParams.get('show_hidden'),'true');assert.equal(url.searchParams.get('show_defaults'),'true');
          return failure==='fast'?route.fulfill({status:503,json:{detail:'fast offline'}}):route.fulfill({json:{rules,can_edit:true}});
        }
        if(p==='/api/config/policies/security')return failure==='xml'?route.fulfill({status:503,json:{detail:'xml offline'}}):route.fulfill({json:{entries:url.searchParams.get('source')==='running'?[]:[entry],scopes:['vsys1','vsys2'],can_edit:url.searchParams.get('source')==='candidate',runtime:{owner:'ffn-controld',valid:true,blockers:[]}}});
        return route.fulfill({json:{}});
      }
      const file=p==='/'?(process.env.TEST_HTML||path.join(root,'static/index.html')):path.join(root,p);
      return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html'});
    });
    await page.goto('http://console.test/');
    await page.evaluate(()=>{document.getElementById('login-screen').style.display='none';document.getElementById('app').style.display='block';renderPolicySecurity(document.getElementById('content-area'));});
    const count=async n=>page.waitForFunction(n=>document.querySelectorAll('#pw-list tbody tr').length===n,n);
    await count(4);
    assert.equal(await page.locator('#pw-list table').count(),1);
    assert.equal(await page.locator('#pw-existing').count(),0);
    assert.equal(await page.locator('#pw-list button').filter({hasText:/^shared-name$/}).count(),2,'Same names in different stores remain distinct');
    const names=await page.locator('#pw-list tbody tr td:nth-child(2)').allTextContents();
    assert.deepEqual(names,['shared-name','shared-name','intrazone-default','interzone-default']);
    assert(!(await page.locator('#pw-list').innerText()).includes('other-tenant'));
    await page.locator('#pw-search').fill('no matching rule');await count(2);
    await page.locator('[data-fast-row="3"] [data-fast-view]').click();
    assert(await page.locator('#rule-desc').isDisabled());assert(await page.locator('#rule-save').isDisabled());
    await page.evaluate(()=>saveRule());assert.equal(writes.length,0);
    await page.keyboard.press('Escape');await page.locator('#pw-search').fill('');await count(4);
    await page.locator('[data-fast-row="2"] [data-fast-view]').first().click();
    await page.locator('#rule-desc').fill('updated description');await page.locator('#rule-save').click();
    await page.locator('#modal-rule').waitFor({state:'hidden'});await count(4);
    assert.equal(writes.length,1);assert.equal(writes[0].p,'/api/policy/rules/2');assert(reads>=2);
    await page.locator('#pw-source').selectOption('running');await count(3);
    assert.equal(await page.locator('[data-fast-clone],[data-fast-delete]').count(),0);
    await page.locator('[data-fast-row="2"] [data-fast-view]').first().click();
    assert(await page.locator('#rule-desc').isDisabled());await page.keyboard.press('Escape');
    await page.locator('#pw-source').selectOption('candidate');await count(4);
    await page.locator('#pw-scope').selectOption('vsys2');await count(4);
    await page.waitForFunction(()=>document.getElementById('pw-list').textContent.includes('other-tenant'));
    assert.equal(await page.locator('[data-fast-row="2"]').count(),0);
    await page.locator('#pw-scope').selectOption('vsys1');await page.locator('[data-fast-row="2"]').waitFor();
    failure='fast';await page.locator('#pw-refresh').click();await count(1);
    assert.match(await page.locator('#pw-status').innerText(),/Fast-path and implicit rules unavailable/);
    failure='xml';await page.locator('#pw-refresh').click();await count(3);
    assert.match(await page.locator('#pw-status').innerText(),/Candidate\/running rules unavailable/);assert(await page.locator('#pw-add').isDisabled());
    failure='';rules[1].name='<img src=x onerror="window.injected=true">';await page.locator('#pw-refresh').click();await count(4);
    assert.equal(await page.locator('#pw-list img').count(),0);assert.equal(await page.evaluate(()=>window.injected),undefined);
    assert.equal(writes.length,1);assert.deepEqual(errors,[]);
    console.log('Combined Security table, scope, search, immutable defaults, source failures, escaping and edit refresh passed.');
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
