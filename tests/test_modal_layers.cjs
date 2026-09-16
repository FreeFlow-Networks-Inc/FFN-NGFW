// Real browser regression for nested VR dialogs, dragging, keyboard and staging.
const {chromium}=require('playwright');
const fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict');
(async()=>{
  const root=path.resolve(__dirname,'..'), writes=[], errors=[];
  const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
  try {
    const page=await browser.newPage({viewport:{width:1400,height:1000}});
    page.on('pageerror',e=>errors.push(e.message));
    await page.route('**/*',async route=>{
      const url=new URL(route.request().url()), p=url.pathname, method=route.request().method();
      if(url.hostname!=='console.test')return route.fulfill({body:'',contentType:'application/javascript'});
      if(p.startsWith('/api/')) {
        if(method!=='GET')writes.push({path:p,method,body:route.request().postDataJSON()});
        const json=method!=='GET'?{status:'candidate-updated'}:
          p.endsWith('/virtual-router-interfaces')?{interfaces:[{name:'ethernet1/1',addresses:['192.0.2.2/24'],virtual_router:'default'}]}:
          p.endsWith('/routing')?{config:{}}:p.endsWith('/routes')?{routes:[]}:
          p.endsWith('/virtual-routers')?{virtual_routers:[]}:
          p.endsWith('/lock')?{locked:false}:p.endsWith('/diff')?{has_changes:true,total_changes:1}:{};
        return route.fulfill({json});
      }
      const file=p==='/'?(process.env.TEST_HTML || path.join(root,'static/index.html')):path.join(root,p);
      return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html'});
    });
    await page.goto('http://console.test/');
    await page.evaluate(()=>{
      document.getElementById('login-screen').style.display='none';document.getElementById('app').style.display='block';
      openVrRouting('default');
    });
    await page.locator('#vrr-ad-static').waitFor();
    await page.evaluate(()=>vrrTab('static'));
    const add=page.getByRole('button',{name:'+ Add Route',exact:true});
    await add.click();await page.locator('#route-iface:enabled').waitFor();
    assert(await page.locator('#modal-info').evaluate(e=>e.inert));
    assert(await page.locator('#modal-route').evaluate(e=>{
      const r=e.querySelector('.modal').getBoundingClientRect();
      return document.elementFromPoint(r.x+r.width/2,r.y+r.height/2).closest('.modal-overlay')===e;
    }),'Route editor must paint above its later-in-DOM parent');
    const title=page.locator('#modal-route h3'), rect=await title.boundingBox();
    const before=await page.locator('#modal-route .modal').boundingBox();
    await page.mouse.move(rect.x+80,rect.y+12);await page.mouse.down();
    await page.mouse.move(rect.x+220,rect.y+92,{steps:5});await page.mouse.up();
    const after=await page.locator('#modal-route .modal').boundingBox();
    assert(after.x>before.x+100 && after.y>before.y+50,'Title bar must move the window');
    await page.locator('#route-dest').fill('198.51.100.0/24');
    await page.keyboard.press('Escape');
    await page.locator('#modal-route').waitFor({state:'hidden'});
    assert(await page.locator('#modal-info').isVisible(),'Escape must preserve the parent editor');
    assert.equal(writes.length,0,'Escape/Cancel cannot save configuration');
    assert(await add.evaluate(e=>document.activeElement===e),'Focus returns to the opener');
    await add.click();await page.locator('#route-iface:enabled').waitFor();
    assert.equal(await page.locator('#route-dest').inputValue(),'','Canceled values are discarded on reopen');
    await page.locator('#route-dest').fill('198.51.100.0/24');
    await page.locator('#route-nh').fill('192.0.2.1');
    await page.locator('#modal-route').getByRole('button',{name:'OK',exact:true}).click();
    await page.locator('#modal-route').waitFor({state:'hidden'});
    assert.equal(writes.length,1);assert.equal(writes[0].path,'/api/network/virtual-routers/default/routes');
    assert(!writes.some(w=>w.path.endsWith('/commit')),'OK stages; it cannot auto-commit');
    await page.locator('#modal-info').getByRole('button',{name:'OK',exact:true}).click();
    await page.locator('#modal-info').waitFor({state:'hidden'});
    assert.equal(writes.length,2);assert.equal(writes[1].path,'/api/network/virtual-routers/default/routing');
    assert(await page.locator('body').evaluate(e=>!e.classList.contains('modal-active')));
    assert(await page.locator('#app').evaluate(e=>!e.inert));
    // New dynamic editors must be tracked and cleaned up when navigation removes them.
    await page.evaluate(()=>{const el=document.createElement('div');el.id='dynamic';el.className='modal-overlay show';el.innerHTML='<div class="modal"><h3>Dynamic editor</h3><button>OK</button></div>';document.getElementById('content-area').appendChild(el);});
    await page.waitForFunction(()=>document.getElementById('dynamic').style.zIndex==='1000');
    await page.evaluate(()=>document.getElementById('content-area').replaceChildren());
    await page.waitForFunction(()=>!document.body.classList.contains('modal-active'));
    assert.deepEqual(errors,[]);
    console.log('Nested VR layering, dragging, Escape, focus restoration, candidate OK/Cancel and navigation cleanup passed.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
