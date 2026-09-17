const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const core=path.resolve(__dirname,'..'),platform=process.env.TEST_PA5200_ROOT||path.join(core,'platform/pa5200');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000},colorScheme:'light'}),errors=[],writes=[];
  page.on('pageerror',e=>errors.push(e.message));
  let candidate=null;
  await page.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url()),name=url.pathname;
   if(url.hostname!=='ffn.test')return route.fulfill({status:200,contentType:'application/javascript',body:''});
   if(name.startsWith('/api/')){
    let body={};
    if(name==='/api/auth/me')body={role:'admin',username:'fixture'};
    if(name==='/api/system/setup')body={config:{hostname:'fixture',timezone:'UTC'}};
    if(name==='/api/system/mp-interfaces')body={ports:['MGT','HA1-A','HA1-B','AUX-1','AUX-2'].map(label=>({name:label,netdev:'fixture0',link:label==='MGT',enabled:label==='MGT',addresses:label==='MGT'?['192.0.2.10/24']:[],gateway:'',dns:[],mtu:1500,revision:'fixture',candidate:label==='MGT'?candidate:null}))};
    if(name==='/api/system/mp-interfaces/MGT'&&request.method()==='PUT'){writes.push(request.postDataJSON());candidate=writes.at(-1).config;body={status:'candidate-updated',requires_commit:true};}
    return route.fulfill({json:body});
   }
   const file=name==='/'?path.join(core,'static/index.html'):name.startsWith('/static/extensions/pa5200/')?path.join(platform,'management/static',path.basename(name)):path.join(core,'static',path.basename(name));
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   const ext=path.extname(file);return route.fulfill({body:fs.readFileSync(file),contentType:({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[ext]});
  });
  await page.goto('http://ffn.test/');
  assert.equal(await page.locator('link[rel=icon]').getAttribute('href'),'/static/favicon.svg');
  await page.locator('.login-theme select').selectOption('dark');
  assert.equal(await page.locator('html').getAttribute('data-theme'),'dark');
  await page.reload();assert.equal(await page.locator('html').getAttribute('data-theme'),'dark');
  await page.evaluate(()=>{document.getElementById('login-screen').style.display='none';document.getElementById('app').style.display='block';switchTab('device');});
  await page.getByRole('button',{name:'Edit',exact:true}).first().waitFor();
  assert.equal(await page.getByRole('button',{name:'Edit',exact:true}).count(),5);
  await page.getByRole('button',{name:'Edit',exact:true}).first().click();
  await page.getByLabel('IPv4 address / prefix').fill('192.0.2.11/24');
  await page.getByRole('button',{name:'Cancel',exact:true}).last().click();assert.equal(writes.length,0);
  await page.getByRole('button',{name:'Edit',exact:true}).first().click();
  await page.getByLabel('Address mode').selectOption('dhcp');
  assert(await page.getByLabel('IPv4 address / prefix').isDisabled());
  await page.getByRole('button',{name:'OK',exact:true}).last().click();
  await page.waitForFunction(()=>!document.querySelector('.modal-overlay.show'));
  assert.equal(writes.length,1);assert.equal(writes[0].config.mode,'dhcp');assert.equal(writes[0].config.address,'');
  await page.screenshot({path:process.env.TEST_SCREENSHOT_DIR?path.join(process.env.TEST_SCREENSHOT_DIR,'setup-dark.png'):undefined});
  // Counter graph removes old host-NIC traces and represents missing samples as gaps.
  await page.evaluate(()=>{
   document.getElementById('content-area').innerHTML='<div id="dash-time"></div><div id="port-cards" class="grid grid-4"></div>';
   charts.throughput={data:{labels:['old'],datasets:[{label:'management RX',data:[99]}]},options:{scales:{y:{title:{text:'pps'}}}},update(){}};
   renderDataPortTraffic({unit:'pps',ports:[{name:'ethernet1/1',rx_pps:34,tx_pps:5,link:true},{name:'ethernet1/2',rx_pps:null,tx_pps:null,link:false,state:'warming'}]});
  });
  assert.equal(await page.locator('.port-card').count(),2);
  assert.match(await page.locator('#port-cards').innerText(),/Link down/);
  assert.deepEqual(await page.evaluate(()=>charts.throughput.data.datasets.map(ds=>ds.label)),['ethernet1/1 RX','ethernet1/1 TX','ethernet1/2 RX','ethernet1/2 TX']);
  await page.evaluate(()=>renderDataPortTraffic(null));
  assert.equal(await page.evaluate(()=>charts.throughput.data.datasets.length),0);
  // Real rear view module; a stalled/unknown fan must not spin.
  await page.evaluate(async()=>{
   const parent=document.getElementById('content-area');parent.replaceChildren();
   window.rearSample={thermal:{available:true,data:{fans:Array.from({length:8},(_,i)=>({bank:Math.floor(i/4)+1,fan:i%4+1,rpm:i===0?0:9000,pwm:191}))}},chassis:{available:true,data:{power_supplies:[{name:'left',present:true,power_good:true},{name:'right',present:true,power_good:false}]}},'chassis-storage':{available:true,data:{bays:['SYS 1','SYS 2','LOG 1','LOG 2'].map(name=>({name,mapped:false,state:'unmapped'})),disks:[]}}};
   const module=await import('/static/extensions/pa5200/chassis.js');
   module.render(parent,async url=>rearSample[url.split('/').pop()].data,rearSample);
  });
  assert.equal(await page.locator('.rear-fan').count(),8);assert.equal(await page.locator('.rear-fan.running').count(),7);
  assert.equal(await page.locator('.rear-psu.good').count(),1);assert.equal(await page.locator('.rear-psu.fault').count(),1);
  assert.equal(await page.locator('.rear-drive').count(),4);
  await page.locator('.topnav select[data-theme-picker]').selectOption('light');
  assert.equal(await page.locator('html').getAttribute('data-theme'),'light');
  if(process.env.TEST_SCREENSHOT_DIR){await page.screenshot({path:path.join(process.env.TEST_SCREENSHOT_DIR,'chassis-light.png')});await page.locator('.topnav select[data-theme-picker]').selectOption('dark');await page.screenshot({path:path.join(process.env.TEST_SCREENSHOT_DIR,'chassis-dark.png')});}
  await page.emulateMedia({reducedMotion:'reduce'});
  assert.equal(await page.locator('.rear-fan.running .blades').first().evaluate(n=>getComputedStyle(n).animationName),'none');
  assert.deepEqual(errors,[]);
  console.log('Theme persistence, favicon, MP candidate OK/Cancel, data-only graph reconciliation, 8 fans/2 PSUs/4 bays and reduced motion passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
