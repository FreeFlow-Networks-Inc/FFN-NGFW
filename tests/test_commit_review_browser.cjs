const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const core=path.resolve(__dirname,'..');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],writes=[];
  page.on('pageerror',e=>errors.push(e.message));
  let mode='normal',commitMode='stale',releaseCommit;
  await page.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(url.hostname!=='ffn.test')return route.fulfill({status:200,body:''});
   if(url.pathname.startsWith('/api/')){
    if(url.pathname==='/api/config/review'){
     if(mode==='offline')return route.fulfill({status:503,json:{detail:'Review service unavailable'}});
     return route.fulfill({json:{revision:'review-1',scope:url.searchParams.get('partial_xpath'),
      validated:url.searchParams.get('validate')==='true',can_commit:mode!=='locked',
      lock:{locked:mode==='locked',holder:'<img src=x onerror=evil()>',reason:'fixture'},
      diff:{has_changes:true,total_changes:1,added:[],removed:[],modified:[{path:'config.description',old:'<img src=x onerror=evil()>',new:'<script>evil()</script>'}]},
      validation:{valid:mode!=='blocked',blockers:mode==='blocked'?[{scope:'vsys1',kind:'qos',name:'test',reason:'No commissioned runtime provider'}]:[]},
      validation_scope:'Policy checks only; configuration apply happens after Commit.',applied:false}});
    }
    if(req.method()!=='GET')writes.push({path:url.pathname,body:req.postDataJSON()});
    if(url.pathname==='/api/config/commit'){
     if(commitMode==='stale')return route.fulfill({status:409,json:{detail:'Configuration changed since review. Preview and validate again.'}});
     await new Promise(resolve=>releaseCommit=resolve);
     return route.fulfill({json:{status:'committed',version:10,apply_status:{overall:'partial-failure'},planes:{published:false}}});
    }
    return route.fulfill({json:{}});
   }
   const file=url.pathname==='/'?path.join(core,'static/index.html'):path.join(core,'static',path.basename(url.pathname));
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   return route.fulfill({body:fs.readFileSync(file),contentType:({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'})[path.extname(file)]});
  });
  await page.goto('http://ffn.test/');
  await page.evaluate(()=>{consoleRole='admin';document.getElementById('login-screen').style.display='none';document.getElementById('app').style.display='block';});
  const preview=async()=>{await page.evaluate(()=>openCommitModal());};
  const validate=async()=>{await page.locator('#btn-validate-commit').click();await page.waitForFunction(()=>!commitReviewLoading);};
  await preview();assert(await page.locator('#btn-do-commit').isDisabled());
  assert.equal(await page.locator('#commit-diff img,#commit-diff script').count(),0);
  assert.match(await page.locator('#commit-diff').innerText(),/<script>evil/);
  await validate();assert(await page.locator('#btn-do-commit').isEnabled());
  await page.locator('#btn-do-commit').click();await page.waitForFunction(()=>!commitPosting);
  assert.match(await page.locator('#commit-msg').innerText(),/Configuration changed since review/);
  assert(await page.locator('#btn-do-commit').isDisabled());assert.equal(writes[0].body.expected_revision,'review-1');
  mode='offline';await preview();assert.match(await page.locator('#commit-validation').innerText(),/unavailable/);
  assert(!/No pending changes/.test(await page.locator('#commit-diff').innerText()));assert(await page.locator('#btn-do-commit').isDisabled());
  mode='locked';await preview();await validate();assert(await page.locator('#btn-do-commit').isDisabled());assert.equal(await page.locator('#commit-lock-banner img').count(),0);
  mode='blocked';await preview();await validate();assert(await page.locator('#btn-do-commit').isDisabled());assert.match(await page.locator('#commit-validation').innerText(),/No commissioned runtime provider/);
  mode='normal';await preview();await validate();await page.locator('#commit-scope').selectOption('custom');
  assert(await page.locator('#btn-do-commit').isDisabled());await validate();assert.match(await page.locator('#commit-validation').innerText(),/Enter a subtree path/);
  assert.equal(writes.length,1,'Blank custom scope must never turn into a full commit');
  await page.locator('#commit-custom-xpath').fill('device.setup');await validate();
  assert(await page.locator('#btn-do-commit').isEnabled());
  if(process.env.TEST_ARTIFACT_DIR){fs.mkdirSync(process.env.TEST_ARTIFACT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.TEST_ARTIFACT_DIR,'commit-review.png')});}
  commitMode='delay';await page.locator('#btn-do-commit').click();await page.waitForFunction(()=>commitPosting);
  await page.evaluate(()=>doCommit());assert.equal(writes.length,2,'Duplicate submission must not send another request');
  assert(await page.locator('#commit-scope').isDisabled());releaseCommit();await page.waitForFunction(()=>!commitPosting);
  assert.match(await page.locator('#commit-msg').innerText(),/Configuration saved/);assert.match(await page.locator('#commit-msg').innerText(),/partial-failure/);
  assert.match(await page.locator('#commit-msg').innerText(),/distribution is unconfirmed/);assert(await page.locator('#btn-do-commit').isDisabled());
  assert.deepEqual(errors,[]);console.log('Commit preview, validation, scoped review, escaping, outage, locks, blockers, stale revision and duplicate submission browser checks passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
