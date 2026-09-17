const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
  try{
    const page=await browser.newPage();
    await page.setContent('<table><tbody id="iface-ae-body"></tbody></table>');
    const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');
    const render=html.slice(html.indexOf('function _renderConfiguredAE()'),html.indexOf('function switchIfaceEditorTab('));
    await page.evaluate(code=>{
      window._escSP=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      window._ifaceState={configured:{'aggregate-ethernet':[{name:'ae1',mode:'layer3'}],ethernet:[]},jumbo:{mtu:1500},aeStatus:[{
        ae_name:'ae1',backend:'pa5200-bcm',state:'blocked',committed:true,
        members:[{name:'ethernet1/23',bcm_port:34,link:true,speed_mbps:100000},{name:'ethernet1/24',bcm_port:35,link:false}],
        blockers:[{message:'LACP negotiation unavailable <img src=x onerror=alert(1)>'}]}]};
      window.eval(code);_renderConfiguredAE();
    },render);
    const text=await page.locator('table').innerText();
    assert.match(text,/BCM \/ OCTEON/);assert.match(text,/100000 Mb\/s/);assert.match(text,/ethernet1\/24: Link down/);
    assert.match(text,/Committed configuration/);assert.match(text,/BLOCKED/);assert(!text.includes('NO KERNEL BOND'));
    assert.equal(await page.locator('img').count(),0);
    await page.evaluate(()=>{
      const live=_ifaceState.aeStatus[0];
      live.partner_consistency={state:'consistent',observed_members:2,expected_members:2};
      live.members[0].partner_observation={actor:{system:'02:00:00:00:00:01',system_priority:32768,key:100,port:101,
        flags:{synchronization:true,collecting:true,distributing:false}}};
      live.members[1].admin_enabled=false;live.members[1].speed_mbps=20000;
      _renderConfiguredAE();
    });
    const vpc=await page.locator('table').innerText();
    assert.match(vpc,/Partner identity: consistent \(2\/2 members observed\)/);
    assert.match(vpc,/Priority 32768 · Key 100 · Port 101/);
    assert.match(vpc,/Peer state synchronization, collecting/);
    assert.match(vpc,/ethernet1\/24: Administratively down/);
    assert(!vpc.includes('20000 Mb/s'));assert.match(vpc,/Passive observations do not verify forwarding/);
    await page.evaluate(()=>{_ifaceState.aeStatus=[{ae_name:'ae1',bond:'bond1',kernel_exists:false}];_renderConfiguredAE();});
    assert.match(await page.locator('table').innerText(),/NO KERNEL BOND/);
    console.log('Aggregate hardware status, physical members, escaped blockers and generic Linux fallback passed.');
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
