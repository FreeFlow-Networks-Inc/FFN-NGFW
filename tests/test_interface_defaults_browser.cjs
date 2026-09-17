const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
  try{
    const page=await browser.newPage();
    await page.setContent('<div id="modal-info"><h2 id="info-modal-title"></h2><div id="info-modal-body"></div></div>');
    const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');
    const modes=html.slice(html.indexOf('const IFACE_MODES'),html.indexOf('let _ifaceState'));
    const editor=html.slice(html.indexOf('function switchIfaceEditorTab('),html.indexOf('let ifaceSavePending'));
    await page.evaluate(code=>{
      window._escSP=value=>String(value);window._ifaceState={configured:{ethernet:[]},caps:{},panToLinux:{},jumbo:{mtu:1500}};
      window.api=async()=>({entries:[]});window.consoleRequest=async()=>({virtual_routers:[]});
      window.eval(code);
    },modes+'\n'+editor);
    await page.evaluate(()=>openIfaceModal('ethernet1/24'));
    assert.equal(await page.locator('#ifm-mode').inputValue(),'none');
    assert.equal(await page.locator('#ifm-state').inputValue(),'down');
    assert.equal(await page.locator('#ifm-state').isDisabled(),true);
    assert.equal(await page.locator('#ifm-l3-block').isVisible(),false);
    await page.selectOption('#ifm-mode','layer3');
    assert.equal(await page.locator('#ifm-state').inputValue(),'auto');
    assert.equal(await page.locator('#ifm-state').isDisabled(),false);
    assert.equal(await page.locator('#ifm-l3-block').isVisible(),true);
    await page.click('#ifm-tab-advanced');
    await page.selectOption('#ifm-state','down');
    await page.selectOption('#ifm-mode','none');await page.selectOption('#ifm-mode','layer3');
    assert.equal(await page.locator('#ifm-state').inputValue(),'down','Mode toggle preserves explicit admin-down');
    await page.evaluate(()=>{_ifaceState.configured.ethernet=[{name:'ethernet1/1',mode:'layer3',link_state:'auto',ip_addresses:['192.0.2.1/24']}];return openIfaceModal('ethernet1/1');});
    assert.equal(await page.locator('#ifm-mode').inputValue(),'layer3');
    assert.equal(await page.locator('#ifm-ip').inputValue(),'192.0.2.1/24');
    console.log('Front-port None defaults, forced admin-down, mode transitions and configured WAN preservation passed.');
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
