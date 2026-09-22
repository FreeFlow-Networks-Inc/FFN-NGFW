const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
 try{
  const page=await browser.newPage();
  await page.setContent('<div id="iface-notice"></div><div id="modal-info"><h3 id="info-modal-title"></h3><div id="info-modal-body"></div></div>');
  const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');
  const modes=html.slice(html.indexOf('const IFACE_MODES'),html.indexOf('let _ifaceState'));
  const editor=html.slice(html.indexOf('function switchIfaceEditorTab('),html.indexOf('async function deleteIface('));
  const options=html.slice(html.indexOf('function subinterfaceOptions('),html.indexOf('function addSubinterfaceAddress('));
  await page.evaluate(code=>{
   window._escSP=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
   window._ifaceState={configured:{ethernet:[],'aggregate-ethernet':[]},caps:{},enriched:{ethernet:[]},jumbo:{mtu:1500}};
   window.snapshot={vsys:'vsys1',revision:'a'.repeat(64),can_edit:true,zone_choices:{layer3:['trust'],layer2:['switch']},virtual_router_choices:['default'],vlan_choices:['users'],aggregate_choices:['ae1'],management_profile_choices:['ping'],lldp_profile_choices:[],entry:{name:'ethernet1/24',mode:'none',comment:'',ip_addresses:[],sub_interfaces:[],zone:'',virtual_router:'',vlan:'',dhcp_client:false,dhcp_default_route:true,dhcp_route_metric:'10',ipv6_enabled:false,mtu:'',interface_management_profile:'',link_speed:'auto',link_duplex:'auto',link_state:'down',aggregate_group:'',lldp_enabled:false,lldp_profile:'',bond_mode:'active-backup',bond_miimon_ms:'100'}};
   window.calls=[];window.saveError='';window.consoleRequest=async(url,opts)=>{if(!opts)return structuredClone(snapshot);calls.push({url,body:JSON.parse(opts.body)});if(saveError)throw Error(saveError);return {status:'updated',name:snapshot.entry.name};};
   window.closeModal=id=>document.getElementById(id).classList.remove('show');window.refreshCommitIndicator=()=>{};window.loadInterfacesFull=()=>{};
   window.eval(code);
  },modes+'\n'+options+'\n'+editor);
  await page.evaluate(()=>openIfaceModal('ethernet1/24'));
  assert.equal(await page.locator('#ifm-mode').inputValue(),'none');assert.equal(await page.locator('#ifm-state').inputValue(),'down');assert.equal(await page.locator('#ifm-state').isDisabled(),true);assert.equal(await page.locator('#ifm-tab-ipv4').isVisible(),false);
  await page.locator('#ifm-mode').selectOption('layer3');assert.equal(await page.locator('#ifm-state').inputValue(),'auto');assert.equal(await page.locator('#ifm-l3-block').isVisible(),true);
  await page.locator('#ifm-zone').selectOption('trust');await page.locator('#ifm-vr').selectOption('default');
  await page.getByRole('tab',{name:'IPv4',exact:true}).click();await page.getByRole('button',{name:'Add IPv4 Address',exact:true}).click();await page.getByLabel('IPv4 address with prefix',{exact:true}).fill('192.0.2.1/24');
  await page.getByRole('tab',{name:'IPv6',exact:true}).click();await page.getByRole('button',{name:'Add IPv6 Address',exact:true}).click();await page.getByLabel('IPv6 address with prefix',{exact:true}).fill('2001:db8::1/64');await page.locator('#ifm-ipv6-enabled').selectOption('yes');
  await page.getByRole('tab',{name:'Advanced',exact:true}).click();await page.locator('#ifm-mgmt').selectOption('ping');await page.locator('#ifm-state').selectOption('down');await page.locator('#ifm-mode').selectOption('none');await page.locator('#ifm-mode').selectOption('layer3');assert.equal(await page.locator('#ifm-state').inputValue(),'down');
  await page.getByRole('button',{name:'OK',exact:true}).click();
  const first=(await page.evaluate(()=>calls))[0];assert.equal(first.url,'/api/config/interfaces');assert.deepEqual(first.body.ip_addresses,['192.0.2.1/24','2001:db8::1/64']);assert.equal(first.body.interface_management_profile,'ping');assert.equal(first.body.revision,'a'.repeat(64));assert.equal(first.body.link_state,'down');
  assert.match(await page.locator('#iface-notice').innerText(),/Commit required/);
  await page.evaluate(()=>{Object.assign(snapshot.entry,calls[0].body,{name:'ethernet1/1',zone:'trust',virtual_router:'default'});saveError='Candidate changed. Refresh and review before retrying.';});
  await page.evaluate(()=>openIfaceModal('ethernet1/1'));await page.locator('#ifm-comment').fill('Unsaved edit');
  await page.getByRole('tab',{name:'IPv4',exact:true}).click();await page.getByRole('button',{name:'Remove IPv4 address',exact:true}).click();await page.getByRole('button',{name:'OK',exact:true}).click();
  assert.match(await page.locator('#ifm-msg').innerText(),/Candidate changed/);assert.equal(await page.locator('#ifm-comment').inputValue(),'Unsaved edit');assert.equal(await page.locator('#ifm-save').isDisabled(),false);assert.deepEqual((await page.evaluate(()=>calls))[1].body.ip_addresses,['2001:db8::1/64']);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal((await page.evaluate(()=>calls)).length,2);
  await page.evaluate(()=>{saveError='';});await page.evaluate(()=>openIfaceModal('ethernet1/1'));
  await page.getByRole('tab',{name:'IPv4',exact:true}).click();await page.getByLabel('IPv4 address with prefix',{exact:true}).fill('invalid');await page.getByRole('tab',{name:'Configuration',exact:true}).click();await page.getByRole('button',{name:'OK',exact:true}).click();assert.equal(await page.locator('#ifm-tab-ipv4').getAttribute('aria-selected'),'true');assert.equal((await page.evaluate(()=>calls)).length,2);
  await page.locator('#ifm-addressing').selectOption('dhcp');await page.locator('#ifm-dhcp-metric').fill('23');assert.equal(await page.locator('#ifm-tab-ipv6').isVisible(),false);await page.getByRole('button',{name:'OK',exact:true}).click();
  const dhcp=(await page.evaluate(()=>calls))[2].body;assert.equal(dhcp.dhcp_client,true);assert.deepEqual(dhcp.ip_addresses,[]);assert.equal(dhcp.dhcp_route_metric,23);
  await page.evaluate(()=>{snapshot.entry.name='ae1';snapshot.entry.mode='layer3';snapshot.entry.bond_mode='802.3ad';});await page.evaluate(()=>openIfaceModal('ae1'));assert.equal(await page.locator('#ifm-bondmode').inputValue(),'802.3ad');await page.getByRole('tab',{name:'Advanced',exact:true}).click();assert.equal(await page.locator('#ifm-speed').isVisible(),false);assert.equal(await page.locator('#ifm-duplex').isDisabled(),true);
  await page.locator('#ifm-mode').selectOption('none');assert.equal(await page.locator('#ifm-state').isDisabled(),false);
  await page.locator('#ifm-state').selectOption('auto');await page.getByRole('tab',{name:'Configuration',exact:true}).click();assert.equal(await page.locator('#ifm-bondmode').isVisible(),true);
  await page.getByRole('button',{name:'OK',exact:true}).click();const linkOnly=(await page.evaluate(()=>calls))[3];assert.equal(linkOnly.url,'/api/config/interfaces');assert.equal(linkOnly.body.mode,'none');assert.equal(linkOnly.body.link_state,'auto');assert.equal(linkOnly.body.bond_mode,'802.3ad');assert.deepEqual(linkOnly.body.ip_addresses,[]);
  await page.evaluate(()=>{snapshot.can_edit=false;});await page.evaluate(()=>openIfaceModal('ae1'));await page.getByRole('tab',{name:'Advanced',exact:true}).click();assert.equal(await page.locator('#ifm-save').isDisabled(),true);assert.equal(await page.locator('#ifm-state').isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Cancel',exact:true}).isDisabled(),false);
  assert.equal((await page.evaluate(()=>calls)).length,4,'No immediate VR, commit, or runtime writes');
  console.log('Parent interface tabs, None/admin-down, IPv4/IPv6 rows, DHCP, atomic candidate save, stale edits, Cancel, read-only and LACP controls passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
