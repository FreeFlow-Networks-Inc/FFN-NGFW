// Complete script initialization plus navigation, request and edit regressions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(__dirname+'/../static/index.html','utf8');
const script = [...html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map(x=>x[1]).join('\n');
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {innerHTML:'',textContent:'',value:'',isConnected:true,
    disabled:false, style:{}, dataset:{}, setAttribute(key,value){this[key]=value;}, classList:{add(){},remove(){},toggle(){}},addEventListener(){},focus(){},setSelectionRange(){}});
  return elements.get(id);
};
const context = vm.createContext({console, window:{}, localStorage:{getItem(){return '';},removeItem(){}},
  document:{getElementById:element,querySelectorAll(){return [];},addEventListener(){}},
  setInterval(){return 1;}, clearInterval(){},setTimeout(){},alert(){},confirm(){return true;},
  fetch:async()=>({ok:true,status:200,json:async()=>({})})});
// Must evaluate the whole bundle: sliced function tests miss declaration-order failures.
vm.runInContext(script,context);
const run = code => vm.runInContext(code,context);
(async()=>{
  context.loadSetupInfo = () => {};
  context.switchTab('device');
  assert.equal(run('currentSubPage'), 'setup', 'First Device click must skip section headings');
  assert(element('content-area').innerHTML.includes('General Settings'));
  element('setup-hostname').value='unsaved-name';
  context.switchSetupTab('services');
  assert.equal(element('setup-panel-management').hidden,true);
  assert.equal(element('setup-panel-services').hidden,false);
  context.switchSetupTab('management');
  assert.equal(element('setup-hostname').value,'unsaved-name','Setup tab switches preserve edits');
  const menus=run('TAB_MENUS');
  const ids=Object.values(menus).flat().filter(x=>x.id).map(x=>x.id);
  assert.equal(new Set(ids).size,ids.length,'Every page must have one menu owner');
  assert.equal(ids.filter(x=>x==='device-updates').length,1);
  assert(!ids.includes('software'));
  assert(menus.device.some(x=>x.id==='dash-hardware'));
  assert(menus.network.some(x=>x.id==='network-qos'));
  assert(run("navigationItems('hardware').some(x=>x.id==='dash-hardware')"));
  run("renderPage = () => {}; switchSubPage('software')");
  assert.equal(run('currentTab'),'device'); assert.equal(run('currentSubPage'),'device-updates');
  run("switchSubPage('network-qos'); switchTab('device'); switchTab('network')");
  assert.equal(run('currentSubPage'),'network-qos');
  assert(run("_netEscape(['<script>', '\"'])").includes('&lt;script&gt;'));
  assert(!run("_netFieldInput({key:'x',type:'list'},['\" onfocus=\"evil()'])").includes('value="" onfocus'));
  const hostile = "\\'\"><img src=x onerror=evil()>";
  for (const render of [context.liveTrafficRowHTML, context.liveSystemLogHTML]) {
    const result = render({timestamp:hostile, message:hostile, severity:hostile});
    assert(!result.includes('<img'), 'WebSocket data must stay text');
    assert(!result.includes('class="sev sev-\\'), 'Severity CSS uses a fixed allowlist');
  }
  for (const render of [context.vrGridRow,context.vrCardHtml]) {
    const result=render({name:hostile},0);
    assert(!result.includes('<img'));
    for (const handler of result.matchAll(/onclick="([^"]*)"/g)) {
      assert(!handler[1].includes('evil'), 'Object names must not be interpolated into JavaScript');
      assert(handler[1].includes('this.dataset.vr'));
    }
  }
  context.api=async()=>({routes:[{id:hostile,dest_cidr:'192.0.2.0/24'}]});
  await context.loadVRRoutes(hostile);
  const route=element('vr-routes-'+hostile).innerHTML;
  assert(!route.includes('<img'));
  assert(route.includes('deleteVRoute(this.dataset.vr,this.dataset.route)'));

  context.fetch=async()=>({ok:false,status:423,json:async()=>({detail:'Locked by another administrator'})});
  await assert.rejects(context.consoleRequest('/fixture'),/Locked/);
  context.fetch=async()=>({ok:true,status:200,json:async()=>({status:'error',message:'Snapshot missing'})});
  await assert.rejects(context.consoleRequest('/fixture'),/Snapshot missing/);
  run("consoleRole = 'admin'; setupBaseline = {hostname:'before', timezone:'UTC', dns_primary:'192.0.2.53', dns_secondary:'', ntp_server:'time.example'}");
  for(const [k,v] of Object.entries(run('setupBaseline'))) element('setup-'+k).value=v;
  element('setup-hostname').value='after';
  let body;
  context.fetch=async(path,opts)=>{body=JSON.parse(opts.body);return {ok:true,status:200,json:async()=>({status:'candidate-updated'})};};
  run('refreshCommitIndicator = () => {}');
  await context.saveSetup();
  assert.deepEqual(body,{hostname:'after'},'Saving one setting must not clear DNS/NTP');
  assert.match(element('setup-msg').textContent,/Saved to candidate/);
  context.fetch=async()=>({ok:false,status:403,json:async()=>({detail:'Forbidden'})});
  element('setup-hostname').value='denied';
  await context.saveSetup();
  assert.equal(run('setupBaseline.hostname'),'after');
  assert.equal(element('setup-msg').textContent,'Forbidden');
  run("consoleRole = 'readonly'");
  body=null;await context.saveSetup();assert.equal(body,null);
  const requested=[];
  context.api=async path=>{requested.push(path);return {ports:[]};};
  run("currentSubPage='dash-throughput'");
  await context.refreshDashboard();
  assert.deepEqual(requested,['/api/dashboard/throughput'],'Throughput view must not fetch or render overview widgets');
  let complete;
  context.api=()=>new Promise(resolve=>{complete=resolve;});
  const pending=context.refreshDashboard();
  element('dash-time').isConnected=false;
  const before=element('port-cards').innerHTML;
  complete({ports:[]});await pending;
  assert.equal(element('port-cards').innerHTML,before,'Late refresh must not update a detached page');
  context.fetch=async()=>({ok:true,status:200,json:async()=>({overall:'partial-failure',
    applied:[{xpath:'ethernet1/5',message:'Disabled'}],errors:[{xpath:'<img src=x>',message:'LACP unsupported'}]})});
  await context.loadTasks();
  assert.match(element('tasks-summary').textContent,/partial-failure/);
  assert.match(element('tasks-body').innerHTML,/LACP unsupported/);
  assert.match(element('tasks-body').innerHTML,/Disabled/);
  assert(!element('tasks-body').innerHTML.includes('<img'));
  context.fetch=async()=>({ok:false,status:503,json:async()=>({detail:'configd unavailable'})});
  await context.loadTasks();
  assert.match(element('tasks-summary').textContent,/configd unavailable/);
  assert.match(element('tasks-body').innerHTML,/unknown/);
  assert(!element('tasks-body').innerHTML.includes('Disabled'),'Failed refresh clears stale successes');
  context.loadCommitDiff=async()=>{};
  for (const overall of ['partial-failure','applied']) {
    context.fetch=async()=>({ok:true,status:200,json:async()=>({status:'committed',type:'full',snapshot:'v8',apply_status:{overall}})});
    await context.doCommit();
    assert.equal(element('commit-msg').style.color,overall==='applied'?'var(--green)':'var(--orange)');
    assert.equal(element('commit-msg').textContent.includes('Applied successfully'),overall==='applied');
  }
  context.loadInterfacesFull=()=>{};
  context.fetch=async()=>({ok:true,status:200,json:async()=>({status:'committed',type:'full',snapshot:'v8',apply_status:{overall:'applied',skipped:[{xpath:'zone-reconcile'}]}})});
  await context.doCommit();
  assert.match(element('commit-msg').textContent,/1 settings skipped/);
  assert.equal(element('commit-msg').style.color,'var(--orange)');
  element('ifm-name').value='ethernet1/1'; element('ifm-mode').value='layer3';
  element('ifm-vr').value='default'; element('ifm-vr').dataset.original='default';
  const writes=[];
  context.fetch=async(path)=>{writes.push(path);return {ok:true,status:200,json:async()=>({status:'created'})};};
  await context.saveIface();
  assert.deepEqual(writes,['/api/interfaces/ethernet1%2F1'],'Unchanged VR must not trigger a runtime write');
  element('ifm-vr').value='new-router';
  context.fetch=async(path)=>path.endsWith('/virtual-router') ?
    {ok:false,status:503,json:async()=>({detail:'MP unavailable'})} :
    {ok:true,status:200,json:async()=>({status:'created'})};
  await context.saveIface();
  assert.match(element('ifm-msg').textContent,/Interface saved to candidate; virtual-router assignment failed: MP unavailable/);
  assert.equal(element('ifm-vr').dataset.original,'default','Failed VR write must remain retryable');
  element('ifm-ip').value='192.0.2.1/24';
  context.switchIfaceEditorTab('advanced');context.switchIfaceEditorTab('config');
  assert.equal(element('ifm-ip').value,'192.0.2.1/24');
  element('zones-vsys-select').value='vsys1'; element('zones-source').value='candidate';
  context.fetch=async()=>({ok:true,status:200,json:async()=>({vsys:'vsys1',revision:'a'.repeat(64),can_edit:true,
    entries:[{name:'<img src=x>',zone_type:'layer3',interfaces:['ethernet1/1'],editable:true,comment:'test'}],
    interface_choices:[{name:'ethernet1/1',mode:'layer3'}],enforcement:'Not enforced'})});
  await context.loadZones();
  assert.equal(element('zones-add').disabled,false);
  assert(!element('zones-tbody').innerHTML.includes('<img'));
  context.openZoneModal();
  assert.match(element('info-modal-body').innerHTML,/ethernet1\/1/,'Zone editor loads its own interface choices');
  context.fetch=async()=>({ok:false,status:503,json:async()=>({detail:'Unavailable'})});
  await context.loadZones();
  assert.equal(element('zones-add').disabled,true);
  assert.match(element('zones-notice').textContent,/Unable to load zones/);
  console.log('Complete UI initialization, unique navigation, role/error handling, escaping and partial settings saves passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
