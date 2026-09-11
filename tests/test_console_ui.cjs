// Complete script initialization plus navigation, request and edit regressions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(__dirname+'/../static/index.html','utf8');
const script = [...html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map(x=>x[1]).join('\n');
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {innerHTML:'',textContent:'',value:'',isConnected:true,
    disabled:false, style:{}, classList:{add(){},remove(){},toggle(){}},addEventListener(){},focus(){},setSelectionRange(){}});
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
  console.log('Complete UI initialization, unique navigation, role/error handling, escaping and partial settings saves passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
