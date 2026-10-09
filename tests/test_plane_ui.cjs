const assert=require('node:assert/strict'), fs=require('node:fs'), vm=require('node:vm');
class Node {
  constructor(tag){this.tag=tag;this.children=[];this.style={};this.value='';this.textContent='';this.isConnected=true;}
  appendChild(n){this.children.push(n);} replaceChildren(){this.children=[];}
  setAttribute(k,v){this[k]=v;}
  all(){return [this,...this.children.flatMap(n=>n.all())];}
}
// A relaying MP: two resources of its own, one reached through its peer, and a
// blocked request on the relayed one. The page must learn all three from this
// rather than from a list of its own.
function inventory(blocked){return {role:'mp',relays:true,resources:{
  network:{controller:['status','validate','apply'],actions:['apply','resolve','result','status','validate'],
           timeouts:{status:25,validate:20,apply:90},relayed:false,blocked:[]},
  bcm:{controller:['status'],actions:['status'],timeouts:{status:25},relayed:false,blocked:[]}},
  peer:{reachable:true,role:'cp',relays:false,resources:{
    nif:{controller:['status','validate','apply'],actions:['apply','resolve','result','status','validate'],
         timeouts:{},relayed:false,blocked:blocked,blocked_total:blocked.length}}}};}
(async()=>{
  let n=0, calls=[], stuck=['3f1c0b6e-0000-4000-8000-00000000abcd'];
  const ctx={window:{ffnExtensions:{request:async(path,opts)=>{
    if(path==='/api/system/control')return {hardware_boot:{phase:'ready',owner:'mp',platform:'demo',hardware_ready:true}};
    if(!opts) return inventory(stuck);
    const req=JSON.parse(opts.body);calls.push(req);
    if(req.action==='status')return {ok:true,trace:['mp','dp'],result:{config:{revision:7}}};
    if(req.action==='validate')return {ok:true,state:'validated',result:{}};
    if(req.action==='resolve'){stuck=[];return {ok:true,state:'reconciled',result:{observed_revision:req.payload.observed_revision}};}
    return {ok:false,state:'unknown',error:'Reply lost'};
  }}},document:{createElement:t=>new Node(t)},crypto:{randomUUID:()=>String(++n)},JSON,Error};
  vm.runInNewContext(fs.readFileSync(__dirname+'/../static/plane-control.js','utf8'),ctx);
  const root=new Node('main');await ctx.window.ffnPlanes.render(root);
  assert(root.all().some(x=>x.textContent.includes('MP hardware startup: ready · demo')));
  const button=name=>root.all().find(x=>x.tag==='button'&&x.textContent===name);
  const selects=()=>root.all().filter(x=>x.tag==='select');
  const input=root.all().find(x=>x.tag==='textarea');
  const [picker,blocked]=selects();

  // Resources come from the daemon, including the one only its peer executes.
  assert.deepEqual(picker.children.map(o=>o.value),['bcm','network','nif']);
  assert.equal(picker.value,'network');
  assert.equal(calls[0].resource,'network','status is read for the shown resource');

  assert(button('Apply validated configuration').disabled);
  input.value=JSON.stringify({revision:7,ports:{p1:{mode:'l3',addresses:['192.0.2.1/24']}}});
  await button('Validate').onclick();
  assert(!button('Apply validated configuration').disabled);
  input.oninput();assert(button('Apply validated configuration').disabled);
  await button('Validate').onclick();await button('Apply validated configuration').onclick();
  const apply=calls.find(x=>x.action==='apply');
  assert(apply);assert(button('Apply validated configuration').disabled);
  assert(button('Validate').disabled,'Unknown outcome requires status refresh');
  await button('Check last request').onclick();
  assert.equal(calls.at(-1).payload.request_id,apply.id);
  assert.equal(calls.filter(x=>x.action==='apply').length,1,'No automatic write retry');

  // Switching resource addresses the new one and surfaces its blocked request.
  picker.value='nif';await picker.onchange();
  assert.equal(calls.at(-1).resource,'nif');
  assert.equal(calls.at(-1).action,'status');
  assert.equal(blocked.children.map(o=>o.value).length,1);
  assert.equal(blocked.value,stuck[0],'The blocking request ID comes from the daemon, not the tab');
  const reconcile=button('Reconcile interrupted request');
  assert(reconcile&&!reconcile.disabled);

  // Reconciliation refuses to proceed without a revision the operator read back.
  const revision=root.all().find(x=>x.tag==='input');
  revision.value='';await reconcile.onclick();
  assert.equal(calls.filter(x=>x.action==='resolve').length,0,'No reconciliation without an observed revision');
  revision.value='7';await reconcile.onclick();
  const resolved=calls.at(-1);
  assert.equal(resolved.action,'resolve');
  assert.equal(resolved.resource,'nif');
  assert.deepEqual(resolved.payload,{request_id:'3f1c0b6e-0000-4000-8000-00000000abcd',observed_revision:7});
  assert.equal(selects()[1].children.length,0,'A reconciled resource is no longer reported blocked');
  assert.equal(calls.filter(x=>x.action==='apply').length,1,'Reconciling never replays the interrupted change');

  // A daemon that cannot describe itself must still leave the page usable, and
  // must say so: one resource shown silently reads as the only one there is.
  const quiet=new Node('main');
  const original=ctx.window.ffnExtensions.request;
  ctx.window.ffnExtensions.request=async(path,opts)=>{ if(!opts) throw new Error('Request rejected'); return original(path,opts); };
  await ctx.window.ffnPlanes.render(quiet);
  assert.equal(calls.at(-1).resource,'network','Falls back to the default resource');
  assert(quiet.all().find(x=>x.tag==='button'&&x.textContent==='Validate'));
  assert(quiet.all().some(x=>x.role==='status'&&x.textContent.includes('did not describe')));
  ctx.window.ffnExtensions.request=original;

  // A pinned provider page keeps its own vocabulary and editor template.
  const nif=new Node('main');
  await ctx.window.ffnPlanes.render(nif,'nif',{enabled:true});
  assert.equal(calls.at(-1).resource,'nif');
  assert.deepEqual(JSON.parse(nif.all().find(x=>x.tag==='textarea').value),{revision:7,enabled:true});
  assert(nif.all().find(x=>x.tag==='h2').textContent.includes('NIF'));
  console.log('Plane UI resource discovery, stale-edit protection, request recovery and reconciliation passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
