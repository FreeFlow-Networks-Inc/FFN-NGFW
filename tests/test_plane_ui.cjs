const assert=require('node:assert/strict'), fs=require('node:fs'), vm=require('node:vm');
class Node {
  constructor(tag){this.tag=tag;this.children=[];this.style={};this.value='';this.textContent='';this.isConnected=true;}
  appendChild(n){this.children.push(n);} replaceChildren(){this.children=[];}
  setAttribute(k,v){this[k]=v;}
  all(){return [this,...this.children.flatMap(n=>n.all())];}
}
(async()=>{
  let n=0, calls=[];
  const ctx={window:{ffnExtensions:{request:async(path,opts)=>{
    const req=JSON.parse(opts.body);calls.push(req);
    if(req.action==='status')return {ok:true,trace:['mp','dp'],result:{config:{revision:7}}};
    if(req.action==='validate')return {ok:true,state:'validated',result:{}};
    return {ok:false,state:'unknown',error:'Reply lost'};
  }}},document:{createElement:t=>new Node(t)},crypto:{randomUUID:()=>String(++n)},JSON,Error};
  vm.runInNewContext(fs.readFileSync(__dirname+'/../static/plane-control.js','utf8'),ctx);
  const root=new Node('main');await ctx.window.ffnPlanes.render(root);
  const button=name=>root.all().find(x=>x.tag==='button'&&x.textContent===name);
  const input=root.all().find(x=>x.tag==='textarea');
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
  console.log('Plane UI validation, stale-edit protection and request recovery passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
