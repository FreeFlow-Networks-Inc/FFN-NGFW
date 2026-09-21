// Reference selection behavior without an appliance or browser dependency.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
function node(){return {children:[],append(...items){this.children.push(...items);},replaceChildren(){this.children=[];},setAttribute(k,v){this[k]=v;}};}
const ctx=vm.createContext({document:{createElement:node},_escSP:v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))});
vm.runInContext(fs.readFileSync(__dirname+'/../static/config-policies.js','utf8'),ctx);
const field={key:'from',label:'Source Zone',mode:'list',ref:'zone',default:['any'],options:[]};
let html=ctx.policyFieldHTML(field,['any'],['tenant-blue','tenant-green'],'nat');
assert.match(html,/<select data-reference="pf-from"/);
assert(!html.includes('<textarea'));
assert.match(html,/tenant-blue/);assert.match(html,/value="any"/);
assert(!ctx.policyFieldHTML(field,[],['new-zone'],'nat').includes('tenant-blue'));
assert(ctx.policyFieldHTML(field,[],['<unsafe>'],'nat').includes('&lt;unsafe&gt;'));
assert(ctx.policyFieldHTML({...field,key:'service',ref:'service'},[],[],'security').includes('value="application-default"'));
assert(!ctx.policyFieldHTML({...field,key:'service',ref:'service'},[],[],'nat').includes('value="application-default"'));
assert(!ctx.policyFieldHTML({...field,key:'tag',ref:'tag',default:[]},[],[],'nat').includes('value="any"'));
assert(ctx.policyFieldHTML({...field,key:'source',ref:'address'},[],['network-object'],'nat').includes('network-object'));
assert(ctx.policyFieldHTML({...field,mode:'text',key:'translated-destination',ref:'address'},'192.0.2.1',[],'nat').includes('value="__literal__" selected'));

function fixture(editable=true){
  const target={value:'any'},chips=node(),select={dataset:{reference:'pf-from'},options:['','any','tenant-blue','tenant-green','application-default'].map(value=>({value}))};
  const container={querySelector:s=>s==='.policy-selected'?chips:null};select.closest=()=>container;
  const form={elements:{'pf-from':target},querySelectorAll:s=>s==='[data-reference]'?[select]:[]};
  ctx.bindPolicyReferences(form,editable);
  return {target,chips,select,add(value){select.value=value;select.onchange();}};
}
const f=fixture();f.add('tenant-blue');assert.equal(f.target.value,'tenant-blue','Specific selection replaces Any');
f.add('tenant-green');f.add('tenant-blue');assert.equal(f.target.value,'tenant-blue\ntenant-green','Multiple unique zones survive form serialization');
assert(f.select.options.find(o=>o.value==='tenant-blue').disabled);
f.chips.children[0].children[1].onclick();assert.equal(f.target.value,'tenant-green','Remove only the chosen item');
f.add('any');assert.equal(f.target.value,'any','Any replaces all specific selections');
f.add('application-default');assert.equal(f.target.value,'application-default');f.add('tenant-blue');assert.equal(f.target.value,'tenant-blue');
const readonly=fixture(false);readonly.add('tenant-blue');assert.equal(readonly.target.value,'any');assert(readonly.chips.children[0].children[1].disabled);
console.log('Dynamic inventories, escaped names, Any exclusivity, multi-selection serialization, removal and read-only controls passed');
assert.match(ctx.natModeNotice('none','dynamic-ip','round-robin',null),/unverified/);
assert.match(ctx.natModeNotice('none','dynamic-ip','round-robin',{destination_distribution:{'round-robin':{supported:true}}}),/is available/);
assert.match(ctx.natModeNotice('none','dynamic-ip','least-sessions',{destination_distribution:{'least-sessions':{supported:false,reason:'Allocator missing'}}}),/Allocator missing/);
assert.match(ctx.natModeNotice('persistent-dynamic-ip-and-port','none','',{}),/not supported/);
assert.match(ctx.policyPlanAction('security',{type:'allow',logging:{start:false,end:true},profiles:{mode:'none',individual:{}}}),/session end/);
assert.equal(ctx.policyPlanAction('security',{type:'deny'}),'Deny');
