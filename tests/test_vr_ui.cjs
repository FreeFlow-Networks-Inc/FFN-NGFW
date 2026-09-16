const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const elements=new Map();
function element(id){if(!elements.has(id))elements.set(id,{children:[],disabled:false,value:'',textContent:'',innerHTML:'',style:{},classList:{add(){},remove(){},toggle(){}},addEventListener(){},replaceChildren(){this.children=[];},appendChild(o){this.children.push(o);},setAttribute(){},removeAttribute(){}});return elements.get(id);}
const html=fs.readFileSync(__dirname+'/../static/index.html','utf8');
const script=[...html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1]).join('\n');
const calls=[];let fail=false;
const rows=[{name:'ethernet1/1',addresses:['192.0.2.2/24'],virtual_router:'default'},
 {name:'ethernet1/2',addresses:[],virtual_router:'tenant'}, {name:'ethernet1/1.100',addresses:[],virtual_router:'default'}];
const context=vm.createContext({console,window:{},document:{getElementById:element,createElement:()=>({}),querySelectorAll:()=>[],addEventListener(){}},localStorage:{getItem(){return '';},removeItem(){}},setInterval(){},clearInterval(){},setTimeout(){},alert(){},confirm(){return true;}});
vm.runInContext(script,context);vm.runInContext(fs.readFileSync(__dirname+'/../static/vr-interfaces.js','utf8'),context);
context.consoleRequest=async(path,options)=>{calls.push({path,options});if(fail)throw Error('inventory unavailable');return {interfaces:rows,status:'updated'};};
(async()=>{
 await context.vrLoadInterfaceChoices('route-iface','default',['ethernet1/1']);
 const options=element('route-iface').children;
 assert(options.some(o=>o.value==='ethernet1/1'&&o.selected));
 assert(options.some(o=>o.value==='ethernet1/2'&&o.disabled));
 assert(options.some(o=>o.value==='ethernet1/1.100'));
 await context.vrLoadInterfaceChoices('vr-ifaces','default',[],true);
 assert(element('vr-ifaces').disabled);assert.equal(element('vr-ifaces').children.filter(o=>o.selected).length,2);
 await context.vrLoadInterfaceChoices('route-iface','default',['missing0']);
 assert(element('route-iface').children.some(o=>o.value==='missing0'&&o.selected));
 const route={id:7,dest_cidr:'0.0.0.0/0',next_hop:'192.0.2.1',dev:'ethernet1/1',metric:0};
 await context.openVRouteModal('default',route);assert.equal(element('route-id').value,7);assert.equal(element('route-metric').value,0);
 context.refreshVrRouteViews=async()=>{};element('route-iface').value='ethernet1/1';element('route-metric').value='0';
 await context.saveVRoute();const write=calls.find(c=>c.options);assert.equal(write.options.method,'PUT');assert(write.path.endsWith('/routes/7'));assert.equal(JSON.parse(write.options.body).metric,0);
 fail=true;await context.openVRouteModal('default',route);const count=calls.length;await context.saveVRoute();assert.equal(calls.length,count,'failed inventory must prevent saves');
 assert(!context.vrRouteRow({...route,dev:'<img onerror=evil()>'},'default').includes('<img'));
 console.log('Virtual Router selection, ownership, editing, errors and escaping passed');
})().catch(e=>{console.error(e);process.exit(1);});
