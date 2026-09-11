const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html=fs.readFileSync(__dirname+'/../static/index.html','utf8');
const helpers=html.slice(html.indexOf('const extensionPages ='),html.indexOf('async function loadPlatform()'));
async function check(enabled) {
  const requests=[],scripts=[],menus=[];
  const context={window:{}, token:'test-token', TAB_MENUS:{dashboard:menus,device:[]}, console,
    doLogout(){}, document:{createElement(){return {};},head:{appendChild(s){scripts.push(s.src);s.onload();}}},
    fetch:async path=>{requests.push(path);return {ok:true,status:200,json:async()=>({extensions:enabled ?
      [{id:'fixture',script:'/static/extensions/fixture/ui.js'}] : []})};}};
  vm.createContext(context);vm.runInContext(helpers,context);
  await vm.runInContext('loadExtensions()',context);
  await vm.runInContext('loadExtensions()',context);
  assert.deepEqual(requests,['/api/system/extensions']);
  assert.deepEqual(scripts,enabled ? ['/static/extensions/fixture/ui.js'] : []);
  context.window.ffnExtensions.register('unselected','Unexpected',()=>{});
  assert.equal(menus.length,0);
  if(enabled) {context.window.ffnExtensions.register('fixture','Selected',()=>{});assert.equal(menus.length,1);
    context.window.ffnExtensions.register('fixture','Duplicate',()=>{});assert.equal(menus.length,1);
    vm.runInContext("extensionDeclarations.set('fixture', [{id:'ports',tab:'device',label:'Hardware ports'}])",context);
    context.window.ffnExtensions.registerPage('fixture','ports',()=>{});
    context.window.ffnExtensions.registerPage('fixture','ports',()=>{});
    context.window.ffnExtensions.registerPage('fixture','unadvertised',()=>{});
    context.window.ffnExtensions.registerPage('unselected','ports',()=>{});
    assert.equal(context.TAB_MENUS.device.length,1);
    assert.equal(context.TAB_MENUS.device[0].label,'Hardware ports');
  }
}
(async()=>{await check(false);await check(true);console.log('Core extension UI isolation tests passed');})().catch(e=>{console.error(e);process.exit(1);});
