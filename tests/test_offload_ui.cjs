const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
const script = html.slice(html.indexOf('function _dpDot('), html.indexOf('async function loadDataplaneStatus('));
const ctx = vm.createContext({_escSP: value => String(value ?? '').replaceAll('<', '&lt;').replaceAll('>', '&gt;')});
vm.runInContext(script, ctx);
const base = {present:true, cp:{reachable:true}, dp:{present:false, inventory_status:'unavailable'}};
assert.match(ctx._offloadHTML(base), /inventory unavailable/);
assert.doesNotMatch(ctx._offloadHTML(base), /not found/);
const out = ctx._offloadHTML({...base, dp:{present:true, agent_acknowledged:true,
  ready:true, boot_id:'<boot>', cpu_count:40, forwarding_verified:false}});
assert.match(out, /Agent ready/);
assert.match(out, /40 cores/);
assert.match(out, /&lt;boot&gt;/);
assert.match(out, /Forwarding not verified/);
assert.doesNotMatch(out, /undefined|not found/);
console.log('DP acknowledgement, unknown inventory, forwarding separation and escaping passed');
