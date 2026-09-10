const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(require('node:path').join(__dirname, '../static/index.html'), 'utf8');
const script = html.slice(html.indexOf('function patchStateHTML('), html.indexOf('async function loadPatches('));
const context = vm.createContext({_escSP: value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))});
vm.runInContext(script, context);
const empty = context.patchStateHTML({});
assert.ok(empty.includes('Baseline — no patch recorded'));
assert.ok(empty.includes('Public key missing'));
assert.ok(!empty.includes('1.0.0'));
assert.ok(empty.includes('disabled onclick="patchAction(\'install\')"'));
const staged = context.patchStateHTML({can_manage:true,worker_available:true,public_key_present:true,
  staged:{version:'2.1',sha256:'a'.repeat(64),files:[{path:'app.py',before:'a',after:'b'},{path:'old.py',before:'a',after:null}]},
  history:[{action:'install',actor:'<script>',status:'failed',message:'<unsafe>'}]});
assert.ok(staged.includes('Review 2 file changes'));
assert.ok(staged.includes('Delete'));
assert.ok(staged.includes('&lt;script&gt;') && !staged.includes('<script>'));
assert.ok(!staged.includes('disabled onclick="patchAction(\'install\')"'));
const running = context.patchStateHTML({can_manage:true,worker_available:true,job:{status:'running'},staged:{sha256:'a'.repeat(64)},recovery_required:true});
assert.ok(running.includes('disabled onclick="patchAction(\'install\')"'));
assert.ok(running.includes('Recover its journal'));
console.log('Patch UI: baseline, staging, busy/recovery controls and escaping passed');
