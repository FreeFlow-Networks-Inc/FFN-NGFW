// The DHCP page renders the candidate servers and the dataplane's view with
// text nodes only, and the editor writes exactly what the API accepts.
const assert = require('assert').strict, fs = require('fs'), vm = require('vm');
const byId = new Map();
function element(tag) {
  const el = {tag, children: [], attrs: {}, textContent: '', className: '', value: '', disabled: false, checked: false, selected: false, style: {},
    classList: {add() {}, remove() {}, toggle() {}},
    appendChild(c) { el.children.push(c); return c; },
    replaceChildren() { el.children = []; },
    setAttribute(k, v) { el.attrs[k] = v; },
    get innerHTML() { return ''; },
    set innerHTML(v) { el.html = v; }};
  Object.defineProperty(el, 'id', {get() { return el._id; }, set(v) { el._id = v; byId.set(v, el); }});
  return el;
}
function text(el) { return (el.textContent || '') + el.children.map(text).join(' '); }
function find(el, pred, out = []) { if (pred(el)) out.push(el); el.children.forEach(c => find(c, pred, out)); return out; }
const calls = [];
const same = (a, b) => assert.equal(JSON.stringify(a), JSON.stringify(b));
let listing = {revision: 'a'.repeat(64), can_edit: true,
  entries: [{interface: 'ae1.69', mode: 'enabled', probe_ip: false, lease_minutes: 1440, pools: ['10.1.0.100-10.1.0.199'], address: '10.1.0.2/22', device: 'ae1.69', problems: [],
             reserved: [{ip: '10.1.0.50', mac: '02:11:22:33:44:99', description: 'printer'}], options: {gateway: '', subnet_mask: '', dns: ['1.1.1.1'], ntp: [], wins: [], dns_suffix: 'lan'}}],
  interface_choices: [{name: 'ae1.69', addresses: ['10.1.0.2/22'], dhcp_client: false, has_server: true},
                      {name: 'ethernet1/5', addresses: ['192.0.2.1/24'], dhcp_client: false, has_server: false},
                      {name: 'ethernet1/1', addresses: [], dhcp_client: true, has_server: false}]};
const status = {available: true, revision: 3, daemon_time: 1000,
  servers: [{interface: 'ae1.69', device: 'ae1.69', state: 'serving', detail: '', bound: 1, offered: 0}],
  leases: [{interface: 'ae1.69', ip: '10.1.0.100', mac: '02:00:00:00:00:01', hostname: '<img onerror=evil()>', state: 'bound', since: 900, expires: 4500}]};
const modalBody = element('div'); modalBody.id = 'info-modal-body';
const modalTitle = element('h3'); modalTitle.id = 'info-modal-title';
const modal = element('div'); modal.id = 'modal-info';
const context = vm.createContext({console, window: {}, Date, Number, JSON, String, Array, Object, encodeURIComponent,
  document: {getElementById: id => byId.get(id), createElement: element, createTextNode: t => ({tag: '#text', textContent: t, children: []})},
  consoleRequest: async (path, options) => { calls.push({path, options}); if (path === '/api/config/dhcp' && !options) return listing;
    if (path === '/api/dhcp/status') return status; return {status: 'updated'}; },
  closeModal() { calls.push({closed: true}); }, refreshCommitIndicator() { calls.push({refreshed: true}); }, confirm: () => true, alert: m => calls.push({alert: m})});
vm.runInContext(fs.readFileSync(__dirname + '/../static/dhcp.js', 'utf8'), context);
const dhcp = context.window.ffnDhcp;
(async () => {
  const page = element('div');
  await dhcp.page(page);
  const rendered = text(page);
  assert(rendered.includes('ae1.69') && rendered.includes('10.1.0.100-10.1.0.199') && rendered.includes('1 d'), 'server row rendered');
  assert(rendered.includes('<img onerror=evil()>'), 'hostname is a text node');
  assert(!find(page, e => e.html && e.html.includes('<img')).length, 'no HTML injection path');
  assert(find(page, e => e.className && e.className.includes('badge-up')).length >= 2, 'serving and bound badges');
  assert(rendered.includes('revision 3'));
  dhcp.edit('ae1.69');
  assert.equal(byId.get('dhcp-pools').value, '10.1.0.100-10.1.0.199');
  assert.equal(byId.get('dhcp-reserved').value, '02:11:22:33:44:99 10.1.0.50 printer');
  assert.equal(byId.get('dhcp-dns1').value, '1.1.1.1');
  assert(byId.get('dhcp-interface').disabled, 'existing server keeps its interface');
  byId.get('dhcp-pools').value = '10.1.0.100-10.1.0.150\n10.1.1.10';
  byId.get('dhcp-lease').value = '';
  byId.get('dhcp-reserved').value = 'AA:BB:CC:DD:EE:FF 10.1.0.51 scanner room\n';
  byId.get('dhcp-probe').checked = true;
  byId.get('dhcp-interface').value = 'ae1.69'; byId.get('dhcp-mode').value = 'enabled';
  const body = dhcp.payload();
  same(body.pools, ['10.1.0.100-10.1.0.150', '10.1.1.10']);
  assert.equal(body.lease_minutes, null);
  same(body.reserved, [{mac: 'aa:bb:cc:dd:ee:ff', ip: '10.1.0.51', description: 'scanner room'}]);
  assert.equal(body.probe_ip, true); assert.equal(body.revision, 'a'.repeat(64));
  same(body.options.dns, ['1.1.1.1']);
  await dhcp.save();
  const put = calls.find(c => c.options && c.options.method === 'PUT');
  assert.equal(put.path, '/api/config/dhcp'); same(JSON.parse(put.options.body).pools, body.pools);
  assert(calls.some(c => c.closed) && calls.some(c => c.refreshed), 'modal closed and commit indicator refreshed');
  await dhcp.remove('ae1.69');
  const del = calls.find(c => c.options && c.options.method === 'DELETE');
  assert.equal(del.path, '/api/config/dhcp/ae1.69?revision=' + 'a'.repeat(64));
  listing = Object.assign({}, listing, {can_edit: false});
  const readonly = element('div');
  await dhcp.page(readonly);
  assert(find(readonly, e => e.tag === 'button' && e.textContent === 'Edit').every(b => b.disabled), 'read-only listing disables editing');
  assert.equal(dhcp.explain({detail: [{loc: ['body', 'pools', 0], msg: 'bad'}]}), 'pools.0: bad');
  console.log('DHCP page rendering, escaping, editor payload, save and delete passed');
})().catch(e => { console.error(e); process.exit(1); });
