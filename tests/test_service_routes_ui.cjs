// The Service Route Configuration card renders the candidate routes and the
// dataplane's view with text nodes only, and the editor writes exactly what
// the API accepts.
const assert = require('assert').strict, fs = require('fs'), vm = require('vm');
const byId = new Map();
function element(tag) {
  const el = {tag, children: [], attrs: {}, textContent: '', className: '', value: '', disabled: false, checked: false, selected: false, style: {},
    classList: {add() {}, remove() {}, toggle() {}},
    appendChild(c) { el.children.push(c); return c; },
    replaceChildren() { el.children = []; },
    remove() { el.removed = true; },
    setAttribute(k, v) { el.attrs[k] = v; },
    get innerHTML() { return ''; },
    set innerHTML(v) { el.html = v; }};
  Object.defineProperty(el, 'id', {get() { return el._id; }, set(v) { el._id = v; byId.set(v, el); }});
  Object.defineProperty(el, 'parentNode', {get() { return el._parent; }, set(v) { el._parent = v; }});
  return el;
}
function text(el) { return (el.textContent || '') + el.children.map(text).join(' '); }
function find(el, pred, out = []) { if (pred(el)) out.push(el); el.children.forEach(c => find(c, pred, out)); return out; }
const calls = [];
const same = (a, b) => assert.equal(JSON.stringify(a), JSON.stringify(b));
const listing = {revision: 'c'.repeat(64), can_edit: true,
  services: [{service: 'dns', label: 'DNS', ports: ['udp/53', 'tcp/53'], interface: 'ethernet1/5', address: '203.0.113.10', device: 'p5', problems: []},
             {service: 'updates', label: 'FFN updates (HTTPS)', ports: ['tcp/443'], interface: '', address: '', device: null, problems: []},
             {service: 'ntp', label: 'NTP', ports: ['udp/123'], interface: 'ethernet1/9', address: '', device: null, problems: ['service route ntp: ethernet1/9 is not a layer3 dataplane interface in the configuration']}],
  interface_choices: [{name: 'ethernet1/5', addresses: ['203.0.113.10', '203.0.113.11']}, {name: 'ae1.69', addresses: ['192.0.2.1']}]};
const status = {available: true, revision: 2,
  services: [{service: 'dns', state: 'routed', detail: 'via p5 as 203.0.113.10'}, {service: 'updates', state: 'management', detail: 'leaves through the management interface'},
             {service: 'ntp', state: 'pending', detail: 'not yet applied on the dataplane'}]};
const modalBody = element('div'); modalBody.id = 'info-modal-body';
const modalTitle = element('h3'); modalTitle.id = 'info-modal-title';
const modal = element('div'); modal.id = 'modal-info';
const context = vm.createContext({console, window: {}, Date, Number, JSON, String, Array, Object, encodeURIComponent,
  document: {getElementById: id => byId.get(id), createElement: element, createTextNode: t => ({tag: '#text', textContent: t, children: []})},
  consoleRequest: async (path, options) => { calls.push({path, options}); if (path === '/api/system/service-routes' && !options) return listing;
    if (path === '/api/system/service-routes/status') return status; return {status: 'updated'}; },
  closeModal() { calls.push({closed: true}); }, refreshCommitIndicator() { calls.push({refreshed: true}); }, confirm: () => true, alert: m => calls.push({alert: m})});
vm.runInContext(fs.readFileSync(__dirname + '/../static/service-routes.js', 'utf8'), context);
const routes = context.window.ffnServiceRoutes;
(async () => {
  const panel = element('div');
  await routes.render(panel);
  const rendered = text(panel);
  assert(rendered.includes('Service Route Configuration'), 'card title');
  assert(rendered.includes('ethernet1/5') && rendered.includes('203.0.113.10') && rendered.includes('via p5 as 203.0.113.10'), 'routed service rendered with the dataplane view');
  assert(rendered.includes('Management interface') && rendered.includes('udp/123'), 'default and ports rendered');
  assert(rendered.includes('is not a layer3 dataplane interface'), 'problem shown');
  assert(!find(panel, e => e.html && e.html.includes('<')).length, 'no HTML injection path');
  assert(find(panel, e => e.className && e.className.includes('badge-up')).length === 1, 'one routed badge');
  routes.edit('dns');
  assert.equal(byId.get('sr-interface').value, 'ethernet1/5');
  assert.equal(byId.get('sr-address').value, '203.0.113.10');
  same(routes.payload('dns'), {revision: listing.revision, service: 'dns', interface: 'ethernet1/5', address: '203.0.113.10'});
  calls.length = 0;
  await routes.save('dns');
  assert.equal(calls[0].path, '/api/system/service-routes');
  assert.equal(calls[0].options.method, 'PUT');
  assert.equal(JSON.parse(calls[0].options.body).service, 'dns');
  assert(calls.some(c => c.closed) && calls.some(c => c.refreshed), 'modal closed and commit indicator refreshed');
  routes.edit('updates');
  assert.equal(byId.get('sr-interface').value, '', 'management default selected');
  assert.equal(byId.get('sr-address').disabled, true, 'no address without an interface');
  console.log('service routes ui ok');
})().catch(e => { console.error(e); process.exit(1); });
