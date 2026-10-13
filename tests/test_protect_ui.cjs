// The FFN Protect pages render the candidate portals and gateways and the
// dataplane's view with text nodes only, and the editors write exactly what
// the API accepts.
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
const listing = {revision: 'b'.repeat(64), can_edit: true,
  portals: [{name: 'main', vsys: 'vsys1', interface: 'ethernet1/5', address: '152.193.185.10', certificate: 'gw', auth_profile: 'users', login_lifetime: 86400,
             connect_method: 'on-demand', gateways: [{name: 'vpn.example.com', priority: 1, description: 'Main'}], root_ca: ['root'], problems: []}],
  gateways: [{name: 'main', vsys: 'vsys1', interface: 'ethernet1/5', address: '152.193.185.10', certificate: 'gw', auth_profile: 'users', tunnel: 'tunnel.1',
              tunnel_address: '10.200.0.1/24', pools: ['10.200.0.10-10.200.0.250'], dns: ['10.1.0.3'], dns_suffix: ['corp.example'], access_routes: ['10.0.0.0/8'],
              exclude_routes: [], ipsec_crypto: 'aes-256-cbc', idle_timeout: 900, login_lifetime: 86400, mtu: 1400, hip: true, problems: ['certificate gw is not in the store']}],
  auth_profiles: [{name: 'users', method: 'local', server_profile: '', allow: ['alice']}],
  server_profiles: {ldap: [{name: 'corp', servers: [{address: 'ldap.corp', port: 636}], ssl: true, verify: true, bind_dn_template: '{user}@corp', has_ca: false, timeout: 5}], radius: []},
  users: [{name: 'alice'}], certificates: [{name: 'gw', subject: 'CN=vpn.example.com', not_after: 'Jan 1 2029', has_key: true, has_chain: false}],
  tunnel_units: {'tunnel.1': '10.200.0.1/24'},
  interface_choices: [{name: 'ethernet1/5', addresses: ['152.193.185.10/32'], dhcp_client: false}, {name: 'ethernet1/1', addresses: [], dhcp_client: true}]};
const status = {available: true, revision: 4, daemon_time: 1000,
  gateways: [{name: 'main', state: 'up', detail: '', sessions: 1, pool_size: 241, pool_used: 1}],
  portals: [{name: 'main', state: 'serving'}],
  sessions: [{id: 1, user: 'alice', gateway: 'main', client_ip: '10.200.0.10', source: '198.51.100.7', peer: '198.51.100.7:4501', mode: 'esp', created: 900, last_seen: 950,
              rx_packets: 10, tx_packets: 12, hostname: '<img onerror=evil()>'}]};
const modalBody = element('div'); modalBody.id = 'info-modal-body';
const modalTitle = element('h3'); modalTitle.id = 'info-modal-title';
const modal = element('div'); modal.id = 'modal-info';
const context = vm.createContext({console, window: {}, Date, Number, JSON, String, Array, Object, encodeURIComponent,
  document: {getElementById: id => byId.get(id), createElement: element, createTextNode: t => ({tag: '#text', textContent: t, children: []})},
  consoleRequest: async (path, options) => { calls.push({path, options}); if (path === '/api/config/protect' && !options) return listing;
    if (path === '/api/protect/status') return status; return {status: 'updated'}; },
  closeModal() { calls.push({closed: true}); }, refreshCommitIndicator() { calls.push({refreshed: true}); }, confirm: () => true, alert: m => calls.push({alert: m})});
vm.runInContext(fs.readFileSync(__dirname + '/../static/protect.js', 'utf8'), context);
const protect = context.window.ffnProtect;
(async () => {
  const page = element('div');
  await protect.page(page, 'gateways');
  let rendered = text(page);
  assert(rendered.includes('tunnel.1 10.200.0.1/24') && rendered.includes('10.200.0.10-10.200.0.250') && rendered.includes('aes-256-cbc'), 'gateway row rendered');
  assert(rendered.includes('certificate gw is not in the store'), 'problems shown');
  assert(rendered.includes('1 / 241 addresses'), 'sessions and pool size shown');
  assert(rendered.includes('<img onerror=evil()>'), 'hostname is a text node');
  assert(!find(page, e => e.html && e.html.includes('<img')).length, 'no HTML injection path');
  assert(find(page, e => e.className && e.className.includes('badge-up')).length >= 2, 'up and esp badges');
  assert(rendered.includes('Active sessions (1)') && rendered.includes('198.51.100.7:4501'), 'session table');
  protect.editGateway('main');
  assert.equal(byId.get('fp-pools').value, '10.200.0.10-10.200.0.250');
  assert.equal(byId.get('fp-tunnel-address').value, '10.200.0.1/24');
  assert.equal(byId.get('fp-hip').checked, true);
  same(protect.gatewayPayload(), {revision: listing.revision, name: 'main', interface: 'ethernet1/5', address: '152.193.185.10', certificate: 'gw', auth_profile: 'users',
    tunnel: 'tunnel.1', tunnel_address: '10.200.0.1/24', pools: ['10.200.0.10-10.200.0.250'], dns: ['10.1.0.3'], dns_suffix: ['corp.example'],
    access_routes: ['10.0.0.0/8'], exclude_routes: [], ipsec_crypto: 'aes-256-cbc', idle_timeout: 900, login_lifetime: 86400, mtu: 1400, hip: true});
  calls.length = 0;
  await protect.save('gateway', protect.gatewayPayload());
  assert.equal(calls[0].path, '/api/config/protect/gateway');
  assert.equal(calls[0].options.method, 'PUT');
  assert.equal(JSON.parse(calls[0].options.body).tunnel, 'tunnel.1');
  assert(calls.some(c => c.closed) && calls.some(c => c.refreshed), 'modal closed and commit indicator refreshed');
  protect.editGateway(null);
  assert.equal(byId.get('fp-tunnel').value, 'tunnel.2', 'next free tunnel unit offered');

  await protect.page(page, 'portals');
  rendered = text(page);
  assert(rendered.includes('vpn.example.com (priority 1)') && rendered.includes('on-demand') && rendered.includes('serving'), 'portal row rendered');
  assert(rendered.includes('{user}@corp') && rendered.includes('CN=vpn.example.com') && rendered.includes('alice'), 'authentication and certificates rendered');
  protect.editPortal('main');
  assert.equal(byId.get('fp-gateways').value, 'vpn.example.com 1 Main');
  same(protect.portalPayload(), {revision: listing.revision, name: 'main', interface: 'ethernet1/5', address: '152.193.185.10', certificate: 'gw', auth_profile: 'users',
    connect_method: 'on-demand', login_lifetime: 86400, gateways: [{name: 'vpn.example.com', priority: 1, description: 'Main'}], root_ca: ['root']});
  calls.length = 0;
  await protect.remove('server-profile/ldap', 'corp');
  assert.equal(calls[0].path, '/api/config/protect/server-profile/ldap/corp?revision=' + listing.revision);
  assert.equal(calls[0].options.method, 'DELETE');
  calls.length = 0;
  protect.editUser(null);
  byId.get('fp-name').value = 'bob'; byId.get('fp-password').value = 'correct horse';
  await protect.save('user', {revision: listing.revision, name: 'bob', password: 'correct horse'});
  assert.equal(calls[0].path, '/api/config/protect/user');
  console.log('protect ui ok');
})().catch(e => { console.error(e); process.exit(1); });
