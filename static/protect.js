/* SPDX-License-Identifier: GPL-2.0-or-later */
/* FFN Protect: portals, gateways, authentication and certificates for the
   GlobalProtect-compatible remote-access service. The editors write the
   candidate configuration (/api/config/protect/...); a commit carries it to
   the dataplane through the platform provider. The status tables show the
   dataplane daemon's own view (/api/protect/status). Text nodes only. */
window.ffnProtect = {
  listing: null,
  status: null,
  kind: 'portals',
  STATE: {up: 'badge-up', serving: 'badge-up', pending: 'badge-info', starting: 'badge-info', unavailable: 'badge-log', error: 'badge-error'},
  node(tag, text, owner, cls) {
    const n = document.createElement(tag);
    if (text !== undefined && text !== null) n.textContent = text;
    if (cls) n.className = cls;
    if (owner) owner.appendChild(n);
    return n;
  },
  badge(state, owner) {
    return this.node('span', state || 'unknown', owner, 'badge ' + (this.STATE[state] || 'badge-log'));
  },
  request(path, options) {
    return window.ffnExtensions && window.ffnExtensions.request ? window.ffnExtensions.request(path, options) : consoleRequest(path, options);
  },
  when(ts) {
    if (!ts) return '';
    return new Date(ts * 1000).toLocaleString();
  },
  seconds(value) {
    if (!value) return '';
    if (value % 86400 === 0) return (value / 86400) + ' d';
    if (value % 3600 === 0) return (value / 3600) + ' h';
    if (value % 60 === 0) return (value / 60) + ' min';
    return value + ' s';
  },
  async load() {
    this.listing = await this.request('/api/config/protect');
    try { this.status = await this.request('/api/protect/status'); }
    catch (e) { this.status = {available: false, reason: e.message, gateways: [], portals: [], sessions: []}; }
  },
  async page(parent, kind) {
    if (!parent) return;
    this.parent = parent;
    this.kind = kind || this.kind;
    parent.replaceChildren();
    const header = this.node('div', undefined, parent, 'page-header');
    this.node('h2', this.kind === 'gateways' ? 'FFN Protect Gateways' : 'FFN Protect Portals', header);
    const actions = this.node('div', undefined, header, 'actions');
    const add = this.node('button', this.kind === 'gateways' ? '+ Add Gateway' : '+ Add Portal', actions, 'btn btn-primary btn-sm');
    add.onclick = () => (this.kind === 'gateways' ? this.editGateway(null) : this.editPortal(null));
    const refresh = this.node('button', 'Refresh', actions, 'btn btn-sm');
    refresh.onclick = () => this.page(parent, this.kind);
    this.node('p', this.kind === 'gateways'
      ? 'A gateway terminates client tunnels on a WAN address of the dataplane: ESP in UDP 4501 with an SSL fallback, one tunnel interface per gateway, in the zone you give that interface. Permit the FFN Protect service in the WAN interface\'s management profile.'
      : 'A portal hands GlobalProtect clients their gateway list and settings from a WAN address of the dataplane; a portal and a gateway may share one address and certificate.', parent, 'text-dim');
    const message = this.node('div', 'Loading…', parent, 'text-dim');
    message.setAttribute('role', 'status');
    try { await this.load(); }
    catch (e) { message.textContent = 'FFN Protect configuration unavailable: ' + e.message; return; }
    message.textContent = '';
    if (this.listing && this.listing.can_edit === false) add.disabled = true;
    if (this.kind === 'gateways') {
      this.renderGateways(parent);
      this.renderSessions(parent);
    } else {
      this.renderPortals(parent);
      this.renderAuthentication(parent);
      this.renderCertificates(parent);
    }
  },
  live(kind, name) {
    const rows = (this.status && this.status[kind]) || [];
    return rows.find(r => r.name === name) || null;
  },
  table(parent, headings) {
    const card = this.node('div', undefined, parent, 'card');
    const wrap = this.node('div', undefined, card, 'table-wrap');
    const table = this.node('table', undefined, wrap);
    const head = this.node('tr', undefined, this.node('thead', undefined, table));
    for (const h of headings) this.node('th', h, head);
    return {card, body: this.node('tbody', undefined, table)};
  },
  rowActions(cell, onEdit, onDelete) {
    const edit = this.node('button', 'Edit', cell, 'btn btn-sm');
    edit.onclick = onEdit;
    const del = this.node('button', 'Delete', cell, 'btn btn-sm btn-danger');
    del.onclick = onDelete;
    if (this.listing.can_edit === false) edit.disabled = del.disabled = true;
  },
  problems(cell, row) {
    for (const p of row.problems || []) this.node('div', p, cell, 'text-warning');
  },
  renderPortals(parent) {
    const {body} = this.table(parent, ['Name', 'Interface / address', 'Certificate', 'Authentication', 'Gateways', 'Connect', 'Dataplane', '']);
    const rows = (this.listing && this.listing.portals) || [];
    if (!rows.length) this.node('td', 'No portals in the candidate configuration.', this.node('tr', undefined, body), 'text-dim').colSpan = 8;
    for (const row of rows) {
      const tr = this.node('tr', undefined, body);
      const name = this.node('td', undefined, tr); this.node('strong', row.name, name); this.problems(name, row);
      this.node('td', row.interface + ' ' + (row.address || ''), tr);
      this.node('td', row.certificate, tr);
      this.node('td', row.auth_profile, tr);
      const gws = this.node('td', undefined, tr);
      for (const g of row.gateways) this.node('div', g.name + ' (priority ' + g.priority + ')', gws);
      this.node('td', row.connect_method, tr);
      const live = this.live('portals', row.name);
      const state = this.node('td', undefined, tr);
      this.badge(live ? live.state : 'pending', state);
      this.rowActions(this.node('td', undefined, tr, 'actions'), () => this.editPortal(row.name), () => this.remove('portal', row.name));
    }
  },
  renderGateways(parent) {
    const {body} = this.table(parent, ['Name', 'Interface / address', 'Tunnel', 'Pools', 'Crypto', 'Authentication', 'Dataplane', 'Sessions', '']);
    const rows = (this.listing && this.listing.gateways) || [];
    if (!rows.length) this.node('td', 'No gateways in the candidate configuration.', this.node('tr', undefined, body), 'text-dim').colSpan = 9;
    for (const row of rows) {
      const tr = this.node('tr', undefined, body);
      const name = this.node('td', undefined, tr); this.node('strong', row.name, name); this.problems(name, row);
      this.node('td', row.interface + ' ' + (row.address || ''), tr);
      this.node('td', row.tunnel + (row.tunnel_address ? ' ' + row.tunnel_address : ' (no address)'), tr);
      const pools = this.node('td', undefined, tr);
      for (const p of row.pools) this.node('div', p, pools);
      this.node('td', row.ipsec_crypto === 'none' ? 'SSL only' : row.ipsec_crypto, tr);
      this.node('td', row.auth_profile, tr);
      const live = this.live('gateways', row.name);
      const state = this.node('td', undefined, tr);
      this.badge(live ? live.state : 'pending', state);
      if (live && live.detail) this.node('div', live.detail, state, 'text-dim');
      this.node('td', live && live.sessions !== undefined ? live.sessions + (live.pool_size ? ' / ' + live.pool_size + ' addresses' : '') : '', tr);
      this.rowActions(this.node('td', undefined, tr, 'actions'), () => this.editGateway(row.name), () => this.remove('gateway', row.name));
    }
  },
  renderSessions(parent) {
    const title = this.node('h3', 'Active sessions', parent);
    const sessions = (this.status && this.status.sessions) || [];
    if (!this.status || !this.status.available) {
      this.node('p', 'Dataplane status unavailable: ' + ((this.status && this.status.reason) || ''), parent, 'text-dim');
      return;
    }
    title.textContent = 'Active sessions (' + sessions.length + ')';
    const {body} = this.table(parent, ['User', 'Gateway', 'Client address', 'From', 'Mode', 'Since', 'Last seen', 'Packets in / out', 'Host']);
    if (!sessions.length) this.node('td', 'No client connected.', this.node('tr', undefined, body), 'text-dim').colSpan = 9;
    for (const s of sessions) {
      const tr = this.node('tr', undefined, body);
      this.node('td', s.user, tr);
      this.node('td', s.gateway, tr);
      this.node('td', s.client_ip, tr);
      this.node('td', s.peer || s.source, tr);
      const mode = this.node('td', undefined, tr);
      this.node('span', s.mode, mode, 'badge ' + (s.mode === 'esp' ? 'badge-up' : s.mode === 'ssl' ? 'badge-info' : 'badge-log'));
      this.node('td', this.when(s.created), tr);
      this.node('td', this.when(s.last_seen), tr);
      this.node('td', (s.rx_packets || 0) + ' / ' + (s.tx_packets || 0), tr);
      this.node('td', s.hostname || '', tr);
    }
    if (this.status.daemon_time) this.node('p', 'Dataplane daemon time ' + this.when(this.status.daemon_time) + ', revision ' + this.status.revision, parent, 'text-dim');
  },
  renderAuthentication(parent) {
    this.node('h3', 'Authentication', parent);
    const profiles = this.table(parent, ['Profile', 'Method', 'Server profile', 'Allowed users', '']);
    const addProfile = this.node('button', '+ Add Authentication Profile', profiles.card, 'btn btn-sm');
    addProfile.onclick = () => this.editAuthProfile(null);
    for (const row of this.listing.auth_profiles || []) {
      const tr = this.node('tr', undefined, profiles.body);
      this.node('td', row.name, tr);
      this.node('td', row.method, tr);
      this.node('td', row.server_profile || '', tr);
      this.node('td', row.allow.length ? row.allow.join(', ') : 'all', tr);
      this.rowActions(this.node('td', undefined, tr, 'actions'), () => this.editAuthProfile(row.name), () => this.remove('auth-profile', row.name));
    }
    const servers = this.table(parent, ['Server profile', 'Kind', 'Servers', 'Settings', '']);
    const addServer = this.node('button', '+ Add LDAP / RADIUS Server Profile', servers.card, 'btn btn-sm');
    addServer.onclick = () => this.editServerProfile(null, null);
    const sp = this.listing.server_profiles || {ldap: [], radius: []};
    for (const kind of ['ldap', 'radius']) {
      for (const row of sp[kind] || []) {
        const tr = this.node('tr', undefined, servers.body);
        this.node('td', row.name, tr);
        this.node('td', kind.toUpperCase(), tr);
        this.node('td', row.servers.map(s => s.address + ':' + s.port).join(', '), tr);
        this.node('td', kind === 'ldap'
          ? (row.ssl ? 'TLS' : 'plain') + (row.verify ? ', verified' : ', unverified') + ', bind ' + row.bind_dn_template + (row.has_ca ? ', own CA' : '')
          : (row.has_secret ? 'shared secret set' : 'no shared secret') + ', timeout ' + row.timeout + ' s', tr);
        this.rowActions(this.node('td', undefined, tr, 'actions'), () => this.editServerProfile(kind, row.name), () => this.remove('server-profile/' + kind, row.name));
      }
    }
    const users = this.table(parent, ['Local user', '']);
    const addUser = this.node('button', '+ Add Local User', users.card, 'btn btn-sm');
    addUser.onclick = () => this.editUser(null);
    for (const row of this.listing.users || []) {
      const tr = this.node('tr', undefined, users.body);
      this.node('td', row.name, tr);
      this.rowActions(this.node('td', undefined, tr, 'actions'), () => this.editUser(row.name), () => this.remove('user', row.name));
    }
    if (this.listing.can_edit === false) addProfile.disabled = addServer.disabled = addUser.disabled = true;
  },
  renderCertificates(parent) {
    this.node('h3', 'Certificates', parent);
    const {card, body} = this.table(parent, ['Name', 'Subject', 'Expires', 'Private key', '']);
    const add = this.node('button', '+ Add Certificate', card, 'btn btn-sm');
    add.onclick = () => this.editCertificate();
    if (this.listing.can_edit === false) add.disabled = true;
    for (const row of this.listing.certificates || []) {
      const tr = this.node('tr', undefined, body);
      this.node('td', row.name, tr);
      this.node('td', row.subject || '', tr);
      this.node('td', row.not_after || '', tr);
      this.node('td', row.has_key ? 'present' : 'missing', tr);
      const del = this.node('button', 'Delete', this.node('td', undefined, tr, 'actions'), 'btn btn-sm btn-danger');
      del.onclick = () => this.remove('certificate', row.name);
      if (this.listing.can_edit === false) del.disabled = true;
    }
  },
  /* ---- editors ---- */
  modal(title) {
    const t = document.getElementById('info-modal-title');
    const body = document.getElementById('info-modal-body');
    if (!t || !body) return null;
    t.textContent = title;
    body.replaceChildren();
    const form = this.node('form', undefined, body);
    form.id = 'fp-form';
    return form;
  },
  finish(form, label, onSubmit) {
    form.onsubmit = (ev) => { ev.preventDefault(); onSubmit(); };
    const actions = this.node('div', undefined, form, 'form-actions');
    const save = this.node('button', label, actions, 'btn btn-primary');
    save.type = 'submit'; save.id = 'fp-save';
    const cancel = this.node('button', 'Cancel', actions, 'btn');
    cancel.type = 'button'; cancel.onclick = () => closeModal('modal-info');
    const msg = this.node('span', '', actions, 'text-dim'); msg.id = 'fp-msg';
    document.getElementById('modal-info').classList.add('show');
  },
  field(form, id, label, control, hint) {
    const group = this.node('div', undefined, form, 'form-group');
    const l = this.node('label', label, group);
    l.htmlFor = id;
    control.id = id;
    group.appendChild(control);
    if (hint) this.node('div', hint, group, 'text-dim');
    return control;
  },
  input(value, placeholder, type) {
    const n = document.createElement('input');
    n.type = type || 'text'; n.value = value === undefined || value === null ? '' : String(value); if (placeholder) n.placeholder = placeholder;
    return n;
  },
  area(value, placeholder, rows) {
    const n = document.createElement('textarea');
    n.value = value || ''; n.rows = rows || 3; if (placeholder) n.placeholder = placeholder;
    return n;
  },
  select(options, value) {
    const n = document.createElement('select');
    for (const o of options) {
      const opt = document.createElement('option');
      opt.value = typeof o === 'string' ? o : o.value;
      opt.textContent = typeof o === 'string' ? o : o.label;
      if (opt.value === value) opt.selected = true;
      n.appendChild(opt);
    }
    return n;
  },
  check(value) {
    const n = document.createElement('input');
    n.type = 'checkbox'; n.checked = !!value;
    return n;
  },
  lines(id) {
    return (document.getElementById(id).value || '').split('\n').map(s => s.trim()).filter(Boolean);
  },
  value(id) {
    return (document.getElementById(id).value || '').trim();
  },
  interfaceSelect(current) {
    const choices = (this.listing.interface_choices || []).filter(c => !c.dhcp_client && c.addresses.length);
    return this.select([{value: '', label: 'Choose an interface'}].concat(choices.map(c => ({value: c.name, label: c.name + ' (' + c.addresses.join(', ') + ')'}))), current);
  },
  names(kind) {
    return (this.listing[kind] || []).map(r => r.name);
  },
  editPortal(name) {
    const existing = name ? (this.listing.portals || []).find(r => r.name === name) : null;
    const row = existing || {name: '', interface: '', address: '', certificate: '', auth_profile: '', login_lifetime: 2592000, connect_method: 'user-logon', gateways: [], root_ca: []};
    const form = this.modal(existing ? 'Edit portal ' + name : 'Add portal');
    if (!form) return;
    const nameInput = this.field(form, 'fp-name', 'Name', this.input(row.name, 'main'));
    if (existing) nameInput.readOnly = true;
    this.field(form, 'fp-interface', 'Interface', this.interfaceSelect(row.interface));
    this.field(form, 'fp-address', 'Address', this.input(row.address, 'first IPv4 address of the interface'), 'One of the interface\'s static IPv4 addresses; empty takes the first.');
    this.field(form, 'fp-certificate', 'Certificate', this.select([''].concat(this.names('certificates')), row.certificate));
    this.field(form, 'fp-auth', 'Authentication profile', this.select([''].concat(this.names('auth_profiles')), row.auth_profile));
    this.field(form, 'fp-connect', 'Connect method', this.select(['user-logon', 'on-demand', 'pre-logon'], row.connect_method));
    this.field(form, 'fp-lifetime', 'Login lifetime (seconds)', this.input(row.login_lifetime, '2592000', 'number'));
    this.field(form, 'fp-gateways', 'Gateways', this.area(row.gateways.map(g => g.name + ' ' + g.priority + (g.description ? ' ' + g.description : '')).join('\n'), 'vpn.example.com 1 Main office', 4),
               'One per line: host-or-address priority(1-5) description. Clients connect to the lowest priority first.');
    this.field(form, 'fp-rootca', 'Root CA certificates for clients', this.area(row.root_ca.join('\n'), 'certificate names, one per line', 2),
               'Certificate store names the agent installs so it trusts the gateway certificate.');
    this.finish(form, existing ? 'Save to candidate' : 'Add to candidate', () => this.save('portal', this.portalPayload()));
  },
  portalPayload() {
    const gateways = this.lines('fp-gateways').map(line => {
      const parts = line.split(/\s+/);
      return {name: parts[0] || '', priority: Number(parts[1] || 1), description: parts.slice(2).join(' ')};
    });
    return {revision: this.listing.revision, name: this.value('fp-name'), interface: this.value('fp-interface'), address: this.value('fp-address'),
            certificate: this.value('fp-certificate'), auth_profile: this.value('fp-auth'), connect_method: this.value('fp-connect'),
            login_lifetime: Number(this.value('fp-lifetime') || 2592000), gateways, root_ca: this.lines('fp-rootca')};
  },
  editGateway(name) {
    const existing = name ? (this.listing.gateways || []).find(r => r.name === name) : null;
    const used = (this.listing.gateways || []).map(r => r.tunnel);
    let nextUnit = 1;
    while (used.includes('tunnel.' + nextUnit)) nextUnit++;
    const row = existing || {name: '', interface: '', address: '', certificate: '', auth_profile: '', tunnel: 'tunnel.' + nextUnit, tunnel_address: '',
                             pools: [], dns: [], dns_suffix: [], access_routes: [], exclude_routes: [], ipsec_crypto: 'aes-128-cbc',
                             idle_timeout: 3600, login_lifetime: 2592000, mtu: 1400, hip: false};
    const form = this.modal(existing ? 'Edit gateway ' + name : 'Add gateway');
    if (!form) return;
    const nameInput = this.field(form, 'fp-name', 'Name', this.input(row.name, 'main'));
    if (existing) nameInput.readOnly = true;
    this.field(form, 'fp-interface', 'Interface', this.interfaceSelect(row.interface));
    this.field(form, 'fp-address', 'Address', this.input(row.address, 'first IPv4 address of the interface'));
    this.field(form, 'fp-certificate', 'Certificate', this.select([''].concat(this.names('certificates')), row.certificate));
    this.field(form, 'fp-auth', 'Authentication profile', this.select([''].concat(this.names('auth_profiles')), row.auth_profile));
    this.field(form, 'fp-tunnel', 'Tunnel interface', this.input(row.tunnel, 'tunnel.1'), 'Created or updated with the gateway; put it in a zone on the Zones page.');
    this.field(form, 'fp-tunnel-address', 'Tunnel address', this.input(row.tunnel_address, '10.200.0.1/24'), 'The gateway\'s own address on the tunnel, with the prefix the client pool lives in.');
    this.field(form, 'fp-pools', 'Client address pools', this.area(row.pools.join('\n'), '10.200.0.10-10.200.0.250', 2), 'One range or address per line.');
    this.field(form, 'fp-dns', 'DNS servers', this.input(row.dns.join(', '), '10.1.0.3, 10.1.0.4'));
    this.field(form, 'fp-suffix', 'DNS suffixes', this.input(row.dns_suffix.join(', '), 'corp.example'));
    this.field(form, 'fp-routes', 'Access routes (split tunnel)', this.area(row.access_routes.join('\n'), '10.0.0.0/8', 3), 'Networks sent through the tunnel; empty sends everything.');
    this.field(form, 'fp-excludes', 'Excluded routes', this.area(row.exclude_routes.join('\n'), '', 2));
    this.field(form, 'fp-crypto', 'Tunnel encryption', this.select([{value: 'aes-128-cbc', label: 'ESP AES-128-CBC with SSL fallback'},
                                                                   {value: 'aes-256-cbc', label: 'ESP AES-256-CBC with SSL fallback'},
                                                                   {value: 'none', label: 'SSL tunnel only'}], row.ipsec_crypto));
    this.field(form, 'fp-idle', 'Idle timeout (seconds)', this.input(row.idle_timeout, '3600', 'number'));
    this.field(form, 'fp-lifetime', 'Login lifetime (seconds)', this.input(row.login_lifetime, '2592000', 'number'));
    this.field(form, 'fp-mtu', 'Tunnel MTU', this.input(row.mtu, '1400', 'number'));
    this.field(form, 'fp-hip', 'Collect host information reports', this.check(row.hip));
    this.finish(form, existing ? 'Save to candidate' : 'Add to candidate', () => this.save('gateway', this.gatewayPayload()));
  },
  gatewayPayload() {
    const list = id => this.value(id).split(',').map(s => s.trim()).filter(Boolean);
    return {revision: this.listing.revision, name: this.value('fp-name'), interface: this.value('fp-interface'), address: this.value('fp-address'),
            certificate: this.value('fp-certificate'), auth_profile: this.value('fp-auth'), tunnel: this.value('fp-tunnel'),
            tunnel_address: this.value('fp-tunnel-address'), pools: this.lines('fp-pools'), dns: list('fp-dns'), dns_suffix: list('fp-suffix'),
            access_routes: this.lines('fp-routes'), exclude_routes: this.lines('fp-excludes'), ipsec_crypto: this.value('fp-crypto'),
            idle_timeout: Number(this.value('fp-idle') || 3600), login_lifetime: Number(this.value('fp-lifetime') || 2592000),
            mtu: Number(this.value('fp-mtu') || 1400), hip: document.getElementById('fp-hip').checked};
  },
  editAuthProfile(name) {
    const existing = name ? (this.listing.auth_profiles || []).find(r => r.name === name) : null;
    const row = existing || {name: '', method: 'local', server_profile: '', allow: []};
    const form = this.modal(existing ? 'Edit authentication profile ' + name : 'Add authentication profile');
    if (!form) return;
    const nameInput = this.field(form, 'fp-name', 'Name', this.input(row.name, 'users'));
    if (existing) nameInput.readOnly = true;
    this.field(form, 'fp-method', 'Method', this.select([{value: 'local', label: 'Local user database'}, {value: 'ldap', label: 'LDAP bind'}, {value: 'radius', label: 'RADIUS'}], row.method));
    const sp = this.listing.server_profiles || {ldap: [], radius: []};
    const profiles = [''].concat((sp.ldap || []).map(r => r.name), (sp.radius || []).map(r => r.name));
    this.field(form, 'fp-server-profile', 'Server profile (LDAP / RADIUS)', this.select(profiles, row.server_profile));
    this.field(form, 'fp-allow', 'Allowed users', this.area(row.allow.join('\n'), 'everyone when empty', 3));
    this.finish(form, existing ? 'Save to candidate' : 'Add to candidate', () => this.save('auth-profile', {
      revision: this.listing.revision, name: this.value('fp-name'), method: this.value('fp-method'), server_profile: this.value('fp-server-profile'), allow: this.lines('fp-allow')}));
  },
  editServerProfile(kind, name) {
    const sp = this.listing.server_profiles || {ldap: [], radius: []};
    const existing = name ? (sp[kind] || []).find(r => r.name === name) : null;
    const row = existing || {name: '', servers: [], ssl: true, verify: true, bind_dn_template: '', timeout: 5};
    const form = this.modal(existing ? 'Edit ' + kind.toUpperCase() + ' server profile ' + name : 'Add server profile');
    if (!form) return;
    const kindSelect = this.field(form, 'fp-kind', 'Kind', this.select([{value: 'ldap', label: 'LDAP'}, {value: 'radius', label: 'RADIUS'}], kind || 'ldap'));
    if (existing) kindSelect.disabled = true;
    const nameInput = this.field(form, 'fp-name', 'Name', this.input(row.name, 'corp-ldap'));
    if (existing) nameInput.readOnly = true;
    this.field(form, 'fp-servers', 'Servers', this.area(row.servers.map(s => s.address + ' ' + s.port).join('\n'), 'ldap.corp.example 636', 2), 'One per line: host port.');
    this.field(form, 'fp-timeout', 'Timeout (seconds)', this.input(row.timeout, '5', 'number'));
    this.field(form, 'fp-bind', 'LDAP bind DN template', this.input(row.bind_dn_template, 'uid={user},ou=people,dc=example,dc=com'),
               '{user} is replaced by the login name; {user}@domain works for Active Directory. The client binds directly, so no service account is stored.');
    this.field(form, 'fp-ssl', 'LDAP over TLS', this.check(row.ssl));
    this.field(form, 'fp-verify', 'Verify the directory certificate', this.check(row.verify));
    this.field(form, 'fp-ca', 'Directory CA certificate (PEM)', this.area('', existing && existing.has_ca ? 'stored; paste to replace' : '-----BEGIN CERTIFICATE-----', 3));
    this.field(form, 'fp-secret', 'RADIUS shared secret', this.input('', existing && existing.has_secret ? 'stored; type to replace' : '', 'password'));
    this.finish(form, existing ? 'Save to candidate' : 'Add to candidate', () => this.save('server-profile', {
      revision: this.listing.revision, kind: this.value('fp-kind'), name: this.value('fp-name'),
      servers: this.lines('fp-servers').map(line => { const p = line.split(/\s+/); return {address: p[0], port: Number(p[1] || (this.value('fp-kind') === 'ldap' ? 636 : 1812))}; }),
      timeout: Number(this.value('fp-timeout') || 5), ssl: document.getElementById('fp-ssl').checked, verify: document.getElementById('fp-verify').checked,
      bind_dn_template: this.value('fp-bind'), ca: this.value('fp-ca'), secret: this.value('fp-secret')}));
  },
  editUser(name) {
    const form = this.modal(name ? 'Set password for ' + name : 'Add local user');
    if (!form) return;
    const nameInput = this.field(form, 'fp-name', 'User name', this.input(name || '', 'alice'));
    if (name) nameInput.readOnly = true;
    this.field(form, 'fp-password', 'Password', this.input('', 'at least 8 characters', 'password'), 'Stored as a PBKDF2-SHA256 hash; never shown again.');
    this.finish(form, name ? 'Save to candidate' : 'Add to candidate', () => this.save('user', {revision: this.listing.revision, name: this.value('fp-name'), password: this.value('fp-password')}));
  },
  editCertificate() {
    const form = this.modal('Add certificate');
    if (!form) return;
    this.field(form, 'fp-name', 'Name', this.input('', 'gateway'));
    this.field(form, 'fp-mode', 'Source', this.select([{value: 'self-signed', label: 'Generate a self-signed certificate'}, {value: 'upload', label: 'Upload PEM certificate and key'}], 'self-signed'));
    this.field(form, 'fp-cn', 'Common name', this.input('', 'vpn.example.com'), 'The name or address clients connect to (self-signed).');
    this.field(form, 'fp-san', 'Additional names or addresses', this.input('', '203.0.113.10, vpn2.example.com'));
    this.field(form, 'fp-days', 'Valid for (days)', this.input(825, '825', 'number'));
    this.field(form, 'fp-cert', 'Certificate (PEM)', this.area('', '-----BEGIN CERTIFICATE-----', 4));
    this.field(form, 'fp-key', 'Private key (PEM)', this.area('', '-----BEGIN ' + 'PRIVATE KEY-----', 4));
    this.field(form, 'fp-chain', 'Chain (PEM, optional)', this.area('', '', 2));
    this.finish(form, 'Add to candidate', () => this.save('certificate', {
      revision: this.listing.revision, name: this.value('fp-name'), mode: this.value('fp-mode'), common_name: this.value('fp-cn'),
      alternative_names: this.value('fp-san').split(',').map(s => s.trim()).filter(Boolean), days: Number(this.value('fp-days') || 825),
      certificate: this.value('fp-cert'), private_key: this.value('fp-key'), chain: this.value('fp-chain')}, 'POST'));
  },
  explain(error) {
    const detail = error && error.detail !== undefined ? error.detail : error && error.message ? error.message : String(error);
    if (Array.isArray(detail)) return detail.map(d => (d.loc || []).slice(1).join('.') + ': ' + d.msg).join('; ');
    return typeof detail === 'string' ? detail : JSON.stringify(detail);
  },
  async save(kind, body, method) {
    const msg = document.getElementById('fp-msg');
    const button = document.getElementById('fp-save');
    if (!body.name) { if (msg) msg.textContent = 'A name is required.'; return; }
    if (button) button.disabled = true;
    if (msg) msg.textContent = 'Saving…';
    try {
      const result = await this.request('/api/config/protect/' + kind, {method: method || 'PUT', body: JSON.stringify(body)});
      if (!result || !['created', 'updated'].includes(result.status)) throw new Error('Candidate update was not confirmed.');
      closeModal('modal-info');
      if (typeof refreshCommitIndicator === 'function') refreshCommitIndicator();
      await this.page(this.parent, this.kind);
    } catch (error) {
      if (msg) msg.textContent = this.explain(error);
      if (button) button.disabled = false;
    }
  },
  async remove(kind, name) {
    if (typeof confirm === 'function' && !confirm('Delete ' + kind.replace('/', ' ') + ' ' + name + ' from the candidate configuration?')) return;
    try {
      await this.request('/api/config/protect/' + kind + '/' + encodeURIComponent(name) + '?revision=' + encodeURIComponent(this.listing.revision), {method: 'DELETE'});
      if (typeof refreshCommitIndicator === 'function') refreshCommitIndicator();
      await this.page(this.parent, this.kind);
    } catch (error) {
      alert('Delete failed: ' + this.explain(error));
    }
  }
};
