/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Network > DHCP: program the dataplane's DHCP servers per interface.
   The editor writes the candidate configuration (/api/config/dhcp); a commit
   carries it to the dataplane through the platform provider. The status and
   lease tables show the dataplane daemon's own view (/api/dhcp/status). */
window.ffnDhcp = {
  listing: null,
  status: null,
  STATE: {serving: 'badge-up', pending: 'badge-info', disabled: 'badge-log', unavailable: 'badge-log',
          'interface-absent': 'badge-warning', 'address-missing': 'badge-warning', error: 'badge-error', stopped: 'badge-warning', starting: 'badge-info'},
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
  leaseText(minutes) {
    if (minutes === null || minutes === undefined) return 'unlimited';
    if (minutes % 1440 === 0) return (minutes / 1440) + ' d';
    if (minutes % 60 === 0) return (minutes / 60) + ' h';
    return minutes + ' min';
  },
  async load() {
    this.listing = await this.request('/api/config/dhcp');
    try { this.status = await this.request('/api/dhcp/status'); }
    catch (e) { this.status = {available: false, reason: e.message, servers: [], leases: []}; }
  },
  async page(parent) {
    if (!parent) return;
    this.parent = parent;
    parent.replaceChildren();
    const header = this.node('div', undefined, parent, 'page-header');
    this.node('h2', 'DHCP Servers', header);
    const actions = this.node('div', undefined, header, 'actions');
    const add = this.node('button', '+ Add DHCP Server', actions, 'btn btn-primary btn-sm');
    add.onclick = () => this.edit(null);
    const refresh = this.node('button', 'Refresh', actions, 'btn btn-sm');
    refresh.onclick = () => this.page(parent);
    const notice = this.node('p', 'Servers are stored in the candidate configuration; commit to serve them. Each server answers on the interface it is bound to, from that interface\'s own address.', parent, 'text-dim');
    const message = this.node('div', 'Loading…', parent, 'text-dim');
    message.setAttribute('role', 'status');
    try { await this.load(); }
    catch (e) { message.textContent = 'DHCP configuration unavailable: ' + e.message; return; }
    message.textContent = '';
    if (this.listing && this.listing.can_edit === false) add.disabled = true;
    this.renderServers(parent);
    this.renderLeases(parent);
  },
  liveFor(name) {
    const rows = (this.status && this.status.servers) || [];
    return rows.find(r => r.interface === name) || null;
  },
  renderServers(parent) {
    const card = this.node('div', undefined, parent, 'card');
    const wrap = this.node('div', undefined, card, 'table-wrap');
    const table = this.node('table', undefined, wrap);
    const head = this.node('tr', undefined, this.node('thead', undefined, table));
    for (const h of ['Interface', 'Mode', 'Server address', 'Pools', 'Lease', 'Gateway / DNS', 'Reservations', 'Dataplane', 'Leases', '']) this.node('th', h, head);
    const body = this.node('tbody', undefined, table);
    const entries = (this.listing && this.listing.entries) || [];
    if (!entries.length) {
      const cell = this.node('td', 'No DHCP servers in the candidate configuration.', this.node('tr', undefined, body), 'text-dim');
      cell.colSpan = 10;
    }
    for (const row of entries) {
      const tr = this.node('tr', undefined, body);
      this.node('td', row.interface, tr, 'mono');
      this.node('td', row.mode, tr);
      this.node('td', row.address || '—', tr, 'mono');
      this.node('td', (row.pools || []).join(', ') || '—', tr, 'mono');
      this.node('td', this.leaseText(row.lease_minutes), tr);
      const opts = row.options || {};
      this.node('td', (opts.gateway || 'interface') + ' / ' + ((opts.dns || []).join(', ') || '—'), tr, 'mono');
      this.node('td', String((row.reserved || []).length), tr);
      const live = this.liveFor(row.interface);
      const state = this.node('td', undefined, tr);
      if (row.problems && row.problems.length) {
        this.badge('error', state);
        this.node('div', row.problems.join('; '), state, 'text-dim');
      } else if (live) {
        this.badge(live.state, state);
        if (live.detail) this.node('div', live.detail, state, 'text-dim');
      } else {
        this.badge('pending', state);
        this.node('div', 'not in the running configuration', state, 'text-dim');
      }
      this.node('td', live && live.bound !== undefined ? live.bound + ' bound' + (live.offered ? ', ' + live.offered + ' offered' : '') : '—', tr);
      const buttons = this.node('td', undefined, tr);
      const edit = this.node('button', 'Edit', buttons, 'btn btn-sm');
      edit.onclick = () => this.edit(row.interface);
      const del = this.node('button', 'Delete', buttons, 'btn btn-sm btn-danger');
      del.onclick = () => this.remove(row.interface);
      if (this.listing.can_edit === false) { edit.disabled = true; del.disabled = true; }
    }
    const foot = this.node('div', undefined, card, 'text-dim');
    if (!this.status || !this.status.available) foot.textContent = 'Dataplane status unavailable' + (this.status && this.status.reason ? ': ' + this.status.reason : '') + '.';
    else foot.textContent = 'Dataplane intent revision ' + (this.status.revision === null || this.status.revision === undefined ? '—' : this.status.revision) + (this.status.daemon_time ? ', daemon view ' + this.when(this.status.daemon_time) : '') + '.';
  },
  renderLeases(parent) {
    const section = this.node('div', undefined, parent, 'section');
    this.node('div', 'Leases', section, 'section-title');
    const card = this.node('div', undefined, section, 'card');
    const table = this.node('table', undefined, this.node('div', undefined, card, 'table-wrap'));
    const head = this.node('tr', undefined, this.node('thead', undefined, table));
    for (const h of ['Interface', 'IP address', 'MAC', 'Hostname', 'State', 'Since', 'Expires']) this.node('th', h, head);
    const body = this.node('tbody', undefined, table);
    const leases = (this.status && this.status.leases) || [];
    if (!leases.length) {
      const cell = this.node('td', this.status && this.status.available ? 'No leases.' : 'Leases are read from the dataplane daemon when it is reachable.', this.node('tr', undefined, body), 'text-dim');
      cell.colSpan = 7;
    }
    for (const l of leases) {
      const tr = this.node('tr', undefined, body);
      this.node('td', l.interface, tr, 'mono');
      this.node('td', l.ip, tr, 'mono');
      this.node('td', l.mac || '', tr, 'mono');
      this.node('td', l.hostname || '', tr);
      const state = this.node('td', undefined, tr);
      this.node('span', l.state, state, 'badge ' + (l.state === 'bound' ? 'badge-up' : l.state === 'offered' ? 'badge-info' : 'badge-warning'));
      this.node('td', this.when(l.since), tr);
      this.node('td', l.expires ? this.when(l.expires) : 'never', tr);
    }
  },
  /* Editor: a form in the shared info modal. */
  field(form, id, label, control) {
    const group = this.node('div', undefined, form, 'form-group');
    const l = this.node('label', label, group);
    l.htmlFor = id;
    control.id = id;
    group.appendChild(control);
    return control;
  },
  input(value, placeholder) {
    const n = document.createElement('input');
    n.type = 'text'; n.value = value || ''; if (placeholder) n.placeholder = placeholder;
    return n;
  },
  edit(name) {
    const existing = name ? ((this.listing && this.listing.entries) || []).find(r => r.interface === name) : null;
    const row = existing || {interface: '', mode: 'enabled', probe_ip: false, lease_minutes: 1440, pools: [], reserved: [], options: {dns: [], ntp: [], wins: []}};
    const title = document.getElementById('info-modal-title');
    const body = document.getElementById('info-modal-body');
    if (!title || !body) return;
    title.textContent = existing ? 'Edit DHCP server on ' + name : 'Add DHCP server';
    body.replaceChildren();
    const form = this.node('form', undefined, body);
    form.id = 'dhcp-form';
    form.onsubmit = (ev) => { ev.preventDefault(); this.save(); };
    const select = document.createElement('select');
    for (const choice of (this.listing && this.listing.interface_choices) || []) {
      const opt = this.node('option', choice.name + (choice.addresses.length ? '  (' + choice.addresses.join(', ') + ')' : choice.dhcp_client ? '  (DHCP client)' : '  (no IPv4 address)'), select);
      opt.value = choice.name;
      opt.disabled = !choice.addresses.length || (choice.has_server && choice.name !== name);
      if (choice.name === row.interface) opt.selected = true;
    }
    select.disabled = !!existing;
    this.field(form, 'dhcp-interface', 'Interface', select);
    const mode = document.createElement('select');
    for (const m of ['enabled', 'disabled']) { const o = this.node('option', m, mode); o.value = m; if (m === row.mode) o.selected = true; }
    this.field(form, 'dhcp-mode', 'Mode', mode);
    const lease = this.input(row.lease_minutes === null ? '' : String(row.lease_minutes), 'minutes; empty for unlimited');
    this.field(form, 'dhcp-lease', 'Lease (minutes, empty = unlimited)', lease);
    const pools = document.createElement('textarea');
    pools.rows = 3; pools.value = (row.pools || []).join('\n'); pools.placeholder = '10.1.0.100-10.1.0.199\none range or address per line';
    this.field(form, 'dhcp-pools', 'IP pools (within the interface subnet)', pools);
    const opts = row.options || {};
    this.field(form, 'dhcp-gateway', 'Gateway (empty = interface address)', this.input(opts.gateway, '10.1.0.2'));
    this.field(form, 'dhcp-mask', 'Subnet mask (empty = interface prefix)', this.input(opts.subnet_mask, '255.255.252.0'));
    this.field(form, 'dhcp-dns1', 'Primary DNS', this.input((opts.dns || [])[0], '1.1.1.1'));
    this.field(form, 'dhcp-dns2', 'Secondary DNS', this.input((opts.dns || [])[1], ''));
    this.field(form, 'dhcp-ntp1', 'Primary NTP', this.input((opts.ntp || [])[0], ''));
    this.field(form, 'dhcp-ntp2', 'Secondary NTP', this.input((opts.ntp || [])[1], ''));
    this.field(form, 'dhcp-wins1', 'Primary WINS', this.input((opts.wins || [])[0], ''));
    this.field(form, 'dhcp-wins2', 'Secondary WINS', this.input((opts.wins || [])[1], ''));
    this.field(form, 'dhcp-suffix', 'DNS suffix', this.input(opts.dns_suffix, 'lan'));
    const reserved = document.createElement('textarea');
    reserved.rows = 3; reserved.value = (row.reserved || []).map(r => [r.mac, r.ip, r.description].filter(Boolean).join(' ')).join('\n');
    reserved.placeholder = 'aa:bb:cc:dd:ee:ff 10.1.0.50 printer\none reservation per line: MAC, address, optional description';
    this.field(form, 'dhcp-reserved', 'Reservations', reserved);
    const probeGroup = this.node('div', undefined, form, 'form-group');
    const probeLabel = this.node('label', undefined, probeGroup);
    const probe = document.createElement('input'); probe.type = 'checkbox'; probe.id = 'dhcp-probe'; probe.checked = !!row.probe_ip;
    probeLabel.appendChild(probe); probeLabel.appendChild(document.createTextNode(' Probe an address (ARP) before offering it'));
    const actions = this.node('div', undefined, form, 'form-actions');
    const save = this.node('button', existing ? 'Save to candidate' : 'Add to candidate', actions, 'btn btn-primary');
    save.type = 'submit'; save.id = 'dhcp-save';
    const cancel = this.node('button', 'Cancel', actions, 'btn');
    cancel.type = 'button'; cancel.onclick = () => closeModal('modal-info');
    const msg = this.node('span', '', actions, 'text-dim'); msg.id = 'dhcp-msg';
    document.getElementById('modal-info').classList.add('show');
  },
  payload() {
    const value = id => (document.getElementById(id).value || '').trim();
    const list = (a, b) => [value(a), value(b)].filter(Boolean);
    const reserved = value('dhcp-reserved').split('\n').map(s => s.trim()).filter(Boolean).map(line => {
      const parts = line.split(/[\s,]+/);
      return {mac: (parts[0] || '').toLowerCase(), ip: parts[1] || '', description: parts.slice(2).join(' ')};
    });
    const lease = value('dhcp-lease');
    return {
      revision: this.listing.revision, interface: value('dhcp-interface'), mode: value('dhcp-mode'),
      probe_ip: document.getElementById('dhcp-probe').checked,
      lease_minutes: lease === '' ? null : Number(lease),
      pools: value('dhcp-pools').split('\n').map(s => s.trim()).filter(Boolean),
      reserved,
      options: {gateway: value('dhcp-gateway'), subnet_mask: value('dhcp-mask'), dns: list('dhcp-dns1', 'dhcp-dns2'),
                ntp: list('dhcp-ntp1', 'dhcp-ntp2'), wins: list('dhcp-wins1', 'dhcp-wins2'), dns_suffix: value('dhcp-suffix')}
    };
  },
  explain(error) {
    const detail = error && error.detail !== undefined ? error.detail : error && error.message ? error.message : String(error);
    if (Array.isArray(detail)) return detail.map(d => (d.loc || []).slice(1).join('.') + ': ' + d.msg).join('; ');
    return typeof detail === 'string' ? detail : JSON.stringify(detail);
  },
  async save() {
    const msg = document.getElementById('dhcp-msg');
    const button = document.getElementById('dhcp-save');
    let body;
    try { body = this.payload(); }
    catch (e) { if (msg) msg.textContent = e.message; return; }
    if (!body.interface) { if (msg) msg.textContent = 'Choose an interface.'; return; }
    if (button) button.disabled = true;
    if (msg) msg.textContent = 'Saving…';
    try {
      const result = await this.request('/api/config/dhcp', {method: 'PUT', body: JSON.stringify(body)});
      if (!result || !['created', 'updated'].includes(result.status)) throw new Error('Candidate update was not confirmed.');
      closeModal('modal-info');
      if (typeof refreshCommitIndicator === 'function') refreshCommitIndicator();
      await this.page(this.parent);
    } catch (error) {
      if (msg) msg.textContent = this.explain(error);
      if (button) button.disabled = false;
    }
  },
  async remove(name) {
    if (typeof confirm === 'function' && !confirm('Delete the DHCP server on ' + name + ' from the candidate configuration?')) return;
    try {
      await this.request('/api/config/dhcp/' + encodeURIComponent(name).replace(/%2F/g, '/') + '?revision=' + encodeURIComponent(this.listing.revision), {method: 'DELETE'});
      if (typeof refreshCommitIndicator === 'function') refreshCommitIndicator();
      await this.page(this.parent);
    } catch (error) {
      alert('Delete failed: ' + this.explain(error));
    }
  }
};
