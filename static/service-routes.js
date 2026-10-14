/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Device > Setup > Services > Service Route Configuration: which dataplane
   interface each of the firewall's own services leaves through. Candidate
   edits go to /api/system/service-routes; a commit installs them on the
   dataplane; the live column is the dataplane's own view. Text nodes only. */
window.ffnServiceRoutes = {
  listing: null,
  status: null,
  STATE: {routed: 'badge-up', management: 'badge-log', pending: 'badge-info', unavailable: 'badge-log'},
  node(tag, text, owner, cls) {
    const n = document.createElement(tag);
    if (text !== undefined && text !== null) n.textContent = text;
    if (cls) n.className = cls;
    if (owner) owner.appendChild(n);
    return n;
  },
  request(path, options) {
    return window.ffnExtensions && window.ffnExtensions.request ? window.ffnExtensions.request(path, options) : consoleRequest(path, options);
  },
  async load() {
    this.listing = await this.request('/api/system/service-routes');
    try { this.status = await this.request('/api/system/service-routes/status'); }
    catch (e) { this.status = {available: false, reason: e.message, services: []}; }
  },
  live(name) {
    return ((this.status && this.status.services) || []).find(r => r.service === name) || null;
  },
  async render(parent) {
    if (!parent) return;
    this.parent = parent;
    const card = this.node('section', undefined, parent, 'card');
    card.id = 'service-routes';
    this.node('h3', 'Service Route Configuration', card);
    this.node('p', 'By default the firewall\'s own services (DNS, NTP, updates, email, syslog, LDAP, RADIUS, SNMP traps) leave through the management interface. A service route sends one service through a faceplate interface with that interface\'s address instead.', card, 'text-dim');
    const message = this.node('div', 'Loading…', card, 'text-dim');
    message.setAttribute('role', 'status');
    try { await this.load(); }
    catch (e) { message.textContent = 'Service routes unavailable: ' + e.message; return; }
    message.textContent = '';
    const wrap = this.node('div', undefined, card, 'table-wrap');
    const table = this.node('table', undefined, wrap);
    const head = this.node('tr', undefined, this.node('thead', undefined, table));
    for (const h of ['Service', 'Ports', 'Source', 'Address', 'Dataplane', '']) this.node('th', h, head);
    const body = this.node('tbody', undefined, table);
    for (const row of this.listing.services) {
      const tr = this.node('tr', undefined, body);
      this.node('td', row.label, tr);
      this.node('td', row.ports.join(', '), tr);
      const source = this.node('td', row.interface || 'Management interface', tr);
      for (const p of row.problems || []) this.node('div', p, source, 'text-warning');
      this.node('td', row.interface ? (row.address || '(first address)') : '', tr);
      const live = this.live(row.service);
      const state = this.node('td', undefined, tr);
      this.node('span', live ? live.state : (row.interface ? 'pending' : 'management'), state, 'badge ' + (this.STATE[live ? live.state : (row.interface ? 'pending' : 'management')] || 'badge-log'));
      if (live && live.detail) this.node('div', live.detail, state, 'text-dim');
      const edit = this.node('button', 'Edit', this.node('td', undefined, tr, 'actions'), 'btn btn-sm');
      edit.onclick = () => this.edit(row.service);
      if (this.listing.can_edit === false) edit.disabled = true;
    }
    if (this.status && this.status.available === false) this.node('p', 'Dataplane status unavailable: ' + (this.status.reason || ''), card, 'text-dim');
  },
  edit(service) {
    const row = this.listing.services.find(r => r.service === service);
    const title = document.getElementById('info-modal-title');
    const body = document.getElementById('info-modal-body');
    if (!row || !title || !body) return;
    title.textContent = 'Service route for ' + row.label;
    body.replaceChildren();
    const form = this.node('form', undefined, body);
    form.id = 'sr-form';
    form.onsubmit = (ev) => { ev.preventDefault(); this.save(service); };
    const group = this.node('div', undefined, form, 'form-group');
    const label = this.node('label', 'Source interface', group);
    const select = document.createElement('select');
    select.id = 'sr-interface'; label.htmlFor = select.id;
    for (const option of [{value: '', label: 'Management interface (default)'}].concat(this.listing.interface_choices.map(c => ({value: c.name, label: c.name + ' (' + c.addresses.join(', ') + ')'})))) {
      const o = document.createElement('option'); o.value = option.value; o.textContent = option.label;
      if (option.value === (row.interface || '')) { o.selected = true; }
      select.appendChild(o);
    }
    select.value = row.interface || '';
    group.appendChild(select);
    const group2 = this.node('div', undefined, form, 'form-group');
    const label2 = this.node('label', 'Source address', group2);
    const address = document.createElement('select');
    address.id = 'sr-address'; label2.htmlFor = address.id;
    group2.appendChild(address);
    const fill = () => {
      address.replaceChildren();
      const choice = this.listing.interface_choices.find(c => c.name === select.value);
      const first = document.createElement('option'); first.value = ''; first.textContent = choice ? 'First address (' + choice.addresses[0] + ')' : '—'; address.appendChild(first);
      for (const a of (choice ? choice.addresses : [])) { const o = document.createElement('option'); o.value = a; o.textContent = a; if (a === row.address) o.selected = true; address.appendChild(o); }
      address.value = choice && choice.addresses.includes(row.address) ? row.address : '';
      address.disabled = !choice;
    };
    fill(); select.onchange = fill;
    this.node('div', 'Ports: ' + row.ports.join(', ') + '. The service is exempt from the security policy on this path, as traffic the firewall itself originates.', form, 'text-dim');
    const actions = this.node('div', undefined, form, 'form-actions');
    const save = this.node('button', 'Save to candidate', actions, 'btn btn-primary');
    save.type = 'submit'; save.id = 'sr-save';
    const cancel = this.node('button', 'Cancel', actions, 'btn');
    cancel.type = 'button'; cancel.onclick = () => closeModal('modal-info');
    const msg = this.node('span', '', actions, 'text-dim'); msg.id = 'sr-msg';
    document.getElementById('modal-info').classList.add('show');
  },
  payload(service) {
    return {revision: this.listing.revision, service, interface: (document.getElementById('sr-interface').value || '').trim(),
            address: (document.getElementById('sr-address').value || '').trim()};
  },
  explain(error) {
    const detail = error && error.detail !== undefined ? error.detail : error && error.message ? error.message : String(error);
    if (Array.isArray(detail)) return detail.map(d => (d.loc || []).slice(1).join('.') + ': ' + d.msg).join('; ');
    return typeof detail === 'string' ? detail : JSON.stringify(detail);
  },
  async save(service) {
    const msg = document.getElementById('sr-msg');
    const button = document.getElementById('sr-save');
    if (button) button.disabled = true;
    if (msg) msg.textContent = 'Saving…';
    try {
      const result = await this.request('/api/system/service-routes', {method: 'PUT', body: JSON.stringify(this.payload(service))});
      if (!result || !['created', 'updated', 'management'].includes(result.status)) throw new Error('Candidate update was not confirmed.');
      closeModal('modal-info');
      if (typeof refreshCommitIndicator === 'function') refreshCommitIndicator();
      const old = document.getElementById('service-routes');
      if (old && old.parentNode) { const parent = old.parentNode; old.remove(); await this.render(parent); }
    } catch (error) {
      if (msg) msg.textContent = this.explain(error);
      if (button) button.disabled = false;
    }
  }
};
