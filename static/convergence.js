/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Configuration convergence: did the committed configuration reach every
   subsystem after the planes booted? The manager computes it from the
   lifecycle replay receipt and live observations (/api/system/convergence);
   this file only renders it. card(parent) is the dashboard strip, page(parent)
   the Device page with details and the re-apply action. */
window.ffnConvergence = {
  LABELS: {'committed-replay': 'Committed replay', 'faceplate': 'Front ports', 'aggregates': 'Aggregates',
           'interface-management': 'Interface management', 'security-runtime': 'Security runtime',
           'management-access': 'Management access', 'dhcp-server': 'DHCP servers'},
  PLANES: {mp: 'MP', cp: 'CP', dp: 'DP'},
  BADGE: {converged: 'badge-up', drift: 'badge-warning', failed: 'badge-error', pending: 'badge-info', unavailable: 'badge-log'},
  WORDS: {converged: 'Converged', drift: 'Drift', failed: 'Failed', pending: 'Pending', unavailable: 'Unavailable'},
  node(tag, text, owner, cls) {
    const n = document.createElement(tag);
    if (text !== undefined && text !== null) n.textContent = text;
    if (cls) n.className = cls;
    if (owner) owner.appendChild(n);
    return n;
  },
  badge(state, owner) {
    return this.node('span', this.WORDS[state] || state, owner, 'badge ' + (this.BADGE[state] || 'badge-log'));
  },
  async fetch() {
    return window.ffnExtensions.request('/api/system/convergence');
  },
  when(ts) {
    if (!ts) return '';
    const age = Math.max(0, Math.round(Date.now() / 1000 - ts));
    return age < 60 ? age + ' s ago' : age < 3600 ? Math.round(age / 60) + ' min ago' : new Date(ts * 1000).toLocaleTimeString();
  },
  /* Dashboard strip: one line, overall badge, one chip per subsystem. */
  async card(parent) {
    if (!parent) return;
    parent.replaceChildren();
    const row = this.node('div', undefined, parent, 'conv-strip');
    const lead = this.node('span', 'Checking…', row, 'conv-lead');
    let report;
    try { report = await this.fetch(); }
    catch (e) { lead.textContent = 'Convergence unavailable'; lead.className = 'conv-lead text-dim'; return; }
    row.replaceChildren();
    const head = this.node('span', undefined, row, 'conv-lead');
    this.badge(report.overall, head);
    this.node('span', report.overall === 'converged' ? 'Committed configuration reached every subsystem'
                     : report.overall === 'pending' ? 'Configuration still converging after boot'
                     : report.overall === 'unavailable' ? 'Some subsystems cannot be observed'
                     : 'Committed configuration has not reached every subsystem', head, 'conv-text');
    const chips = this.node('span', undefined, row, 'conv-chips');
    for (const s of report.subsystems) {
      const chip = this.node('span', undefined, chips, 'conv-chip conv-' + s.state);
      chip.title = s.summary;
      this.node('i', undefined, chip, 'conv-dot');
      this.node('span', this.LABELS[s.id] || s.id, chip);
    }
    const link = this.node('a', 'Details', row, 'conv-link');
    link.href = '#'; link.onclick = async (ev) => { ev.preventDefault(); if (typeof switchTab === 'function') await switchTab('device'); if (typeof switchSubPage === 'function') switchSubPage('device-convergence'); };
    this.node('span', 'checked ' + this.when(report.checked_at), row, 'conv-when text-dim');
  },
  /* Device page: table of subsystems, details, re-check and re-apply. */
  async page(parent) {
    if (!parent) return;
    parent.replaceChildren();
    const toolbar = this.node('div', undefined, parent, 'conv-toolbar');
    const recheck = this.node('button', 'Re-check', toolbar, 'btn btn-sm');
    const reapply = this.node('button', 'Re-apply committed configuration', toolbar, 'btn btn-sm');
    reapply.disabled = true;
    const status = this.node('span', '', toolbar, 'text-dim'); status.setAttribute('role', 'status');
    const summary = this.node('div', undefined, parent, 'card conv-summary');
    const table = this.node('div', undefined, parent, 'card');
    const self = this;
    async function load() {
      recheck.disabled = true; status.textContent = 'Checking…';
      let report;
      try { report = await self.fetch(); }
      catch (e) { status.textContent = 'Convergence unavailable: ' + (e && e.message || e); recheck.disabled = false; return; }
      recheck.disabled = false;
      status.textContent = 'checked ' + self.when(report.checked_at) + (report.generation ? ' · generation ' + report.generation.slice(0, 12) : '');
      reapply.disabled = !(report.actions || []).includes('reapply');
      summary.replaceChildren();
      const h = self.node('h3', 'Overall', summary);
      const line = self.node('div', undefined, summary, 'conv-overall');
      self.badge(report.overall, line);
      self.node('span', {
        converged: 'The committed configuration has reached every subsystem that can be observed.',
        pending: 'The planes are still applying the committed configuration; this clears on its own.',
        drift: 'At least one subsystem differs from the committed configuration. Re-apply replays all of it through configd.',
        failed: 'The replay or a subsystem reported a failure; inspect the details before re-applying.',
        unavailable: 'Some subsystems cannot be observed; what is observable agrees.'
      }[report.overall] || '', line, 'conv-text');
      if (report.processor_boots) {
        self.node('div', 'CP boot ' + String(report.processor_boots.cp || '?').slice(0, 8) + ' · DP boot ' + String(report.processor_boots.dp || '?').slice(0, 8)
                  + ' · MP boot ' + String(report.mp_boot_id || '?').slice(0, 8), summary, 'sub');
      }
      table.replaceChildren();
      self.node('h3', 'Subsystems', table);
      const wrap = self.node('div', undefined, table, 'table-wrap');
      const t = self.node('table', undefined, wrap);
      const thead = self.node('thead', undefined, t); const tr = self.node('tr', undefined, thead);
      for (const col of ['Subsystem', 'Plane', 'State', 'Summary']) self.node('th', col, tr);
      const tbody = self.node('tbody', undefined, t);
      for (const s of report.subsystems) {
        const r = self.node('tr', undefined, tbody);
        self.node('td', self.LABELS[s.id] || s.id, r);
        self.node('td', self.PLANES[s.plane] || s.plane, r);
        self.badge(s.state, self.node('td', undefined, r));
        const cell = self.node('td', s.summary, r);
        if (s.details && s.details.length) {
          const det = self.node('details', undefined, cell);
          self.node('summary', s.details.length + ' detail' + (s.details.length === 1 ? '' : 's'), det);
          const ul = self.node('ul', undefined, det, 'conv-details');
          for (const d of s.details) self.node('li', d, ul);
        }
      }
    }
    recheck.onclick = load;
    reapply.onclick = async () => {
      if (!confirm('Replay the whole committed configuration through configd now? Running sessions are not affected; interface and policy state is re-applied.')) return;
      reapply.disabled = true; status.textContent = 'Requesting replay…';
      try {
        const r = await window.ffnExtensions.request('/api/system/convergence/reapply', {method: 'POST'});
        status.textContent = r.started ? 'Replay started (' + r.unit + '); re-check in a minute' : 'Not started: ' + r.reason;
      } catch (e) { status.textContent = 'Re-apply failed: ' + (e && e.message || e); }
      setTimeout(load, 4000);
    };
    await load();
  }
};
