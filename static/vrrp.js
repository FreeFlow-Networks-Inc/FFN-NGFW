/* Candidate VRRP configuration. No direct hardware or service operations. */
let vrrpGeneration = 0;
function renderNetworkVRRP(container) {
  if (typeof refreshTimer !== 'undefined' && refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  const text = v => _escSP(v ?? '');
  container.innerHTML = `<div class="page-header"><h2>VRRP</h2></div>
    <div class="filters-bar"><label>Configuration <select id="vrrp-source"><option value="candidate">Candidate</option><option value="running">Running</option></select></label>
    <label>Virtual System <select id="vrrp-scope"></select></label><button class="btn" id="vrrp-refresh">Refresh</button><button class="btn btn-primary" id="vrrp-add" disabled>Add</button></div>
    <p>Participation shares gateway addresses with a peer on the same network. Passthrough carries advertisements within a Layer 2 VLAN domain. ISP route selection is configured in Virtual Routers.</p>
    <p id="vrrp-status" role="status"></p><div class="card" id="vrrp-list"></div><div class="modal-overlay" id="vrrp-editor" role="dialog" aria-modal="true" aria-labelledby="object-title"></div>`;
  const list = document.getElementById('vrrp-list'), status = document.getElementById('vrrp-status'), add = document.getElementById('vrrp-add');
  const scope = document.getElementById('vrrp-scope');
  scope.add(new Option(typeof currentVsys === 'string' ? currentVsys : 'vsys1'));
  const load = async () => {
    const generation = ++vrrpGeneration;
    document.getElementById('vrrp-editor').classList.remove('show');
    add.disabled = true; list.textContent = 'Loading VRRP configuration…';
    const url = '/api/config/network/vrrp?' + new URLSearchParams({source: document.getElementById('vrrp-source').value, scope: scope.value});
    try {
      const data = await consoleRequest(url);
      if (!list.isConnected || generation !== vrrpGeneration) return;
      const selected = scope.value;
      scope.replaceChildren(...data.choices.scopes.map(s => new Option(s, s, false, s === selected)));
      status.textContent = data.plan.runtime + '. OK stages changes; Commit is required.';
      const rows = data.entries.filter(e => e.scope === scope.value);
      list.innerHTML = '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Mode</th><th>Interface / Domain</th><th>Family</th><th>Virtual Addresses</th><th>Configured</th><th>Actions</th></tr></thead><tbody>' + rows.map((e,i) =>
        `<tr><td><button class="btn btn-sm" data-edit="${i}">${text(e.name)}</button></td><td>${e.mode === 'participate' ? 'Participation' : 'Layer 2 Passthrough'}</td><td>${text(e.interface || e.domain)}</td><td>${text(e.family)}</td><td>${text((e.virtual_addresses || []).join(', '))}</td><td>${e.enabled ? 'Enabled · activation unavailable' : 'Disabled'}</td><td><button class="btn btn-sm" data-delete="${i}" ${data.can_edit ? '' : 'disabled'}>Delete</button></td></tr>`).join('') + '</tbody></table></div>' + (rows.length ? '' : '<p>No VRRP entries configured.</p>');
      add.disabled = !data.can_edit; add.onclick = () => edit(null);
      list.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => edit(rows[Number(b.dataset.edit)]));
      list.querySelectorAll('[data-delete]').forEach(b => b.onclick = async () => {
        const entry = rows[Number(b.dataset.delete)];
        if (!confirm('Delete ' + entry.name + ' from candidate configuration?')) return;
        b.disabled = true;
        try { await consoleRequest('/api/config/network/vrrp', {method:'POST',body:JSON.stringify({action:'delete',name:entry.name,revision:data.revision})}); refreshCommitIndicator(); if(list.isConnected) await load(); }
        catch(e) { if(status.isConnected) status.textContent=e.message; b.disabled=false; }
      });
      function edit(existing) {
        let draft = structuredClone(existing || {...data.defaults.participate, name:'',mode:'participate',scope:scope.value});
        const writable = data.can_edit;
        const options = (values, selected) => values.map(v => `<option value="${text(v)}" ${v === selected ? 'selected' : ''}>${text(v)}</option>`).join('');
        function draw() {
          const l3 = data.choices.interfaces.filter(i => i.mode === 'layer3').map(i => i.name);
          const common = `<label>Name<input name="name" required maxlength="63" value="${text(draft.name)}" ${existing ? 'readonly' : ''}></label>
            <label>Mode<select name="mode">${options(['participate','passthrough'],draft.mode)}</select></label>
            <label>Enabled<select name="enabled">${options(['no','yes'],draft.enabled?'yes':'no')}</select></label>`;
          const family = draft.mode === 'participate' ? ['ipv4','ipv6'] : ['ipv4','ipv6','both'];
          let fields = `<label>Address Family<select name="family">${options(family,draft.family)}</select></label>`;
          if(draft.mode === 'participate') {
            const selected = new Set(draft.virtual_addresses);
            const addressOptions = data.choices.addresses.map(a => ({value:a.name,label:a.name+' — '+a.value}));
            for(const value of selected) if(!addressOptions.some(a=>a.value===value)) addressOptions.push({value,label:value});
            fields += `<label>Interface<select name="interface" required><option value="">Select interface</option>${options(l3,draft.interface)}</select></label>
              <label>Virtual Router ID<input name="vrid" type="number" min="1" max="255" required value="${text(draft.vrid)}"></label>
              <label>Priority<input name="priority" type="number" min="1" max="254" required value="${text(draft.priority)}"></label>
              <label>Advertisement Interval (ms)<input name="advert_ms" type="number" min="10" max="40950" step="10" required value="${text(draft.advert_ms)}"></label>
              <label>Preempt<select name="preempt">${options(['yes','no'],draft.preempt?'yes':'no')}</select></label>
              <label>Virtual Addresses<select name="virtual_addresses" multiple size="5" required>${addressOptions.map(a=>`<option value="${text(a.value)}" ${selected.has(a.value)?'selected':''}>${text(a.label)}</option>`).join('')}</select></label>
              <label>Add literal VIP (CIDR)<input id="vrrp-literal" placeholder="Address/prefix"><button type="button" class="btn btn-sm" id="vrrp-add-address">Add Address</button></label>
              <label>Tracked Interfaces<select name="track_interfaces" multiple size="4">${l3.filter(i=>i!==draft.interface).map(i=>`<option ${draft.track_interfaces.includes(i)?'selected':''}>${text(i)}</option>`).join('')}</select></label>
              <p>VRRPv3 multicast; starts in Backup. VIPs must share the interface subnet. Loss of a tracked interface withdraws ownership. VRID and VIPs must match the peer.</p>`;
          } else {
            fields += `<label>Layer 2 VLAN Domain<select name="domain" required><option value="">Select VLAN domain</option>${options(Object.keys(data.choices.domains),draft.domain)}</select></label>
              <p>Only VRRP multicast advertisements with hop limit 255 are eligible. The runtime must preserve bridge and VLAN isolation; advertisements are never routed.</p>`;
          }
          objectDialog(document.getElementById('vrrp-editor'),(existing?'Edit':'Add')+' VRRP',`<form id="vrrp-form" class="object-form">${common}${fields}<p id="vrrp-error" role="alert"></p><div class="modal-footer"><button type="submit" class="btn btn-primary" ${writable?'':'disabled'}>OK</button><button type="button" class="btn" id="vrrp-cancel">${writable?'Cancel':'Close'}</button></div></form>`);
          const form = document.getElementById('vrrp-form');
          if(!writable) for(const e of form.querySelectorAll('input,select,button:not(#vrrp-cancel)')) e.disabled=true;
          document.getElementById('vrrp-cancel').onclick=()=>document.getElementById('object-close').click();
          const read = () => {
            const values=new FormData(form), entry={...draft,name:values.get('name'),enabled:values.get('enabled')==='yes',family:values.get('family')};
            if(draft.mode==='participate') {
              for(const k of ['interface']) entry[k]=values.get(k);
              for(const k of ['vrid','priority','advert_ms']) entry[k]=Number(values.get(k));
              for(const k of ['virtual_addresses','track_interfaces']) entry[k]=values.getAll(k);
              entry.preempt=values.get('preempt')==='yes';
            } else entry.domain=values.get('domain');
            return entry;
          };
          form.elements.mode.onchange=()=>{const before=read(),mode=form.elements.mode.value;draft={...structuredClone(data.defaults[mode]),name:before.name,scope:scope.value,enabled:before.enabled,mode};draw();};
          if(draft.mode==='participate') {
            form.elements.interface.onchange=()=>{draft=read();draft.track_interfaces=draft.track_interfaces.filter(i=>i!==draft.interface);draw();};
            document.getElementById('vrrp-add-address').onclick=()=>{const value=document.getElementById('vrrp-literal').value.trim();if(!value)return;draft=read();if(!draft.virtual_addresses.includes(value))draft.virtual_addresses.push(value);draw();};
          }
          form.onsubmit=async event=>{
            event.preventDefault();if(!writable)return;const button=form.querySelector('[type=submit]');button.disabled=true;
            try { const entry=read();await consoleRequest('/api/config/network/vrrp',{method:'POST',body:JSON.stringify({action:existing?'update':'create',name:entry.name,revision:data.revision,entry})});refreshCommitIndicator();if(list.isConnected)await load(); }
            catch(e){if(form.isConnected)document.getElementById('vrrp-error').textContent=e.message;button.disabled=false;}
          };
        }
        draw();
      }
    } catch(e) { if(list.isConnected && generation===vrrpGeneration){status.textContent=e.message;list.textContent='VRRP configuration unavailable.';} }
  };
  scope.onchange=load;document.getElementById('vrrp-source').onchange=load;document.getElementById('vrrp-refresh').onclick=load;load();
}
