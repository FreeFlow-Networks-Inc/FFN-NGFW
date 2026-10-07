/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The page asks the selected daemon what it offers instead of carrying a list
   of its own. A platform that installs its own controllers therefore appears
   here without a core change, and a core that cannot describe a node says so
   rather than presenting an empty or invented vocabulary.

   render(parent)                     every resource the daemon reports
   render(parent, resource)           that resource only
   render(parent, resource, seed)     with the provider's own editor template */
window.ffnPlanes = {
  async render(parent, resource, seed) {
    parent.replaceChildren();
    const pinned = resource !== undefined;
    let current = resource || 'network';
    function node(tag, text, owner = parent) {
      const n = document.createElement(tag);
      if (text !== undefined) n.textContent = text;
      owner.appendChild(n); return n;
    }
    node('h2', pinned && current === 'nif' ? 'NIF link control' : 'Control planes');
    node('p', 'Changes apply through the selected MP control daemon. Review validation before applying. These changes are separate from XML candidate/commit.');
    const bootMessage = node('p', 'MP hardware startup: checking…');
    bootMessage.setAttribute('role', 'status');
    const chooser = node('label', 'Resource');
    const picker = node('select', undefined, chooser);
    chooser.hidden = true;
    const message = node('p', 'Reading execution-plane state…'); message.setAttribute('role','status');
    const observed = node('pre'); observed.style.whiteSpace='pre-wrap'; observed.style.maxHeight='320px'; observed.style.overflow='auto';
    const refresh = node('button', 'Refresh runtime state'); refresh.className='btn';
    /* An interrupted apply blocks further writes to its resource until an
       operator reconciles it. The daemon reports which request is blocking, so
       recovery no longer depends on the browser tab that issued it. */
    const stuck = node('p'); stuck.hidden = true; stuck.setAttribute('role','status');
    const recovery = node('div'); recovery.hidden = true;
    const blocked = node('select', undefined, recovery);
    const revision = node('input', undefined, recovery); revision.type='number';
    revision.setAttribute('aria-label','Revision observed after repairing the interrupted change');
    const reconcile = node('button', 'Reconcile interrupted request', recovery); reconcile.className='btn';
    node('p', 'Reconciling records that you inspected runtime state and repaired it. It neither re-runs the interrupted change nor claims that it succeeded.', recovery);
    const label = node('label', 'Configuration patch (JSON)');
    const input = node('textarea', undefined, label); input.rows=12; input.style.width='100%';
    const validate = node('button', 'Validate'); validate.className='btn'; validate.disabled=true;
    const apply = node('button', 'Apply validated configuration'); apply.className='btn'; apply.disabled=true;
    const query = node('button', 'Check last request'); query.className='btn'; query.disabled=true;
    const output = node('pre'); output.style.whiteSpace='pre-wrap';
    let validated = null, lastId = null, busy = false, described = null, undescribed = false;
    async function call(action, payload, id=crypto.randomUUID()) {
      return window.ffnExtensions.request('/api/system/planes', {method:'POST',body:JSON.stringify({v:1,id,resource:current,action,payload})});
    }
    function buttons(state) {
      busy=state; refresh.disabled=state; validate.disabled=state; picker.disabled=state;
      apply.disabled=state || validated!==input.value; query.disabled=state || !lastId;
      reconcile.disabled=state || !blocked.value; input.disabled=state;
    }
    /* Local and relayed resources both count: a node describes what a client
       may address through it, not only what it executes itself. */
    function collect(description, into) {
      const map = into || new Map();
      const resources = (description && description.resources) || {};
      for (const name of Object.keys(resources)) {
        const entry = resources[name], known = map.get(name) || {actions:[], blocked:[], total:0};
        const listed = entry.blocked || [];
        map.set(name, {actions:[...new Set([...known.actions, ...(entry.actions||[])])],
                       blocked:[...known.blocked, ...listed],
                       // The daemon caps the list, so the count is the count.
                       total:known.total + (typeof entry.blocked_total === 'number' ? entry.blocked_total : listed.length)});
      }
      if (description && description.peer && description.peer.reachable) collect(description.peer, map);
      return map;
    }
    function options(select, values) {
      select.replaceChildren();
      for (const value of values) { const o=node('option', value, select); o.value=value; }
      select.value = values.length ? values[0] : '';
    }
    function template(observedRevision) {
      if (seed) return Object.assign({revision:observedRevision}, seed);
      /* Deprecated: a provider should pass its own seed. Retained so an
         already-installed platform page keeps working. */
      if (current === 'nif') return {revision:observedRevision, enabled:true};
      if (current === 'network') return {revision:observedRevision, ports:{}};
      return {revision:observedRevision};
    }
    function showBlocked() {
      const entry = described && described.get(current);
      const ids = (entry && entry.blocked) || [];
      const total = (entry && entry.total) || ids.length;
      stuck.hidden = recovery.hidden = total === 0;
      stuck.textContent = total ? 'Writes to '+current+' are blocked by '+total+' unresolved request(s)'+
        (total > ids.length ? ', of which '+ids.length+' are listed here' : '')+
        '. Inspect and repair runtime state, then reconcile each one.' : '';
      options(blocked, ids);
    }
    async function describe() {
      try { described = collect(await window.ffnExtensions.request('/api/system/planes')); }
      catch (e) { described = null; }
      undescribed = !described || !described.size;
      if (undescribed) {
        // Kept on screen by load(): an operator who is not told the list is
        // missing reads one shown resource as the only one there is.
        described = null; chooser.hidden = true;
        return;
      }
      if (pinned) return;
      // Two nodes' resources are merged here, so the order has to be imposed
      // rather than inherited from whichever answered first.
      const names = [...described.keys()].sort();
      if (!names.includes(current)) current = names[0];
      options(picker, names);
      picker.value = current;
      chooser.hidden = names.length < 2;
    }
    async function load() {
      buttons(true); validated=null;
      // Status comes from controld. The browser never initiates detection or boot.
      try {
        const control = await window.ffnExtensions.request('/api/system/control');
        const boot = control.hardware_boot || {phase: 'unavailable'};
        bootMessage.textContent = 'MP hardware startup: ' + boot.phase +
          (boot.platform ? ' · ' + boot.platform : '') +
          (boot.current_step ? ' · ' + boot.current_step : '') +
          (boot.error ? ' · ' + boot.error : '') +
          (boot.waiting_for?.length ? ' · ' + boot.waiting_for.join('; ') : '') +
          (boot.hardware_ready ? ' · Hardware acknowledged; traffic enforcement is checked separately.' : '');
      } catch (e) { bootMessage.textContent = 'MP hardware startup: status unavailable.'; }
      try {
        const response=await call('status',{});
        if(!parent.isConnected) return;
        if(!response.ok) throw new Error(response.error);
        const cfg=response.result.config;
        observed.textContent=JSON.stringify(response.result,null,2);
        input.value=JSON.stringify(template(cfg.revision),null,2);
        message.textContent='Observed revision '+cfg.revision+' through '+response.trace.join(' → ')+'.'+
          (undescribed ? ' The control daemon did not describe its resources, so only '+current+' is shown.' : '');
      } catch(e) { message.textContent=e.message; }
      finally { showBlocked(); buttons(false); }
    }
    input.oninput=()=>{validated=null;apply.disabled=true;};
    picker.onchange=async()=>{ if(busy) return; current=picker.value; output.textContent=''; lastId=null; await load(); };
    refresh.onclick=async()=>{ if(busy) return; await describe(); await load(); };
    reconcile.onclick=async()=>{
      if(busy || !blocked.value) return;
      const observedRevision=Number(revision.value);
      if(revision.value==='' || !Number.isInteger(observedRevision) || observedRevision<0) {
        message.textContent='Enter the revision you read back from runtime status.'; return;
      }
      buttons(true);
      try {
        const response=await call('resolve',{request_id:blocked.value,observed_revision:observedRevision});
        if(!parent.isConnected) return;
        output.textContent=JSON.stringify(response,null,2);
        message.textContent=response.ok ? 'Request '+blocked.value+' reconciled. The interrupted change was not replayed.' : response.error;
        if(response.ok) await describe();
      } catch(e) { message.textContent=e.message; }
      finally { showBlocked(); buttons(false); }
    };
    validate.onclick=async()=>{
      if(busy) return; buttons(true); validated=null;
      try {
        const value=input.value, response=await call('validate',JSON.parse(value));
        if(!parent.isConnected) return;
        output.textContent=JSON.stringify(response,null,2);
        if(response.ok) { validated=value; message.textContent='Validation passed. Review the proposed configuration below.'; }
        else message.textContent=response.error;
      } catch(e) { message.textContent=e.message; }
      finally { buttons(false); }
    };
    apply.onclick=async()=>{
      if(busy || validated!==input.value) return;
      buttons(true); lastId=crypto.randomUUID(); validated=null;
      message.textContent='Applying request '+lastId+'…';
      try {
        const response=await call('apply',JSON.parse(input.value),lastId);
        if(!parent.isConnected) return;
        output.textContent=JSON.stringify(response,null,2);
        message.textContent='Request '+lastId+': '+response.state+'. Refresh runtime state before another change.';
      } catch(e) { message.textContent='Request '+lastId+': '+e.message+'. Check the request before another change.'; }
      finally { buttons(false); validate.disabled=true; }
    };
    query.onclick=async()=>{
      if(busy || !lastId) return; buttons(true);
      try { output.textContent=JSON.stringify(await call('result',{request_id:lastId}),null,2); }
      catch(e) { message.textContent=e.message; }
      finally { buttons(false); validate.disabled=true; }
    };
    await describe();
    await load();
  }
};
