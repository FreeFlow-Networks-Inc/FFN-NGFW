/* SPDX-License-Identifier: GPL-2.0-or-later */
window.ffnPlanes = {
  async render(parent, resource = 'network') {
    parent.replaceChildren();
    function node(tag, text, owner = parent) {
      const n = document.createElement(tag);
      if (text !== undefined) n.textContent = text;
      owner.appendChild(n); return n;
    }
    node('h2', resource === 'nif' ? 'NIF link control' : 'Control planes');
    node('p', 'Changes apply through the selected MP control daemon. Review validation before applying. These changes are separate from XML candidate/commit.');
    const message = node('p', 'Reading execution-plane state…'); message.setAttribute('role','status');
    const observed = node('pre'); observed.style.whiteSpace='pre-wrap'; observed.style.maxHeight='320px'; observed.style.overflow='auto';
    const refresh = node('button', 'Refresh runtime state'); refresh.className='btn';
    const label = node('label', 'Configuration patch (JSON)');
    const input = node('textarea', undefined, label); input.rows=12; input.style.width='100%';
    const validate = node('button', 'Validate'); validate.className='btn'; validate.disabled=true;
    const apply = node('button', 'Apply validated configuration'); apply.className='btn'; apply.disabled=true;
    const query = node('button', 'Check last request'); query.className='btn'; query.disabled=true;
    const output = node('pre'); output.style.whiteSpace='pre-wrap';
    let validated = null, lastId = null, busy = false;
    async function call(action, payload, id=crypto.randomUUID()) {
      return window.ffnExtensions.request('/api/system/planes', {method:'POST',body:JSON.stringify({v:1,id,resource,action,payload})});
    }
    function buttons(state) {
      busy=state; refresh.disabled=state; validate.disabled=state;
      apply.disabled=state || validated!==input.value; query.disabled=state || !lastId;
      input.disabled=state;
    }
    async function load() {
      buttons(true); validated=null;
      try {
        const response=await call('status',{});
        if(!parent.isConnected) return;
        if(!response.ok) throw new Error(response.error);
        const cfg=response.result.config;
        observed.textContent=JSON.stringify(response.result,null,2);
        input.value=JSON.stringify(resource==='nif'?{revision:cfg.revision,enabled:true}:{revision:cfg.revision,ports:{}},null,2);
        message.textContent='Observed revision '+cfg.revision+' through '+response.trace.join(' → ')+'.';
      } catch(e) { message.textContent=e.message; }
      finally { buttons(false); }
    }
    input.oninput=()=>{validated=null;apply.disabled=true;};
    refresh.onclick=load;
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
    await load();
  }
};
