/* SPDX-License-Identifier: GPL-2.0-or-later */
const policyKinds={security:'Security',nat:'NAT',qos:'QoS',pbf:'Policy Based Forwarding',decryption:'Decryption',
  'tunnel-inspect':'Tunnel Inspection','application-override':'Application Override',authentication:'Authentication',dos:'DoS Protection',sdwan:'SD-WAN'};
let policyWorkspaceGeneration=0;
function policySpec(row){return {name:row.name,description:row.description||'',enabled:row.enabled,settings:structuredClone(row.settings)};}
function policyActionText(kind,s){
  if(kind==='nat')return 'Source: '+(s['source-type']||'none')+' '+(s['translated-source']||[]).join(', ')+' '+(s['source-interface']||'')+'; Destination: '+(s['translated-destination']||'unchanged')+(s['translated-port']?':'+s['translated-port']:'');
  if(kind==='qos')return 'Class '+(s.class||'');
  if(kind==='application-override')return (s.protocol||'')+'/'+(s.port||'')+' → '+(s.application||'');
  return s.action||s['authentication-enforcement']||s['traffic-distribution-profile']||'';
}
function securityInventory(data, fast, scope) {
  const implicit = r => !!r.is_implicit || [r.kind,r.name].some(v=>['intrazone-default','interzone-default'].includes(String(v||'').toLowerCase()));
  const rows = data.entries.map((r,i)=>({r,i,fast:false,implicit:implicit(r)}));
  const vsys = /^vsys([1-9][0-9]*)$/.exec(scope)?.[1];
  for (const original of fast.rules || []) {
    if (Number(original.vsys || 0)!==0 && String(original.vsys)!==vsys) continue;
    const r={...original};
    r.is_immutable=!!(r.is_immutable || r.immutable || implicit(r) || r.kind && r.kind!=='user');
    rows.push({r,i:rows.length,fast:true,implicit:implicit(r)});
  }
  const rank = row => row.r.kind==='lab-mgmt'?0:row.implicit?(row.r.kind==='intrazone-default'||row.r.name==='intrazone-default'?3:4):row.fast?2:1;
  return rows.sort((a,b)=>rank(a)-rank(b));
}
function fastPathRow(row, index, editable) {
  const r=row.r, text=v=>_escSP(v??''), locked=r.is_immutable, compilation=r.compilation;
  const state=locked?(row.implicit?'Implicit / read only':'System / read only'):r.enabled?'Enabled':'Disabled';
  const issue=compilation?(compilation.included?(compilation.compatible?'Compatible':'Blocked: '+compilation.issue):'Excluded'+(compilation.issue?': '+compilation.issue:'')):'Application unconfirmed';
  return `<tr data-fast-row="${text(r.id)}" class="${r.enabled?'':'policy-disabled'}"><td>${text(r.position)}</td>
    <td><button class="btn btn-sm" data-fast-view="${index}">${text(r.name || 'Rule '+r.id)}</button></td>
    <td>${text(state)}<br><span class="text-dim">${text(issue)}</span></td>
    <td>${text(r.src_iface?'Interface: '+r.src_iface:'Any interface')}<br>${text(r.src_ip)}</td>
    <td>${text(r.dst_iface?'Interface: '+r.dst_iface:'Any interface')}<br>${text(r.dst_ip)}</td>
    <td>${text(r.proto || 'any')} · ${text(r.src_port || '*')} → ${text(r.dst_port || '*')}</td>
    <td>${text(r.action)}</td><td>—</td><td>Fast path · stored<br>${text(r.vsys?'vsys'+r.vsys:'All virtual systems')}</td><td>${text(r.hit_count??'—')}</td>
    <td>${locked?'Read only':`<button class="btn btn-sm" data-fast-view="${index}">${editable?'Edit':'View'}</button>`+
      (editable?` <button class="btn btn-sm" data-fast-clone="${index}">Clone</button> <button class="btn btn-sm" data-fast-delete="${index}">Delete</button>`:'')}</td></tr>`;
}
function renderPolicyWorkspace(c,kind){
  if(typeof refreshTimer!=='undefined'&&refreshTimer){clearInterval(refreshTimer);refreshTimer=null;}
  ++policyWorkspaceGeneration;
  c.innerHTML=`<div class="page-header"><h2>${policyKinds[kind]}</h2></div>
    <div class="filters-bar"><input id="pw-search" type="search" aria-label="Search policy rules" placeholder="Search rules, matches or actions">
    <label>Virtual System <select id="pw-scope"><option>vsys1</option></select></label>
    <label>Configuration <select id="pw-source"><option value="candidate">Candidate</option><option value="running">Running</option></select></label>
    <button class="btn" id="pw-refresh">Refresh</button><span id="pw-count"></span></div>
    <p id="pw-status" role="status">Loading rulebase from control daemon…</p><div id="pw-list" class="card"></div>
    <div class="workflow-actions"><button class="btn btn-primary" id="pw-add" disabled>Add</button>
    <button class="btn" id="pw-validate">Validate activation</button>
    ${kind==='dos'?'<button class="btn" id="pw-dos">DoS engine controls</button>':''}
    <span class="text-dim">Candidate changes require Commit. New rules start disabled.</span></div>
    <div class="modal-overlay" id="pw-editor" role="dialog" aria-modal="true" aria-labelledby="object-title"></div>`;
  for(const id of ['pw-scope','pw-source','pw-refresh'])document.getElementById(id)[id==='pw-refresh'?'onclick':'onchange']=()=>loadPolicyWorkspace(c,kind);
  const legacy=(renderer)=>{
    ++policyWorkspaceGeneration;renderer(c);const button=document.createElement('button');button.className='btn';button.textContent='Back to '+policyKinds[kind];button.onclick=()=>renderPolicyWorkspace(c,kind);c.prepend(button);
  };
  if(kind==='dos')document.getElementById('pw-dos').onclick=()=>legacy(renderPolicyDDoS);
  loadPolicyWorkspace(c,kind);
}
async function loadPolicyWorkspace(c,kind){
  const generation=++policyWorkspaceGeneration,table=document.getElementById('pw-list'),editor=document.getElementById('pw-editor');
  const source=document.getElementById('pw-source').value,scope=document.getElementById('pw-scope').value;
  const add=document.getElementById('pw-add'),status=document.getElementById('pw-status');
  editor.classList.remove('show');table.textContent='Loading…';add.disabled=true;document.getElementById('pw-validate').disabled=true;
  try{
    const url='/api/config/policies/'+kind+'?scope='+encodeURIComponent(scope);
    const results=await Promise.allSettled([consoleRequest(url+'&source='+source),
      kind==='security'?consoleRequest('/api/policy/rules?show_hidden=true&show_defaults=true'):Promise.resolve({rules:[]})]);
    const xmlError=results[0].status==='rejected'?results[0].reason.message:'';
    const fastError=results[1].status==='rejected'?results[1].reason.message:'';
    if(xmlError && kind!=='security')throw results[0].reason;
    const data=xmlError?{entries:[],scopes:[scope],can_edit:false,runtime:{owner:'ffn-controld',valid:false,blockers:[]}}:results[0].value;
    const fast=fastError?{rules:[],can_edit:false}:results[1].value;
    if(!Array.isArray(data.entries)||!Array.isArray(fast.rules))throw new Error('Invalid rule inventory');
    if(!table.isConnected||generation!==policyWorkspaceGeneration)return;
    const select=document.getElementById('pw-scope');select.innerHTML=data.scopes.map(s=>`<option>${_escSP(s)}</option>`).join('');select.value=scope;
    status.textContent=(xmlError?'Candidate/running rules unavailable: '+xmlError:
      'Control owner: '+data.runtime.owner+' · '+(data.runtime.valid?'No enabled XML policies to apply.':data.runtime.blockers.length+' enabled rule(s) block activation.'))+
      (kind==='security'?(fastError?' · Fast-path and implicit rules unavailable: '+fastError:' · Implicit rules are always shown and read only. Fast-path rows show stored policy in both views.'):'')+
      ' Dataplane application is not confirmed.';
    add.disabled=!data.can_edit;add.onclick=()=>editPolicyWorkspace(data,url,null,()=>loadPolicyWorkspace(c,kind));
    document.getElementById('pw-validate').disabled=!!xmlError;
    document.getElementById('pw-validate').onclick=async()=>{
      objectDialog(editor,'Policy Activation Validation','<pre id="pw-validation">Checking control daemon…</pre>');const target=document.getElementById('pw-validation');
      try{const report=await consoleRequest('/api/config/policies/status?source='+source);
        if(target.isConnected)target.textContent=report.blockers.length?report.blockers.map(b=>b.scope+' / '+policyKinds[b.kind]+' / '+b.name+': '+b.reason).join('\n'):'No enabled XML policies. Disabled definitions can be committed; no runtime enforcement is claimed.';
      }catch(e){if(target.isConnected)target.textContent=e.message;}
    };
    const inventory=kind==='security'?securityInventory(data,fast,scope):data.entries.map((r,i)=>({r,i}));
    const draw=()=>{
      const q=document.getElementById('pw-search').value.toLowerCase();
      const rows=inventory.filter(row=>row.implicit || row.r.is_immutable || JSON.stringify(row.r).toLowerCase().includes(q));
      document.getElementById('pw-count').textContent=rows.length+' of '+inventory.length+' rules';
      const text=v=>_escSP(Array.isArray(v)?v.join(', '):v||'');
      table.innerHTML='<div class="table-wrap"><table><thead><tr><th>#</th><th>Name</th><th>State</th><th>Source Zone / Address</th><th>Destination Zone / Address</th><th>Application / Service</th><th>Action</th><th>Tags</th>'+ (kind==='security'?'<th>Policy Source</th><th>Hits</th>':'') +'<th>Actions</th></tr></thead><tbody>'+rows.map((row,index)=>{
        if(row.fast)return fastPathRow(row,index,source==='candidate'&&fast.can_edit);
        const {r,i}=row;
        const s=r.settings,locked=!data.can_edit||!r.editable||row.implicit;
        return `<tr class="${r.enabled?'':'policy-disabled'}"><td>${r.position}</td><td><button class="btn btn-sm" data-rule-edit="${i}">${text(r.name)}</button></td><td>${row.implicit?'Implicit / read only':r.editable?text(r.state):'Imported / read only'}</td>
          <td>${text(s.from)}<br>${text(s.source)}</td><td>${text(s.to)}<br>${text(s.destination)}</td><td>${text(s.application)}<br>${text(s.service)}</td>
          <td>${text(policyActionText(kind,s))}</td><td>${text(s.tag)}</td>${kind==='security'?`<td>${text(source)} · XML</td><td>—</td>`:''}<td>
          <button class="btn btn-sm" data-rule-clone="${i}" ${locked?'disabled':''}>Clone</button>
          <button class="btn btn-sm" data-rule-op="toggle" data-index="${i}" ${locked?'disabled':''}>${r.enabled?'Disable':'Enable'}</button>
          <button class="btn btn-sm" data-rule-op="up" data-index="${i}" aria-label="Move rule up" ${locked||i===0?'disabled':''}>↑</button>
          <button class="btn btn-sm" data-rule-op="down" data-index="${i}" aria-label="Move rule down" ${locked||i===data.entries.length-1?'disabled':''}>↓</button>
          <button class="btn btn-sm" data-rule-op="delete" data-index="${i}" ${locked?'disabled':''}>Delete</button></td></tr>`;
      }).join('')+'</tbody></table></div>'+(rows.length?'':'<p>No matching rules.</p>');
      const reload=()=>loadPolicyWorkspace(c,kind);
      table.querySelectorAll('[data-fast-view],[data-fast-clone]').forEach(b=>b.onclick=()=>{
        const clone=b.hasAttribute('data-fast-clone'),row=rows[Number(clone?b.dataset.fastClone:b.dataset.fastView)].r;
        if(clone&&row.is_immutable)return;
        editRule(clone?{...row,id:null,name:(row.name+'-copy').slice(0,127),enabled:0,position:0}:row,
          {canEdit:source==='candidate'&&!!fast.can_edit&&!row.is_immutable,reload});
      });
      table.querySelectorAll('[data-fast-delete]').forEach(b=>b.onclick=async()=>{
        const row=rows[Number(b.dataset.fastDelete)].r;
        if(row.is_immutable||source!=='candidate'||!fast.can_edit||!confirm('Delete '+row.name+' from stored fast-path policy?'))return;
        b.disabled=true;
        try{await consoleRequest('/api/policy/rules/'+encodeURIComponent(row.id),{method:'DELETE'});if(generation===policyWorkspaceGeneration)await reload();}
        catch(e){if(table.isConnected&&generation===policyWorkspaceGeneration){status.textContent=e.message;b.disabled=false;}}
      });
      table.querySelectorAll('[data-rule-edit]').forEach(b=>b.onclick=()=>editPolicyWorkspace(data,url,data.entries[Number(b.dataset.ruleEdit)],()=>loadPolicyWorkspace(c,kind)));
      table.querySelectorAll('[data-rule-clone]').forEach(b=>b.onclick=()=>editPolicyWorkspace(data,url,data.entries[Number(b.dataset.ruleClone)],()=>loadPolicyWorkspace(c,kind),true));
      table.querySelectorAll('[data-rule-op]').forEach(b=>b.onclick=async()=>{
        const row=data.entries[Number(b.dataset.index)],op=b.dataset.ruleOp;
        if(op==='delete'&&!confirm('Delete '+row.name+' from candidate configuration?'))return;
        const payload={action:['up','down'].includes(op)?'move':op,revision:data.revision,name:row.name};
        if(op==='toggle')payload.enabled=!row.enabled;
        if(op==='up'||op==='down')payload.position=row.position+(op==='up'?-1:1);
        b.disabled=true;
        try{await consoleRequest(url,{method:'POST',body:JSON.stringify(payload)});refreshCommitIndicator();if(generation===policyWorkspaceGeneration)await loadPolicyWorkspace(c,kind);}
        catch(e){if(table.isConnected&&generation===policyWorkspaceGeneration){status.textContent=e.message;b.disabled=false;}}
      });
    };
    document.getElementById('pw-search').oninput=draw;draw();
  }catch(e){if(table.isConnected&&generation===policyWorkspaceGeneration){status.textContent=e.message;table.textContent='Rulebase unavailable. Editing is disabled.';}}
}
function policyFieldHTML(f,value,choices){
  const id='pf-'+f.key,text=v=>_escSP(v??''),options=f.options;
  if(f.mode==='list'){
    const refs=[...new Set([...(choices||[]),...options])];
    return `<label>${text(f.label)}<textarea name="${id}" placeholder="One value per line">${text((value||[]).join('\n'))}</textarea>${refs.length?`<select data-add-to="${id}" aria-label="Add ${text(f.label)}"><option value="">Add configured value…</option>${refs.map(v=>`<option>${text(v)}</option>`).join('')}</select>`:''}</label>`;
  }
  if(options.length)return `<label>${text(f.label)}<select name="${id}">${options.map(v=>`<option value="${text(v)}" ${v===value?'selected':''}>${text(v)}</option>`).join('')}</select></label>`;
  return `<label>${text(f.label)}<input name="${id}" value="${text(value)}" maxlength="1024" ${choices?.length?`list="${id}-choices"`:''}>${choices?.length?`<datalist id="${id}-choices">${choices.map(v=>`<option value="${text(v)}">`).join('')}</datalist>`:''}</label>`;
}
function editPolicyWorkspace(snapshot,url,existing,reload,clone=false){
  const box=document.getElementById('pw-editor'),generation=policyWorkspaceGeneration;
  const row=existing?policySpec(existing):{name:'',description:'',enabled:false,settings:Object.fromEntries(snapshot.schema.fields.map(f=>[f.key,f.default??'']))};
  if(clone){row.name='';row.enabled=false;}
  const editable=snapshot.can_edit&&(!existing||existing.editable),tabs=[...new Set(['General',...snapshot.schema.fields.map(f=>f.tab)])];
  const body=`<form id="pw-form" class="object-form"><div class="setup-tabs policy-tabs" role="tablist">${tabs.map((t,i)=>`<button class="${i===0?'active':''}" type="button" role="tab" aria-selected="${i===0}" data-tab="${i}">${_escSP(t)}</button>`).join('')}</div>
    ${tabs.map((tab,i)=>`<div data-panel="${i}" class="policy-panel" role="tabpanel" ${i?'hidden':''}>
      ${tab==='General'?`<label>Name<input name="rule-name" required maxlength="63" ${existing&&!clone?'readonly':''} value="${_escSP(row.name)}"></label>
      <label>Description<textarea name="rule-description" maxlength="1024">${_escSP(row.description)}</textarea></label>
      <label>Enabled<select name="rule-enabled"><option value="false" ${row.enabled?'':'selected'}>No</option><option value="true" ${row.enabled?'selected':''}>Yes</option></select></label>`:''}
      ${snapshot.schema.fields.filter(f=>f.tab===tab).map(f=>policyFieldHTML(f,row.settings[f.key]??f.default??'',snapshot.choices[f.key])).join('')}</div>`).join('')}
    <p class="text-dim">The control daemon stores this rule in candidate configuration. Activation requires a commissioned runtime provider; unsupported enabled rules block Commit.</p>
    <p id="pw-message" role="alert"></p><div class="modal-footer"><button type="submit" class="btn btn-primary" ${editable?'':'disabled'}>OK</button><button type="button" class="btn" id="pw-cancel">${editable?'Cancel':'Close'}</button></div></form>`;
  objectDialog(box,(clone?'Clone ':existing?(editable?'Edit ':'View '):'Add ')+snapshot.label+' Rule',body);
  const form=document.getElementById('pw-form');
  if(!editable)for(const e of form.querySelectorAll('input,select,textarea'))e.disabled=true;
  form.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{
    form.querySelectorAll('[data-panel]').forEach(p=>p.hidden=p.dataset.panel!==b.dataset.tab);
    form.querySelectorAll('[data-tab]').forEach(t=>{t.classList.toggle('active',t===b);t.setAttribute('aria-selected',String(t===b));});
  });
  form.querySelectorAll('[data-add-to]').forEach(s=>s.onchange=()=>{
    if(!s.value)return;const target=form.elements[s.dataset.addTo];let values=target.value.split(/\r?\n/).filter(Boolean);
    if(s.value!=='any')values=values.filter(v=>v!=='any');if(!values.includes(s.value))values.push(s.value);target.value=values.join('\n');s.value='';
  });
  document.getElementById('pw-cancel').onclick=()=>document.getElementById('object-close').click();
  form.onsubmit=async event=>{
    event.preventDefault();if(!editable)return;const data=new FormData(form),button=form.querySelector('[type=submit]');
    const rule={name:data.get('rule-name'),description:data.get('rule-description'),enabled:data.get('rule-enabled')==='true',settings:{}};
    for(const f of snapshot.schema.fields){const value=data.get('pf-'+f.key)||'';rule.settings[f.key]=f.mode==='list'?value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean):value;}
    button.disabled=true;
    try{await consoleRequest(url,{method:'POST',body:JSON.stringify({action:existing&&!clone?'update':'create',revision:snapshot.revision,name:existing&&!clone?existing.name:undefined,rule})});
      refreshCommitIndicator();if(generation===policyWorkspaceGeneration)await reload();
    }catch(e){if(form.isConnected&&generation===policyWorkspaceGeneration){document.getElementById('pw-message').textContent=e.message;button.disabled=false;}}
  };
}
