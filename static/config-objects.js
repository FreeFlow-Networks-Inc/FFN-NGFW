/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Typed candidate object editor. The API owns schemas, permissions and validation. */
const objectLabels = {
  address:'Addresses', 'address-group':'Address Groups', region:'Regions',
  'dynamic-user-group':'Dynamic User Groups', application:'Applications',
  'application-group':'Application Groups', 'application-filter':'Application Filters',
  service:'Services', 'service-group':'Service Groups', tag:'Tags', device:'Devices',
  'external-list':'External Dynamic Lists'
};
const objectGroups = ['address-group','application-group','service-group'];
let objectRequestId = 0;
function objectSummary(o) {
  return o.members.length ? o.members.join(', ') : o.value ||
    Object.entries(o.settings || {}).filter(([,v])=>v && (!Array.isArray(v)||v.length))
      .map(([k,v])=>k+': '+(Array.isArray(v)?v.join(', '):v)).join('; ');
}
function objectMatches(o, query) {
  return [o.name,o.type,o.description,objectSummary(o),...(o.tags||[])].join(' ').toLowerCase().includes(query.toLowerCase());
}
function objectColumns(snapshot) {
  if(snapshot.schema)return snapshot.schema.fields.map(f=>({label:f.label,value:o=>o.settings?.[f.key]||''}));
  if(objectGroups.includes(snapshot.kind))return [{label:'Members / Match',value:o=>o.type==='dynamic'?o.value:o.members}];
  return snapshot.kind==='service'?[{label:'Destination Port',value:o=>o.value},{label:'Source Port',value:o=>o.source_port}]:[{label:'Address',value:o=>o.value}];
}
function renderConfigObjects(c, kind) {
  ++objectRequestId;
  c.innerHTML = `<div class="page-header"><h2>${objectLabels[kind]}</h2></div>
    <div class="filters-bar"><input id="object-search" type="search" aria-label="Search objects" placeholder="Search name, value, tags or description">
    <label>Location <select id="object-scope"><option value="shared">Shared</option></select></label>
    <label>Configuration <select id="object-source"><option value="candidate">Candidate</option><option value="running">Running</option></select></label>
    <button id="object-refresh" class="btn">Refresh</button><span id="object-count" aria-live="polite"></span></div>
    <div id="object-list" class="card">Loading…</div>
    <div class="workflow-actions"><button id="object-add" class="btn btn-primary" disabled>Add</button>
    ${kind==='application'?'<button id="object-catalog" class="btn">Application Database</button>':''}
    <span class="text-dim">Changes require Commit.</span></div>
    <div id="object-editor" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="object-title"></div>`;
  c.dataset.objectKind = kind;
  for (const id of ['object-source','object-scope','object-refresh']) {
    document.getElementById(id)[id==='object-refresh'?'onclick':'onchange'] = ()=>loadConfigObjects(c,kind);
  }
  if(kind==='application') document.getElementById('object-catalog').onclick=()=>{
    ++objectRequestId; renderObjectsAppCatalog(c);
    const button=document.createElement('button');button.className='btn';button.textContent='Back to Applications';
    button.onclick=()=>renderConfigObjects(c,kind);c.prepend(button);
  };
  loadConfigObjects(c,kind);
}
async function loadConfigObjects(c, kind) {
  const id=++objectRequestId, list=document.getElementById('object-list');
  const source=document.getElementById('object-source').value, scope=document.getElementById('object-scope').value;
  const add=document.getElementById('object-add'), editor=document.getElementById('object-editor');
  editor.classList.remove('show'); add.disabled=true; list.textContent='Loading objects…';
  document.getElementById('object-count').textContent='';
  try {
    const base='/api/config/objects/'+kind, query='?scope='+encodeURIComponent(scope);
    const r=await consoleRequest(base+query+'&source='+source);
    if(!list.isConnected || id!==objectRequestId) return;
    const select=document.getElementById('object-scope');
    select.innerHTML=r.scopes.map(v=>`<option value="${_escSP(v)}">${_escSP(v==='shared'?'Shared':v)}</option>`).join('');select.value=scope;
    add.disabled=!r.can_edit;add.onclick=()=>editConfigObject(r,base,query,null,()=>loadConfigObjects(c,kind));
    const draw=()=>{
      const q=document.getElementById('object-search').value;
      const rows=r.entries.map((o,i)=>({o,i})).filter(({o})=>objectMatches(o,q));
      document.getElementById('object-count').textContent=rows.length+' of '+r.entries.length+' items';
      const columns=objectColumns(r),display=v=>_escSP(Array.isArray(v)?v.join(', '):v);
      list.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Name</th><th>Location</th><th>Type</th>${columns.map(f=>'<th>'+_escSP(f.label)+'</th>').join('')}<th>Tags</th><th>Description</th><th>Actions</th></tr></thead><tbody>`+
        rows.map(({o,i})=>`<tr><td><button class="btn btn-sm" data-edit="${i}" ${r.can_edit&&o.editable?'':'disabled'}>${_escSP(o.name)}</button>${o.editable?'':' <span title="Imported settings are protected from changes">Read only</span>'}</td>
        <td>${_escSP(scope==='shared'?'Shared':scope)}</td><td>${_escSP(o.type)}</td>${columns.map(f=>'<td>'+display(f.value(o))+'</td>').join('')}
        <td>${_escSP((o.tags||[]).join(', '))}</td><td>${_escSP(o.description)}</td><td>
        <button class="btn btn-sm" data-ref="${i}">References</button>
        <button class="btn btn-sm" data-clone="${i}" ${r.can_edit&&o.editable?'':'disabled'}>Clone</button>
        <button class="btn btn-sm" data-delete="${i}" ${r.can_edit&&o.editable?'':'disabled'}>Delete</button></td></tr>`).join('')+
        '</tbody></table></div>'+(rows.length?'':'<p class="text-dim">No matching objects.</p>');
      list.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>editConfigObject(r,base,query,r.entries[Number(b.dataset.edit)],()=>loadConfigObjects(c,kind)));
      list.querySelectorAll('[data-clone]').forEach(b=>b.onclick=()=>editConfigObject(r,base,query,r.entries[Number(b.dataset.clone)],()=>loadConfigObjects(c,kind),true));
      list.querySelectorAll('[data-ref]').forEach(b=>b.onclick=async()=>{
        const o=r.entries[Number(b.dataset.ref)];
        objectDialog(editor,'References: '+o.name,'<pre id="object-references">Loading…</pre>');
        const target=document.getElementById('object-references');
        try {
          const refs=await consoleRequest(base+'/'+encodeURIComponent(o.name)+'/references'+query+'&source='+source);
          if(id===objectRequestId && target.isConnected) target.textContent=refs.references.map(x=>x.path).join('\n')||'No references.';
        } catch(e){if(target.isConnected)target.textContent=e.message;}
      });
      list.querySelectorAll('[data-delete]').forEach(b=>b.onclick=async()=>{
        const o=r.entries[Number(b.dataset.delete)];
        if(!confirm('Delete '+o.name+' from candidate configuration?'))return;
        b.disabled=true;
        try {
          await consoleRequest(base+'/'+encodeURIComponent(o.name)+query+'&revision='+r.revision,{method:'DELETE'});
          refreshCommitIndicator();if(id===objectRequestId)await loadConfigObjects(c,kind);
        } catch(e){if(id===objectRequestId){objectDialog(editor,'Cannot delete object','<p id="object-error" role="alert"></p>');document.getElementById('object-error').textContent=e.message;b.disabled=false;}}
      });
    };
    document.getElementById('object-search').oninput=draw;draw();
  } catch(e){if(list.isConnected&&id===objectRequestId)list.textContent=e.message;}
}
function objectDialog(box,title,body) {
  const previous=document.activeElement;
  box.innerHTML=`<div class="modal object-dialog"><div class="modal-header"><h3 id="object-title">${_escSP(title)}</h3><button class="btn" id="object-close" aria-label="Close dialog">×</button></div><div class="modal-body">${body}</div></div>`;
  box.classList.add('show');
  const close=()=>{box.classList.remove('show');if(previous&&previous.isConnected)previous.focus();};
  document.getElementById('object-close').onclick=close;
  box.onkeydown=e=>{
    if(e.key==='Escape'){e.preventDefault();close();}
    if(e.key==='Tab'){
      const controls=[...box.querySelectorAll('button,input,select,textarea,a[href]')].filter(x=>!x.disabled && x.getClientRects().length);
      const first=controls[0],last=controls[controls.length-1];
      if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
      else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
    }
  };
  box.querySelector('input,select,textarea,button').focus();
}
function objectField(f, value) {
  const name='setting-'+f.key, v=value??'', required=f.required?'required':'';
  if(f.mode==='lines')return `<label>${_escSP(f.label)} <small>(one per line)</small><textarea name="${name}" ${required}>${_escSP(Array.isArray(v)?v.join('\n'):v)}</textarea></label>`;
  if(f.options.length)return `<label>${_escSP(f.label)}<select name="${name}" ${required}>${f.required?'':'<option value="">Select…</option>'}${f.options.map(x=>`<option value="${_escSP(x)}" ${x===v?'selected':''}>${_escSP(x)}</option>`).join('')}</select></label>`;
  return `<label>${_escSP(f.label)}<input name="${name}" maxlength="4096" ${required} value="${_escSP(v)}"></label>`;
}
function objectPayload(form,snapshot) {
  const data=new FormData(form), lines=v=>(v||'').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  const payload={revision:snapshot.revision,name:data.get('name'),type:data.get('type'),description:data.get('description'),
    value:data.get('value')||'',source_port:data.get('source_port')||'',members:data.getAll('members'),tags:data.getAll('tags'),settings:{}};
  for(const f of snapshot.schema?.fields||[]) payload.settings[f.key]=f.mode==='lines'?lines(data.get('setting-'+f.key)):data.get('setting-'+f.key)||'';
  if(snapshot.kind==='address-group'&&payload.type==='dynamic')payload.members=[];
  if(snapshot.kind==='address-group'&&payload.type==='static')payload.value='';
  return payload;
}
function editConfigObject(snapshot,base,query,existing,reload,clone=false) {
  const box=document.getElementById('object-editor'),generation=objectRequestId,kind=snapshot.kind;
  const group=objectGroups.includes(kind),service=kind==='service',schema=snapshot.schema;
  const choices=schema?(schema.types||[schema.type]):kind==='address-group'?['static','dynamic']:group?['static']:service?['tcp','udp']:['ip-netmask','ip-range','fqdn'];
  const o=existing||{name:'',type:choices[0],value:'',source_port:'',members:[],tags:[],settings:{},description:''};
  const memberChoices=[...new Set([...snapshot.member_choices.filter(x=>clone||x.name!==o.name).map(x=>x.name),...o.members])].sort();
  const tagChoices=[...new Set([...snapshot.tag_choices,...(o.tags||[])])].sort();
  const options=(values,selected)=>values.map(v=>`<option value="${_escSP(v)}" ${selected.includes(v)?'selected':''}>${_escSP(v)}</option>`).join('');
  const extraNote=['application','application-filter','device','dynamic-user-group','external-list'].includes(kind)?
    '<p class="text-dim">This editor stores definitions. Application identification, device/user matching and external-list retrieval require runtime engine integration.</p>':'';
  objectDialog(box,(clone?'Clone ':existing?'Edit ':'Add ')+snapshot.label,`<form id="object-form" class="object-form">
    <label>Name<input name="name" maxlength="63" required ${existing&&!clone?'readonly':''} value="${_escSP(clone?'':o.name)}"></label>
    <label>Location<input readonly value="${_escSP(snapshot.scope)}"></label>
    <label>Description<textarea name="description" maxlength="1024">${_escSP(o.description)}</textarea></label>
    <label>Type<select name="type">${options(choices,[o.type])}</select></label>
    ${group?`<fieldset id="object-members"><legend>Members</legend><input id="object-member-search" type="search" placeholder="Find a member" aria-label="Find a member"><select name="members" multiple size="8" aria-label="Members">${options(memberChoices,o.members)}</select><small>Use Ctrl or Command to select multiple members.</small></fieldset>`:''}
    ${!schema&&(!group||kind==='address-group')?`<label id="object-value">${service?'Destination ports':group?'Match criteria (quoted tags with and/or)':'Address'}<input name="value" value="${_escSP(o.value)}"></label>`:''}
    ${service?`<label>Source ports<input name="source_port" value="${_escSP(o.source_port)}"></label>`:''}
    ${(schema?.fields||[]).map(f=>objectField(f,o.settings?.[f.key])).join('')}
    ${kind!=='tag'?`<label>Tags<select name="tags" multiple size="4">${options(tagChoices,o.tags||[])}</select></label>`:''}
    ${extraNote}<p id="object-message" role="alert"></p><div class="modal-footer"><button class="btn btn-primary" type="submit">OK</button><button class="btn" id="object-cancel" type="button">Cancel</button></div></form>`);
  const form=document.getElementById('object-form');
  document.getElementById('object-cancel').onclick=()=>document.getElementById('object-close').click();
  if(group)document.getElementById('object-member-search').oninput=e=>{
    for(const option of form.elements.members.options)option.hidden=!option.selected&&!option.value.toLowerCase().includes(e.target.value.toLowerCase());
  };
  const updateType=()=>{
    if(kind==='address-group'){
      const dynamic=form.elements.type.value==='dynamic';
      document.getElementById('object-members').hidden=dynamic;form.elements.members.disabled=dynamic;
      document.getElementById('object-value').hidden=!dynamic;form.elements.value.disabled=!dynamic;form.elements.value.required=dynamic;
    }
  };
  form.elements.type.onchange=updateType;updateType();
  form.onsubmit=async event=>{
    event.preventDefault();const button=form.querySelector('[type=submit]');button.disabled=true;
    try {
      const update=existing&&!clone;
      await consoleRequest(base+(update?'/'+encodeURIComponent(existing.name):'')+query,{method:update?'PUT':'POST',body:JSON.stringify(objectPayload(form,snapshot))});
      refreshCommitIndicator();if(generation===objectRequestId)await reload();
    } catch(e){if(generation===objectRequestId&&form.isConnected){document.getElementById('object-message').textContent=e.message;button.disabled=false;}}
  };
  form.elements.name.focus();
}
