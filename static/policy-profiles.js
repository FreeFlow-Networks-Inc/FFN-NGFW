/* SPDX-License-Identifier: GPL-2.0-or-later */
let policyProfileGeneration=0;
function renderPolicyProfiles(container,kind,scope='vsys1',back=null,backLabel='Back to policy'){
  if(typeof refreshTimer!=='undefined'&&refreshTimer){clearInterval(refreshTimer);refreshTimer=null;}
  ++policyWorkspaceGeneration;
  const label=kind==='qos'?'QoS':'Decryption',text=v=>_escSP(v??'');
  container.innerHTML=`<div class="page-header"><h2>${label} Profiles</h2></div><div class="filters-bar">
    <label>Configuration <select id="pp-source"><option value="candidate">Candidate</option><option value="running">Running</option></select></label>
    <button class="btn" id="pp-refresh">Refresh</button><button class="btn btn-primary" id="pp-add" disabled>Add</button>${back?'<button class="btn" id="pp-back">'+text(backLabel)+'</button>':''}</div>
    <p id="pp-status" role="status"></p><div id="pp-list" class="card"></div><div class="modal-overlay" id="pp-editor" role="dialog" aria-modal="true" aria-labelledby="object-title"></div>`;
  const list=document.getElementById('pp-list'),status=document.getElementById('pp-status'),add=document.getElementById('pp-add');
  const load=async()=>{
    const generation=++policyProfileGeneration,source=document.getElementById('pp-source').value;
    document.getElementById('pp-editor').classList.remove('show');add.disabled=true;list.textContent='Loading profiles…';
    const url='/api/config/policy-profiles/'+kind+'?'+new URLSearchParams({scope,source});
    try{
      const data=await consoleRequest(url);if(!list.isConnected||generation!==policyProfileGeneration)return;
      status.textContent=data.location+' · '+data.runtime+'. OK stages candidate changes; Commit is required.';
      add.disabled=!data.can_edit;add.onclick=()=>edit(null);
      list.innerHTML='<div class="table-wrap"><table><thead><tr><th>Name</th><th>Settings</th><th>Actions</th></tr></thead><tbody>'+data.entries.map((p,i)=>`<tr><td><button class="btn btn-sm" data-edit="${i}">${text(p.name)}</button></td><td>${kind==='qos'?text('Max: '+(p.settings['max-mbps']||'inherit')+' Mbps · Guaranteed: '+p.settings['guaranteed-mbps']+' Mbps · 8 classes'):text(p.settings['min-version']+' through '+p.settings['max-version'])}${p.editable?'':' · Imported / read only'}</td><td><button class="btn btn-sm" data-delete="${i}" ${data.can_edit&&p.editable?'':'disabled'}>Delete</button></td></tr>`).join('')+'</tbody></table></div>'+(data.entries.length?'':'<p>No profiles configured.</p>');
      list.querySelectorAll('[data-edit]').forEach(button=>button.onclick=()=>edit(data.entries[Number(button.dataset.edit)]));
      list.querySelectorAll('[data-delete]').forEach(button=>button.onclick=async()=>{
        const p=data.entries[Number(button.dataset.delete)];if(!confirm('Delete '+p.name+' from candidate configuration?'))return;
        button.disabled=true;
        try{await consoleRequest(url,{method:'POST',body:JSON.stringify({action:'delete',name:p.name,revision:data.revision})});refreshCommitIndicator();if(list.isConnected)await load();}
        catch(e){if(status.isConnected)status.textContent=e.message;button.disabled=false;}
      });
      function edit(existing){
        const s=structuredClone(existing?.settings||data.defaults),editable=data.can_edit&&(!existing||existing.editable);
        const number=(name,value)=>`<input name="${name}" type="number" min="0" max="1000000" step="any" required value="${text(value)}">`;
        let fields;
        if(kind==='qos')fields=`<label>Egress Maximum (Mbps)${number('max-mbps',s['max-mbps'])}</label><label>Egress Guaranteed (Mbps)${number('guaranteed-mbps',s['guaranteed-mbps'])}</label>
          <p>Zero maximum inherits the enclosing limit. Zero guaranteed bandwidth provides no guarantee. Classes are assigned by QoS policy; a scheduler and egress binding are required for enforcement.</p>
          <div class="table-wrap" style="grid-column:1 / -1"><table><thead><tr><th>Class</th><th>Priority</th><th>Maximum (Mbps)</th><th>Guaranteed (Mbps)</th></tr></thead><tbody>${s.classes.map(row=>`<tr><td>${row.id}</td><td><select name="class${row.id}.priority" aria-label="Class ${row.id} Priority">${data.priorities.map(p=>`<option ${p===row.priority?'selected':''}>${text(p)}</option>`).join('')}</select></td><td>${number('class'+row.id+'.max-mbps',row['max-mbps'])}</td><td>${number('class'+row.id+'.guaranteed-mbps',row['guaranteed-mbps'])}</td></tr>`).join('')}</tbody></table></div>`;
        else fields=data.fields.map(f=>`<label>${text(f.label)}<select name="${text(f.key)}">${f.options.map(v=>`<option ${v===s[f.key]?'selected':''}>${text(v)}</option>`).join('')}</select></label>`).join('')+'<p>Certificate checks for traffic excluded from decryption require visible handshake metadata. A profile does not enable TLS interception by itself.</p>';
        objectDialog(document.getElementById('pp-editor'),(existing?'Edit ':'Add ')+label+' Profile',`<form id="pp-form" class="object-form"><label>Name<input name="name" maxlength="63" required ${existing?'readonly':''} value="${text(existing?.name||'')}"></label>${fields}<p>${existing&&!existing.editable?'Unsupported imported fields are preserved; only recognized settings are shown.':''}</p><p id="pp-message" role="alert"></p><div class="modal-footer"><button type="submit" class="btn btn-primary" ${editable?'':'disabled'}>OK</button><button type="button" class="btn" id="pp-cancel">${editable?'Cancel':'Close'}</button></div></form>`);
        const form=document.getElementById('pp-form');
        if(!editable)for(const input of form.querySelectorAll('input,select'))input.disabled=true;
        document.getElementById('pp-cancel').onclick=()=>document.getElementById('object-close').click();
        form.onsubmit=async event=>{
          event.preventDefault();if(!editable)return;const values=new FormData(form),settings=structuredClone(s),button=form.querySelector('[type=submit]');
          if(kind==='qos'){
            for(const key of ['max-mbps','guaranteed-mbps'])settings[key]=Number(values.get(key));
            for(const row of settings.classes){row.priority=values.get('class'+row.id+'.priority');for(const key of ['max-mbps','guaranteed-mbps'])row[key]=Number(values.get('class'+row.id+'.'+key));}
          }else for(const f of data.fields)settings[f.key]=values.get(f.key);
          button.disabled=true;
          try{await consoleRequest(url,{method:'POST',body:JSON.stringify({action:existing?'update':'create',name:existing?.name,revision:data.revision,profile:{name:values.get('name'),settings}})});refreshCommitIndicator();if(list.isConnected)await load();}
          catch(e){if(form.isConnected)document.getElementById('pp-message').textContent=e.message;button.disabled=false;}
        };
      }
    }catch(e){if(list.isConnected&&generation===policyProfileGeneration){status.textContent=e.message;list.textContent='Profiles unavailable.';}}
  };
  document.getElementById('pp-source').onchange=load;document.getElementById('pp-refresh').onclick=load;
  if(back)document.getElementById('pp-back').onclick=back;load();
}

let qosInterfaceGeneration=0;
function renderQoSInterfaces(container){
  if(typeof refreshTimer!=='undefined'&&refreshTimer){clearInterval(refreshTimer);refreshTimer=null;}
  const text=v=>_escSP(v??'');
  container.innerHTML=`<div class="page-header"><h2>QoS Interfaces</h2></div><div class="filters-bar">
    <label>Configuration <select id="qi-source"><option value="candidate">Candidate</option><option value="running">Running</option></select></label>
    <button class="btn" id="qi-refresh">Refresh</button><button class="btn btn-primary" id="qi-add" disabled>Add</button><button class="btn" id="qi-profiles">QoS Profiles</button><button class="btn" id="qi-policies">Classification Rules</button></div>
    <p id="qi-status" role="status"></p><div class="card" id="qi-list"></div><div class="modal-overlay" id="qi-editor" role="dialog" aria-modal="true" aria-labelledby="object-title"></div>`;
  const list=document.getElementById('qi-list'),status=document.getElementById('qi-status'),add=document.getElementById('qi-add');
  const load=async()=>{
    const generation=++qosInterfaceGeneration,source=document.getElementById('qi-source').value,url='/api/config/qos/interfaces?source='+source;
    add.disabled=true;list.textContent='Loading QoS interfaces…';status.textContent='';document.getElementById('qi-editor').classList.remove('show');
    try{
      const data=await consoleRequest(url);if(!list.isConnected||generation!==qosInterfaceGeneration)return;
      status.textContent=data.plan.runtime+'. OK stages candidate changes; no bandwidth settings are applied by this editor.';
      add.disabled=!data.can_edit;add.onclick=()=>edit(null);
      const budgets=new Map(data.plan.interfaces.map(p=>[p.interface,p])),errors=new Map(data.plan.blockers.map(p=>[p.interface,p.reason]));
      list.innerHTML='<div class="table-wrap"><table><thead><tr><th>Interface</th><th>Profile</th><th>Requested State</th><th>Effective Maximum</th><th>Class Guarantees</th><th>Default Class</th><th>Validation / Actions</th></tr></thead><tbody>'+data.entries.map((e,i)=>{
        const budget=budgets.get(e.interface);
        return `<tr><td><button class="btn btn-sm" data-edit="${i}">${text(e.interface)}</button></td><td>${text(e.profile)}</td><td>${e.enabled?'Enabled — activation blocked':'Disabled'}</td><td>${budget?text(budget.max_mbps)+' Mbps':'Unavailable'}</td><td>${budget?text(budget.guaranteed_mbps)+' Mbps':'Unavailable'}</td><td>${text(e['default-class'])}</td><td>${text(errors.get(e.interface)||'Budget valid')} ${e.editable?'':' · Imported / read only'} <button class="btn btn-sm" data-budget="${i}" ${budget?'':'disabled'}>Class Budget</button> <button class="btn btn-sm" data-delete="${i}" ${data.can_edit&&e.editable?'':'disabled'}>Delete</button></td></tr>`;
      }).join('')+'</tbody></table></div>'+(data.entries.length?'':'<p>No QoS interfaces configured. Add a data interface and attach an eight-class QoS profile.</p>');
      list.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>edit(data.entries[Number(b.dataset.edit)]));
      list.querySelectorAll('[data-budget]').forEach(b=>b.onclick=()=>{
        const p=budgets.get(data.entries[Number(b.dataset.budget)].interface);
        objectDialog(document.getElementById('qi-editor'),'Class Budget — '+p.interface,
          `<p>Egress maximum: ${text(p.max_mbps)} Mbps · Unreserved capacity: ${text(p.unreserved_mbps)} Mbps · Default class: ${p.default_class}</p><p>Calculated configuration only. Queue occupancy, counters and scheduler application are unavailable.</p><div class="table-wrap"><table id="qi-classes"><thead><tr><th>Class</th><th>Priority</th><th>Maximum (Mbps)</th><th>Guaranteed (Mbps)</th></tr></thead><tbody>${p.classes.map(c=>`<tr><td>${c.id}</td><td>${text(c.priority)}</td><td>${text(c['max-mbps'])}</td><td>${text(c['guaranteed-mbps'])}</td></tr>`).join('')}</tbody></table></div><div class="modal-footer"><button class="btn" onclick="document.getElementById('object-close').click()">Close</button></div>`);
      });
      list.querySelectorAll('[data-delete]').forEach(b=>b.onclick=async()=>{
        const e=data.entries[Number(b.dataset.delete)];if(!confirm('Remove QoS attachment for '+e.interface+' from candidate?'))return;
        b.disabled=true;
        try{await consoleRequest(url,{method:'POST',body:JSON.stringify({action:'delete',name:e.interface,revision:data.revision})});refreshCommitIndicator();if(list.isConnected)await load();}
        catch(error){if(status.isConnected)status.textContent=error.message;b.disabled=false;}
      });
      function edit(existing){
        const editable=data.can_edit&&(!existing||existing.editable),spec=existing||{interface:'',...data.defaults};
        const options=(values,selected)=>['',...new Set([...values,...(selected?[selected]:[])])].map(v=>`<option value="${text(v)}" ${v===selected?'selected':''}>${text(v||'Select…')}</option>`).join('');
        objectDialog(document.getElementById('qi-editor'),(existing?'Edit':'Add')+' QoS Interface',`<form class="object-form" id="qi-form">
          <label>Data Interface<select name="interface" required ${existing?'disabled':''}>${options(data.interfaces,spec.interface)}</select></label>
          <label>QoS Profile<select name="profile" required>${options(data.profiles,spec.profile)}</select></label>
          <label>Egress Maximum (Mbps)<input name="max-mbps" type="number" min="0.000001" max="1000000" step="any" required value="${text(spec['max-mbps'])}"></label>
          <label>Default Class<select name="default-class">${Array.from({length:8},(_,i)=>`<option value="${i+1}" ${i+1===spec['default-class']?'selected':''}>${i+1}</option>`).join('')}</select></label>
          <label>Requested State<select name="enabled"><option value="no" ${!spec.enabled?'selected':''}>Disabled</option><option value="yes" ${spec.enabled?'selected':''}>Enabled</option></select></label>
          <p>Profiles apply to egress traffic. The default class receives traffic with no classification match. Enabled attachments require a commissioned scheduler before Commit. Management ports are excluded.</p><p id="qi-message" role="alert"></p>
          <div class="modal-footer"><button type="submit" class="btn btn-primary" ${editable?'':'disabled'}>OK</button><button type="button" class="btn" id="qi-cancel">${editable?'Cancel':'Close'}</button></div></form>`);
        const form=document.getElementById('qi-form');if(!editable)form.querySelectorAll('input,select').forEach(e=>e.disabled=true);
        document.getElementById('qi-cancel').onclick=()=>document.getElementById('object-close').click();
        form.onsubmit=async event=>{
          event.preventDefault();if(!editable)return;const values=new FormData(form),button=form.querySelector('[type=submit]');button.disabled=true;
          const attachment={interface:existing?.interface||values.get('interface'),profile:values.get('profile'),enabled:values.get('enabled')==='yes','max-mbps':Number(values.get('max-mbps')),'default-class':Number(values.get('default-class'))};
          try{await consoleRequest(url,{method:'POST',body:JSON.stringify({action:existing?'update':'create',name:existing?.interface,revision:data.revision,attachment})});refreshCommitIndicator();if(list.isConnected)await load();}
          catch(error){if(form.isConnected)document.getElementById('qi-message').textContent=error.message;button.disabled=false;}
        };
      }
    }catch(error){if(list.isConnected&&generation===qosInterfaceGeneration){status.textContent=error.message;list.textContent='QoS interfaces unavailable.';}}
  };
  document.getElementById('qi-source').onchange=load;document.getElementById('qi-refresh').onclick=load;
  document.getElementById('qi-profiles').onclick=()=>renderPolicyProfiles(container,'qos','vsys1',()=>renderQoSInterfaces(container),'Back to QoS Interfaces');
  document.getElementById('qi-policies').onclick=()=>switchSubPage('policy-qos');load();
}
