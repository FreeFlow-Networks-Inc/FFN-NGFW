/* SPDX-License-Identifier: GPL-2.0-or-later */
let policyProfileGeneration=0;
function renderPolicyProfiles(container,kind,scope='vsys1',back=null){
  if(typeof refreshTimer!=='undefined'&&refreshTimer){clearInterval(refreshTimer);refreshTimer=null;}
  ++policyWorkspaceGeneration;
  const label=kind==='qos'?'QoS':'Decryption',text=v=>_escSP(v??'');
  container.innerHTML=`<div class="page-header"><h2>${label} Profiles</h2></div><div class="filters-bar">
    <label>Configuration <select id="pp-source"><option value="candidate">Candidate</option><option value="running">Running</option></select></label>
    <button class="btn" id="pp-refresh">Refresh</button><button class="btn btn-primary" id="pp-add" disabled>Add</button>${back?'<button class="btn" id="pp-back">Back to policy</button>':''}</div>
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
