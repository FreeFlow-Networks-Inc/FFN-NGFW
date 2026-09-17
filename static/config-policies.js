/* SPDX-License-Identifier: GPL-2.0-or-later */
const policyKinds={security:'Security',nat:'NAT',qos:'QoS',pbf:'Policy Based Forwarding',decryption:'Decryption',
  'tunnel-inspect':'Tunnel Inspection','application-override':'Application Override',authentication:'Authentication',dos:'DoS Protection',sdwan:'SD-WAN'};
let policyWorkspaceGeneration=0;
function policySpec(row){return {name:row.name,description:row.description||'',enabled:row.enabled,settings:structuredClone(row.settings)};}
const policyOptionLabels={'universal':'Universal','intrazone':'Intrazone','interzone':'Interzone',
  allow:'Allow',deny:'Deny',drop:'Drop','reset-client':'Reset Client','reset-server':'Reset Server',
  'reset-both':'Reset Both Client and Server',none:'None',group:'Group',profiles:'Profiles',yes:'Yes',no:'No'};
const securityProfileKeys=['antivirus','vulnerability','anti-spyware','url-filtering','file-blocking','data-filtering','crucible-analysis'];
function policyUsage(r,fast=false){
  // Stored SQL counters have no agent identity, configuration generation or
  // observation time. Never present them as measured dataplane usage.
  if(fast||!r.usage?.available)return {count:'Unavailable',first:'Unavailable',last:'Unavailable',reason:r.usage?.reason||'No verified per-rule dataplane statistics'};
  const u=r.usage,date=v=>v?new Date(v).toLocaleString():(u.hit_count===0?'Never':'Unavailable');
  return {count:u.hit_count??'Unavailable',first:date(u.first_hit),last:date(u.last_hit),reason:u.source||'Dataplane'};
}
function securityCells(r,fast,source){
  const s=r.settings||{},text=v=>_escSP(Array.isArray(v)?v.join(', '):v??''),cell=v=>'<td>'+text(v)+'</td>';
  const u=policyUsage(r,fast),profiles=s['profile-mode']==='group'?'Group: '+s['profile-group']:
    securityProfileKeys.filter(k=>s[k]).map(k=>k+': '+s[k]).join('; ')||'None';
  const values=fast?[
    r.kind==='intrazone-default'?'Intrazone':r.kind==='interzone-default'?'Interzone':'—', '—',
    r.src_iface?'Interface: '+r.src_iface:'Any interface',r.src_ip,'—','—',
    r.dst_iface?'Interface: '+r.dst_iface:'Any interface',r.dst_ip,'—','—',
    (r.proto||'any')+' · '+(r.src_port||'*')+' → '+(r.dst_port||'*'),r.action,'—','—',
    'Fast path · stored / '+(r.vsys?'vsys'+r.vsys:'All virtual systems')
  ]:[policyOptionLabels[s['rule-type']]||s['rule-type']||'Universal',s.tag,s.from,s.source,s['source-user'],s['source-device'],
    s.to,s.destination,s['destination-device'],s.application,s.service,
    (policyOptionLabels[s.action]||s.action)+(s['icmp-unreachable']==='yes'?' + ICMP Unreachable':''),profiles,
    ['Start: '+(s['log-start']||'no'),'End: '+(s['log-end']||'yes'),'Forward: '+(s['log-setting']||'None')].join('; '),source+' · XML'];
  return values.map(cell).join('')+`<td title="${text(u.reason)}">${text(u.count)}</td><td>${text(u.last)}</td><td>${text(u.first)}</td>`;
}
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
    if (['lab-mgmt','mgmt'].includes(original.kind)) continue;
    if (Number(original.vsys || 0)!==0 && String(original.vsys)!==vsys) continue;
    const r={...original};
    r.is_immutable=!!(r.is_immutable || r.immutable || implicit(r) || r.kind && r.kind!=='user');
    rows.push({r,i:rows.length,fast:true,implicit:implicit(r)});
  }
  const rank = row => row.implicit?(row.r.kind==='intrazone-default'||row.r.name==='intrazone-default'?3:4):row.fast?2:1;
  return rows.sort((a,b)=>rank(a)-rank(b));
}
function fastPathRow(row, index, editable) {
  const r=row.r, text=v=>_escSP(v??''), locked=r.is_immutable, compilation=r.compilation;
  const state=locked?(row.implicit?'Implicit / read only':'System / read only'):r.enabled?'Enabled':'Disabled';
  const issue=compilation?(compilation.included?(compilation.compatible?'Compatible':'Blocked: '+compilation.issue):'Excluded'+(compilation.issue?': '+compilation.issue:'')):'Application unconfirmed';
  return `<tr data-fast-row="${text(r.id)}" class="${r.enabled?'':'policy-disabled'}"><td>${text(r.position)}</td>
    <td><button class="btn btn-sm" data-fast-view="${index}">${text(r.name || 'Rule '+r.id)}</button></td>
    <td>${text(state)}<br><span class="text-dim">${text(issue)}</span></td>
    ${securityCells(r,true,'')}
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
    ${['nat','qos','pbf','decryption'].includes(kind)?'<button class="btn" id="pw-plan" disabled>Preview policy plan</button><button class="btn" id="pw-test" disabled>Test policy match</button>':''}
    ${kind==='nat'?'<button class="btn" id="pw-nat-preview">NAT translation preview</button>':''}
    ${kind==='dos'?'<button class="btn" id="pw-dos">DoS engine controls</button>':''}
    <span class="text-dim">Candidate changes require Commit. New rules start disabled.</span></div>
    <div class="modal-overlay" id="pw-editor" role="dialog" aria-modal="true" aria-labelledby="object-title"></div>`;
  for(const id of ['pw-scope','pw-source','pw-refresh'])document.getElementById(id)[id==='pw-refresh'?'onclick':'onchange']=()=>loadPolicyWorkspace(c,kind);
  const legacy=(renderer)=>{
    ++policyWorkspaceGeneration;renderer(c);const button=document.createElement('button');button.className='btn';button.textContent='Back to '+policyKinds[kind];button.onclick=()=>renderPolicyWorkspace(c,kind);c.prepend(button);
  };
  if(kind==='dos')document.getElementById('pw-dos').onclick=()=>legacy(renderPolicyDDoS);
  if(kind==='nat')document.getElementById('pw-nat-preview').onclick=()=>previewNatWorkspace();
  loadPolicyWorkspace(c,kind);
}
async function loadPolicyWorkspace(c,kind){
  const generation=++policyWorkspaceGeneration,table=document.getElementById('pw-list'),editor=document.getElementById('pw-editor');
  const source=document.getElementById('pw-source').value,scope=document.getElementById('pw-scope').value;
  const add=document.getElementById('pw-add'),status=document.getElementById('pw-status');
  editor.classList.remove('show');table.textContent='Loading…';add.disabled=true;document.getElementById('pw-validate').disabled=true;
  for(const id of ['pw-plan','pw-test']){const button=document.getElementById(id);if(button)button.disabled=true;}
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
      'Control owner: '+data.runtime.owner+' · '+(data.runtime.valid?(data.runtime.runtime_state==='requires-dataplane-validation'?'Commit will validate the NAT dataplane before activation.':'No enabled XML policies to apply.'):data.runtime.blockers.length+' enabled rule(s) block activation.'))+
      (kind==='security'?(fastError?' · Fast-path and implicit rules unavailable: '+fastError:' · Implicit rules are always shown and read only. Fast-path rows show stored policy in both views.'):'')+
      ' Dataplane application is not confirmed.';
    add.disabled=!data.can_edit;add.onclick=()=>editPolicyWorkspace(data,url,null,()=>loadPolicyWorkspace(c,kind));
    for(const [id,test] of [['pw-plan',false],['pw-test',true]]){
      const button=document.getElementById(id);
      if(button){button.disabled=false;button.onclick=()=>inspectPolicyWorkspace(data,kind,source,scope,test);}
    }
    document.getElementById('pw-validate').disabled=!!xmlError;
    document.getElementById('pw-validate').onclick=async()=>{
      objectDialog(editor,'Policy Activation Validation','<pre id="pw-validation">Checking control daemon…</pre>');const target=document.getElementById('pw-validation');
      try{const report=await consoleRequest('/api/config/policies/status?source='+source);
        if(target.isConnected)target.textContent=report.blockers.length?report.blockers.map(b=>b.scope+' / '+policyKinds[b.kind]+' / '+b.name+': '+b.reason).join('\n'):report.runtime_state==='requires-dataplane-validation'?'NAT compilation passed. Commit still requires dataplane validation and an apply acknowledgment.':'No enabled XML policies. Disabled definitions can be committed; no runtime enforcement is claimed.';
      }catch(e){if(target.isConnected)target.textContent=e.message;}
    };
    const inventory=kind==='security'?securityInventory(data,fast,scope):data.entries.map((r,i)=>({r,i}));
    const draw=()=>{
      const q=document.getElementById('pw-search').value.toLowerCase();
      const rows=inventory.filter(row=>row.implicit || row.r.is_immutable || JSON.stringify(row.r).toLowerCase().includes(q));
      document.getElementById('pw-count').textContent=rows.length+' of '+inventory.length+' rules';
      const text=v=>_escSP(Array.isArray(v)?v.join(', '):v||'');
      const columns=kind==='security'?['Type','Tags','Source Zone','Source Address','Source User','Source Device','Destination Zone','Destination Address','Destination Device','Application','Service','Action','Profiles','Logging','Policy Source','Hit Count','Last Hit','First Hit']:['Source Zone / Address','Destination Zone / Address','Application / Service','Action','Tags'];
      table.innerHTML='<div class="table-wrap"><table><thead><tr><th>#</th><th>Name</th><th>State</th>'+columns.map(t=>'<th>'+t+'</th>').join('')+'<th>Actions</th></tr></thead><tbody>'+rows.map((row,index)=>{
        if(row.fast)return fastPathRow(row,index,source==='candidate'&&fast.can_edit);
        const {r,i}=row;
        const s=r.settings,locked=!data.can_edit||!r.editable||row.implicit;
        return `<tr class="${r.enabled?'':'policy-disabled'}"><td>${r.position}</td><td><button class="btn btn-sm" data-rule-edit="${i}">${text(r.name)}</button></td><td>${row.implicit?'Implicit / read only':r.editable?text(r.state):'Imported / read only'}</td>
          ${kind==='security'?securityCells(r,false,source):`<td>${text(s.from)}<br>${text(s.source)}</td><td>${text(s.to)}<br>${text(s.destination)}</td><td>${text(s.application)}<br>${text(s.service)}</td><td>${text(policyActionText(kind,s))}</td><td>${text(s.tag)}</td>`}<td>
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
  if(options.length)return `<label>${text(f.label)}<select name="${id}">${options.map(v=>`<option value="${text(v)}" ${v===value?'selected':''}>${text(policyOptionLabels[v]||v)}</option>`).join('')}</select></label>`;
  if(f.mode==='member-text'||f.key==='log-setting')return `<label>${text(f.label)}<select name="${id}"><option value="">None</option>${[...new Set([...(choices||[]),...(value?[value]:[])])].map(v=>`<option value="${text(v)}" ${v===value?'selected':''}>${text(v)}</option>`).join('')}</select></label>`;
  return `<label>${text(f.label)}<input name="${id}" value="${text(value)}" maxlength="1024" ${choices?.length?`list="${id}-choices"`:''}>${choices?.length?`<datalist id="${id}-choices">${choices.map(v=>`<option value="${text(v)}">`).join('')}</datalist>`:''}</label>`;
}
function policyPlanAction(kind,action){
  if(!action)return 'Unavailable';
  if(kind==='qos')return 'Assign class '+action.class;
  if(kind==='pbf')return action.type==='forward'?'Forward via '+action.interface+' · Next hop '+(action.next_hop||'directly connected'):action.type==='discard'?'Discard':'Use normal routing';
  if(kind==='decryption')return action.type==='no-decrypt'?'Do not decrypt':'Decrypt · '+action.inspection+(action.certificate?' · Certificate '+action.certificate:'')+(action.profile?' · Profile '+action.profile:'');
  const s=action.source_translation,d=action.destination_translation;
  return 'Source: '+(s.interface?'Interface '+s.interface:s.address?s.type+' '+s.address:'unchanged')+'; Destination: '+(d?d.address+(d.port?':'+d.port:''):'unchanged');
}
async function inspectPolicyWorkspace(snapshot,kind,source,scope,test){
  const box=document.getElementById('pw-editor'),text=v=>_escSP(v??''),base='/api/config/policies/'+kind;
  const query='?'+new URLSearchParams({source,scope}),title=policyKinds[kind]+(test?' Match Test':' Policy Plan');
  const choices=(key)=>['<option value="">Select…</option>',...(snapshot.choices[key]||[]).map(v=>'<option>'+text(v)+'</option>')].join('');
  const form=test?`<form id="pw-test-form" class="object-form">
    <p>Enter packet addresses and zones at this policy's lookup stage.${kind==='nat'?' Use the original packet and the destination zone from the original route lookup.':''} Identity and application are supplied test values.</p>
    <label>Source Zone<select name="from_zone" required>${choices('from')}</select></label><label>Destination Zone<select name="to_zone" required>${choices('to')}</select></label>
    <label>Source IPv4<input name="source" required placeholder="192.0.2.10"></label><label>Destination IPv4<input name="destination" required placeholder="198.51.100.20"></label>
    <label>Protocol<select name="protocol"><option>tcp</option><option>udp</option><option>icmp</option><option>other</option></select></label>
    <label>Source Port<input name="source_port" type="number" min="1" max="65535"></label><label>Destination Port<input name="destination_port" type="number" min="1" max="65535"></label>
    <label>Application (optional)<input name="application"></label><label>Source User (optional)<input name="source_user"></label>
    <label>Egress Interface (optional)<input name="egress_interface"></label>
    <div class="modal-footer"><button type="submit" class="btn btn-primary">Test Match</button><button type="button" class="btn" id="pw-test-close">Close</button></div></form>`:'';
  objectDialog(box,title,form+'<div id="pw-plan-result" role="status">'+(test?'No traffic is sent and no configuration is changed.':'Compiling policy…')+'</div>');
  const target=document.getElementById('pw-plan-result');
  const requirements=report=>'<p>'+text(report.enforcement)+'</p><ul>'+report.runtime_requirements.map(r=>'<li>'+text(r)+'</li>').join('')+'</ul><p class="text-dim">'+text(report.semantics)+'</p>';
  if(test){
    const f=document.getElementById('pw-test-form');
    document.getElementById('pw-test-close').onclick=()=>document.getElementById('object-close').click();
    f.elements.protocol.onchange=()=>{for(const key of ['source_port','destination_port'])f.elements[key].disabled=!['tcp','udp'].includes(f.elements.protocol.value);};
    f.onsubmit=async event=>{
      event.preventDefault();const packet=Object.fromEntries([...new FormData(f)].filter(([k,v])=>v!==''));
      for(const key of ['source_port','destination_port'])if(packet[key])packet[key]=Number(packet[key]);
      const button=f.querySelector('[type=submit]');button.disabled=true;target.textContent='Testing rule order…';
      try{
        const report=await consoleRequest(base+'/test'+query,{method:'POST',body:JSON.stringify({packet})});
        if(!target.isConnected)return;
        target.innerHTML='<p><strong>'+text(report.status==='matched'?'Matched: '+report.selected.name:report.status==='indeterminate'?'Cannot determine a match':'No matching enabled rule')+'</strong></p>'+
          (report.selected?'<p>'+text(policyPlanAction(kind,report.selected.action))+'</p>':'')+
          '<ol>'+report.trace.map(r=>'<li>'+text(r.name+': '+r.result+(r.reason?' — '+r.reason:''))+'</li>').join('')+'</ol>'+requirements(report);
      }catch(e){if(target.isConnected)target.textContent=e.message;}finally{button.disabled=false;}
    };
    return;
  }
  try{
    const report=await consoleRequest(base+'/preview'+query);if(!target.isConnected)return;
    target.innerHTML='<p><strong>'+text(report.valid?'Compilation passed':'Compilation blocked')+'</strong> · '+text(source)+' · '+text(scope)+'</p>'+requirements(report)+
      '<div class="table-wrap"><table><thead><tr><th>#</th><th>Rule</th><th>Resolved match</th><th>Intended action</th></tr></thead><tbody>'+report.plan.rules.map(r=>{
        const m=r.match;return '<tr><td>'+r.position+'</td><td>'+text(r.name)+'</td><td>'+text(m?m.from.join(', ')+' / '+m.source.join(', ')+' → '+m.to.join(', ')+' / '+m.destination.join(', '):r.error)+'</td><td>'+text(policyPlanAction(kind,r.action))+'</td></tr>';
      }).join('')+'</tbody></table></div><p>'+report.disabled_rules+' disabled rule(s) excluded.</p>';
  }catch(e){if(target.isConnected)target.textContent=e.message;}
}
async function previewNatWorkspace(){
  const editor=document.getElementById('pw-editor'),source=document.getElementById('pw-source').value;
  objectDialog(editor,'NAT translation preview','<div id="nat-preview" role="status">Reading NAT compilation and dataplane status…</div>');
  const target=document.getElementById('nat-preview'),text=v=>_escSP(v??'');
  try{
    const report=await consoleRequest('/api/config/nat/preview?source='+source);
    if(!target.isConnected)return;
    const state=report.runtime,active=state.applied&&state.digest===report.digest;
    const usage=new Map((state.usage||[]).map(u=>[JSON.stringify([u.scope,u.name]),u]));
    target.innerHTML=`<p><strong>${active?'This rule plan is applied':report.valid?'Compilation passed':'Compilation blocked'}</strong> · ${text(source)} configuration</p>
      <p>${state.available?'Dataplane: '+text(state.provider)+' · '+text(state.machine)+' · '+text(state.byteorder)+' endian':text(state.error||'Dataplane unavailable')}</p>
      <p>${report.commissioned?'Commit validates and applies this plan through the MP control daemon.':'NAT activation is not commissioned. Rules can be staged; enabled rules cannot be committed yet.'}</p>
      ${report.blockers.length?'<ul>'+report.blockers.map(b=>'<li>'+text(b.scope+' / '+b.name+': '+b.reason)+'</li>').join('')+'</ul>':''}
      <div class="table-wrap"><table><thead><tr><th>Rule</th><th>Original packet</th><th>Source translation</th><th>Destination translation</th></tr></thead><tbody>${report.plan.rules.map(r=>`<tr><td>${text(r.scope+' / '+r.name)}</td><td>${text(r.source.join(', '))} → ${text(r.destination.join(', '))}<br>${text(r.ingress.join(', '))} → ${text(r.egress.join(', '))}</td><td>${text(r.snat.type==='none'?'None':r.snat.interface?'Interface '+r.snat.interface:r.snat.type+' '+r.snat.address)}</td><td>${text(r.dnat?r.dnat.address+(r.dnat.port?':'+r.dnat.port:''):'None')}</td></tr>`).join('')}</tbody></table></div>
      <p class="text-dim">${report.disabled_rules} disabled rule(s) excluded. First matching NAT rule wins. NAT does not permit traffic through Security policy. Existing sessions retain their translations.</p>`;
    target.innerHTML+='<p><strong>NAT connection counters</strong></p><p>Counters measure initial connection packets, not total session traffic. They reset when a new NAT generation is applied.</p><ul>'+report.plan.rules.map(r=>{
      const u=usage.get(JSON.stringify([r.scope,r.name])),known=active&&u?.available;
      return '<li>'+text(r.scope+' / '+r.name)+': '+(known?text(u.packets)+' initial packets · '+text(u.bytes)+' bytes':'Unavailable')+'</li>';
    }).join('')+'</ul>';
  }catch(e){if(target.isConnected)target.textContent=e.message;}
}
function editPolicyWorkspace(snapshot,url,existing,reload,clone=false){
  const box=document.getElementById('pw-editor'),generation=policyWorkspaceGeneration;
  const row=existing?policySpec(existing):{name:'',description:'',enabled:false,settings:Object.fromEntries(snapshot.schema.fields.map(f=>[f.key,f.default??'']))};
  if(clone){row.name='';row.enabled=false;}
  const editable=snapshot.can_edit&&(!existing||existing.editable),tabs=[...new Set(['General',...snapshot.schema.fields.map(f=>f.tab)])];
  const security=snapshot.kind==='security',usage=policyUsage(clone?{}:existing||{});
  if(security)tabs.push('Rule Usage');
  const body=`<form id="pw-form" class="object-form"><div class="setup-tabs policy-tabs" role="tablist">${tabs.map((t,i)=>`<button class="${i===0?'active':''}" type="button" role="tab" aria-selected="${i===0}" data-tab="${i}">${_escSP(t)}</button>`).join('')}</div>
    ${tabs.map((tab,i)=>`<div data-panel="${i}" class="policy-panel" role="tabpanel" ${i?'hidden':''}>
      ${tab==='General'?`<label>Name<input name="rule-name" required maxlength="63" ${existing&&!clone?'readonly':''} value="${_escSP(row.name)}"></label>
      <label>Description<textarea name="rule-description" maxlength="1024">${_escSP(row.description)}</textarea></label>
      <label>Enabled<select name="rule-enabled"><option value="false" ${row.enabled?'':'selected'}>No</option><option value="true" ${row.enabled?'selected':''}>Yes</option></select></label>`:''}
      ${snapshot.schema.fields.filter(f=>f.tab===tab).map(f=>policyFieldHTML(f,row.settings[f.key]??f.default??'',snapshot.choices[f.key])).join('')}
      ${tab==='Rule Usage'?`<dl><dt>Hit Count</dt><dd>${_escSP(String(usage.count))}</dd><dt>Last Hit</dt><dd>${_escSP(usage.last)}</dd><dt>First Hit</dt><dd>${_escSP(usage.first)}</dd></dl><p>${_escSP(usage.reason)}</p><p>Usage is read only and is not copied when cloning a rule.</p>`:''}</div>`).join('')}
    <p class="text-dim">The control daemon stores this rule in candidate configuration. Activation requires a commissioned runtime provider; unsupported enabled rules block Commit.</p>
    <p id="pw-message" role="alert"></p><div class="modal-footer"><button type="submit" class="btn btn-primary" ${editable?'':'disabled'}>OK</button><button type="button" class="btn" id="pw-cancel">${editable?'Cancel':'Close'}</button></div></form>`;
  objectDialog(box,(clone?'Clone ':existing?(editable?'Edit ':'View '):'Add ')+snapshot.label+' Rule',body);
  const form=document.getElementById('pw-form');
  if(security){
    const mode=form.elements['pf-profile-mode'];
    const syncProfiles=()=>{
      for(const key of ['profile-group',...securityProfileKeys]){
        const control=form.elements['pf-'+key];
        control.closest('label').hidden=key==='profile-group'?mode.value!=='group':mode.value!=='profiles';
      }
    };
    mode.onchange=syncProfiles;syncProfiles();
  }
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
    if(security){
      const s=rule.settings;
      if(s['profile-mode']!=='group')s['profile-group']='';
      if(s['profile-mode']!=='profiles')for(const key of securityProfileKeys)s[key]='';
    }
    button.disabled=true;
    try{await consoleRequest(url,{method:'POST',body:JSON.stringify({action:existing&&!clone?'update':'create',revision:snapshot.revision,name:existing&&!clone?existing.name:undefined,rule})});
      refreshCommitIndicator();if(generation===policyWorkspaceGeneration)await reload();
    }catch(e){if(form.isConnected&&generation===policyWorkspaceGeneration){document.getElementById('pw-message').textContent=e.message;button.disabled=false;}}
  };
}
