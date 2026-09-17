/* Candidate-only editor for detected external management-plane interfaces. */
(() => {
  const el=(tag,text,parent)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(parent)parent.append(n);return n;};
  async function render(parent) {
    const root=el('section',undefined,parent);root.className='card';
    el('h3','External Management Interfaces',root);
    const message=el('p','Reading MP interfaces…',root);
    let result;
    try { result=await consoleRequest('/api/system/mp-interfaces');await loadConsoleRole(); }
    catch(e){if(root.isConnected)message.textContent=e.message;return;}
    if(!root.isConnected)return;
    message.textContent=result.ports.length?'Edit settings, select OK, then Commit to apply. Changing an active management address can disconnect this session.':'No external management interface provider is selected.';
    const wrap=el('div',undefined,root);wrap.className='table-wrap';
    const table=el('table',undefined,wrap),head=el('tr',undefined,el('thead',undefined,table));
    for(const title of ['Port','Link','Current IPv4','Candidate mode / address','MTU',''])el('th',title,head);
    const body=el('tbody',undefined,table);
    for(const port of result.ports){
      const row=el('tr',undefined,body);
      for(const value of [port.name,port.link?'Up':'Down',(port.addresses||[]).join(', ')||'—',
        port.candidate?port.candidate.mode+(port.candidate.address?' · '+port.candidate.address:''):'Current system configuration',port.candidate?.mtu||port.mtu])el('td',String(value),row);
      const b=el('button','Edit',el('td',undefined,row));b.className='btn btn-sm';b.disabled=!consoleCanWrite();
      b.onclick=()=>edit(port,()=>{root.remove();render(parent);});
    }
  }
  function edit(port,refresh){
    const overlay=el('div',undefined,document.body);overlay.className='modal-overlay';
    const modal=el('div',undefined,overlay);modal.className='modal';modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');modal.setAttribute('aria-label',port.name+' management interface');
    el('h3',port.name+' — Management Interface',modal);
    const form=el('form',undefined,modal), fields={};
    const current=port.candidate||{mode:port.enabled?(port.dhcp?'dhcp':'static'):'disabled',address:port.addresses?.[0]||'',gateway:port.gateway||'',dns:port.dns||[],mtu:port.mtu||1500,description:''};
    for(const [key,label] of [['description','Description'],['mode','Address mode'],['address','IPv4 address / prefix'],['gateway','Default gateway'],['dns','DNS servers (comma separated)'],['mtu','MTU']]){
      const group=el('div',undefined,form);group.className='form-group';
      const title=el('label',label,group), input=el(key==='mode'?'select':'input',undefined,group);input.id='mp-edit-'+key;title.htmlFor=input.id;fields[key]=input;
      if(key==='mode')for(const value of ['static','dhcp','disabled']){const option=el('option',value==='dhcp'?'DHCP':value==='static'?'Static':'Disabled',input);option.value=value;}
      if(key==='mtu'){input.type='number';input.min=576;input.max=9000;input.required=true;}
      if(key==='description')input.maxLength=128;
      input.value=key==='dns'?current.dns.join(', '):current[key];
    }
    const mode=()=>{for(const key of ['address','gateway'])fields[key].disabled=fields.mode.value!=='static';fields.address.required=fields.mode.value==='static';};mode();fields.mode.onchange=mode;
    const message=el('p','Changes remain in the candidate until Commit.',form);message.setAttribute('role','status');
    const actions=el('div',undefined,form);actions.className='form-actions';
    const cancel=el('button','Cancel',actions);cancel.type='button';cancel.className='btn';cancel.onclick=()=>overlay.remove();
    const ok=el('button','OK',actions);ok.type='submit';ok.className='btn btn-primary';
    form.onsubmit=async event=>{
      event.preventDefault();ok.disabled=true;cancel.disabled=true;
      const config=Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,v.value.trim()]));
      config.mtu=Number(config.mtu);config.dns=config.dns.split(',').map(v=>v.trim()).filter(Boolean);
      if(config.mode!=='static'){config.address='';config.gateway='';}
      try{
        const response=await consoleRequest('/api/system/mp-interfaces/'+encodeURIComponent(port.name),{method:'PUT',body:JSON.stringify({revision:port.revision,config})});
        if(response.status!=='candidate-updated')throw new Error('Candidate update was not confirmed');
        overlay.remove();refreshCommitIndicator();refresh();
      }catch(e){message.textContent=e.message;ok.disabled=false;cancel.disabled=false;}
    };
    overlay.classList.add('show');
  }
  window.ffnMpInterfaces={render};
})();
