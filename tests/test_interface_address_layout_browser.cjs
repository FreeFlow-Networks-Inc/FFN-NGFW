const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.TEST_BROWSER?{executablePath:process.env.TEST_BROWSER}:{})});
  try {
    const page=await browser.newPage();
    const root=path.join(__dirname,'../static'),html=fs.readFileSync(path.join(root,'index.html'),'utf8');
    const styles=html.match(/<style>([\s\S]*?)<\/style>/)[1]+['console-shell.css','modal-layers.css','config-objects.css','theme.css'].map(f=>fs.readFileSync(path.join(root,f),'utf8')).join('\n');
    const code=html.slice(html.indexOf('function interfaceAddressRow('),html.indexOf('function addSubinterfaceAddress('));
    for(const form of ['interface-form','subinterface-form'])for(const width of [1100,600,375])for(const theme of ['light','dark']) {
      await page.setViewportSize({width,height:800});
      await page.setContent(`<style>${styles}</style><div class="modal-overlay show"><div class="modal"><h3>Interface addresses</h3><div id="info-modal-body"><form id="${form}"><fieldset class="${form==='interface-form'?'ifm':'sif'}-fields"><table><thead><tr><th>Address / Prefix</th><th>Actions</th></tr></thead><tbody></tbody></table></fieldset><div class="settings-toolbar"><button type="button">Cancel</button><button type="button">OK</button></div></form></div></div></div>`);
      await page.evaluate(({code,theme})=>{
        document.documentElement.dataset.theme=theme;
        window._escSP=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
        window.eval(code);
        const objects=Array.from({length:100},(_,i)=>({name:'Address-object-with-a-long-name-'.repeat(4)+i,value:'2001:db8:1234:5678::1/64',family:6,scope:'shared'}));
        document.querySelector('tbody').append(interfaceAddressRow(6,objects[0].name,{address_choices:objects}));
      },{code,theme});
      const menu=page.getByLabel('IPv6 address object',{exact:true});
      await menu.selectOption({index:50});
      assert.equal(await page.getByLabel('IPv6 address with prefix',{exact:true}).inputValue(),await menu.inputValue());
      const geometry=await page.evaluate(()=>{
        const modal=document.querySelector('.modal'),cell=document.querySelector('td'),input=cell.querySelector('input'),select=cell.querySelector('select');
        const box=e=>e.getBoundingClientRect();
        return {overflow:modal.scrollWidth-modal.clientWidth,left:box(modal).left,right:box(modal).right,viewport:innerWidth,overlap:box(input).top<box(select).bottom,inputRight:box(input).right,cellRight:box(cell).right};
      });
      assert(geometry.overflow<=1,JSON.stringify({form,width,theme,geometry}));
      assert(geometry.left>=0&&geometry.right<=geometry.viewport);
      assert(!geometry.overlap&&geometry.inputRight<=geometry.cellRight);
      await menu.selectOption('');
      assert.equal(await page.getByLabel('IPv6 address with prefix',{exact:true}).getAttribute('readonly'),null);
      await page.getByLabel('IPv6 address with prefix',{exact:true}).fill('2001:db8::2/64');
      await page.getByRole('button',{name:'Cancel',exact:true}).click();
    }
    console.log('Interface and subinterface address layouts passed: long names, 100 objects, three viewport sizes, both themes, object and literal entry.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
