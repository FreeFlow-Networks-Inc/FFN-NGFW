"""Revision-checked parent interface editor; all changes stay in candidate XML."""
import copy
import ipaddress
import xml.etree.ElementTree as ET
from typing import Literal
from fastapi import Depends
from pydantic import BaseModel, Field
from ffn_config_subinterfaces import SubinterfaceStore, PARENT
from ffn_config_zones import digest, fail

MODES=('layer3','layer2','virtual-wire','tap','aggregate-group','ha','decrypt-mirror')

class InterfaceEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    name: str
    vsys: str = 'vsys1'
    mode: Literal['none','layer3','layer2','virtual-wire','tap','aggregate-group','ha','decrypt-mirror'] = 'none'
    ip_addresses: list[str] = Field(default_factory=list,max_length=128)
    dhcp_client: bool = False
    dhcp_default_route: bool = True
    dhcp_route_metric: int = Field(default=10,ge=1,le=65535)
    ipv6_enabled: bool = False
    mtu: int | None = Field(default=None,ge=576,le=9216)
    interface_management_profile: str = Field(default='',max_length=63)
    zone: str = Field(default='',max_length=63)
    virtual_router: str = Field(default='',max_length=63)
    vlan: str = Field(default='',max_length=63)
    aggregate_group: str = Field(default='',max_length=63)
    link_speed: Literal['auto','10','100','1000','2500','5000','10000','25000','40000','50000','100000','200000','400000'] = 'auto'
    link_duplex: Literal['auto','full','half'] = 'auto'
    link_state: Literal['auto','up','down'] = 'auto'
    lldp_enabled: bool = False
    lldp_profile: str = Field(default='',max_length=63)
    bond_mode: Literal['active-backup','802.3ad','balance-rr','balance-xor','balance-tlb','balance-alb','broadcast'] = 'active-backup'
    bond_miimon_ms: int = Field(default=100,ge=1,le=60000)
    comment: str = Field(default='',max_length=1024)
    class Config:
        extra='forbid'

def child(parent,tag):
    node=parent.find(tag)
    return node if node is not None else ET.SubElement(parent,tag)

def scalar(parent,tag,value):
    nodes=parent.findall(tag)
    if len(nodes)>1 or any(n.attrib or len(n) for n in nodes):
        fail('Unsupported imported setting: '+tag,409)
    for node in nodes: parent.remove(node)
    if value is not None and value!='': ET.SubElement(parent,tag).text=str(value)

class InterfaceStore(SubinterfaceStore):
    def entry(self,dev,name):
        if not PARENT.fullmatch(name): fail('Select a physical or aggregate parent interface')
        kind='aggregate-ethernet' if name.startswith('ae') else 'ethernet'
        entries=[e for e in dev.findall('network/interface/'+kind+'/entry') if e.get('name')==name]
        if len(entries)>1: fail('Duplicate interface entries require repair',409)
        return (entries[0] if entries else None),kind

    def shape(self,entry,name):
        node=entry if entry is not None else ET.Element('entry',name=name)
        modes=[m for m in MODES if node.find(m) is not None]
        if len(modes)>1: fail('Conflicting interface modes require repair',409)
        mode=modes[0] if modes else 'none'
        values={'name':name,'mode':mode,'ip_addresses':[e.get('name','') for e in node.findall('layer3/ip/entry')],
                'sub_interfaces':[e.get('name','') for e in node.findall(mode+'/units/entry')],
                'dhcp_client':node.findtext('layer3/dhcp-client/enable')=='yes',
                'dhcp_default_route':node.findtext('layer3/dhcp-client/create-default-route','yes')=='yes',
                'dhcp_route_metric':node.findtext('layer3/dhcp-client/default-route-metric','10'),
                'ipv6_enabled':node.findtext('layer3/ipv6/enabled')=='yes',
                'lldp_enabled':node.findtext('lldp/enable')=='yes'}
        paths={'comment':('comment',''),'mtu':('layer3/mtu',''),
               'interface_management_profile':('layer3/interface-management-profile',''),
               'aggregate_group':('aggregate-group',''),'link_speed':('link-speed','auto'),
               'link_duplex':('link-duplex','auto'),'link_state':('link-state','auto'),
               'lldp_profile':('lldp/profile',''),'bond_mode':('layer3/bond/mode','active-backup'),
               'bond_miimon_ms':('layer3/bond/miimon','100')}
        values.update({key:node.findtext(path,default) for key,(path,default) in paths.items()})
        if mode=='none': values['link_state']='down'
        return values

    def listing(self,name,vsys,source='candidate'):
        _,dev,owner,revision=self.load(vsys,source)
        entry,kind=self.entry(dev,name)
        # Use actual ownership even when the caller has an old interface grid.
        owners=[e for e in dev.findall('vsys/entry') if any(m.text==name for m in e.findall('import/network/interface/member'))]
        if len(owners)>1: fail('Interface imported into multiple virtual systems',409)
        if owners: owner=owners[0];vsys=owner.get('name')
        row=self.shape(entry,name)
        groups=self.memberships(dev,owner,row['mode'])
        for field,group in groups.items():
            names=self.membership_names(group,name)
            if len(names)>1: fail('Conflicting '+field+' memberships require repair',409)
            row[field]=names[0] if names else ''
        return {'revision':revision,'source':source,'vsys':vsys,'exists':entry is not None,'kind':kind,'entry':row,
                'zone_choices':{mode:[e.get('name') for e in owner.findall('zone/entry') if e.get('name') and e.find('network/'+mode) is not None] for mode in MODES},
                'virtual_router_choices':[e.get('name') for e in dev.findall('network/virtual-router/entry') if e.get('name')],
                'vlan_choices':[e.get('name') for e in dev.findall('network/vlan/entry') if e.get('name')],
                'aggregate_choices':[e.get('name') for e in dev.findall('network/interface/aggregate-ethernet/entry') if e.get('name')],
                'management_profile_choices':[e.get('name') for e in dev.findall('network/profiles/interface-management-profile/entry') if e.get('name')],
                'lldp_profile_choices':[e.get('name') for e in dev.findall('network/profiles/lldp-profile/entry') if e.get('name')]}

    def mutate(self,spec,user,physical_names):
        if user.get('role') not in ('admin','superuser'): fail('Requires admin or superuser role',403)
        lock=self.manager.lock_status()
        if lock['locked'] and lock.get('holder')!=user['username']: fail('Configuration locked by another administrator',423)
        root,dev,owner,revision=self.load(spec.vsys)
        if revision!=spec.revision: fail('Candidate changed. Refresh and review before retrying.',409)
        entry,kind=self.entry(dev,spec.name)
        if kind=='ethernet' and spec.name not in physical_names: fail('Interface is not an available data port',422)
        for other in dev.findall('vsys/entry'):
            if other is not owner and any(m.text==spec.name for m in other.findall('import/network/interface/member')):
                fail('Interface belongs to another virtual system',409)
        old=self.shape(entry,spec.name)
        if spec.mode!=old['mode'] and entry is not None:
            if old['sub_interfaces']: fail('Remove subinterfaces before changing the parent mode',409)
            old_mode=entry.find(old['mode'])
            known={'ip','dhcp-client','ipv6','mtu','interface-management-profile','bond'} if old['mode']=='layer3' else set()
            if old_mode is not None and any(n.tag not in known for n in old_mode):
                fail('Mode change would discard additional imported settings',409)
            if old['mode']=='layer3' and any(n.text==spec.name for n in root.findall('.//static-route/entry/interface')):
                fail('Remove static-route interface references before changing mode',409)
        if spec.mode!='layer3' and (spec.ip_addresses or spec.mtu is not None or spec.interface_management_profile or spec.dhcp_client or spec.virtual_router or spec.ipv6_enabled):
            fail('IP, routing and management settings require Layer 3')
        if spec.mode!='layer2' and spec.vlan: fail('VLAN membership requires Layer 2')
        if spec.mode not in ('layer3','layer2','tap','virtual-wire') and spec.zone: fail('This mode does not accept a security zone')
        if kind=='aggregate-ethernet' and spec.mode not in ('none','layer2','layer3'): fail('Aggregate interfaces support None, Layer 2 or Layer 3')
        aggregates=[e.get('name') for e in dev.findall('network/interface/aggregate-ethernet/entry')]
        if spec.mode=='aggregate-group' and (kind!='ethernet' or spec.aggregate_group not in aggregates): fail('Select an existing aggregate interface')
        if spec.mode!='aggregate-group' and spec.aggregate_group: fail('Aggregate membership requires Aggregate Group mode')
        addresses=[]
        for address in spec.ip_addresses:
            try:
                if '/' not in address: raise ValueError()
                address=str(ipaddress.ip_interface(address))
            except ValueError: fail('IP addresses must be valid IPv4 or IPv6 CIDRs')
            if address not in addresses: addresses.append(address)
        if spec.dhcp_client and addresses: fail('DHCP requires no static interface addresses')
        if (spec.ipv6_enabled or any(':' in a for a in addresses)) and spec.mtu is not None and spec.mtu<1280: fail('IPv6 requires MTU of at least 1280')
        for field,path in [('interface_management_profile','interface-management-profile'),('lldp_profile','lldp-profile')]:
            value=getattr(spec,field)
            profiles=[e.get('name') for e in dev.findall('network/profiles/'+path+'/entry')]
            if value and value not in profiles and value!=old[field]: fail('Select an existing '+field.replace('_',' '))
        for value in (spec.comment,spec.interface_management_profile,spec.lldp_profile):
            if any(not(c in '\t\n\r' or 0x20<=ord(c)<=0xD7FF or 0xE000<=ord(c)<=0xFFFD or 0x10000<=ord(c)<=0x10FFFF) for c in value): fail('Invalid XML characters')
        # Work on the parsed snapshot; publish only after every operation validates.
        node=copy.deepcopy(entry) if entry is not None else ET.Element('entry',name=spec.name)
        if old['mode']!=spec.mode:
            for mode in MODES:
                for n in node.findall(mode): node.remove(n)
        scalar(node,'comment',spec.comment)
        scalar(node,'link-state','down' if spec.mode=='none' else (spec.link_state if spec.link_state!='auto' else None))
        scalar(node,'link-speed',spec.link_speed if spec.link_speed!='auto' else None)
        scalar(node,'link-duplex',spec.link_duplex if spec.link_duplex!='auto' else None)
        lldp=child(node,'lldp')
        scalar(lldp,'enable','yes' if spec.lldp_enabled and spec.mode!='none' else 'no')
        scalar(lldp,'profile',spec.lldp_profile)
        if spec.mode=='aggregate-group': scalar(node,'aggregate-group',spec.aggregate_group)
        elif spec.mode!='none':
            mode=child(node,spec.mode)
            if spec.mode=='layer3':
                ip=mode.find('ip')
                if ip is not None:
                    if ip.attrib or any(e.tag!='entry' or set(e.attrib)!={'name'} or len(e) for e in ip): fail('Imported IP settings cannot be safely replaced',409)
                    mode.remove(ip)
                if addresses:
                    ip=ET.SubElement(mode,'ip')
                    for address in addresses: ET.SubElement(ip,'entry',name=address)
                dhcp=mode.find('dhcp-client')
                if spec.dhcp_client:
                    dhcp=child(mode,'dhcp-client')
                    for tag,value in [('enable','yes'),('create-default-route','yes' if spec.dhcp_default_route else 'no'),('default-route-metric',spec.dhcp_route_metric)]: scalar(dhcp,tag,value)
                elif dhcp is not None: scalar(dhcp,'enable','no')
                if spec.ipv6_enabled or mode.find('ipv6') is not None:
                    scalar(child(mode,'ipv6'),'enabled','yes' if spec.ipv6_enabled else 'no')
                scalar(mode,'mtu',spec.mtu)
                scalar(mode,'interface-management-profile',spec.interface_management_profile)
                if kind=='aggregate-ethernet':
                    bond=child(mode,'bond');scalar(bond,'mode',spec.bond_mode);scalar(bond,'miimon',spec.bond_miimon_ms)
        # Clear former memberships on mode changes, without touching child memberships.
        if old['mode']!=spec.mode:
            for group in self.memberships(dev,owner,old['mode']).values(): self.set_membership(group,spec.name,'','former mode')
        for field,group in self.memberships(dev,owner,spec.mode).items(): self.set_membership(group,spec.name,getattr(spec,field),field)
        parent=child(child(child(dev,'network'),'interface'),kind)
        if entry is not None: index=list(parent).index(entry);parent.remove(entry);parent.insert(index,node)
        else: parent.append(node)
        imported=child(child(child(owner,'import'),'network'),'interface')
        if not any(m.text==spec.name for m in imported.findall('member')): ET.SubElement(imported,'member').text=spec.name
        if not lock['locked'] and not self.manager.acquire_lock(user['username'],'editing interfaces'): fail('Could not acquire configuration lock',423)
        self.manager._save(root,self.candidate)
        return {'status':'updated' if entry is not None else 'created','name':spec.name,'requires_commit':True,'revision':digest(self.manager.get_candidate())}

def install(app,current_user,audit,manager,candidate,physical_names):
    @app.get('/api/config/interfaces')
    async def listing(name: str,vsys: str='vsys1',source: str='candidate',user=Depends(current_user)):
        if source not in ('candidate','running'): fail('Source must be candidate or running')
        result=InterfaceStore(manager,candidate).listing(name,vsys,source)
        result['can_edit']=source=='candidate' and user.get('role') in ('admin','superuser')
        return result

    @app.put('/api/config/interfaces')
    async def save(spec: InterfaceEdit,user=Depends(current_user)):
        result=InterfaceStore(manager,candidate).mutate(spec,user,physical_names())
        await audit(user,'interface_edit',spec.name)
        return result
