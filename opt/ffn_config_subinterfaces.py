"""Candidate-only VLAN subinterface editing with revision and reference checks."""
import ipaddress
import copy
import re
import xml.etree.ElementTree as ET
from typing import Literal
from pydantic import BaseModel, Field
from ffn_config_zones import ZoneStore, fail, digest

PARENT = re.compile(r'(ethernet[0-9]+/[0-9]+|ae[0-9]+)\Z')
class SubinterfaceEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    parent: str
    unit: int = Field(ge=1,le=9999)
    tag: int = Field(ge=1,le=4094)
    mode: Literal['layer2','layer3'] = 'layer3'
    vsys: str = 'vsys1'
    ip_addresses: list[str] = Field(default_factory=list,max_length=128)
    interface_management_profile: str = Field(default='',max_length=63)
    mtu: int | None = Field(default=None,ge=576,le=9216)
    comment: str = Field(default='',max_length=1024)
    class Config:
        extra = 'forbid'

class SubinterfaceStore(ZoneStore):
    def parent_entry(self, dev, parent):
        if not PARENT.fullmatch(parent): fail('Invalid parent interface name')
        kind = 'aggregate-ethernet' if parent.startswith('ae') else 'ethernet'
        entries = [e for e in dev.findall('network/interface/'+kind+'/entry') if e.get('name')==parent]
        if len(entries)!=1: fail('Parent must be an existing, uniquely configured interface',404)
        modes = [m for m in ('layer2','layer3') if entries[0].find(m) is not None]
        if len(modes)!=1: fail('Parent must be Layer 2 or Layer 3',409)
        return entries[0],modes[0]

    def describe(self, entry, parent, mode):
        name=entry.get('name','')
        suffix=name.removeprefix(parent+'.')
        known={'tag','ip','interface-management-profile','mtu','comment','adjust-tcp-mss'}
        editable = suffix.isdigit() and 1<=int(suffix)<=9999 and all(n.tag in known for n in entry)
        editable &= len({n.tag for n in entry})==len(entry)
        tag=entry.findtext('tag','')
        editable &= tag.isdigit() and 1<=int(tag)<=4094
        for n in entry:
            if n.tag=='adjust-tcp-mss': continue
            if n.tag=='ip': editable &= not n.attrib and all(c.tag=='entry' and set(c.attrib)=={'name'} and len(c)==0 for c in n)
            else: editable &= not n.attrib and len(n)==0
        return {'name':name,'unit':int(suffix) if suffix.isdigit() else None,'parent':parent,'mode':mode,
                'tag':entry.findtext('tag',''),'ip_addresses':[n.get('name','') for n in entry.findall('ip/entry')],
                'mtu':entry.findtext('mtu',''),'interface_management_profile':entry.findtext('interface-management-profile',''),
                'comment':entry.findtext('comment',''),'editable':bool(editable)}

    def listing(self,parent,vsys,source='candidate'):
        _,dev,_,revision=self.load(vsys,source)
        node,mode=self.parent_entry(dev,parent)
        return {'parent':parent,'vsys':vsys,'source':source,'mode':mode,'revision':revision,
                'entries':[self.describe(e,parent,mode) for e in node.findall(mode+'/units/entry')],
                'runtime_note':'Changes require Commit. VLAN forwarding support depends on the selected platform; check Tasks for the apply result.'}

    def mutate(self,parent,unit,vsys,revision,user,spec=None,create=False):
        if user.get('role') not in ('admin','superuser'): fail('Requires admin or superuser role',403)
        if not 1<=unit<=9999: fail('Subinterface ID must be 1–9999')
        lock=self.manager.lock_status()
        if lock['locked'] and lock.get('holder')!=user['username']: fail('Configuration locked by another administrator',423)
        root,dev,owner,current=self.load(vsys)
        if revision!=current: fail('Candidate changed. Refresh and review before retrying.',409)
        node,mode=self.parent_entry(dev,parent)
        name=f'{parent}.{unit}'
        for other in dev.findall('vsys/entry'):
            if other is owner: continue
            imported=[e.text for e in other.findall('import/network/interface/member')]
            if name in imported or parent in imported: fail('Interface belongs to another virtual system',409)
        units=node.find(mode+'/units')
        found=[e for e in node.findall(mode+'/units/entry') if e.get('name')==name]
        if len(found)>1: fail('Duplicate subinterface entries must be repaired first',409)
        entry=found[0] if found else None
        if create and entry is not None: fail('Subinterface already exists',409)
        if not create and entry is None: fail('Subinterface not found',404)
        if spec is None:
            imports=set(e for e in root.findall('.//vsys/entry/import/network/interface/member'))
            if any(e.text==name and e not in imports for e in root.findall('.//member')):
                fail('Subinterface is referenced by a zone, router, or another configuration object',409)
            units.remove(entry)
            for imported in owner.findall('import/network/interface'):
                for member in list(imported):
                    if member.tag=='member' and member.text==name: imported.remove(member)
        else:
            if (spec.parent,spec.unit,spec.vsys)!=(parent,unit,vsys): fail('Interface identity does not match request')
            if spec.mode!=mode: fail('Subinterface mode must match the parent')
            if entry is not None and not self.describe(entry,parent,mode)['editable']:
                fail('Imported subinterface contains settings this editor cannot safely replace',409)
            for sibling in node.findall(mode+'/units/entry'):
                tag=sibling.findtext('tag','')
                if sibling is not entry and tag.isdigit() and int(tag)==spec.tag: fail('VLAN tag already exists on this parent',409)
            if mode=='layer2' and (spec.ip_addresses or spec.mtu is not None or spec.interface_management_profile):
                fail('Layer 2 subinterfaces cannot have IP addresses, MTU overrides, or management profiles in this editor')
            addresses=[]
            for value in spec.ip_addresses:
                try: value=str(ipaddress.ip_interface(value))
                except ValueError: fail('IP addresses must be valid IPv4 or IPv6 CIDRs')
                if value not in addresses: addresses.append(value)
            if any(':' in a for a in addresses) and spec.mtu is not None and spec.mtu<1280: fail('IPv6 requires MTU of at least 1280')
            for text in [spec.comment,spec.interface_management_profile]:
                if any(not(c in '\t\n\r' or 0x20<=ord(c)<=0xD7FF or 0xE000<=ord(c)<=0xFFFD or 0x10000<=ord(c)<=0x10FFFF) for c in text): fail('Invalid XML characters')
            replacement=ET.Element('entry',name=name)
            if entry is not None and entry.find('adjust-tcp-mss') is not None:
                replacement.append(copy.deepcopy(entry.find('adjust-tcp-mss')))
            ET.SubElement(replacement,'tag').text=str(spec.tag)
            if addresses:
                ip=ET.SubElement(replacement,'ip')
                for address in addresses: ET.SubElement(ip,'entry',name=address)
            for tag,value in [('interface-management-profile',spec.interface_management_profile),('mtu',spec.mtu),('comment',spec.comment)]:
                if value is not None and value!='': ET.SubElement(replacement,tag).text=str(value)
            if units is None: units=ET.SubElement(node.find(mode),'units')
            if entry is not None:
                index=list(units).index(entry);units.remove(entry);units.insert(index,replacement)
            else: units.append(replacement)
            imported=owner
            for tag in ('import','network','interface'):
                child=imported.find(tag)
                imported=child if child is not None else ET.SubElement(imported,tag)
            if name not in [e.text for e in imported.findall('member')]: ET.SubElement(imported,'member').text=name
        if not lock['locked'] and not self.manager.acquire_lock(user['username'],'editing subinterfaces'): fail('Could not acquire configuration lock',423)
        self.manager._save(root,self.candidate)
        return {'status':'deleted' if spec is None else 'created' if create else 'updated','name':name,'requires_commit':True,'revision':digest(self.manager.get_candidate())}
