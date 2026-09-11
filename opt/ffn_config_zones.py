"""Validated, revision-checked candidate security-zone configuration."""
import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Literal
from defusedxml import ElementTree as SafeET
from fastapi import HTTPException
from pydantic import BaseModel, Field

ZONE_TYPES = {'layer3', 'layer2', 'virtual-wire', 'tap', 'tunnel', 'external'}
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}\Z')

class ZoneEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    name: str = Field(min_length=1, max_length=63)
    zone_type: Literal['layer3','layer2','virtual-wire','tap','tunnel','external'] = 'layer3'
    interfaces: list[str] = Field(default_factory=list, max_length=1024)
    enable_user_identification: bool = False
    zone_protection_profile: str = Field(default='', max_length=63)
    log_setting: str = Field(default='', max_length=63)
    comment: str = Field(default='', max_length=1024)
    class Config:
        extra = 'forbid'

def fail(message, code=422):
    raise HTTPException(code, message)

def digest(xml):
    return hashlib.sha256(xml.encode()).hexdigest()

def describe(entry):
    net = entry.find('network')
    types = [n.tag for n in net if n.tag in ZONE_TYPES] if net is not None else []
    typ = types[0] if len(types) == 1 else 'unsupported'
    editable = len(types)==1 and bool(NAME.fullmatch(entry.get('name','')))
    if net is not None:
        managed = [n for n in net if n.tag in ZONE_TYPES or n.tag in ('zone-protection-profile','log-setting')]
        editable &= len({n.tag for n in managed}) == len(managed)
        for node in managed:
            editable &= not node.attrib
            if node.tag in ZONE_TYPES:
                editable &= all(m.tag=='member' and not m.attrib and len(m)==0 for m in node)
            else:
                editable &= len(node)==0
    return {'name':entry.get('name'), 'zone_type':typ,
            'interfaces':[n.text for n in entry.findall('network/'+typ+'/member') if n.text],
            'enable_user_identification':entry.findtext('enable-user-identification') == 'yes',
            'zone_protection_profile':entry.findtext('network/zone-protection-profile',''),
            'log_setting':entry.findtext('network/log-setting',''), 'comment':entry.findtext('comment',''),
            'editable':bool(editable)}

class ZoneStore:
    def __init__(self, manager, candidate):
        self.manager, self.candidate = manager, candidate

    def load(self, vsys, source='candidate'):
        if not NAME.fullmatch(vsys): fail('Invalid virtual-system name')
        xml = self.manager.get_running() if source == 'running' else self.manager.get_candidate()
        root = SafeET.fromstring(xml, forbid_dtd=True)
        dev = next((e for e in root.findall('devices/entry') if e.get('name')=='localhost.localdomain'), None)
        owner = next((e for e in dev.findall('vsys/entry') if e.get('name')==vsys), None) if dev is not None else None
        if owner is None: fail('Virtual system not found',404)
        return root, dev, owner, digest(xml)

    def choices(self, dev):
        result = {}
        for kind in ('ethernet','aggregate-ethernet','loopback','tunnel','vlan'):
            for entry in dev.findall('network/interface/'+kind+'/entry'):
                name = entry.get('name','')
                mode = next((m for m in ('layer3','layer2','virtual-wire','tap','aggregate-group','ha') if entry.find(m) is not None), None)
                if kind in ('loopback','tunnel','vlan'): mode = 'layer3'
                if mode in ZONE_TYPES and name: result[name] = mode
                for submode in ('layer2','layer3'):
                    for sub in entry.findall(submode+'/units/entry'):
                        if sub.get('name'): result[sub.get('name')] = submode
        return result

    def listing(self, vsys, source='candidate'):
        _,dev,owner,revision = self.load(vsys,source)
        rows = [describe(e) for e in owner.findall('zone/entry')]
        assigned = {name:z['name'] for z in rows for name in z['interfaces']}
        return {'vsys':vsys, 'source':source, 'revision':revision, 'entries':rows,
                'interface_choices':[{'name':name,'mode':mode,'zone':assigned.get(name)} for name,mode in sorted(self.choices(dev).items())],
                'requires_commit':True, 'enforcement':'Zone configuration is stored in candidate XML. The current zone applier does not program dataplane policy enforcement.'}

    def mutate(self, vsys, name, revision, user, spec=None, create=False):
        if user.get('role') not in ('admin','superuser'): fail('Requires admin or superuser role',403)
        if not NAME.fullmatch(name) or name == 'any': fail('Invalid or reserved zone name')
        lock = self.manager.lock_status()
        if lock['locked'] and lock.get('holder') != user['username']: fail('Configuration locked by another administrator',423)
        root,dev,owner,current = self.load(vsys)
        if revision != current: fail('Candidate changed. Refresh and review before retrying.',409)
        container = owner.find('zone')
        matches = [e for e in owner.findall('zone/entry') if e.get('name')==name]
        if len(matches)>1: fail('Duplicate zone entries must be repaired first',409)
        entry = matches[0] if matches else None
        if create and entry is not None: fail('Zone already exists',409)
        if not create and entry is None: fail('Zone not found',404)
        if spec is None:
            # Conservative references across rulebases, including shared rules.
            if any((m.text or '')==name for tag in ('from','to') for m in root.findall('.//'+tag+'/member')):
                fail('Zone is referenced by policy. Remove references before deleting.',409)
            container.remove(entry)
        else:
            if spec.name != name: fail('Zone renaming is not supported')
            for text in [spec.comment,spec.zone_protection_profile,spec.log_setting,*spec.interfaces]:
                if any(not(c in '\t\n\r' or 0x20<=ord(c)<=0xD7FF or 0xE000<=ord(c)<=0xFFFD or 0x10000<=ord(c)<=0x10FFFF) for c in text): fail('Invalid XML characters')
            if len(set(spec.interfaces)) != len(spec.interfaces): fail('Interface membership must be unique')
            available = self.choices(dev)
            if spec.zone_type in ('external','tunnel') and spec.interfaces:
                fail('Membership editing for this zone type is not implemented')
            existing = describe(entry) if entry is not None else None
            if existing and not existing['editable']: fail('Imported zone type cannot safely be edited',409)
            for member in spec.interfaces:
                # Preserve a pre-existing unresolved member, but do not introduce one.
                preserved = existing and member in existing['interfaces'] and spec.zone_type==existing['zone_type']
                if member not in available and not preserved: fail('Interface is not configured: '+member)
                if member in available and available[member] != spec.zone_type: fail('Interface type does not match zone type: '+member)
                for zone in owner.findall('zone/entry'):
                    if zone.get('name') != name and member in describe(zone)['interfaces']: fail('Interface already belongs to zone '+zone.get('name',''),409)
                for other in dev.findall('vsys/entry'):
                    if other is owner: continue
                    if member in [m.text for m in other.findall('import/network/interface/member')]:
                        fail('Interface belongs to another virtual system: '+member,409)
                    if any(member in describe(z)['interfaces'] for z in other.findall('zone/entry')):
                        fail('Interface belongs to a zone in another virtual system: '+member,409)
            if container is None: container=ET.SubElement(owner,'zone')
            if entry is None: entry=ET.SubElement(container,'entry',name=name)
            net=entry.find('network')
            if net is None: net=ET.SubElement(entry,'network')
            # Retain unrelated imported zone settings. Replace only managed fields.
            for child in list(net):
                if child.tag in ZONE_TYPES or child.tag in ('zone-protection-profile','log-setting'): net.remove(child)
            group=ET.SubElement(net,spec.zone_type)
            for member in spec.interfaces: ET.SubElement(group,'member').text=member
            for tag,value in [('zone-protection-profile',spec.zone_protection_profile),('log-setting',spec.log_setting)]:
                if value: ET.SubElement(net,tag).text=value
            for tag,value in [('enable-user-identification','yes' if spec.enable_user_identification else 'no'),('comment',spec.comment)]:
                for child in list(entry):
                    if child.tag == tag: entry.remove(child)
                if value: ET.SubElement(entry,tag).text=value
        if not lock['locked'] and not self.manager.acquire_lock(user['username'],'editing zones'): fail('Could not acquire configuration lock',423)
        self.manager._save(root,self.candidate)
        return {'status':'deleted' if spec is None else 'created' if create else 'updated', 'requires_commit':True, 'revision':digest(self.manager.get_candidate())}
