#!/usr/bin/env python3
"""FFN config -> bmfw DataplaneConfig. INVARIANT: never place a mgmt/control iface
into a vsys zone/ct-zone (that breaks the box's own conntrack -> SSH/WebUI)."""
import json, sqlite3, sys, re, os
from xml.etree import ElementTree as ET
DB="/var/lib/ffn-ngfw/config-v2.db"; XML="/var/lib/ffn-ngfw/config/running-config.xml"
MGMT_PORTS=[22,443,8443]
REAL=set(os.listdir("/sys/class/net"))   # interfaces that exist right now
def _mgmt_ifaces():
    """Interfaces allowed to reach the box's own admin services (INPUT accept).

    Was hardcoded to ["eno1np0","ztbtov4b2k"] -- the BUILD HOST's NIC. On any
    other chassis that name is simply absent from /sys/class/net, so the only
    mgmt rule nft ever emitted was the ZeroTier one and ssh on the real mgmt
    port fell through to the chain's policy drop. Order: the provisioned list,
    then any overlay control iface, then the default-route iface as a floor so
    the box cannot lock itself out of its own management path.

    The default-route iface is a LAST resort on purpose: on a deployed
    firewall that route often points out an untrusted port, and making it a
    mgmt iface would both expose admin services there and (via NEVER_VSYS)
    pull it out of every vsys zone.
    """
    ifs=[]
    def add(x):
        if x and x in REAL and x not in ifs: ifs.append(x)
    try:
        for ln in open("/etc/ffn-ngfw/mgmt-ifaces"): add(ln.split("#")[0].strip())
    except Exception: pass
    for d in sorted(REAL):
        if d.startswith(("zt","wg")): add(d)          # ZeroTier / WireGuard
    if not ifs:
        try:
            for ln in list(open("/proc/net/route"))[1:]:
                p=ln.split()
                if len(p)>2 and p[1]=="00000000": add(p[0])
        except Exception: pass
    return ifs
MGMT_IFACES=_mgmt_ifaces()
NEVER_VSYS=set(MGMT_IFACES)|{"lo","tmfifo_net0"}          # control/mgmt: never in a vsys
MGMT_KINDS={"lab-mgmt","mgmt"}
def _aliases():
    m={}
    try:
        for e in ET.parse(XML).getroot().iter("interface-alias"):
            for en in e.findall("entry"):
                ln=en.findtext("linux-name")
                if ln: m[en.get("name")]=ln
    except Exception: pass
    return m
def _vsyses(al):
    out=[]
    try:
        for v in ET.parse(XML).getroot().iter("vsys"):
            for en in v.findall("entry"):
                nm=en.get("name") or "vsys1"; mm=re.search(r"(\d+)$",nm); vid=int(mm.group(1)) if mm else 1
                ifs=[]; imp=en.find("import")
                if imp is not None:
                    for mem in imp.iter("member"):
                        lx=al.get((mem.text or "").split(".")[0])
                        if lx and lx in REAL and lx not in NEVER_VSYS and lx not in ifs:
                            ifs.append(lx)              # data ifaces only
                out.append((nm,vid,ifs))
    except Exception: pass
    return out or [("vsys1",1,[])]
# --- Interface Management Profiles: map FFN service keys -> nft (proto, ports) ---
SVC2PORTS={
    "permit_ssh":("tcp",[22]), "permit_https":("tcp",[443,8443]),
    "permit_http":("tcp",[80]), "permit_http_ocsp":("tcp",[80]), "permit_ocsp":("tcp",[80]),
    "permit_telnet":("tcp",[23]), "permit_snmp":("udp",[161]),
    "permit_user_id":("tcp",[5007]), "permit_userid":("tcp",[5007]),
}
def _yes(v): return str(v).strip().lower() in ("yes","true","1","on")
def _profiles(con):
    out={}
    try:
        for x in con.execute("SELECT name,config FROM net_resources WHERE kind='interface-mgmt-profiles'"):
            try: out[x[0]]=json.loads(x[1] or "{}")
            except Exception: out[x[0]]={}
    except Exception: pass
    return out
def _iface_mgmt(al, profs):
    """Per-interface mgmt: only interfaces that ATTACH a profile get admin services."""
    mgmt=[]
    try:
        root=ET.parse(XML).getroot()
        for eth in root.iter("ethernet"):
            for en in eth.findall("entry"):
                l3=en.find("layer3")
                if l3 is None: continue
                pn=l3.findtext("interface-management-profile")
                if not pn or pn not in profs: continue
                dev=al.get(en.get("name"))
                if not dev or dev not in REAL: continue
                svc=profs[pn]; tcp=[]; udp=[]; icmp=False
                for k,(proto,ports) in SVC2PORTS.items():
                    if _yes(svc.get(k,"no")): (tcp if proto=="tcp" else udp).extend(ports)
                if _yes(svc.get("permit_ping","no")): icmp=True
                pips=[p for p in (svc.get("permitted_ips") or []) if p]
                if not (tcp or udp or icmp): continue
                ent={"iface":dev,"profile":pn}
                if tcp: ent["tcp"]=sorted(set(tcp))
                if udp: ent["udp"]=sorted(set(udp))
                if icmp: ent["icmp"]=True
                if pips: ent["permitted_ip"]=pips
                mgmt.append(ent)
    except Exception: pass
    return mgmt
zn=lambda i:"z_"+re.sub(r"[^A-Za-z0-9]","_",i)
pm=lambda p:{"tcp":"tcp","udp":"udp","icmp":"icmp"}.get((p or "any").lower(),"any")
am=lambda a:{"permit":"allow","allow":"allow","deny":"deny","drop":"deny","reject":"reject"}.get((a or "permit").lower(),"allow")
al=_aliases(); con=sqlite3.connect(DB); con.row_factory=sqlite3.Row
profs=_profiles(con); ifmgmt=_iface_mgmt(al,profs)
rules=[dict(x) for x in con.execute("SELECT * FROM policy_rules WHERE enabled=1 AND COALESCE(hidden,0)=0 ORDER BY position")]
vconf=[]; first=True
for (nm,vid,data_ifs) in _vsyses(al):
    ro=[]
    if first:
        for r in rules:
            if (r.get("kind") or "") in MGMT_KINDS: continue        # mgmt rules -> input chain, not vsys
            si,di=r.get("src_iface"),r.get("dst_iface")
            if (si and si in NEVER_VSYS) or (di and di in NEVER_VSYS): continue
            fz=zn(si) if (si and si in data_ifs) else "any"
            tz=zn(di) if (di and di in data_ifs) else "any"
            rr={"name":(r.get("name") or ("rule%d"%r["id"]))[:31],"from_zone":fz,"to_zone":tz,
                "src":r.get("src_ip") or "any","dst":r.get("dst_ip") or "any",
                "proto":pm(r.get("proto")),"action":am(r.get("action")),"enabled":True}
            dp=r.get("dst_port") or 0
            if dp: rr["dports"]=[int(dp)]
            ro.append(rr)
        first=False
    zones=[{"name":zn(i),"interfaces":[i],"kind":"trust"} for i in data_ifs]
    vconf.append({"name":nm,"vsys_id":vid,"zones":zones,"rules":ro})
cfg={"table":"ffn_ngfw","mgmt_ifaces":MGMT_IFACES,"mgmt_tcp_ports":MGMT_PORTS,
     "nfqueue_base":0,"queue_bypass":True,"default_forward":"drop","enable_nat":True,"mgmt":ifmgmt,"vsys":vconf}
json.dump(cfg,sys.stdout,indent=2)
