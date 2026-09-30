"""Native Linux regression: replace a primary IPv4 address without losing its route."""
import json, os, sys, uuid, tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_linux_network as n

def main():
 token=uuid.uuid4().hex[:8]; ns='ffn-ip-'+token; peer='ffn-peer-'+token
 with tempfile.TemporaryDirectory() as directory:
  n.NS=ns;n.STATE=Path(directory)/'network.json';n.OVERLAY_STATE=Path(directory)/'overlay.json';n.PORT_BACKEND='native'
  try:
   for name in (ns,peer):n.run('ip','netns','add',name)
   n.run('ip','link','add','a'+token,'type','veth','peer','name','b'+token)
   n.run('ip','link','set','a'+token,'netns',ns);n.run('ip','link','set','b'+token,'netns',peer)
   n.ip('link','set','a'+token,'name','p1');n.ip('link','set','p1','up');n.ip('address','add','198.18.1.1/24','dev','p1')
   n.run('ip','-n',peer,'address','add','198.18.1.2/24','dev','b'+token);n.run('ip','-n',peer,'link','set','b'+token,'up')
   cfg={'revision':1,'ports':{'p1':{'mode':'l3','addresses':['198.18.1.1/24']}},'routes':[{'dst':'0.0.0.0/0','via':'198.18.1.2','dev':'p1','metric':100}]}
   n.configure_route('add',cfg['routes'][0]);n.save(cfg)
   result=n.patch(cfg,{'revision':1,'ports':{'p1':{'mode':'l3','addresses':['198.18.1.3/24']}}})
   assert n.live_addresses('p1')=={'198.18.1.3/24'}
   assert any(r.get('gateway')=='198.18.1.2' for r in json.loads(n.ip('-j','route')))
   n.run('ip','netns','exec',ns,'ping','-n','-c','2','-W','2','198.18.1.2')
   cfg=result['config']
   try:
    with patch.object(n,'save',side_effect=OSError('simulated storage failure')):
     n.patch(cfg,{'revision':2,'ports':{'p1':{'mode':'l3','addresses':['198.18.1.4/24']}}})
   except RuntimeError:pass
   else:raise AssertionError('Expected rollback')
   assert n.live_addresses('p1')=={'198.18.1.3/24'}
   n.run('ip','netns','exec',ns,'ping','-n','-c','2','-W','2','198.18.1.2')
   print('PASS same-subnet address replacement, retained default route, ping and rollback')
   import ffn_static_routes as health
   health.STATE=Path(directory)/'health.json'
   monitored=dict(cfg['routes'][0],track_link=True,monitor=dict(enabled=True,targets=['198.18.1.2'],interval=1,timeout=1,failure_count=1,recovery_count=1))
   n.configure_route('del',cfg['routes'][0]);cfg['routes']=[monitored];n.save(cfg)
   # Probe runs inside this isolated namespace; no installed route is needed.
   health.tick(n);assert n.route_present(monitored),health.load()
   n.run('ip','-n',peer,'link','set','b'+token,'down')
   health.tick(n);assert not n.route_present(monitored),health.load()
   n.run('ip','-n',peer,'link','set','b'+token,'up')
   __import__('time').sleep(1.1);health.tick(n);assert n.route_present(monitored),health.load()
   # A second default with a higher metric remains eligible independently.
   n.run('ip','link','add','c'+token,'type','veth','peer','name','d'+token)
   n.run('ip','link','set','c'+token,'netns',ns);n.run('ip','link','set','d'+token,'netns',peer)
   n.ip('link','set','c'+token,'name','p2');n.ip('link','set','p2','up');n.ip('address','add','198.18.2.1/24','dev','p2')
   n.run('ip','-n',peer,'address','add','198.18.2.2/24','dev','d'+token);n.run('ip','-n',peer,'link','set','d'+token,'up')
   backup=dict(dst='0.0.0.0/0',via='198.18.2.2',dev='p2',metric=200,track_link=True)
   cfg['ports']['p2']=dict(mode='l3',addresses=['198.18.2.1/24']);cfg['routes'].append(backup);n.save(cfg)
   health.tick(n);assert n.route_present(backup)
   assert json.loads(n.ip('-j','route','get','203.0.113.1'))[0]['dev']=='p1'
   n.run('ip','-n',peer,'link','set','b'+token,'down');health.tick(n)
   assert json.loads(n.ip('-j','route','get','203.0.113.1'))[0]['dev']=='p2'
   assert len(json.loads(n.STATE.read_text())['routes'])==2
   health.tick(n,stop=True);assert not n.route_present(monitored) and not n.route_present(backup)
   print('PASS multiple metric defaults, lower-metric preference and link-down fallback with desired routes retained')
   print('PASS raw ICMP monitoring without a default route, link withdrawal, recovery and stop cleanup')
  finally:
   for name in (ns,peer):
    try:n.run('ip','netns','delete',name)
    except RuntimeError:pass
if __name__=='__main__':main()
