"""Native Linux check: TAP MAC survives destruction/recreation of its namespace."""
import json
from pathlib import Path
import sys
import tempfile
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_linux_network as net


def main():
    name='ffn-mac-'+uuid.uuid4().hex[:8]
    net.NS=name
    try:
        with tempfile.TemporaryDirectory(prefix=name+'-') as directory:
            net.STATE=Path(directory)/'network.json'
            cfg={'revision':0,'ports':{'p1':{'mode':'disabled'}}}
            net.start(cfg)
            first=json.loads(net.ip('-j','link','show','dev','p1'))[0]
            net.run('ip','netns','delete',name)
            net.start(cfg)
            second=json.loads(net.ip('-j','link','show','dev','p1'))[0]
            assert first['address']==second['address'],(first,second)
            assert 'UP' not in second['flags'],second
            print('TAP recreation preserved its saved MAC and disabled state')
    finally:
        if net.exists():net.run('ip','netns','delete',name)


if __name__=='__main__':main()
