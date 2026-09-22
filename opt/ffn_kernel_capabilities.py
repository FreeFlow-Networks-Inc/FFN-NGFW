"""Read-only kernel feature evidence; installed userspace is not enforcement."""
import gzip
import platform
from pathlib import Path

FEATURES={
    'nat-round-robin':('NFT_NUMGEN',),
    'nat-address-hash':('NFT_HASH',),
    'qos-htb':('NET_SCH_HTB','NET_CLS_FW'),
    'qos-fair-queue':('NET_SCH_FQ_CODEL',),
    'policy-routing':('IP_MULTIPLE_TABLES',),
    'transparent-proxy':('NFT_TPROXY','NF_TPROXY_IPV4'),
}
MODULES={'NFT_NUMGEN':'nft_numgen','NFT_HASH':'nft_hash','NET_SCH_HTB':'sch_htb',
         'NET_SCH_FQ_CODEL':'sch_fq_codel','NET_CLS_FW':'cls_fw',
         'NFT_TPROXY':'nft_tproxy','NF_TPROXY_IPV4':'nf_tproxy_ipv4'}


def inspect(config=None, module_root=Path('/sys/module')):
    release=platform.release();source=None
    if config is None:
        for path in (Path('/proc/config.gz'),Path('/boot')/('config-'+release)):
            try:
                data=path.read_bytes()
                config=(gzip.decompress(data) if path.suffix=='.gz' else data).decode()
                source=str(path);break
            except (OSError,ValueError,UnicodeError):continue
    else:source='provided configuration'
    values={}
    if config is not None:
        for line in config.splitlines():
            if line.startswith('CONFIG_') and '=' in line:
                key,value=line.split('=',1);values[key[7:]]=value
            elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
                values[line[9:-11]]='n'
    features={}
    for name,symbols in FEATURES.items():
        evidence={symbol:values.get(symbol,'unknown') for symbol in symbols}
        loaded={symbol:bool(symbol in MODULES and (module_root/MODULES[symbol]).is_dir()) for symbol in symbols}
        effective={symbol:'m' if loaded[symbol] else value for symbol,value in evidence.items()}
        supported=False if 'n' in effective.values() else None if 'unknown' in effective.values() else True
        features[name]=dict(compiled=supported,symbols=evidence,modules_loaded=loaded,
                            state='missing' if supported is False else 'unverified' if supported is None else 'compiled',
                            runtime_verified=False)
    return dict(release=release,source=source,features=features)
