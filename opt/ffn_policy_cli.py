# SPDX-License-Identifier: GPL-2.0-or-later
"""FFN-CLI command extension using the same authenticated API as the WebUI."""
import json
from urllib.parse import urlencode


HELP='''show policies <kind> [vsys] [candidate|running]
show policies nat-preview [candidate|running]
show policies nat-tools
show policies status [candidate|running]
request policies <kind> <create|update|delete|move|toggle> <JSON> [vsys]
Use the displayed revision in mutations. Create/update use a rule object with
name, description, enabled and settings. Rules save to candidate; use commit.
Security settings include source-device, destination-device, source-user,
rule-type, action, icmp-unreachable, profile-mode (none|group|profiles),
profile-group, antivirus, vulnerability, anti-spyware, url-filtering,
file-blocking, data-filtering, crucible-analysis, log-start, log-end and
log-setting. Use the returned schema and choices for exact keys and references.
Rule usage is read only; unavailable statistics are not zero hits.
Kinds: security nat qos pbf decryption tunnel-inspect application-override
authentication dos sdwan. The same runtime blockers apply in CLI and WebUI.'''


def handle(tokens,api,token):
    if len(tokens)<2 or tokens[0] not in ('show','request') or tokens[1]!='policies':return False
    if len(tokens)<3:print(HELP);return True
    kind=tokens[2]
    if tokens[0]=='show' and kind=='nat-tools':
        print(json.dumps(api('/api/system/dataplane-tools',token=token),indent=2));return True
    if tokens[0]=='show' and kind=='nat-preview':
        source='running' if 'running' in tokens[3:] else 'candidate'
        print(json.dumps(api('/api/config/nat/preview?'+urlencode(dict(source=source)),token=token),indent=2));return True
    if tokens[0]=='show':
        source=next((x for x in tokens[3:] if x in ('candidate','running')),'candidate')
        scope=next((x for x in tokens[3:] if x not in ('candidate','running')),'vsys1')
        result=api('/api/config/policies/'+kind+'?'+urlencode(dict(scope=scope,source=source)),token=token)
    else:
        if len(tokens) not in (5,6):print(HELP);return True
        try:payload=json.loads(tokens[4])
        except ValueError:print('Invalid JSON policy request');return True
        if not isinstance(payload,dict):print('Policy request must be a JSON object');return True
        payload['action']=tokens[3]
        result=api('/api/config/policies/'+kind+'?'+urlencode(dict(scope=tokens[5] if len(tokens)==6 else 'vsys1')),method='POST',body=payload,token=token)
    print(json.dumps(result,indent=2));return True
