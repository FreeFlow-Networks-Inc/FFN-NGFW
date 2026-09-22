"""Local-only in-memory Objects API for browser regression tests. No appliance access."""
import sys
from pathlib import Path
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from test_config_objects import ObjectTests

root=Path(__file__).resolve().parents[1]
fixture=ObjectTests();fixture.setUp();app=fixture.client.app
app.mount('/static',StaticFiles(directory=root/'static'),name='static')


@app.get('/')
def page():
    shell=(root/'static/index.html').read_text(encoding='utf-8')
    style=shell[shell.index('<style>'):shell.index('</style>')+8]
    return HTMLResponse('''<!doctype html><html><head>'''+style+'''
    <link rel="stylesheet" href="/static/console-shell.css">
    <link rel="stylesheet" href="/static/config-objects.css"></head><body>
    <main id="content-area"></main><script>
    function _escSP(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
    async function consoleRequest(path,options){const r=await fetch(path,{...options,headers:{'Content-Type':'application/json'}});const data=await r.json();if(!r.ok)throw Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));return data;}
    function refreshCommitIndicator(){}
    </script><script src="/static/config-objects.js"></script></body></html>''')


if __name__=='__main__':uvicorn.run(app,host='127.0.0.1',port=int(sys.argv[1]))
