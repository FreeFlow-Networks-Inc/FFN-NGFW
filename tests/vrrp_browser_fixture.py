"""Loopback-only browser fixture with real candidate/controller operations."""
import sys
import uvicorn
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from objects_browser_fixture import page, root
from test_vrrp import VrrpTests

fixture = VrrpTests(); fixture.setUp(); app = fixture.f.client.app
app.mount('/static', StaticFiles(directory=root / 'static'), name='static')


@app.get('/')
def vrrp_page():
    return HTMLResponse(page().body.decode().replace('</body>', '<script src="/static/vrrp.js"></script></body>'))


if __name__ == '__main__':
    try: uvicorn.run(app, host='127.0.0.1', port=int(sys.argv[1]))
    finally: fixture.doCleanups()
