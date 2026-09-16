"""Loopback-only policy fixture using the actual daemon controller and API."""
import sys
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from test_policy_config import PolicyTests
from objects_browser_fixture import page,root

fixture=PolicyTests();fixture.setUp();app=fixture.client.app
app.mount('/static',StaticFiles(directory=root/'static'),name='static')


@app.get('/')
def policy_page():
    return HTMLResponse(page().body.decode().replace('</body>','<script src="/static/config-policies.js"></script></body>'))


if __name__=='__main__':
    try:uvicorn.run(app,host='127.0.0.1',port=int(sys.argv[1]))
    finally:fixture.tearDown()
