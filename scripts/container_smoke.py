"""Verify the disposable Compose stack, never a production database."""
import json
import os
import re
from http.cookiejar import CookieJar
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.error import HTTPError

base = 'http://127.0.0.1:5090'
client = build_opener(HTTPCookieProcessor(CookieJar()))

def request(path, payload=None, method=None):
    headers = {'X-Sentinel-Request': '1', 'Content-Type': 'application/json', 'Origin': base}
    req = Request(base + path, data=json.dumps(payload).encode() if payload is not None else None, method=method, headers=headers)
    with client.open(req, timeout=30) as response:
        return response.read()

def api(path, payload=None, method=None):
    return json.loads(request(path, payload, method))

assert api('/api/health')['database'] == 'postgresql'
html = request('/').decode()
assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', html)
assert assets and 'id="root"' in html
for asset in assets:
    assert request(asset)
try:
    request('/api/incidents')
except HTTPError as error:
    assert error.code == 401
else:
    raise AssertionError('Unauthenticated evidence was exposed')
assert api('/api/auth/login', {'username': 'analyst', 'password': os.environ['SENTINEL_BOOTSTRAP_PASSWORD']})['role'] == 'analyst'
result = api('/api/simulations', {'scenario': 'account_takeover'})
assert result['events_created'] == 11
items = api('/api/incidents')['items']
item = next(i for i in items if i['title'] == 'Possible account takeover')
assert item['score'] == 95 and item['severity'] == 'critical'
assert len(api('/api/incidents/' + str(item['id']))['evidence']) == 11
for status in ['investigating', 'contained', 'resolved']:
    api('/api/incidents/' + str(item['id']), {'status': status, 'version': item['version'], 'assigned_to': 'analyst', 'reason': 'Disposable CI evidence workflow verification'}, 'PATCH')
    item = api('/api/incidents/' + str(item['id']))
report = api('/api/incidents/' + str(item['id']) + '/report', {}, 'POST')
assert b'## Evidence timeline' in request(report['download_url'])
assert item['status'] == 'resolved'
print('Docker/PostgreSQL smoke passed: assets, authentication, simulation, detection, workflow and report.')
