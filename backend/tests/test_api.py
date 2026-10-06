from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.main import create_app
from app.models import Base, SessionToken, User

HEADERS = {'X-Sentinel-Request': '1'}
PASSWORD = 'Disposable-test-password-2026'

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('SENTINEL_BOOTSTRAP_PASSWORD', PASSWORD)
    monkeypatch.delenv('OLLAMA_MODEL', raising=False)
    monkeypatch.setenv('SIMULATION_INTERVAL_SECONDS','0')
    directory = Path('data/tests')
    directory.mkdir(parents=True,exist_ok=True)
    db_path = directory / (uuid4().hex+'.db')
    database_url = os.getenv('TEST_DATABASE_URL', 'sqlite:///'+str(db_path))
    if not database_url.startswith('sqlite') and not database_url.endswith('/sentinel_test'):
        raise RuntimeError('External integration tests require a dedicated database named sentinel_test')
    app = create_app(database_url)
    if not database_url.startswith('sqlite'):
        Base.metadata.drop_all(app.state.engine)
    with TestClient(app) as client:
        yield client
    db_path.unlink(missing_ok=True)
    if not database_url.startswith('sqlite'):
        Base.metadata.drop_all(app.state.engine)

def login(client, username='admin'):
    response = client.post('/api/auth/login',json={'username':username,'password':PASSWORD},headers=HEADERS)
    assert response.status_code == 200
    return response

def event(number=1, **overrides):
    return {'external_id':f'test-{number}','kind':'login_failed','service':'api','actor':'demo',
        'source_ip':'203.0.113.10','message':'Fictional authentication failure',
        'occurred_at':'2026-10-04T12:00:00Z',**overrides}

def send(client, number=1, **overrides):
    overrides.setdefault('occurred_at',(datetime.now(timezone.utc)-timedelta(seconds=15)).isoformat())
    return client.post('/api/events',json=event(number,**overrides),headers=HEADERS)

def incident(client):
    response = send(client,kind='privilege_changed')
    assert response.status_code == 201
    return client.get('/api/incidents/'+str(response.json()['incident_id'])).json()

@pytest.mark.parametrize('path',['/api/events','/api/incidents','/api/dashboard','/api/audit','/api/incidents/1'])
def test_reads_require_authentication(client,path):
    assert client.get(path).status_code == 401

def test_login_cookie_and_storage(client):
    result=login(client)
    assert 'HttpOnly' in result.headers['set-cookie'] and 'SameSite=strict' in result.headers['set-cookie']
    token=client.cookies.get('sentinel_session')
    with client.app.state.sessions() as db:
        stored=db.scalar(select(SessionToken))
        assert stored.token_hash != token and len(stored.token_hash)==64
        user=db.scalar(select(User).where(User.username=='admin'))
        assert user.password_hash != PASSWORD

def test_login_failure_and_rate_limit(client):
    for _ in range(5):
        assert client.post('/api/auth/login',json={'username':'admin','password':'wrong'},headers=HEADERS).status_code==401
    assert client.post('/api/auth/login',json={'username':'admin','password':PASSWORD},headers=HEADERS).status_code==429

def test_logout_revokes_token(client):
    login(client)
    token=client.cookies.get('sentinel_session')
    assert client.post('/api/auth/logout',headers=HEADERS).status_code==200
    client.cookies.set('sentinel_session',token)
    assert client.get('/api/auth/me').status_code==401

@pytest.mark.parametrize('role',['viewer','analyst'])
def test_external_ingestion_and_fixed_simulation_permissions(client,role):
    login(client,role)
    assert send(client).status_code==403
    assert client.post('/api/simulations',json={'scenario':'credential_attack'},headers=HEADERS).status_code==(403 if role=='viewer' else 201)
    assert client.get('/api/audit').status_code==403

def test_viewer_cannot_modify_incident(client):
    login(client);item=incident(client);login(client,'viewer')
    assert client.post(f'/api/incidents/{item["id"]}/notes',json={'body':'note'},headers=HEADERS).status_code==403
    assert client.patch(f'/api/incidents/{item["id"]}',json={'status':'investigating','version':1,'reason':'Review evidence'},headers=HEADERS).status_code==403

def test_csrf_header_and_origin(client):
    login(client)
    assert client.post('/api/events',json=event()).status_code==403
    assert client.post('/api/events',json=event(),headers={**HEADERS,'Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/auth/login',json={'username':'admin','password':PASSWORD},headers={**HEADERS,'Origin':'https://evil.example'}).status_code==403

@pytest.mark.parametrize('invalid',[
    {'source_ip':'not-an-address'},{'kind':'unknown'},{'service':''},{'message':'x'*501},
    {'occurred_at':'2026-01-01T12:00:00Z'},{'occurred_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()},
    {'occurred_at':datetime.now().isoformat()},{'external_id':'bad id!'}])
def test_event_validation(client,invalid):
    login(client)
    assert send(client,**invalid).status_code==422
    assert client.get('/api/events').json()['items']==[]

def test_idempotency_and_id_collision(client):
    login(client)
    payload=event(occurred_at=datetime.now(timezone.utc).isoformat())
    first=client.post('/api/events',json=payload,headers=HEADERS)
    second=client.post('/api/events',json=payload,headers=HEADERS)
    assert first.status_code==201 and second.status_code==200 and second.json()['duplicate']
    assert len(client.get('/api/events').json()['items'])==1
    payload['message']='Different evidence'
    assert client.post('/api/events',json=payload,headers=HEADERS).status_code==409

def test_detection_threshold_and_evidence(client):
    login(client)
    for n in range(4):
        assert send(client,n).json()['incident_id'] is None
    fifth=send(client,5).json()['incident_id']
    sixth=send(client,6).json()['incident_id']
    assert fifth==sixth
    result=client.get(f'/api/incidents/{fifth}').json()
    assert len(result['evidence'])==6 and result['severity']=='high' and result['score']==70

def test_unrelated_subjects_do_not_combine(client):
    login(client)
    for n in range(6):
        send(client,n,actor=f'user-{n}')
    assert client.get('/api/incidents').json()['items']==[]

def test_out_of_window_does_not_trigger(client):
    login(client)
    for n in range(4):
        send(client,n,occurred_at=(datetime.now(timezone.utc)-timedelta(minutes=20)).isoformat())
    assert send(client,5).json()['incident_id'] is None

def test_concurrent_ingestion_has_one_incident(client):
    login(client)
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses=list(pool.map(lambda n:send(client,n),range(6)))
    assert all(r.status_code==201 for r in responses)
    items=client.get('/api/incidents').json()['items']
    assert len(items)==1 and items[0]['evidence_count']==6

def test_status_version_notes_audit_and_new_detection(client):
    login(client);item=incident(client);id=item['id']
    assert client.patch(f'/api/incidents/{id}',json={'status':'resolved','version':1,'reason':'Verified evidence'},headers=HEADERS).status_code==409
    change={'status':'investigating','version':1,'reason':'Reviewing privilege change'}
    assert client.patch(f'/api/incidents/{id}',json=change,headers=HEADERS).status_code==200
    assert client.patch(f'/api/incidents/{id}',json=change,headers=HEADERS).status_code==409
    assert client.post(f'/api/incidents/{id}/notes',json={'body':'Owner confirmed a scheduled change.'},headers=HEADERS).status_code==201
    assert client.patch(f'/api/incidents/{id}',json={'status':'resolved','version':2,'reason':'Owner confirmed change'},headers=HEADERS).status_code==200
    assert send(client,2,kind='privilege_changed').json()['incident_id']!=id
    actions=[a['action'] for a in client.get('/api/audit').json()['items']]
    assert 'incident.updated' in actions and 'incident.note_added' in actions

def test_analysis_is_honestly_labelled(client):
    login(client);item=incident(client)
    response=client.post(f'/api/incidents/{item["id"]}/analysis',headers=HEADERS)
    assert response.status_code==200
    result=response.json()
    assert result['mode']=='evidence_briefing' and 'not an AI model' in result['limitations'] and result['evidence_ids']==[1]

def test_local_model_unavailable_falls_back(client,monkeypatch):
    login(client);item=incident(client);monkeypatch.setenv('OLLAMA_MODEL','no-model-for-test')
    response=client.post(f'/api/incidents/{item["id"]}/analysis',headers=HEADERS)
    assert response.json()['mode']=='evidence_briefing'

def test_websocket_authentication_and_live_update(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/api/live'):pass
    login(client)
    with client.websocket_connect('/api/live',headers={'Origin':'http://testserver'}) as socket:
        assert socket.receive_json()['type']=='connected'
        send(client,kind='privilege_changed')
        assert socket.receive_json()['type']=='events.changed'

def test_websocket_rejects_cross_origin(client):
    from starlette.websockets import WebSocketDisconnect
    login(client)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/api/live',headers={'Origin':'https://evil.example'}):pass

@pytest.mark.parametrize('path',['/api/events?limit=1000','/api/events?before=-1','/api/incidents?status=bad','/api/incidents?severity=bad','/api/incidents?limit=1000'])
def test_query_bounds(client,path):
    login(client)
    assert client.get(path).status_code==422

def test_simulation_and_dashboard(client):
    login(client)
    result=client.post('/api/simulations',json={'scenario':'credential_attack'},headers=HEADERS)
    assert result.status_code==201 and result.json()['events_created']==6 and len(result.json()['incident_ids'])==1
    data=client.get('/api/dashboard').json()
    assert data['events']==6 and data['active_incidents']==1 and sum(data['trend'])==6

def test_cursor_pagination(client):
    login(client)
    for n in range(3):send(client,n,kind='login_success')
    first=client.get('/api/events?limit=2').json()
    second=client.get('/api/events?limit=2&before='+str(first['next_cursor'])).json()
    assert [e['id'] for e in first['items']]==[3,2] and [e['id'] for e in second['items']]==[1]
