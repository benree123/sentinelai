"""Security and workflow regression checks for the refurbished workspace."""
import base64, json
from datetime import timedelta
from sqlalchemy import select
from test_api import client, login, incident, HEADERS, PASSWORD
from app.models import User,UserProfile,SessionToken,AccountToken,utcnow
from app.security import token_hash


def test_email_login_and_jwt_refresh_rotation(client):
    result=login(client,'admin@sentinel.local')
    token=client.cookies.get('sentinel_session')
    assert len(token.split('.'))==3
    claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'=='))
    assert claims['aud']=='sentinel-web'
    old_refresh=client.cookies.get('sentinel_refresh')
    assert client.post('/api/auth/refresh',headers=HEADERS).status_code==200
    assert client.cookies.get('sentinel_refresh')!=old_refresh
    client.cookies.set('sentinel_refresh',old_refresh,path='/api/auth')
    assert client.post('/api/auth/refresh',headers=HEADERS).status_code==401


def test_tampered_access_token_rejected(client):
    login(client)
    token=client.cookies.get('sentinel_session')
    client.cookies.clear()
    client.cookies.set('sentinel_session',token[:-3]+'bad')
    assert client.get('/api/auth/me').status_code==401


def test_refresh_requires_same_origin(client):
    login(client)
    assert client.post('/api/auth/refresh').status_code==403
    assert client.post('/api/auth/refresh',headers={**HEADERS,'Origin':'https://other.example'}).status_code==403


def test_admin_endpoints_are_enforced_for_analyst_and_manager(client):
    login(client,'analyst')
    assert client.get('/api/admin/users').status_code==403
    assert client.patch('/api/admin/users/1',json={'role':'viewer','state':'active'},headers=HEADERS).status_code==403
    login(client,'manager')
    assert client.get('/api/admin/users').status_code==403
    assert client.post('/api/simulations',json={'scenario':'normal_activity'},headers=HEADERS).status_code==201


def test_suspension_revokes_existing_sessions(client):
    login(client,'analyst')
    analyst_token=client.cookies.get('sentinel_session')
    login(client)
    users=client.get('/api/admin/users').json()['items']
    analyst=next(u for u in users if u['username']=='analyst')
    assert client.patch('/api/admin/users/'+str(analyst['id']),json={'role':'analyst','state':'suspended'},headers=HEADERS).status_code==200
    client.cookies.clear();client.cookies.set('sentinel_session',analyst_token)
    assert client.get('/api/auth/me').status_code==401
    assert client.post('/api/auth/login',json={'username':'analyst','password':PASSWORD},headers=HEADERS).status_code==401


def test_administrator_cannot_demote_or_suspend_self(client):
    login(client)
    user=client.get('/api/auth/me').json()
    assert client.patch('/api/admin/users/'+str(user['id']),json={'role':'viewer','state':'active'},headers=HEADERS).status_code==409
    assert client.patch('/api/admin/users/'+str(user['id']),json={'role':'admin','state':'suspended'},headers=HEADERS).status_code==409


def test_takeover_score_uses_correlated_stored_evidence(client):
    login(client)
    result=client.post('/api/simulations',json={'scenario':'account_takeover'},headers=HEADERS)
    assert result.status_code==201
    rows=client.get('/api/incidents').json()['items']
    takeover=next(i for i in rows if i['title']=='Possible account takeover')
    assert takeover['score']==95 and takeover['severity']=='critical'
    details=client.get('/api/incidents/'+str(takeover['id'])).json()
    assert len(details['evidence'])==11
    assert 'Successful authentication after failure burst: +35' in details['explanation']


def test_contain_escalate_assign_and_report(client):
    login(client);item=incident(client)
    for status in ['investigating','contained','escalated','resolved']:
        result=client.patch('/api/incidents/'+str(item['id']),json={'status':status,'version':item['version'],'assigned_to':'manager','reason':'Verified fictional workflow transition'},headers=HEADERS)
        assert result.status_code==200
        item=client.get('/api/incidents/'+str(item['id'])).json()
    result=client.post('/api/incidents/'+str(item['id'])+'/report',headers=HEADERS)
    assert result.status_code==200
    assert result.json()['status']=='resolved' and result.json()['timeline']
    assert result.json()['briefing']['mode']=='evidence_briefing'
    analytics=client.get('/api/analytics').json()
    assert analytics['resolved']==1 and analytics['mean_resolution_minutes'] is not None


def test_copilot_answers_from_evidence_and_labels_fallback(client):
    login(client);item=incident(client)
    result=client.post('/api/incidents/'+str(item['id'])+'/copilot',json={'question':'What accounts were affected?'},headers=HEADERS)
    assert result.status_code==200
    assert 'demo' in result.json()['summary']
    assert result.json()['mode']=='evidence_briefing'
    assert result.json()['evidence_ids']==[1]
    login(client,'viewer')
    assert client.post('/api/incidents/'+str(item['id'])+'/copilot',json={'question':'Suggest steps'},headers=HEADERS).status_code==403


def test_system_health_does_not_claim_unconfigured_services(client):
    login(client)
    result=client.get('/api/system/health').json()
    assert result['ai_service']=='not_configured' and result['redis']=='not_configured'
    assert result['database']['status']=='connected'
    assert client.get('/api/intelligence').json()['external_enrichment'] is False


def test_owner_cannot_revoke_other_users_session(client):
    login(client,'analyst')
    session_id=client.get('/api/auth/sessions').json()['items'][0]['id']
    login(client,'viewer')
    assert client.delete('/api/auth/sessions/'+session_id,headers=HEADERS).status_code==404


def configure_mail(monkeypatch):
    from app import workspace
    delivered=[]
    monkeypatch.setenv('SMTP_HOST','smtp.example.test')
    monkeypatch.setenv('SMTP_FROM','demo@example.test')
    monkeypatch.setenv('SENTINEL_PUBLIC_URL','https://sentinel.example.test')
    monkeypatch.setattr(workspace,'send_account_mail',lambda email,token,purpose:delivered.append((email,token,purpose)))
    return delivered


def test_registration_requires_verification_and_starts_as_viewer(client,monkeypatch):
    monkeypatch.setenv('REQUIRE_EMAIL_VERIFICATION','true')
    delivered=configure_mail(monkeypatch)
    payload={'email':'new@example.test','display_name':'New Analyst','password':PASSWORD}
    assert client.post('/api/auth/register',json=payload,headers=HEADERS).status_code==201
    assert client.post('/api/auth/login',json={'username':payload['email'],'password':PASSWORD},headers=HEADERS).status_code==401
    token=delivered[0][1]
    assert client.post('/api/auth/verify-email',json={'token':token},headers=HEADERS).status_code==200
    assert client.post('/api/auth/verify-email',json={'token':token},headers=HEADERS).status_code==400
    result=client.post('/api/auth/login',json={'username':payload['email'],'password':PASSWORD},headers=HEADERS)
    assert result.status_code==200 and result.json()['role']=='viewer'


def test_password_reset_is_single_use_and_revokes_sessions(client,monkeypatch):
    delivered=configure_mail(monkeypatch)
    login(client)
    old_access=client.cookies.get('sentinel_session')
    assert client.post('/api/auth/forgot-password',json={'email':'admin@sentinel.local'},headers=HEADERS).status_code==200
    token=delivered[0][1]
    body={'token':token,'password':'Changed-test-password-2026'}
    assert client.post('/api/auth/reset-password',json=body,headers=HEADERS).status_code==200
    assert client.get('/api/auth/me').status_code==401
    assert client.post('/api/auth/reset-password',json=body,headers=HEADERS).status_code==400
    result=client.post('/api/auth/login',json={'username':'admin','password':body['password']},headers=HEADERS)
    assert result.status_code==200


def test_email_workflows_fail_honestly_without_smtp(client,monkeypatch):
    monkeypatch.delenv('SMTP_HOST',raising=False)
    monkeypatch.setenv('REQUIRE_EMAIL_VERIFICATION','true')
    assert client.post('/api/auth/register',json={'email':'new@example.test','display_name':'New User','password':PASSWORD},headers=HEADERS).status_code==503
    assert client.post('/api/auth/forgot-password',json={'email':'admin@sentinel.local'},headers=HEADERS).status_code==503
    config=client.get('/api/auth/config').json()
    assert not config['email_enabled'] and not config['google_enabled']


def test_account_lockout_covers_email_alias_and_multiple_ips(client):
    from fastapi.testclient import TestClient
    for i in range(5):
        other=TestClient(client.app,client=(f'198.51.100.{i+1}',1000+i))
        username='admin' if i%2 else 'admin@sentinel.local'
        assert other.post('/api/auth/login',json={'username':username,'password':'wrong'},headers=HEADERS).status_code==401
    other=TestClient(client.app,client=('198.51.100.99',9999))
    assert other.post('/api/auth/login',json={'username':'admin@sentinel.local','password':PASSWORD},headers=HEADERS).status_code==429


def test_manual_admin_route_rejects_analyst(client):
    login(client,'analyst')
    assert client.get('/admin/users').status_code==403
    login(client)
    assert client.get('/admin/users').status_code in (200,503)


def test_explicit_incident_view_is_audited_without_mutating_incident(client):
    login(client);item=incident(client)
    response=client.post('/api/incidents/'+str(item['id'])+'/view',headers=HEADERS)
    assert response.status_code==200
    assert client.get('/api/incidents/'+str(item['id'])).json()['version']==item['version']
    rows=client.get('/api/audit').json()['items']
    assert any(a['action']=='incident.viewed' for a in rows)


def test_additional_simulator_events_use_detection_pipeline(client):
    login(client)
    for scenario,expected in [('suspicious_ip','medium'),('large_data_request','critical'),('unauthorized_access','high'),('password_reset',None)]:
        response=client.post('/api/simulations',json={'scenario':scenario},headers=HEADERS)
        assert response.status_code==201 and response.json()['events_created']==1
        ids=response.json()['incident_ids']
        if expected:
            assert len(ids)==1
            assert client.get('/api/incidents/'+str(ids[0])).json()['severity']==expected
        else:
            assert ids==[]


def test_report_download_is_authenticated_and_uses_exact_snapshot(client):
    login(client);item=incident(client)
    result=client.post('/api/incidents/'+str(item['id'])+'/report',headers=HEADERS)
    path=result.json()['download_url']
    download=client.get(path)
    assert download.status_code==200
    assert 'attachment' in download.headers['content-disposition']
    assert item['reference'] in download.text and '## Evidence timeline' in download.text
    assert 'evidence_briefing' in download.text and 'not an AI model result' in download.text
    login(client,'viewer')
    assert client.get(path).status_code==403
    client.cookies.clear()
    assert client.get(path).status_code==401


def test_simulation_rejects_arbitrary_targets_and_streams_progress(client):
    login(client,'analyst')
    for field in ['target','source_ip','domain','url','credentials','command']:
        result=client.post('/api/simulations',json={'scenario':'account_takeover',field:'not-allowed'},headers=HEADERS)
        assert result.status_code==422
    with client.websocket_connect('/api/live') as ws:
        assert ws.receive_json()['type']=='connected'
        result=client.post('/api/simulations',json={'scenario':'account_takeover'},headers=HEADERS)
        assert result.status_code==201
        updates=[]
        while True:
            msg=ws.receive_json()
            if msg['type']=='simulation.progress':
                updates.append(msg)
                if msg['stage']=='complete':break
        assert updates[0]['processed']==0 and updates[-1]['processed']==11
        assert updates[-1]['total']==11
        assert all(a['run_id']==result.json()['run_id'] for a in updates)
        events=client.get('/api/events').json()['items']
        assert all(e['simulated'] for e in events)
        assert all(e['source_ip']=='203.0.113.42' for e in events)


def test_direct_registration_without_email_is_read_only(client, monkeypatch):
    monkeypatch.delenv('SMTP_HOST', raising=False)
    monkeypatch.setenv('REQUIRE_EMAIL_VERIFICATION','false')
    payload={'email':'direct@example.test','display_name':'Direct User','password':PASSWORD}
    response=client.post('/api/auth/register',json=payload,headers=HEADERS)
    assert response.status_code==201
    assert 'Sign in' in response.json()['message']
    assert client.post('/api/auth/login',json={'username':payload['email'],'password':PASSWORD},headers=HEADERS).status_code==200
    assert client.get('/api/auth/me').json()['role']=='viewer'
    assert client.post('/api/simulations',json={'scenario':'normal_activity'},headers=HEADERS).status_code==403
    assert client.get('/api/admin/users').status_code==403


def test_production_configuration_fails_closed(monkeypatch):
    import pytest
    from app.config import validate_configuration, secure_cookies
    monkeypatch.setenv('SENTINEL_ENV','production')
    monkeypatch.setenv('COOKIE_SECURE','false')
    with pytest.raises(RuntimeError,match='Secure cookies'):validate_configuration()
    monkeypatch.setenv('COOKIE_SECURE','true')
    monkeypatch.delenv('SENTINEL_JWT_KEY',raising=False)
    with pytest.raises(RuntimeError,match='signing key|SENTINEL_JWT_KEY'):validate_configuration()
    monkeypatch.setenv('SENTINEL_JWT_KEY','ab'*32)
    monkeypatch.setenv('SENTINEL_PUBLIC_URL','http://unsafe.example')
    with pytest.raises(RuntimeError,match='HTTPS'):validate_configuration()
    monkeypatch.setenv('SENTINEL_PUBLIC_URL','https://sentinel.example')
    validate_configuration()
    assert secure_cookies()


def test_blank_incident_reason_rejected(client):
    login(client);item=incident(client)
    result=client.patch('/api/incidents/'+str(item['id']),json={'status':'investigating','version':item['version'],'reason':'      '},headers=HEADERS)
    assert result.status_code==422


def test_report_route_is_unique(client):
    assert len([r for r in client.app.routes if getattr(r,'path',None)=='/api/reports/{report_id}/download'])==1


def test_jwt_rejects_signed_unexpected_header():
    import base64, json, hashlib, hmac
    from app.security import jwt_encode, jwt_decode
    key=b'x'*32
    token=jwt_encode('fixture-session',key)
    _,body,_=token.split('.')
    header=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
    message=header+'.'+body
    signature=base64.urlsafe_b64encode(hmac.new(key,message.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
    assert jwt_decode(message+'.'+signature,key) is None
    assert jwt_decode('x'*5000,key) is None


def test_health_and_request_correlation(client):
    live=client.get('/api/live-check')
    assert live.status_code==200 and live.json()['status']=='alive'
    assert len(live.headers['x-request-id'])==32
    assert client.get('/api/health').json()['status']=='healthy'


def test_parallel_login_failures_count_toward_account_lockout(client):
    from concurrent.futures import ThreadPoolExecutor
    from fastapi.testclient import TestClient
    def fail(number):
        other=TestClient(client.app,client=(f'198.51.100.{number+1}',2000+number))
        return other.post('/api/auth/login',json={'username':'admin','password':'wrong'},headers=HEADERS).status_code
    with ThreadPoolExecutor(max_workers=5) as executor:
        assert list(executor.map(fail,range(5)))==[401]*5
    other=TestClient(client.app,client=('198.51.100.99',9999))
    assert other.post('/api/auth/login',json={'username':'admin','password':PASSWORD},headers=HEADERS).status_code==429
