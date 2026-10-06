import asyncio, json, logging, os, secrets, threading, time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, Depends, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, IPvAnyAddress, ConfigDict
from sqlalchemy import create_engine, select, func, update, text, event as sa_event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from .models import Base, User, SessionToken, Event, Incident, Evidence, Note, Audit, UserProfile, AccountToken, utcnow
from .security import hash_password, verify_password, token_hash, jwt_encode, jwt_decode
from .detection import detect, RULES
from .analysis import analyze

from .config import validate_configuration, secure_cookies

log = logging.getLogger('sentinel')
COOKIE = 'sentinel_session'

class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=128)

class EventInput(BaseModel):
    external_id: str = Field(min_length=1, max_length=80, pattern=r'^[a-zA-Z0-9_-]+$')
    kind: Literal['login_failed', 'login_success', 'privilege_changed', 'suspicious_access', 'service_error', 'password_reset', 'unknown_device', 'suspicious_ip', 'api_rate_limit', 'unusual_geo', 'unauthorized_access', 'large_data_request', 'account_lockout']
    service: str = Field(min_length=1, max_length=80)
    actor: str = Field(min_length=1, max_length=80)
    source_ip: IPvAnyAddress
    message: str = Field(min_length=1, max_length=500)
    occurred_at: datetime

    @field_validator('occurred_at')
    @classmethod
    def validate_time(cls, value):
        if value.tzinfo is None:
            raise ValueError('Timestamp must include a UTC offset')
        value = value.astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
        if value > now + timedelta(minutes=1) or value < now - timedelta(days=1):
            raise ValueError('Events must be within the last 24 hours, with at most one minute of clock skew')
        return value.replace(tzinfo=None)

class IncidentChange(BaseModel):
    status: Literal['open', 'investigating', 'contained', 'escalated', 'resolved', 'dismissed']
    version: int = Field(ge=1)
    assigned_to: str | None = Field(default=None, max_length=80)
    reason: str = Field(min_length=5, max_length=500)

    @field_validator('reason')
    @classmethod
    def meaningful_reason(cls, value):
        if len(value.strip()) < 5:
            raise ValueError('Provide a meaningful reason of at least five characters')
        return value.strip()

class NoteInput(BaseModel):
    body: str = Field(min_length=1, max_length=2000)
    @field_validator('body')
    @classmethod
    def not_blank(cls, value):
        if not value.strip():
            raise ValueError('Note cannot be blank')
        return value.strip()

class SimulationInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scenario: Literal['credential_attack', 'privilege_change', 'data_access', 'service_errors', 'normal_activity', 'account_takeover', 'unknown_device', 'api_abuse', 'geographic_anomaly', 'account_lockout', 'suspicious_ip', 'password_reset', 'large_data_request', 'unauthorized_access']

def event_json(e):
    return {'id': e.id, 'external_id': e.external_id, 'kind': e.kind, 'service': e.service,
        'actor': e.actor, 'source_ip': e.source_ip, 'message': e.message,
        'occurred_at': e.occurred_at.isoformat() + 'Z', 'simulated': e.external_id.startswith('demo-')}

def incident_json(i, count=0):
    return {'id': i.id, 'reference': f'INC-{i.id:04d}', 'title': i.title, 'rule': i.rule,
        'severity': i.severity, 'score': i.score, 'status': i.status, 'assigned_to': i.assigned_to,
        'version': i.version, 'explanation': i.explanation, 'evidence_count': count,
        'created_at': i.created_at.isoformat() + 'Z', 'updated_at': i.updated_at.isoformat() + 'Z'}

def create_app(database_url=None, seed=True, frontend_dir=None):
    validate_configuration()
    data_dir = Path(__file__).resolve().parents[1] / 'data'
    data_dir.mkdir(exist_ok=True)
    url = database_url or os.getenv('DATABASE_URL', 'sqlite:///' + str(data_dir / 'sentinel.db'))
    engine = create_engine(url, connect_args={'check_same_thread': False, 'timeout': 20} if url.startswith('sqlite') else {}, pool_pre_ping=True)
    if engine.dialect.name == 'sqlite':
        @sa_event.listens_for(engine, 'connect')
        def sqlite_config(connection, _):
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA journal_mode=WAL')
    sessions = sessionmaker(engine, expire_on_commit=False)
    key_path = data_dir / 'jwt.key'
    if not os.getenv('SENTINEL_JWT_KEY') and not key_path.exists():
        key_path.write_text(secrets.token_hex(32), encoding='utf-8')
    jwt_key = bytes.fromhex(os.getenv('SENTINEL_JWT_KEY') or key_path.read_text().strip())
    if len(jwt_key) < 32:
        raise RuntimeError('JWT signing key must contain at least 32 bytes')
    sockets = {}
    login_attempts = {}
    account_failures = {}
    rate_lock = threading.Lock()
    mutation_attempts = {}

    @asynccontextmanager
    async def lifespan(app):
        Base.metadata.create_all(engine)
        if seed:
            with sessions.begin() as db:
                if not db.scalar(select(User.id).limit(1)):
                    password = os.getenv('SENTINEL_BOOTSTRAP_PASSWORD') or secrets.token_urlsafe(24)
                    if len(password) < 12:
                        raise RuntimeError('Bootstrap password must have at least 12 characters')
                    for username, role in [('admin', 'admin'), ('analyst', 'analyst'), ('viewer', 'viewer'), ('manager', 'manager')]:
                        db.add(User(username=username, role=role, password_hash=hash_password(password)))
                    if not os.getenv('SENTINEL_BOOTSTRAP_PASSWORD'):
                        (data_dir / 'local-credentials.txt').write_text(f'Local demo accounts: admin, manager, analyst, viewer\nPassword: {password}\n', encoding='utf-8')
                        log.info('Local demo credentials created in data/local-credentials.txt; excluded from Git')
        with sessions.begin() as db:
            if seed and not db.scalar(select(User.id).where(User.username=='manager')):
                administrator=db.scalar(select(User).where(User.username=='admin'))
                if administrator:
                    db.add(User(username='manager',role='manager',password_hash=administrator.password_hash))
                    db.flush()
            for user in db.scalars(select(User)):
                if not db.get(UserProfile, user.id):
                    db.add(UserProfile(user_id=user.id, email=user.username+'@sentinel.local', display_name=user.username.title(), verified=True))
        yield
        engine.dispose()

    app = FastAPI(title='SentinelAI', version='0.2.0', lifespan=lifespan,
        description='Fictional security event processing and incident investigation. No real monitoring or automated containment.')
    app.state.sessions = sessions
    app.state.engine = engine

    @app.middleware('http')
    async def security_headers(request, call_next):
        request_id = uuid4().hex
        started = time.monotonic()
        response = await call_next(request)
        response.headers['X-Request-ID'] = request_id
        log.info(json.dumps({'request_id':request_id,'method':request.method,'path':request.url.path,'status':response.status_code,'duration_ms':round((time.monotonic()-started)*1000,1)}))
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store' if request.url.path.startswith('/api') else 'no-cache'
        if not request.url.path.startswith(('/docs', '/redoc')):
            response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        return response

    def db_dependency():
        with sessions() as db:
            yield db

    def session_user(token):
        if not token:
            return None
        session_id = jwt_decode(token, jwt_key)
        if not session_id:
            return None
        with sessions() as db:
            stored = db.get(SessionToken, token_hash(session_id))
            if not stored or stored.expires_at <= utcnow():
                return None
            user = db.get(User, stored.user_id)
            profile = db.get(UserProfile, user.id) if user else None
            if not user or (profile and (profile.state != 'active' or not profile.verified)):
                return None
            return {'id': user.id, 'username': user.username, 'role': user.role, 'email': profile.email if profile else '', 'display_name': profile.display_name if profile else user.username}

    def current_user(request: Request):
        user = session_user(request.cookies.get(COOKIE))
        if not user:
            raise HTTPException(401, 'Sign in to access SentinelAI')
        return user

    def permit(*roles):
        def dependency(request: Request, user=Depends(current_user)):
            if user['role'] not in roles:
                raise HTTPException(403, 'Your role does not allow this action')
            if request.method not in ('GET', 'HEAD'):
                if request.headers.get('X-Sentinel-Request') != '1':
                    raise HTTPException(403, 'Required same-origin request header is missing')
                origin = request.headers.get('origin')
                if origin and origin != str(request.base_url).rstrip('/'):
                    raise HTTPException(403, 'Cross-origin writes are not allowed')
                with rate_lock:
                    now = time.monotonic()
                    attempts = [t for t in mutation_attempts.get(user['id'], []) if now-t < 60]
                    if len(attempts) >= 60:
                        raise HTTPException(429, 'Write limit reached; try again in a minute')
                    mutation_attempts[user['id']] = attempts + [now]
            return user
        return dependency

    async def broadcast(topic, payload=None):
        for socket, token in list(sockets.items()):
            try:
                if not session_user(token):
                    await socket.close(code=1008)
                    sockets.pop(socket, None)
                    continue
                await socket.send_json({'type': topic, 'at': utcnow().isoformat()+'Z', **(payload or {})})
            except Exception:
                sockets.pop(socket, None)

    def writer_lock(db):
        # Database-level serialization protects detection thresholds across processes.
        if engine.dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        elif engine.dialect.name == 'postgresql':
            db.execute(text('SELECT pg_advisory_xact_lock(7359101)'))

    def process_event(payload, username):
        with sessions() as db:
            writer_lock(db)
            existing = db.scalar(select(Event).where(Event.external_id == payload.external_id))
            if existing:
                same = all(getattr(existing, field) == value for field, value in {
                    **payload.model_dump(exclude={'source_ip'}), 'source_ip': str(payload.source_ip)}.items())
                if not same:
                    raise HTTPException(409, 'External ID already belongs to a different event')
                return {'event': event_json(existing), 'incident_id': None, 'duplicate': True}
            record = Event(**{**payload.model_dump(exclude={'source_ip'}), 'source_ip': str(payload.source_ip)})
            db.add(record)
            db.flush()
            incident = detect(db, record)
            db.add(Audit(actor=username, action='event.ingested', target=f'event:{record.id}',
                detail=f'{record.kind}; incident:{incident.id if incident else "none"}'))
            db.commit()
            log.info(json.dumps({'action': 'event.ingested', 'event_id': record.id, 'incident_id': incident.id if incident else None}))
            return {'event': event_json(record), 'incident_id': incident.id if incident else None, 'duplicate': False}

    @app.get('/api/live-check')
    def live_check():
        return {'status':'alive'}

    @app.get('/api/health')
    def health(db=Depends(db_dependency)):
        db.execute(text('SELECT 1'))
        return {'status': 'healthy', 'version': '0.2.0', 'database': engine.dialect.name,
            'summary_mode': 'local_model' if os.getenv('OLLAMA_MODEL') else 'evidence_briefing'}

    @app.post('/api/auth/login')
    def login(payload: LoginInput, request: Request, response: Response, db=Depends(db_dependency)):
        if request.headers.get('X-Sentinel-Request') != '1':
            raise HTTPException(403, 'Required same-origin request header is missing')
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            raise HTTPException(403, 'Cross-origin login is not allowed')
        address = request.client.host if request.client else 'unknown'
        with rate_lock:
            now = time.monotonic()
            attempts = [t for t in login_attempts.get(address, []) if now-t < 60]
            if len(attempts) >= 5:
                raise HTTPException(429, 'Too many login attempts; wait one minute')
            login_attempts[address] = attempts + [now]
        identifier = payload.username.strip().lower()
        profile = db.scalar(select(UserProfile).where(UserProfile.email == identifier))
        user = db.get(User, profile.user_id) if profile else db.scalar(select(User).where(User.username == identifier))
        profile = db.get(UserProfile, user.id) if user else None
        account_key = str(user.id) if user else identifier
        with rate_lock:
            failures=[t for t in account_failures.get(account_key,[]) if now-t<900]
            if len(failures)>=5:
                raise HTTPException(429,'Too many attempts for this account; wait fifteen minutes')
        # Use the same expensive derivation for unknown accounts to reduce username timing leakage.
        fallback = 'pbkdf2_sha256$600000$' + '00'*16 + '$' + '00'*32
        valid = verify_password(payload.password, user.password_hash if user else fallback)
        if not user or not valid or (profile and (profile.state != 'active' or not profile.verified)):
            with rate_lock:
                failed_at=time.monotonic()
                account_failures[account_key]=[t for t in account_failures.get(account_key,[]) if failed_at-t<900]+[failed_at]
            raise HTTPException(401, 'Username or password is incorrect')
        with rate_lock:
            account_failures.pop(account_key,None)
        token = secrets.token_urlsafe(32)
        db.add(SessionToken(token_hash=token_hash(token), user_id=user.id, expires_at=utcnow()+timedelta(days=7)))
        db.add(Audit(actor=user.username, action='auth.login', target='session', detail='Session created'))
        db.commit()
        response.set_cookie(COOKIE, jwt_encode(token, jwt_key), httponly=True, secure=secure_cookies(), samesite='strict', max_age=900)
        response.set_cookie('sentinel_refresh', token, httponly=True, secure=secure_cookies(), samesite='strict', max_age=604800, path='/api/auth')
        return {'username': user.username, 'role': user.role, 'email': profile.email if profile else '', 'display_name': profile.display_name if profile else user.username}

    @app.get('/api/auth/me')
    def me(user=Depends(current_user)):
        return user

    @app.post('/api/auth/logout')
    async def logout(request: Request, response: Response, user=Depends(permit('admin','manager','analyst','viewer')), db=Depends(db_dependency)):
        session = db.get(SessionToken, token_hash(jwt_decode(request.cookies[COOKIE], jwt_key)))
        db.delete(session)
        db.add(Audit(actor=user['username'], action='auth.logout', target='session', detail='Session revoked'))
        db.commit()
        response.delete_cookie(COOKIE)
        response.delete_cookie('sentinel_refresh', path='/api/auth')
        await broadcast('session.changed')
        return {'ok': True}

    @app.post('/api/events', status_code=201)
    async def ingest(payload: EventInput, user=Depends(permit('admin')), response: Response=None):
        result = await asyncio.to_thread(process_event, payload, user['username'])
        if result['duplicate']:
            response.status_code = 200
        else:
            await broadcast('events.changed')
        return result

    @app.get('/api/events')
    def events(limit: int=50, before: int | None=None, kind: str | None=None,
        user=Depends(current_user), db=Depends(db_dependency)):
        if not 1 <= limit <= 100 or (before is not None and before < 1):
            raise HTTPException(422, 'Invalid pagination bounds')
        query = select(Event)
        if before:
            query = query.where(Event.id < before)
        if kind:
            query = query.where(Event.kind == kind)
        rows = list(db.scalars(query.order_by(Event.id.desc()).limit(limit+1)))
        return {'items': [event_json(e) for e in rows[:limit]], 'next_cursor': rows[limit-1].id if len(rows)>limit else None}

    @app.get('/api/incidents')
    def incidents(status: str | None=None, severity: str | None=None,
        limit: int=50, user=Depends(current_user), db=Depends(db_dependency)):
        if not 1 <= limit <= 100:
            raise HTTPException(422, 'Limit must be between 1 and 100')
        query = select(Incident)
        if status:
            if status not in ['open','investigating','contained','escalated','resolved','dismissed']:
                raise HTTPException(422, 'Invalid incident status')
            query = query.where(Incident.status == status)
        if severity:
            if severity not in ['low','medium','high','critical']:
                raise HTTPException(422, 'Invalid severity')
            query = query.where(Incident.severity == severity)
        rows = list(db.scalars(query.order_by(Incident.updated_at.desc()).limit(limit)))
        counts = dict(db.execute(select(Evidence.incident_id, func.count()).group_by(Evidence.incident_id)).all())
        return {'items': [incident_json(i, counts.get(i.id,0)) for i in rows]}

    @app.get('/api/incidents/{incident_id}')
    def detail(incident_id: int, user=Depends(current_user), db=Depends(db_dependency)):
        incident = db.get(Incident, incident_id)
        if not incident:
            raise HTTPException(404, 'Incident not found')
        evidence = list(db.scalars(select(Event).join(Evidence, Event.id==Evidence.event_id).where(Evidence.incident_id==incident_id).order_by(Event.occurred_at)))
        notes = list(db.scalars(select(Note).where(Note.incident_id==incident_id).order_by(Note.id)))
        return {**incident_json(incident,len(evidence)), 'evidence': [event_json(e) for e in evidence],
            'notes': [{'id': n.id,'author': n.author,'body': n.body,'created_at': n.created_at.isoformat()+'Z'} for n in notes]}

    @app.patch('/api/incidents/{incident_id}')
    async def change(incident_id: int, payload: IncidentChange, user=Depends(permit('admin','manager','analyst')), db=Depends(db_dependency)):
        if payload.assigned_to and not db.scalar(select(User.id).where(User.username==payload.assigned_to, User.role.in_(['admin','manager','analyst']))):
            raise HTTPException(422, 'Assignee must be an existing analyst or administrator')
        incident = db.get(Incident, incident_id)
        if not incident:
            raise HTTPException(404, 'Incident not found')
        transitions = {'open': ['open','investigating','dismissed'], 'investigating': ['investigating','contained','escalated','resolved','dismissed'], 'contained': ['contained','investigating','escalated','resolved'], 'escalated': ['escalated','investigating','contained','resolved'], 'resolved': [], 'dismissed': []}
        if payload.status not in transitions[incident.status]:
            raise HTTPException(409, 'Invalid status transition; investigate before resolving. Closed incidents are immutable.')
        previous_status = incident.status
        result = db.execute(update(Incident).where(Incident.id==incident_id, Incident.version==payload.version).values(
            status=payload.status, assigned_to=payload.assigned_to, version=Incident.version+1, updated_at=utcnow()))
        if result.rowcount != 1:
            raise HTTPException(409, 'Incident changed since you opened it; refresh and retry')
        db.add(Audit(actor=user['username'], action='incident.updated', target=f'incident:{incident_id}', detail=f'{previous_status} -> {payload.status}: {payload.reason}'))
        db.commit()
        await broadcast('incidents.changed')
        return {'ok': True}

    @app.post('/api/incidents/{incident_id}/notes', status_code=201)
    async def add_note(incident_id: int, payload: NoteInput, user=Depends(permit('admin','manager','analyst')), db=Depends(db_dependency)):
        if not db.get(Incident, incident_id):
            raise HTTPException(404, 'Incident not found')
        db.add(Note(incident_id=incident_id, author=user['username'], body=payload.body))
        db.add(Audit(actor=user['username'], action='incident.note_added', target=f'incident:{incident_id}', detail='Analyst note added'))
        db.commit()
        await broadcast('incidents.changed')
        return {'ok': True}

    @app.post('/api/incidents/{incident_id}/analysis')
    async def analysis(incident_id: int, user=Depends(permit('admin','manager','analyst')), db=Depends(db_dependency)):
        incident = db.get(Incident, incident_id)
        if not incident:
            raise HTTPException(404, 'Incident not found')
        evidence = list(db.scalars(select(Event).join(Evidence, Event.id==Evidence.event_id).where(Evidence.incident_id==incident_id).order_by(Event.id)))
        briefing = await analyze(incident, evidence)
        db.add(Audit(actor=user['username'], action='incident.analyzed', target=f'incident:{incident_id}', detail=briefing['mode']))
        db.commit()
        return briefing

    @app.get('/api/audit')
    def audit(user=Depends(permit('admin')), db=Depends(db_dependency)):
        rows = db.scalars(select(Audit).order_by(Audit.id.desc()).limit(100))
        return {'items': [{'id': a.id, 'actor': a.actor, 'action': a.action, 'target': a.target,
            'detail': a.detail, 'created_at': a.created_at.isoformat()+'Z'} for a in rows]}

    @app.get('/api/dashboard')
    def dashboard(user=Depends(current_user), db=Depends(db_dependency)):
        active = Incident.status.not_in(['resolved','dismissed'])
        severity = dict(db.execute(select(Incident.severity,func.count()).where(active).group_by(Incident.severity)).all())
        recent = list(db.scalars(select(Event).where(Event.occurred_at>=utcnow()-timedelta(hours=24))))
        buckets = [0]*24
        for e in recent:
            age = int((utcnow()-e.occurred_at).total_seconds()//3600)
            if 0 <= age < 24:
                buckets[23-age] += 1
        return {'events': db.scalar(select(func.count()).select_from(Event)), 'events_today': db.scalar(select(func.count()).select_from(Event).where(Event.occurred_at>=utcnow().replace(hour=0,minute=0,second=0,microsecond=0))),
            'active_incidents': db.scalar(select(func.count()).select_from(Incident).where(active)),
            'critical': severity.get('critical',0), 'investigating': db.scalar(select(func.count()).select_from(Incident).where(Incident.status=='investigating')),
            'severity': severity, 'trend': buckets, 'rules': [{'id': r[0], 'kind': k, 'score': r[1], 'threshold': r[4], 'window_minutes': r[5]} for k,r in RULES.items()]}

    @app.post('/api/simulations', status_code=201)
    async def simulate(payload: SimulationInput, user=Depends(permit('admin','manager','analyst'))):
        kinds = {'suspicious_ip': ('suspicious_ip',1), 'password_reset': ('password_reset',1), 'large_data_request': ('large_data_request',1), 'unauthorized_access': ('unauthorized_access',1), 'account_takeover': ('login_failed',8), 'unknown_device': ('unknown_device',1),
            'api_abuse': ('api_rate_limit',4), 'geographic_anomaly': ('unusual_geo',1), 'account_lockout': ('account_lockout',1), 'credential_attack': ('login_failed',6), 'privilege_change': ('privilege_changed',1),
            'data_access': ('suspicious_access',1), 'service_errors': ('service_error',4), 'normal_activity': ('login_success',3)}
        kind, count = kinds[payload.scenario]
        run = uuid4().hex[:8]
        records = []
        total = count+3 if payload.scenario=='account_takeover' else count
        delay=max(0,min(2,float(os.getenv('SIMULATION_INTERVAL_SECONDS','1.1'))))
        async def progress(stage):
            await broadcast('simulation.progress',{'run_id':run,'scenario':payload.scenario,'actor':user['username'],'processed':len(records),'total':total,'stage':stage,'incident_ids':sorted(set(r['incident_id'] for r in records if r['incident_id']))})
        await progress('started')
        for number in range(count):
            event = EventInput(external_id=f'demo-{run}-{number}',kind=kind,service='customer-api',
                actor=f'demo-user-{run}',source_ip='203.0.113.42',message=f'Fictional {payload.scenario.replace("_"," ")} scenario, event {number+1}',
                occurred_at=datetime.now(timezone.utc)-timedelta(seconds=(count-number)*15))
            records.append(await asyncio.to_thread(process_event,event,user['username']))
            await broadcast('events.changed')
            await progress('processing')
            await asyncio.sleep(delay)
        if payload.scenario == 'account_takeover':
            for kind in ['unknown_device', 'login_success', 'unauthorized_access']:
                event = EventInput(external_id=f'demo-{run}-{kind}', kind=kind,service='customer-api', actor=f'demo-user-{run}', source_ip='203.0.113.42', message='Fictional account takeover sequence: '+kind, occurred_at=datetime.now(timezone.utc))
                records.append(await asyncio.to_thread(process_event,event,user['username']))
                await broadcast('events.changed')
                await progress('processing')
                await asyncio.sleep(delay)
            count = len(records)
        await broadcast('events.changed')
        await progress('complete')
        return {'run_id':run,'scenario':payload.scenario,'events_created':count,'incident_ids':sorted(set(r['incident_id'] for r in records if r['incident_id']))}

    @app.websocket('/api/live')
    async def live(socket: WebSocket):
        origin = socket.headers.get('origin')
        expected = ('https://' if socket.url.scheme=='wss' else 'http://') + socket.headers.get('host','')
        token = socket.cookies.get(COOKIE)
        if not session_user(token) or (origin and origin != expected):
            await socket.close(code=1008)
            return
        await socket.accept()
        sockets[socket] = token
        await socket.send_json({'type':'connected'})
        try:
            while True:
                try:
                    await asyncio.wait_for(socket.receive_text(), timeout=30)
                except asyncio.TimeoutError:
                    pass
                if not session_user(token):
                    await socket.close(code=1008)
                    break
                await socket.send_json({'type':'heartbeat'})
        except WebSocketDisconnect:
            pass
        finally:
            sockets.pop(socket,None)

    from .workspace import install_workspace
    install_workspace(app, sessions, engine, permit, current_user, db_dependency, broadcast, jwt_key, writer_lock)

    frontend = Path(frontend_dir or Path(__file__).resolve().parents[2]/'frontend/dist')
    from fastapi.responses import FileResponse
    @app.get('/admin/users', include_in_schema=False)
    def admin_page(user=Depends(permit('admin'))):
        if not (frontend/'index.html').exists():
            raise HTTPException(503,'Frontend build is unavailable; build the frontend first')
        return FileResponse(frontend/'index.html')
    if frontend.exists():
        app.mount('/', StaticFiles(directory=frontend,html=True),name='dashboard')
    return app

app = create_app()
