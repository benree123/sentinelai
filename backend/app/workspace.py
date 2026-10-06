"""Account lifecycle and analyst workspace endpoints."""
import os, secrets, smtplib, ssl
from datetime import timedelta
from email.message import EmailMessage
from urllib.parse import urlencode, urlparse
import httpx
from fastapi import Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, delete, func, text
from .models import User, UserProfile, SessionToken, AccountToken, Incident, Event, Evidence, Audit, Note, IncidentReport, utcnow
from .security import hash_password, token_hash, jwt_encode, jwt_decode
from .analysis import analyze
from typing import Literal
from .config import secure_cookies, require_verification

class EmailInput(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    @field_validator('email')
    @classmethod
    def email_format(cls, value):
        value = value.strip().lower()
        if value.count('@') != 1 or '.' not in value.split('@')[1] or any(c.isspace() for c in value):
            raise ValueError('Enter a valid email address')
        return value

class Registration(EmailInput):
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=128)

class TokenInput(BaseModel):
    token: str = Field(min_length=20, max_length=200)

class ResetInput(TokenInput):
    password: str = Field(min_length=12, max_length=128)

class UserChange(BaseModel):
    role: Literal['admin','manager','analyst','viewer']
    state: Literal['active','suspended']

class InviteInput(EmailInput):
    display_name: str = Field(min_length=2, max_length=120)
    role: Literal['manager','analyst','viewer'] = 'viewer'

class CopilotInput(BaseModel):
    question: str = Field(min_length=3, max_length=1000)


def mail_ready():
    return all(os.getenv(k) for k in ['SMTP_HOST','SMTP_FROM','SENTINEL_PUBLIC_URL'])


def send_account_mail(email, token, purpose):
    if not mail_ready():
        raise HTTPException(503, 'Email delivery is not configured. Ask your administrator to configure SMTP.')
    base = os.environ['SENTINEL_PUBLIC_URL'].rstrip('/')
    if urlparse(base).scheme!='https' and not (urlparse(base).scheme=='http' and urlparse(base).hostname in ['localhost','127.0.0.1']):
        raise HTTPException(503, 'Account email requires an HTTPS public URL')
    message = EmailMessage()
    message['From'] = os.environ['SMTP_FROM']
    message['To'] = email
    message['Subject'] = 'SentinelAI — '+('verify your email' if purpose=='verify' else 'set your password')
    message.set_content('Open this link to continue: '+base+'/?'+urlencode({'account_action':purpose,'token':token})+'\nThis link expires in 30 minutes. If you did not request it, ignore this email.')
    try:
        with smtplib.SMTP(os.environ['SMTP_HOST'], int(os.getenv('SMTP_PORT','587')), timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if os.getenv('SMTP_USERNAME'):
                smtp.login(os.environ['SMTP_USERNAME'], os.environ['SMTP_PASSWORD'])
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException):
        raise HTTPException(503, 'Email delivery failed. Try again later.')


def install_workspace(app, sessions, engine, permit, current_user, db_dependency, broadcast, jwt_key, writer_lock):
    def check_origin(request):
        if request.headers.get('X-Sentinel-Request') != '1' or (request.headers.get('origin') and request.headers['origin'] != str(request.base_url).rstrip('/')):
            raise HTTPException(403, 'Same-origin request required')
    attempts = {}
    import time, threading
    limit_lock = threading.Lock()
    def public_limit(request):
        check_origin(request)
        key = request.client.host if request.client else 'unknown'
        with limit_lock:
            now = time.monotonic()
            rows = [t for t in attempts.get(key,[]) if now-t < 60]
            if len(rows) >= 5:
                raise HTTPException(429, 'Too many requests; wait one minute')
            attempts[key] = rows+[now]
    def account_token(db, user, purpose):
        db.execute(delete(AccountToken).where(AccountToken.user_id==user.id,AccountToken.purpose==purpose))
        raw = secrets.token_urlsafe(32)
        db.add(AccountToken(token_hash=token_hash(raw),user_id=user.id,purpose=purpose,expires_at=utcnow()+timedelta(minutes=30)))
        return raw
    def users_json(db, user):
        profile = db.get(UserProfile,user.id)
        return {'id':user.id,'username':user.username,'role':user.role,'email':profile.email if profile else '', 'display_name':profile.display_name if profile else user.username,'state':profile.state if profile else 'active','verified':profile.verified if profile else True}

    @app.get('/api/auth/config')
    def auth_config():
        return {'verification_required':require_verification(),'email_enabled':mail_ready(),'google_enabled':False,'microsoft_enabled':False, 'mfa_enabled':False,'access_minutes':15,'refresh_days':7}

    @app.post('/api/auth/refresh')
    def refresh(request:Request,response:Response,db=Depends(db_dependency)):
        check_origin(request)
        writer_lock(db)
        raw=request.cookies.get('sentinel_refresh')
        session=db.get(SessionToken,token_hash(raw)) if raw else None
        profile=db.get(UserProfile,session.user_id) if session else None
        if not session or session.expires_at<=utcnow() or (profile and (profile.state!='active' or not profile.verified)):
            raise HTTPException(401,'Session expired; sign in again')
        user_id=session.user_id
        deadline=session.expires_at
        db.delete(session)
        new=secrets.token_urlsafe(32)
        db.add(SessionToken(token_hash=token_hash(new),user_id=user_id,expires_at=deadline))
        db.commit()
        response.set_cookie('sentinel_session',jwt_encode(new,jwt_key),httponly=True,secure=secure_cookies(),samesite='strict',max_age=900)
        response.set_cookie('sentinel_refresh',new,httponly=True,secure=secure_cookies(),samesite='strict',path='/api/auth',max_age=max(0,int((deadline-utcnow()).total_seconds())))
        return {'ok':True}

    @app.get('/api/auth/sessions')
    def user_sessions(request:Request,user=Depends(current_user),db=Depends(db_dependency)):
        current=jwt_decode(request.cookies.get('sentinel_session',''),jwt_key)
        rows=db.scalars(select(SessionToken).where(SessionToken.user_id==user['id'],SessionToken.expires_at>utcnow()))
        return {'items':[{'id':s.token_hash,'expires_at':s.expires_at.isoformat()+'Z','current':s.token_hash==token_hash(current)} for s in rows]}

    @app.delete('/api/auth/sessions/{session_id}')
    async def revoke_session(session_id:str,user=Depends(permit('admin','manager','analyst','viewer')),db=Depends(db_dependency)):
        row=db.get(SessionToken,session_id)
        if not row or row.user_id!=user['id']:
            raise HTTPException(404,'Session not found')
        db.delete(row)
        db.add(Audit(actor=user['username'],action='auth.session_revoked',target='session',detail='Session revoked by owner'))
        db.commit()
        await broadcast('session.changed')
        return {'ok':True}

    @app.post('/api/auth/register', status_code=201)
    def register(payload:Registration,request:Request,db=Depends(db_dependency)):
        public_limit(request)
        verification = require_verification()
        if verification and not mail_ready():
            raise HTTPException(503,'Account registration requires configured email verification')
        writer_lock(db)
        if db.scalar(select(UserProfile).where(UserProfile.email==payload.email)):
            return {'message':'If this address is eligible, verification instructions will be sent.' if verification else 'Account request processed. Sign in with your email and password.'}
        user=User(username='user-'+secrets.token_hex(8),role='viewer',password_hash=hash_password(payload.password))
        db.add(user);db.flush()
        db.add(UserProfile(user_id=user.id,email=payload.email,display_name=payload.display_name,verified=not verification))
        if verification:
            raw=account_token(db,user,'verify')
            send_account_mail(payload.email,raw,'verify')
        db.add(Audit(actor='registration',action='auth.registered',target=f'user:{user.id}',detail='Viewer role; '+('pending email verification' if verification else 'direct registration; email ownership not checked')))
        db.commit()
        return {'message':'If this address is eligible, verification instructions will be sent.' if verification else 'Account request processed. Sign in with your email and password.'}

    @app.post('/api/auth/forgot-password')
    def forgot(payload:EmailInput,request:Request,db=Depends(db_dependency)):
        public_limit(request)
        if not mail_ready():
            raise HTTPException(503,'Password recovery requires configured email delivery')
        writer_lock(db)
        profile=db.scalar(select(UserProfile).where(UserProfile.email==payload.email))
        if profile:
            user=db.get(User,profile.user_id)
            send_account_mail(payload.email,account_token(db,user,'reset'),'reset')
            db.commit()
        return {'message':'If an account matches, a recovery email will be sent.'}

    def consume_token(db,raw,purpose):
        writer_lock(db)
        row=db.get(AccountToken,token_hash(raw))
        if not row or row.purpose!=purpose or row.expires_at<=utcnow():
            raise HTTPException(400,'Link is invalid or expired')
        user=db.get(User,row.user_id)
        db.delete(row)
        return user

    @app.post('/api/auth/verify-email')
    def verify(payload:TokenInput,request:Request,db=Depends(db_dependency)):
        public_limit(request)
        user=consume_token(db,payload.token,'verify')
        db.get(UserProfile,user.id).verified=True
        db.add(Audit(actor=user.username,action='auth.email_verified',target=f'user:{user.id}',detail='Email ownership confirmed'))
        db.commit()
        return {'message':'Email verified. You can now sign in.'}

    @app.post('/api/auth/reset-password')
    def reset(payload:ResetInput,request:Request,db=Depends(db_dependency)):
        public_limit(request)
        user=consume_token(db,payload.token,'reset')
        user.password_hash=hash_password(payload.password)
        db.get(UserProfile,user.id).verified=True
        db.execute(delete(SessionToken).where(SessionToken.user_id==user.id))
        db.add(Audit(actor=user.username,action='auth.password_reset',target=f'user:{user.id}',detail='Password changed; all sessions revoked'))
        db.commit()
        return {'message':'Password updated. Sign in with your new password.'}

    @app.get('/api/admin/users')
    def users(user=Depends(permit('admin')),db=Depends(db_dependency)):
        return {'items':[users_json(db,u) for u in db.scalars(select(User).order_by(User.id))]}

    @app.get('/api/analysts')
    def analysts(user=Depends(current_user),db=Depends(db_dependency)):
        return {'items':[{'username':u.username,'display_name':p.display_name} for u,p in db.execute(select(User,UserProfile).join(UserProfile).where(User.role.in_(['admin','manager','analyst']),UserProfile.state=='active',UserProfile.verified==True))]}

    @app.patch('/api/admin/users/{user_id}')
    async def modify_user(user_id:int,payload:UserChange,user=Depends(permit('admin')),db=Depends(db_dependency)):
        writer_lock(db)
        target=db.get(User,user_id);profile=db.get(UserProfile,user_id)
        if not target or not profile:
            raise HTTPException(404,'User not found')
        if target.id==user['id'] and (payload.role!='admin' or payload.state!='active'):
            raise HTTPException(409,'You cannot remove your own administrative access')
        if target.role=='admin' and (payload.role!='admin' or payload.state!='active'):
            count=db.scalar(select(func.count()).select_from(User).join(UserProfile).where(User.role=='admin',UserProfile.state=='active'))
            if count<=1:
                raise HTTPException(409,'At least one active administrator is required')
        target.role=payload.role;profile.state=payload.state
        db.execute(delete(SessionToken).where(SessionToken.user_id==target.id))
        db.add(Audit(actor=user['username'],action='user.updated',target=f'user:{user_id}',detail=f'Role: {payload.role}; state: {payload.state}; sessions revoked'))
        db.commit();await broadcast('users.changed')
        return users_json(db,target)

    @app.post('/api/admin/users/invite',status_code=201)
    def invite(payload:InviteInput,user=Depends(permit('admin')),db=Depends(db_dependency)):
        if not mail_ready():
            raise HTTPException(503,'Invitations require configured SMTP email delivery')
        writer_lock(db)
        if db.scalar(select(UserProfile).where(UserProfile.email==payload.email)):
            raise HTTPException(409,'Email already belongs to an account')
        target=User(username='user-'+secrets.token_hex(8),role=payload.role,password_hash=hash_password(secrets.token_urlsafe(32)))
        db.add(target);db.flush()
        db.add(UserProfile(user_id=target.id,email=payload.email,display_name=payload.display_name,verified=False))
        send_account_mail(payload.email,account_token(db,target,'reset'),'reset')
        db.add(Audit(actor=user['username'],action='user.invited',target=f'user:{target.id}',detail='Invitation sent; '+payload.role))
        db.commit()
        return {'message':'Invitation sent.'}

    @app.get('/api/analytics')
    def analytics(user=Depends(current_user),db=Depends(db_dependency)):
        incidents=list(db.scalars(select(Incident)))
        closed=[i for i in incidents if i.status=='resolved']
        return {'total_incidents':len(incidents),'resolved':len(closed),'mean_resolution_minutes':round(sum((i.updated_at-i.created_at).total_seconds()/60 for i in closed)/len(closed),1) if closed else None,
          'statuses':dict(db.execute(select(Incident.status,func.count()).group_by(Incident.status)).all()),
          'attack_types':dict(db.execute(select(Incident.rule,func.count()).group_by(Incident.rule)).all()),
          'top_accounts':[{'actor':actor,'events':n} for actor,n in db.execute(select(Event.actor,func.count()).group_by(Event.actor).order_by(func.count().desc()).limit(8))],
          'risk_distribution':{'0–39':sum(i.score<40 for i in incidents),'40–69':sum(40<=i.score<70 for i in incidents),'70–89':sum(70<=i.score<90 for i in incidents),'90–100':sum(i.score>=90 for i in incidents)}}

    @app.get('/api/intelligence')
    def intelligence(user=Depends(current_user),db=Depends(db_dependency)):
        rows=db.execute(select(Event.source_ip,func.count()).group_by(Event.source_ip).order_by(func.count().desc()).limit(50))
        items=[]
        for ip,count in rows:
            linked=list(db.scalars(select(Incident).join(Evidence).join(Event,Event.id==Evidence.event_id).where(Event.source_ip==ip).distinct()))
            items.append({'source_ip':ip,'events':count,'incidents':len(linked),'max_risk':max([i.score for i in linked],default=0),'country':None,'source':'Internal fictional dataset'})
        return {'items':items,'external_enrichment':False}

    @app.get('/api/system/health')
    async def system_health(user=Depends(current_user),db=Depends(db_dependency)):
        db.execute(text('SELECT 1'))
        ai='not_configured'
        if os.getenv('OLLAMA_MODEL'):
            try:
                async with httpx.AsyncClient(timeout=2,trust_env=False) as client:
                    response=await client.get('http://127.0.0.1:11434/api/tags')
                    response.raise_for_status()
                    names=[m['name'] for m in response.json().get('models',[])]
                    wanted=os.environ['OLLAMA_MODEL']
                    ai='available' if wanted in names or wanted+':latest' in names else 'model_missing'
            except (httpx.HTTPError,ValueError,KeyError):
                ai='unavailable'
        return {'api':'healthy','database':{'status':'connected','engine':engine.dialect.name},'event_processor':'inline_transactional','redis':'not_configured','ai_service':ai,'email':'configured' if mail_ready() else 'not_configured','websocket':'available','version':'0.2.0'}

    def context(db,incident_id):
        incident=db.get(Incident,incident_id)
        if not incident:
            raise HTTPException(404,'Incident not found')
        events=list(db.scalars(select(Event).join(Evidence,Event.id==Evidence.event_id).where(Evidence.incident_id==incident_id).order_by(Event.occurred_at)))
        return incident,events

    @app.post('/api/incidents/{incident_id}/view')
    def viewed(incident_id:int,user=Depends(permit('admin','manager','analyst','viewer')),db=Depends(db_dependency)):
        if not db.get(Incident,incident_id):
            raise HTTPException(404,'Incident not found')
        db.add(Audit(actor=user['username'],action='incident.viewed',target=f'incident:{incident_id}',detail='Investigation opened by user'))
        db.commit()
        return {'ok':True}

    @app.post('/api/incidents/{incident_id}/copilot')
    async def copilot(incident_id:int,payload:CopilotInput,user=Depends(permit('admin','manager','analyst')),db=Depends(db_dependency)):
        incident,events=context(db,incident_id)
        result=await analyze(incident,events,question=payload.question)
        db.add(Audit(actor=user['username'],action='incident.copilot_used',target=f'incident:{incident_id}',detail='Evidence-grounded question; '+result['mode']))
        db.commit()
        return result

    @app.post('/api/incidents/{incident_id}/report')
    async def report(incident_id:int,user=Depends(permit('admin','manager','analyst')),db=Depends(db_dependency)):
        incident,events=context(db,incident_id)
        briefing=await analyze(incident,events)
        notes=list(db.scalars(select(Note).where(Note.incident_id==incident_id).order_by(Note.id)))
        result={'reference':f'INC-{incident.id:04d}','generated_at':utcnow().isoformat()+'Z','title':incident.title,'severity':incident.severity,'status':incident.status,'risk_score':incident.score,'assigned_to':incident.assigned_to,'rule':incident.rule,'risk_explanation':incident.explanation,'briefing':briefing,
            'timeline':[{'id':e.id,'at':e.occurred_at.isoformat()+'Z','kind':e.kind,'actor':e.actor,'source_ip':e.source_ip,'service':e.service,'message':e.message} for e in events],
            'actions':[{'author':n.author,'body':n.body,'at':n.created_at.isoformat()+'Z'} for n in notes]}
        report_id=secrets.token_hex(16)
        content=[f"# SentinelAI incident report — {result['reference']}", f"Generated: {result['generated_at']}", '## Incident details',
            f"Title: {incident.title}\n\nSeverity: {incident.severity}\n\nRisk: {incident.score}/100\n\nStatus: {incident.status}\n\nAssigned analyst: {incident.assigned_to or 'Unassigned'}",
            '## Executive assessment', briefing['summary'], 'Analysis mode: '+briefing['mode'], '## Risk explanation', incident.explanation,
            '## Evidence timeline']
        content.extend(f"- {e.occurred_at.isoformat()} UTC — EVT-{e.id} — {e.kind}\n  Account: {e.actor}; source: {e.source_ip}; service: {e.service}\n  {e.message}" for e in events)
        content.extend(['## Analyst findings and actions'])
        content.extend(f'- {n.created_at.isoformat()} UTC — {n.author}: {n.body}' for n in notes)
        if not notes: content.append('No analyst notes recorded.')
        content.extend(['## Recommended investigation steps'])
        content.extend(f'{i+1}. {step}' for i,step in enumerate(briefing['next_steps']))
        content.extend(['## Limitations', briefing['limitations'], 'Fictional data. Workflow status records analyst decisions; no real containment actions are executed.'])
        db.add(IncidentReport(id=report_id,incident_id=incident_id,author=user['username'],content='\n\n'.join(content)))
        result['download_url']='/api/reports/'+report_id+'/download'
        db.add(Audit(actor=user['username'],action='incident.report_generated',target=f'incident:{incident_id}',detail=briefing['mode']))
        db.commit()
        return result

    @app.get('/api/reports/{report_id}/download')
    def download_report(report_id:str,user=Depends(permit('admin','manager','analyst')),db=Depends(db_dependency)):
        artifact=db.get(IncidentReport,report_id)
        if not artifact:
            raise HTTPException(404,'Report not found')
        return Response(artifact.content,media_type='text/markdown; charset=utf-8',headers={'Content-Disposition':f'attachment; filename=INC-{artifact.incident_id:04d}-report.md'})
