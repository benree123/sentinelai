from datetime import timedelta
from sqlalchemy import select, func
from .models import Event, Incident, Evidence, utcnow

RULES = {
    'login_failed': ('AUTH-001', 70, 'high', 'Repeated authentication failures', 5, 10),
    'privilege_changed': ('IAM-002', 85, 'critical', 'Privileged access changed', 1, 10),
    'suspicious_access': ('DATA-003', 95, 'critical', 'Unusual access to protected data', 1, 10),
    'unknown_device': ('DEVICE-005',25,'low','Previously unseen device reported',1,10),
    'suspicious_ip': ('IP-006',55,'medium','Suspicious source reported',1,10),
    'api_rate_limit': ('API-007',60,'medium','API rate limit exceeded',3,5),
    'unusual_geo': ('GEO-008',65,'medium','Unusual geographic login reported',1,10),
    'unauthorized_access': ('ACCESS-009',80,'high','Unauthorized endpoint access',1,10),
    'large_data_request': ('DATA-010',90,'critical','Large data request reported',1,10),
    'account_lockout': ('AUTH-011',40,'medium','Account lockout reported',1,10),
    'service_error': ('OPS-004', 45, 'medium', 'Service error burst', 3, 5),
}

def detect(db, event):
    if event.kind in ['login_success','unauthorized_access']:
        related = list(db.scalars(select(Event).where(Event.actor==event.actor, Event.source_ip==event.source_ip,
            Event.service==event.service, Event.occurred_at>=event.occurred_at-timedelta(minutes=10), Event.occurred_at<=event.occurred_at).order_by(Event.occurred_at)))
        failed = [e for e in related if e.kind=='login_failed']
        succeeded = [e for e in related if e.kind=='login_success' and failed and e.occurred_at>=max(f.occurred_at for f in failed)]
        if len(failed)>=5 and succeeded:
            key=f'AUTH-001:{event.actor}:{event.source_ip}:{event.service}'
            incident=db.scalar(select(Incident).where(Incident.correlation_key==key,Incident.status.not_in(['resolved','dismissed'])))
            if incident:
                factors=[('Repeated authentication failures',40),('Successful authentication after failure burst',35)]
                if any(e.kind=='unknown_device' for e in related): factors.append(('Unknown device reported',10))
                if any(e.kind=='unauthorized_access' for e in related): factors.append(('Unauthorized endpoint access',10))
                incident.score=sum(weight for _,weight in factors)
                incident.severity='critical' if incident.score>=90 else 'high'
                incident.title='Possible account takeover'
                incident.explanation='AUTH-001 correlated sequence: '+ '; '.join(f'{name}: +{weight}' for name,weight in factors)+'. Total '+str(incident.score)+'/100. These are deterministic rule weights, not proof of account compromise.'
                incident.version+=1;incident.updated_at=utcnow()
                for candidate in related:
                    if db.get(Evidence,(incident.id,candidate.id)) is None: db.add(Evidence(incident_id=incident.id,event_id=candidate.id))
                return incident
    if event.kind not in RULES:
        return None
    rule, score, severity, title, threshold, minutes = RULES[event.kind]
    # Correlate only matching subjects; unrelated users cannot trigger each other's rules.
    key = f'{rule}:{event.actor}:{event.source_ip}:{event.service}'
    watermark = db.scalar(select(func.max(Event.occurred_at)).where(
        Event.kind == event.kind, Event.actor == event.actor,
        Event.source_ip == event.source_ip, Event.service == event.service))
    if event.occurred_at < watermark - timedelta(minutes=minutes):
        return None
    candidates = list(db.scalars(select(Event).where(
        Event.kind == event.kind, Event.actor == event.actor,
        Event.source_ip == event.source_ip, Event.service == event.service,
        Event.occurred_at >= watermark - timedelta(minutes=minutes),
        Event.occurred_at <= watermark).order_by(Event.id)))
    if len(candidates) < threshold:
        return None
    incident = db.scalar(select(Incident).where(Incident.correlation_key == key,
        Incident.status.not_in(['resolved', 'dismissed'])))
    if not incident:
        incident = Incident(correlation_key=key, rule=rule, title=title, severity=severity,
            score=score, explanation=f'{rule}: {len(candidates)} matching {event.kind} event(s) for {event.actor} from {event.source_ip} on {event.service} within {minutes} minutes. Threshold: {threshold}. This is a signal for investigation, not proof of compromise.')
        db.add(incident)
        db.flush()
    else:
        incident.version += 1
        incident.updated_at = utcnow()
    for candidate in candidates:
        if db.get(Evidence, (incident.id, candidate.id)) is None:
            db.add(Evidence(incident_id=incident.id, event_id=candidate.id))
    return incident
