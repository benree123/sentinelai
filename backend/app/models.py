from datetime import datetime, timezone
from sqlalchemy import String, Text, ForeignKey, Index, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(20))

class SessionToken(Base):
    __tablename__ = 'sessions'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    expires_at: Mapped[datetime]

class UserProfile(Base):
    __tablename__ = 'user_profiles'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    display_name: Mapped[str] = mapped_column(String(120))
    state: Mapped[str] = mapped_column(String(20), default='active')
    verified: Mapped[bool] = mapped_column(default=False)

class AccountToken(Base):
    __tablename__ = 'account_tokens'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    purpose: Mapped[str] = mapped_column(String(20))
    expires_at: Mapped[datetime]

class IncidentReport(Base):
    __tablename__ = 'incident_reports'
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id'))
    author: Mapped[str] = mapped_column(String(80))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

class Event(Base):
    __tablename__ = 'events'
    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str] = mapped_column(String(80), unique=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    service: Mapped[str] = mapped_column(String(80))
    actor: Mapped[str] = mapped_column(String(80), index=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    message: Mapped[str] = mapped_column(String(500))
    occurred_at: Mapped[datetime] = mapped_column(index=True)
    received_at: Mapped[datetime] = mapped_column(default=utcnow)

class Incident(Base):
    __tablename__ = 'incidents'
    id: Mapped[int] = mapped_column(primary_key=True)
    correlation_key: Mapped[str] = mapped_column(String(200))
    rule: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(160))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    score: Mapped[int]
    status: Mapped[str] = mapped_column(String(20), default='open', index=True)
    explanation: Mapped[str] = mapped_column(Text)
    assigned_to: Mapped[str | None] = mapped_column(String(80), nullable=True)
    version: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)
    __table_args__ = (Index('uq_active_correlation', 'correlation_key', unique=True,
        sqlite_where=text("status NOT IN ('resolved', 'dismissed')"),
        postgresql_where=text("status NOT IN ('resolved', 'dismissed')")),)

class Evidence(Base):
    __tablename__ = 'evidence'
    incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id'), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey('events.id'), primary_key=True)

class Note(Base):
    __tablename__ = 'notes'
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id'), index=True)
    author: Mapped[str] = mapped_column(String(80))
    body: Mapped[str] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

class Audit(Base):
    __tablename__ = 'audit'
    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(120))
    detail: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
