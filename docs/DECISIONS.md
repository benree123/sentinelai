# Engineering decisions

## Correctness before parallel throughput

A detection threshold is a read-modify-write operation. Two concurrent requests can each see too few records if they read before the other commits. An ingestion transaction acquires SQLite's write reservation or a PostgreSQL transaction advisory lock before checking idempotency, inserting an event, evaluating rules, linking evidence, and recording the audit entry. A partial unique index is a second defense against duplicate active incidents. The tradeoff is serialized ingestion. A later version should partition work by correlation key and measure contention before increasing throughput.

## Late events and event-time windows

The concurrent-ingestion test initially failed because the last arriving event could have an earlier timestamp than previously committed records. The engine now evaluates the current window from the maximum timestamp for the correlated subject. This supports late arrivals inside the window without letting very old records reopen historical windows. The 24-hour ingestion bound is separate from each rule's shorter window.

## JWT access plus revocable server sessions

The refurbishment uses 15-minute signed HS256 access cookies and random refresh credentials with seven-day absolute expiry. Refresh rotates the credential transactionally under the database writer lock, preventing replay of a used refresh credential. A digest of the underlying session identifier is stored; roles and suspension remain authoritative on the server. Logout, password reset, role changes, and suspension revoke sessions. Signing keys come from `SENTINEL_JWT_KEY` or a generated local file excluded from Git. The Docker app-data volume persists that local key. Key rotation across a deployed cluster still requires operational design.

HttpOnly and SameSite Strict cookies, custom request headers, no CORS access, and exact origin checks protect browser writes. WebSocket connections validate the same access token and reconnect after rotation. IP and canonical-account limits are currently in-process; they are not a distributed lockout service.

## Human-led investigation

The API rejects an open-to-resolved shortcut. An analyst records a reason to start investigation, then can contain, escalate, or resolve with a reason. Assignment changes use the same version check. Version comparison occurs in the SQL update condition so two analysts cannot silently overwrite one another. Notes and updates produce audit entries in the same transaction. The ledger supports accountability, but is not cryptographically tamper-evident.

## Streaming plus reconciliation

WebSockets deliver lightweight invalidation notifications rather than all evidence. The browser fetches authenticated API data after a notification and periodically reconciles. This avoids assuming every socket message is durable. The current socket registry is in-process; multiple workers require a shared pub/sub layer and a durable outbox for cross-worker notifications.

## Honest analysis boundaries

The default briefing does not impersonate AI. Optional local model analysis is separately labelled, uses structured output validation, and retains the canonical evidence IDs from the database. The model cannot execute response actions. This is a reliability boundary, not a claim that prompt injection or hallucination is fully solved.

## Local-first SQL

SQLite provides an easy local start, while The CI definition schedules the same API suite for PostgreSQL; the complete pre-release run passed on SQLite and PostgreSQL. Docker Compose describes the intended local PostgreSQL setup. A configuration file alone is not evidence of a successful deployment. Schema migrations, retention, and operational measurements are future work.
