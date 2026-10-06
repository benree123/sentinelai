# Repository audit before changes

Reviewed backend models, ingestion/detection, authentication, account lifecycle, reporting, analysis, frontend authentication/workspace/simulation/client, tests, Docker, Compose, CI, documentation and dependency manifests.

## Findings
- Registration requires SMTP even in the local demo; user requested direct account creation. Preserve verification as a configurable production policy; default local registration must work without email.
- Docker and Compose default insecure cookies without a production guard. Add explicit environment validation and a distinct production override.
- Report download is registered twice. Remove duplicate endpoint.
- JWT parser does not validate its header; add explicit HS256/type and bounded input checks.
- Incident reason allows whitespace-only text. Validate meaningful reason.
- Authentication configuration and analyst directory promises can reject without visible error handling.
- Workspace pages lack loading, empty, retry and stale request protection.
- Incident dialog lacks keyboard focus containment and restoration.
- No root developer command surface or root pytest import configuration.
- Requirements include unused Alembic/OpenTelemetry packages with no actual migration/tracing integration.
- README role/scenario/test descriptions lag current implementation.

## Existing design retained
Transactional ingestion with SQLite write reservations/Postgres advisory locks; unique active correlations; optimistic incident versions; salted PBKDF2; JWT plus rotating revocable session digests; API RBAC; same-origin custom-header write protection; WebSocket authentication; safe fixed fictional scenarios; labelled deterministic fallback; human-only response decisions.

## Baseline execution
TypeScript check passed. Three frontend tests passed. Standard Vite build fails with OS spawn EPERM in this restricted Windows environment; record this limitation, do not suppress it. Backend suite started before changes. Docker is not installed. External integration and CI results must remain unclaimed.
