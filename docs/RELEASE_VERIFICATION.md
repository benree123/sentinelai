# Release verification — 5 October 2026

The user authorized public GitHub source publication after successful standard build, CI and Docker/PostgreSQL runtime checks. All pre-release gates passed on a private GitHub Linux runner.

| Gate | Executed check | Result |
|---|---|---|
| Standard build | npm ci; npm run build (tsc --noEmit && vite build) | Passed; 1,583 modules, Vite build 4.14 seconds |
| Frontend tests | npm test | All 3 session-refresh regressions passed |
| SQLite backend | python -m pytest tests -q | 67 passed; 1 framework warning; 63.66 seconds |
| PostgreSQL backend | Same suite against disposable sentinel_test on PostgreSQL 17 | 67 passed; 1 framework warning; 73.73 seconds |
| JavaScript advisories | npm audit --audit-level=high | Zero reported vulnerabilities |
| Python advisories | pip-audit -r backend/requirements.txt | No known vulnerabilities found |
| Docker build/start | docker compose up --build --wait --wait-timeout 180 | App and PostgreSQL containers healthy; standard Vite build also passed inside the image |
| Runtime workflow | python3 scripts/container_smoke.py | Passed: served Vite assets, unauthenticated access rejection, analyst login, eleven-event safe simulation, critical 95/100 incident, linked evidence, investigating/contained/resolved transitions and report download |

Private verification commit: 36b39324dee3f9e04d4b37afddff13e8d94c7912. All four jobs concluded success. Maintainer-only evidence: https://github.com/benree123/sentinelai-verification/actions/runs/37399610646. The public repository workflow repeats these checks; its badge and run links are public evidence.

The original Windows host still blocks Node child-process launches with spawn EPERM and has no Docker/WSL installation. This does not require replacing Vite: the normal build succeeded in two clean Linux environments. No errors were suppressed.

SMTP remains optional for the portfolio. Local direct registration activates viewer access without asserting email ownership. Recovery/invitations require real SMTP. OAuth and MFA remain documented roadmap items. Actual LLM inference, external threat intelligence, cloud deployment and production operations are not claimed.

The short walkthrough is an edited sequence of actual local browser captures with captions, fictional data and deterministic-assistant labels. Source publication does not imply a hosted production service or a LinkedIn post.
