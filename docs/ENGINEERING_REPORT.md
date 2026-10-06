# SentinelAI engineering report — 5 October 2026

The existing React/TypeScript + FastAPI/SQLAlchemy architecture is preserved. Local refurbishment is complete for the changes below. This is a credible portfolio demonstration, not a certified or verified production deployment. The local results below are historical; subsequent remote verification passed. See RELEASE_VERIFICATION.md for the release evidence.

## Problems discovered and fixed

1. **Registration blocked without SMTP.** Local registration now activates read-only viewer access immediately; email ownership is not asserted. Verification remains configurable and defaults to enabled in production. Recovery/invitations retain the actual SMTP prerequisite. Duplicate registration retains a generic response.
2. **Insecure production cookie defaults.** An explicit production mode refuses insecure cookies, missing/invalid signing keys and non-HTTPS public URLs. Added a production Compose override. Docker no longer embeds an insecure-cookie default.
3. **Duplicate report download route.** Removed the duplicate declaration; authenticated stored-snapshot download remains intact.
4. **JWT parser accepted unexpected signed headers.** Header/type/algorithm and token size are checked before accepting claims. Existing issuer/audience/expiry/signature checks remain.
5. **Whitespace-only incident reasons.** Backend now requires at least five meaningful characters.
6. **Concurrent login failures could overwrite one another.** Failure accumulation now rereads and appends under the lock instead of using the earlier snapshot. Five parallel failures from different IPs are tested to lock the account.
7. **Launch-directory-dependent storage.** SQLite, signing key and local credential files now resolve against backend/data; the root launch command preserves the existing database.
8. **Missing client error handling and workspace states.** Auth configuration and analyst directory failures are caught; workspace pages show loading/error/retry/empty states and discard stale data responses. Page keys isolate requests on navigation.
9. **Dialog accessibility.** Investigation/simulation dialogs focus a control, contain Tab/Shift+Tab navigation, restore focus on close and retain Escape support. Added visible keyboard outlines.
10. **Sensitive administrative decisions lacked confirmation.** Role/access changes and other-session revocation ask for confirmation before submission.
11. **Repository usability and misleading documentation.** Added root developer scripts and pytest import configuration; rewritten README separates implemented, optional and planned capabilities. Removed unused Alembic/Mako/MarkupSafe/OpenTelemetry dependency declarations; no migration/tracing integration is claimed.
12. **Environment secret variants not excluded.** Ignore files now cover .env.* while retaining .env.example.

## Preserved and incrementally improved

Shared transactional event ingestion/detection, durable evidence and audit records, incident version conflicts/state transitions, salted PBKDF2, rotating revocable refresh credentials, API roles, WebSocket authentication/origin checks, deterministic risk and labelled model fallback remain. The Simulation Lab emits fixed fictional events over time, rejects target/command/credential fields, and shows live progress. Analysts can run these fixed simulations; arbitrary event ingestion stays admin-only. See SIMULATION_LAB.md.

Liveness is separate from database readiness. Responses carry a generated X-Request-ID. Structured application logging calls include request method/path/status/duration without bodies/cookies/passwords. Operational log handlers, central collection and alerting still require deployment configuration; no OpenTelemetry integration is claimed.

## Files changed

| Files | Purpose |
|---|---|
| backend/app/config.py (new) | Deployment validation and verification/cookie policy |
| backend/app/main.py | Registration-adjacent session cookie policy, storage paths, meaningful reasons, request correlation/liveness, concurrent lockout fix, paced fixed simulations/progress |
| backend/app/security.py | Bounded JWT/header validation |
| backend/app/workspace.py | Direct or verified registration, secure refresh cookies, auth policy configuration, duplicate report-route removal |
| backend/app/analysis.py | Actual takeover observations, human-reviewed next actions and 500-character bounds on individual model hypotheses/steps |
| backend/tests/test_analysis.py (new) | Three invalid structured-model-content fallback regressions using a mocked local transport |
| backend/tests/test_api.py | Fixed-simulation permissions and deterministic test pacing |
| backend/tests/test_workspace.py | Registration, production guard, JWT, reason, route uniqueness, liveness/request ID, simulation progress and parallel lockout regressions |
| backend/requirements.txt | Remove unused dependency declarations |
| frontend/src/Authentication.tsx | Direct-registration copy, error handling and truthful email requirements |
| frontend/src/WorkspacePage.tsx | Loading/empty/retry states, stale-response protection, activation labels and account/session confirmations |
| frontend/src/main.tsx | Simulation routing/live progress, copilot actions, initial loading, caught directory errors, modal focus containment, keyed workspace pages |
| frontend/src/SimulationLab.tsx (new) | Fixed scenario selection, lab facts and live progress |
| frontend/src/api.ts | Simulated event contract |
| frontend/src/styles.css | Responsive simulation layout, restrained panel styling and focus outlines |
| frontend/package.json | Explicit typecheck command |
| package.json (new), pytest.ini (new) | Root setup/development/build/test commands and predictable backend imports |
| Dockerfile, compose.yaml, compose.production.yaml (new) | Separate local and HTTPS production policies |
| .env.example, .gitignore, .dockerignore | Document policy settings and exclude environment secrets/generated files |
| .github/workflows/ci.yml | Add Python advisory audit to existing SQLite/PostgreSQL/frontend/container jobs |
| README.md, docs/DECISIONS.md, docs/REFURBISHMENT.md | Accurate architecture, launch commands, feature boundaries and CI wording |
| docs/AUDIT.md, docs/SIMULATION_LAB.md, this report | Findings, staged simulation explanation and exact validation |
| docs/screenshots/direct-registration.jpg, overview-current.jpg | Actual local UI proof |

Existing tests and working functionality were retained. This local audit preceded remote CI verification. Mail delivery and cloud deployment remain unverified.

## Exact validation commands and results

The restricted Windows host uses installed Python dependencies from a workspace directory. Before Python checks, this session set:

```powershell
$env:PYTHONPATH='C:\Users\akpuc\Documents\Codex\2026-10-04\i-x20\work\sentinel\deps'
```

This points to dependency packages only; root pytest.ini supplies the backend application import path. A normal clone uses a virtual environment and requirements.txt.

| Command and working directory | Actual result |
|---|---|
| `python -m pytest tests -q` — backend, baseline before fixes | 57 passed; 2 warnings; 529.29 seconds |
| `python -m pytest -q` — repository root, expanded suite | 63 passed; 2 warnings; 611.96 seconds |
| `python -m pytest outputs/SentinelAI/backend/tests/test_workspace.py -k 'parallel_login_failures or account_lockout' -q` — host workspace, after final lockout change | 2 passed, 25 deselected; 2 warnings; 28.07 seconds. Includes the new 64th test and existing lockout regression. A single final 67-case local run is not claimed; the 63-case suite plus targeted lockout and model-bound regressions were executed. |
| `python -m pytest backend/tests/test_analysis.py -q` � root after final model bounds | 3 passed; 1 cache warning; 0.85 seconds. Mocked model responses test oversized summary/hypothesis/action fallback; no real inference claimed. |
| `python -m pytest --collect-only -q` — repository root before final extra test | 63 collected successfully |
| `npm run typecheck` — frontend and root script | Passed strict TypeScript checking, including final UI changes |
| `npm test` — frontend; `npm run test:frontend` — root | All 3 client session-refresh regressions passed |
| `npm run build` — frontend | Failed: Windows `spawn EPERM` while Vite loads config through esbuild |
| `npm exec -- vite build --configLoader runner` — frontend | Also failed: Windows `spawn EPERM` in Vite filesystem resolution |
| `node_modules\@esbuild\win32-x64\esbuild.exe src\main.tsx --bundle --minify --format=esm --target=es2022 --outfile=dist\app.js --define:process.env.NODE_ENV='"production"'` — frontend | Direct executable bundle passed; final JS 277.7 KB/CSS 29.1 KB. This is the local preview build, not a passing Vite build. |
| `python -m compileall -q outputs/SentinelAI/backend/app` — host workspace | Passed |
| `python -c "import sys; sys.path.insert(0,'outputs/SentinelAI/backend'); import app.main, app.workspace, app.analysis, app.config; print('Python imports passed')"` — host workspace | Imports passed |
| `npm run dev:backend` — repository root | Actual API startup complete on 127.0.0.1:5090; existing DB preserved; WebSocket accepted |
| `npm audit --audit-level=high --json` — frontend | Zero reported advisories in every severity; 120 total dependency entries in report |
| `python work/check_advisories.py` — host workspace | Queried official PyPI JSON for all 27 pinned requirements; zero query errors, zero reported advisories |
| `python work/scan_sentinel.py` — host workspace | 39 tracked files inspected; no matched private-key/AWS/GitHub-token patterns or tracked local credential stores |
| `python work/check_local_secret.py` — host workspace | 48 source files inspected before this report; zero matches for actual generated local password |
| `git -C outputs/SentinelAI diff --check` — host workspace | Passed |

Backend warnings remain visible: Starlette deprecates its httpx TestClient transport; pytest cannot write its cache temporary directory under this host's restrictions. Neither affected test results. No warnings were suppressed. The subsequent Linux CI runs passed all 67 cases on both SQL databases, with only the framework deprecation warning. Review the framework-supported test client migration as dependencies evolve.

README commands are mapped to existing tools; root typecheck, frontend test and backend startup were executed. Root pytest was executed. Fresh dependency installation and a complete fresh-clone Vite build were not verified in this restricted host. Docker remains unavailable on that Windows host; the subsequent Linux CI run verified image startup and PostgreSQL integration. CI defines checks but the later successful run is documented in RELEASE_VERIFICATION.md.

## Browser and media verification

Actual local browser checks showed direct registration without the SMTP warning, successful analyst sign-in, preserved incident evidence, and incident INC-0006 progressing through investigating, contained and resolved. Dashboard active/critical counters updated to 7/2. No arbitrary target was contacted.

The repository demo video is a **90-second portrait illustrated walkthrough assembled from actual browser captures**, with edited timing and on-screen captions. Briefing/copilot sections explicitly say deterministic evidence assistant. It has no narration/music and is not represented as an uninterrupted screen recording. Login password remains masked; only fictional account information appears. FFmpeg decoding verified 2,160 frames at 24 fps, 720×1280, duration 00:01:30.00; visual storyboard and end-frame review were performed.

## Remaining limitations and next improvements

1. Standard Vite build, Docker image/runtime and PostgreSQL suite are now verified on CI; complete deployment-specific TLS, operations and provisioning review before production use.
2. Add reviewed migrations, backups, retention and measured query performance. Current analytics enumerate incident records and are suited to a bounded demo dataset.
3. Replace process-local rate limits and sockets with shared coordination and durable event delivery before multiple workers. Rotating refresh credentials across separate tabs also need explicit browser coordination/replay-grace design; the current coalescing is within one tab.
4. Configure and verify TLS/trusted proxies, SMTP, production account provisioning and key rotation. Local direct registration does not verify email ownership.
5. Configure actual model inference and evaluate evidence faithfulness; grounding/output schemas cannot guarantee truth. Model hypotheses/actions are bounded individually as well as in count; the fallback tests cover oversized structured content.
6. Implement OAuth/MFA only with tested providers/flows. Do not add fake buttons or integrations.
7. Complete a desktop/mobile accessibility review with automated checks and assistive technology. Current browser verification used the actual narrow in-app viewport; full breakpoint/device coverage is not claimed.
8. Add observability exporters/operational dashboards and audited log retention. Request IDs/logging calls alone are not a monitoring integration.

The source ZIP is refreshed separately after final validation. The user explicitly authorized GitHub source publication after successful CI, build and Docker/PostgreSQL verification.
