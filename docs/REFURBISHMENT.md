# SentinelAI refurbishment — implementation status

The requested destination is **AI-Powered Security Operations & Incident Response**. Release 0.2 improves the local application with source publication authorized after successful verification. It does not claim the entire production roadmap is finished.

| Requested capability | Current implementation / boundary |
|---|---|
| Professional authentication | Corporate sign-in, email/username login, 15-minute JWT access, rotating seven-day refresh credentials, logout/revocation, IP and canonical-account lockout, recovery/verification flows, session list/revocation. SMTP is required for account emails; local direct registration works without verification. Google/Microsoft OAuth and optional MFA are not implemented. |
| Four roles | Administrator, SOC Manager, Security Analyst, Viewer/Auditor. Backend enforcement includes manual `/admin/users` navigation. |
| Live SOC dashboard | Real database counts, UTC-today events, 24-hour activity, severity queue, WebSocket invalidation and reconciliation. |
| Event simulator | Fourteen selectable scenarios, thirteen accepted event kinds. The takeover scenario sends eleven fictional events through the shared ingestion/detection transaction. |
| AI threat analyst | Structured local Ollama adapter plus clearly labelled deterministic fallback. Actual model inference is not connected/verified in this environment. Analysis is requested by an analyst rather than run by a background worker. |
| SOC copilot | Bounded incident-context questions; structured model output when configured; evidence-based fallback for risk, timeline, accounts, and investigation steps. |
| Incident timeline | Stored event timestamps and evidence; copilot timeline summary with honest mode labels. |
| Risk explanation | Deterministic signal rules and additive takeover weights; the demonstrated complete sequence scores 95/100. |
| Incident management | Open → Investigating → Contained / Escalated → Resolved; assignment, evidence, version checks, notes, recorded reasons. Dismissal remains available where permitted. Status changes do not execute real containment. |
| Live notifications | Critical alert toast and persistent notification control with an Investigate action. |
| Threat intelligence | Internal source counts, linked incidents and highest risk. No fabricated countries, IP reputation claims, or external feed connection. |
| Analytics | Workflow counts, rules, risk distribution, top account event volume, resolution metrics. |
| Reports | Readable Markdown report containing incident details, assessment mode, evidence timeline, risk explanation, analyst notes and recommendations. PDF export is future work. |
| Audit | Login/logout, ingest, explicit investigation opening, notes, assignments/status, analysis/copilot/report use, user administration and session revocation. Application append-only, not tamper-evident storage. |
| Health | API/database check, configured Ollama model probe, email configuration, event-processing and WebSocket status. Redis is explicitly not configured. |
| Docker | App + PostgreSQL configuration and persistent app-data volume. Separate frontend, Redis, worker, durable queue and cloud deployment remain future architecture. Docker/PostgreSQL build and runtime smoke passed on the Linux CI runner; Docker is unavailable on the original Windows host. |
| CI/CD | Workflow source defines backend SQLite/PostgreSQL tests, frontend type/build/dependency checks and Docker build. The complete pre-release workflow passed; cloud/production deployment is not claimed. |
| Tests | See ENGINEERING_REPORT.md for the latest executed test counts and results. Original regression tests plus refurbishment checks for tokens, privileges, suspension, recovery, scoring, workflow, health and audit. See README for actual local results. |
| API docs | FastAPI `/docs`, including new account, administration, analytics, intelligence, copilot and report endpoints. |
| User management | Directory, role changes, suspend/reactivate, invitations, session invalidation, self-demotion protection. Invitation delivery needs SMTP. |

## Local review

1. Sign out to review the redesigned first screen. Demo usernames remain admin, manager, analyst and viewer; the local credentials file contains the generated password.
2. Sign in as admin. Run **Account takeover sequence**, watch real-time counters, and open the critical incident.
3. Ask **Why was this marked critical?** or **Summarize the timeline**. Check the evidence IDs and analysis label.
4. Assign an analyst, record a reason, investigate, contain/escalate and resolve. Export the report.
5. Review User management, Security analytics, Threat intelligence, System health, My sessions and Audit trail.
6. Sign in as analyst and manually visit `/admin/users`; backend access is rejected.

## Remaining integration decisions

A functioning local model, SMTP provider, OAuth app registrations, optional MFA design, Redis/worker architecture, production migrations, and deployment must be configured and verified before presenting the full platform as complete. No external credentials are included in source control. GitHub source publication is authorized after the successful checks. LinkedIn posting remains separate.
