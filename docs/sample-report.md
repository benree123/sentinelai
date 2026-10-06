# SentinelAI incident report — INC-0004

Generated: 2026-10-05T00:24:21.592530Z

## Incident details

Title: Possible account takeover

Severity: critical

Risk: 95/100

Status: open

Assigned analyst: Unassigned

## Executive assessment

Possible account takeover affects customer-api. 11 event(s) are linked to incident INC-0004.

Analysis mode: evidence_briefing

## Risk explanation

AUTH-001 correlated sequence: Repeated authentication failures: +40; Successful authentication after failure burst: +35; Unknown device reported: +10; Unauthorized endpoint access: +10. Total 95/100. These are deterministic rule weights, not proof of account compromise.

## Evidence timeline

- 2026-10-05T00:00:13.387406 UTC — EVT-12 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 1

- 2026-10-05T00:00:28.530674 UTC — EVT-13 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 2

- 2026-10-05T00:00:43.670062 UTC — EVT-14 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 3

- 2026-10-05T00:00:58.805192 UTC — EVT-15 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 4

- 2026-10-05T00:01:13.936572 UTC — EVT-16 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 5

- 2026-10-05T00:01:29.082731 UTC — EVT-17 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 6

- 2026-10-05T00:01:44.220890 UTC — EVT-18 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 7

- 2026-10-05T00:01:59.348891 UTC — EVT-19 — login_failed
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover scenario, event 8

- 2026-10-05T00:02:14.502701 UTC — EVT-20 — unknown_device
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover sequence: unknown_device

- 2026-10-05T00:02:14.635436 UTC — EVT-21 — login_success
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover sequence: login_success

- 2026-10-05T00:02:14.790746 UTC — EVT-22 — unauthorized_access
  Account: demo-user-fd13c869; source: 203.0.113.42; service: customer-api
  Fictional account takeover sequence: unauthorized_access

## Analyst findings and actions

No analyst notes recorded.

## Recommended investigation steps

1. Review the linked timestamps and source addresses.

2. Confirm the activity with the account or service owner.

3. Document findings before resolving or escalating.

## Limitations

This local briefing is deterministic, not an AI model result. It does not prove a breach or execute response actions.

Fictional data. Workflow status records analyst decisions; no real containment actions are executed.