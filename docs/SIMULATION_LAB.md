# Simulation Lab implementation

`backend/app/main.py` generates paced, fixed fictional telemetry through the existing validation/ingestion/detection transaction. Analysts, managers and admins may run the lab; external ingestion remains admin-only. `SimulationInput` forbids extra fields. WebSockets broadcast started/processing/complete progress with a run identifier. The default interval is 1.1 seconds; tests set `SIMULATION_INTERVAL_SECONDS=0` without bypassing ingestion.

`backend/app/analysis.py` describes the actual linked takeover evidence, exposes supporting IDs and human-reviewed next actions. It does not impersonate model inference.

`frontend/src/SimulationLab.tsx` renders fourteen scenarios, fixed lab facts, progress and resulting incident links. `main.tsx` subscribes to progress, provides analyst navigation, and presents copilot recommendations. `api.ts` includes the simulated flag; `styles.css` contains responsive lab styling.

`backend/tests/test_api.py` covers role restrictions. `test_workspace.py` checks forbidden target/IP/domain/URL/credential/command fields, WebSocket progress and eleven stored fictional events. To verify incrementally: run these focused tests, strict typechecking, then the complete suite. Finally trigger Account takeover in the local browser and inspect the 95/100 incident/evidence and separate low-risk device signal.

No real target is contacted. Changes preserve the application architecture. Recorded assistant sections must retain the deterministic label until actual inference is configured and verified. Source publication follows the verified release checks.
