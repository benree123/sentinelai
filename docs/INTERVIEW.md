# Interview walkthrough

1. Sign in as an administrator. Run a credential attack scenario and explain why the first four events create no incident, while the fifth reaches the threshold.
2. Open the incident. Show its six linked events, rule ID, risk weight, and explanation. Distinguish a detection signal from proof of compromise.
3. Add a note. Start investigation with a reason, then resolve it. Show the audit trail and explain how version conflicts protect concurrent edits.
4. Sign out and use the viewer account. Explain why hiding buttons alone is insufficient and point to server-side role checks and negative tests.
5. Explain external-ID idempotency, the ingestion transaction, partial unique indexes, and the event-time watermark. Describe the late-arrival bug caught by the concurrency test.
6. Open a second session and run a scenario. Explain WebSocket invalidation, periodic reconciliation, and why a multi-worker version needs shared pub/sub.
7. Prepare a briefing. Explain that the default is deterministic, show where the local Ollama adapter is configured, and describe output validation/fallback. Do not claim model inference you have not run.
8. Open the test suite and CI result. Explain one meaningful failure case from each category: authorization, validation, concurrency, workflow, and streaming.

Before an interview, change a detection threshold, add a new test, and explain the change without relying on generated descriptions. Employers can assess your understanding more reliably than a polished screenshot alone.
