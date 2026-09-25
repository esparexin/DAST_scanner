# ADR-0003: Scan Lifecycle State Machine

## Status
Accepted

## Context
Scans are long-running, multi-phase operations. We need a well-defined
state machine to track progress, enable cancellation, and ensure reliability.

## Decision
Implement a strict state machine for scan lifecycle:

```
CREATED → VALIDATING → QUEUED → DISCOVERING → CRAWLING → PASSIVE_ANALYSIS
→ ACTIVE_TESTING → API_TESTING → VERIFYING → EVIDENCE → REPORTING → COMPLETED
```

Terminal states: COMPLETED, FAILED, CANCELLED, TIMEOUT

State transitions are:
- Validated (only allowed transitions can occur).
- Persisted to MongoDB.
- Published via Redis pub/sub for real-time UI updates.
- Logged for observability.

Only BullMQ workers drive state transitions. API handlers enqueue work
but never execute scan phases directly.

## Consequences
- Clear visibility into scan progress.
- Reliable cancellation at any phase.
- Recovery possible from known states.
- Workers are stateless; state lives in the database.
