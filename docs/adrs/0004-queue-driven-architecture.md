# ADR-0004: Queue-Driven Architecture with BullMQ

## Status
Accepted

## Context
Security scans are long-running (minutes to hours). Executing them in
web request handlers would cause timeouts, poor UX, and reliability issues.

## Decision
Use Redis + BullMQ for all scan execution:
1. API handlers create scan records and enqueue jobs.
2. Workers consume jobs and execute scan phases.
3. Each phase can enqueue follow-up jobs for the next phase.
4. Progress is reported via database updates and Redis pub/sub.
5. Workers are horizontally scalable.

## Consequences
- API remains responsive.
- Scans survive API restarts.
- Workers can be scaled independently.
- Redis becomes a critical dependency.
- Job failure/retry logic needed.
