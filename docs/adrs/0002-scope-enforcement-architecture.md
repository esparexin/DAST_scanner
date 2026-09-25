# ADR-0002: Scope Enforcement Architecture

## Status
Accepted

## Context
The scanner sends HTTP requests to external systems. Without proper controls,
it could be used to attack unauthorized targets. This is the highest-risk
aspect of the platform.

## Decision
Implement a centralized scope enforcement layer (`packages/scope/`) that:
1. Is the ONLY path for validating outbound requests.
2. Is called by the HTTP client before every request.
3. Validates against allowed/excluded hosts and paths.
4. Blocks private/internal IP ranges.
5. Enforces rate limits, request counts, and duration limits.
6. Cannot be bypassed by individual checks or workers.

The HTTP client (`packages/http-client/`) integrates scope validation as a
non-optional middleware. Individual vulnerability checks receive a pre-configured
HTTP client and never construct raw HTTP requests.

## Consequences
- All outbound traffic is auditable and controllable.
- No scan can operate without a valid, authorized scope.
- Performance overhead from validation (acceptable for safety).
- Single point of enforcement (must be thoroughly tested).
