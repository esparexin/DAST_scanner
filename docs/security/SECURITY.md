# Security Policy

## Platform Security Model

This platform is a security testing tool. By nature it can generate potentially
harmful requests. The following controls ensure it operates safely and ethically.

## Authorization Requirement

**Fundamental rule: NO AUTHORIZATION + NO VALID SCOPE = NO SCAN.**

Every scan requires:
- A Project with an owner.
- A Target with an explicit authorization state set to `AUTHORIZED`.
- At least one allowed host/domain.
- Scope boundaries (allowed/excluded hosts, paths).
- Rate limits, concurrency limits, request limits, timeout limits.

## Scope Enforcement

Every outbound HTTP request MUST pass through the centralized scope validation
layer (`packages/scope/`). This layer:

1. Validates the request URL against allowed hosts.
2. Validates the request URL against excluded hosts.
3. Validates the request path against allowed paths.
4. Validates the request path against excluded paths.
5. Enforces rate limits.
6. Enforces request count limits.
7. Enforces response size limits.
8. Enforces scan duration limits.
9. Rejects any request that fails validation.

No package may bypass this layer. The HTTP client (`packages/http-client/`)
integrates scope validation as a mandatory middleware.

## Kill Switch

Every running scan can be cancelled at any time via:
- UI cancel button
- API endpoint
- CLI command
- Worker timeout

Cancellation is propagated to all active workers and pending jobs.

## Dry-Run Mode

Before active testing, users can request a dry-run that displays:
- Target scope
- Discovered endpoints
- Planned test categories
- Authentication profiles
- Estimated request volume
- Rate/concurrency limits
- Excluded areas

No requests to the target are made during dry-run beyond initial discovery.

## Credential Security

- Authentication secrets are encrypted at rest (AES-256-GCM).
- Credentials are NEVER included in:
  - Frontend API responses
  - Log output
  - Finding descriptions
  - Report content
  - Evidence snapshots (auto-redacted)
- Credential fields use write-only semantics in the API.

## Data Classification

| Data Type          | Classification | Storage          | Logging  |
|--------------------|---------------|------------------|----------|
| Auth secrets       | SECRET        | Encrypted        | NEVER    |
| Session tokens     | SECRET        | Encrypted        | NEVER    |
| API keys           | SECRET        | Encrypted        | NEVER    |
| Target URLs        | INTERNAL      | Plaintext        | Allowed  |
| Findings           | INTERNAL      | Plaintext        | Allowed  |
| Evidence           | INTERNAL      | Redacted secrets | Allowed  |
| User passwords     | SECRET        | Hashed (bcrypt)  | NEVER    |
| Scan config        | INTERNAL      | Plaintext        | Allowed  |

## Vulnerability Disclosure

If you discover a security vulnerability in this platform itself,
please report it responsibly. Do not open a public issue.

Contact: security@[organization].com

## Audit Logging

All security-relevant actions are logged to the audit log:
- User authentication events
- Project/target creation/modification
- Authorization state changes
- Scan creation/start/stop/cancel
- Scope modifications
- Report generation
- Configuration changes

Audit logs are append-only and include: timestamp, actor, action, resource, details.
