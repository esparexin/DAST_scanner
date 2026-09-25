# Threat Model

## System Description

A web application and API security testing platform that sends crafted HTTP
requests to authorized target systems to discover vulnerabilities.

## Assets

| Asset                     | Sensitivity | Description                          |
|---------------------------|-------------|--------------------------------------|
| Target credentials        | CRITICAL    | Auth tokens, API keys, passwords     |
| Platform user credentials | CRITICAL    | User passwords, session tokens       |
| Scan results / findings   | HIGH        | Vulnerability details for targets    |
| Evidence / PoCs           | HIGH        | Proof of exploitation                |
| Target system access      | CRITICAL    | Ability to send requests to targets  |
| Platform configuration    | MEDIUM      | Scan profiles, rules, settings       |
| Audit logs                | HIGH        | Record of all security actions       |

## Threat Actors

### T1: Unauthorized Scanner Use
**Threat**: An attacker gains access to the platform and scans unauthorized targets.
**Impact**: Legal liability, unauthorized access to third-party systems.
**Mitigations**:
- Mandatory authorization state on targets.
- Scope enforcement on every outbound request.
- Authentication + RBAC on platform access.
- Audit logging of all scan activity.

### T2: Scope Escape
**Threat**: A scan sends requests outside the authorized scope.
**Impact**: Testing unauthorized systems, legal liability.
**Mitigations**:
- Centralized scope validation layer.
- URL validation before every outbound request.
- No direct HTTP access bypassing the scope layer.
- Redirect following validates each hop against scope.
- DNS rebinding protection (resolve and validate before connecting).

### T3: Credential Theft
**Threat**: Target authentication credentials are exposed via logs, API, UI, or reports.
**Impact**: Unauthorized access to target systems.
**Mitigations**:
- Encryption at rest for all secrets.
- Write-only API semantics for credential fields.
- Automatic redaction in evidence, logs, and reports.
- No credential data in frontend responses.

### T4: Platform Compromise
**Threat**: An attacker compromises the platform itself.
**Impact**: Access to all target credentials, scan data, and authorized targets.
**Mitigations**:
- Standard web application security (input validation, auth, CSRF protection).
- Principle of least privilege for service accounts.
- Container isolation for workers.
- Network segmentation.
- Regular dependency updates.

### T5: Malicious Scan Configuration
**Threat**: A legitimate user configures a scan to cause harm (DoS via high rate).
**Impact**: Disruption of target systems.
**Mitigations**:
- Maximum rate limits enforced at platform level.
- Maximum concurrency limits.
- Maximum request count limits.
- Maximum scan duration limits.
- Response size limits.
- Crawl depth limits.

### T6: SSRF via Scanner
**Threat**: Scanner is tricked into requesting internal resources.
**Impact**: Internal network exposure.
**Mitigations**:
- Scope validation rejects private/internal IP ranges by default.
- Explicit allowlist required for all target hosts.
- DNS resolution validated against private ranges.
- Redirect targets validated against scope.

### T7: Destructive Testing
**Threat**: Active tests cause data modification or deletion on targets.
**Impact**: Data loss or corruption on target systems.
**Mitigations**:
- Read-preference for detection (observe, don't modify).
- Safe mutation strategies (use test-specific values).
- No automatic exploitation beyond detection + verification.
- Clear separation: Detection → Verification → Proof → Exploitation.
- Destructive testing requires explicit opt-in.

### T8: Report Data Leakage
**Threat**: Reports containing vulnerability details are accessed by unauthorized parties.
**Impact**: Disclosure of target vulnerabilities to attackers.
**Mitigations**:
- Reports are scoped to project/organization.
- RBAC on report access.
- Credential redaction in all report formats.
- Secure report storage and delivery.

## Trust Boundaries

```
┌─────────────────────────────────────────────┐
│              Trusted Platform               │
│  ┌────────┐  ┌─────────┐  ┌──────────────┐  │
│  │Frontend│  │ API     │  │ Workers      │  │
│  │        │──│         │──│              │  │
│  └────────┘  └────┬────┘  └──────┬───────┘  │
│                   │              │           │
│              ┌────▼────┐  ┌─────▼────────┐  │
│              │MongoDB  │  │Redis/BullMQ  │  │
│              └─────────┘  └──────────────┘  │
└──────────────────────────────┬───────────────┘
                               │
              ┌────────────────▼────────────────┐
              │     SCOPE ENFORCEMENT GATE      │
              │  (Trust boundary - all requests  │
              │   validated here)                │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │     Untrusted Target Systems     │
              │  (External web apps and APIs)    │
              └─────────────────────────────────┘
```

## Risk Matrix

| Threat | Likelihood | Impact   | Risk   | Mitigation Status |
|--------|-----------|----------|--------|-------------------|
| T1     | Medium    | Critical | High   | Designed          |
| T2     | Medium    | Critical | High   | Designed          |
| T3     | Medium    | High     | High   | Designed          |
| T4     | Low       | Critical | Medium | Designed          |
| T5     | Medium    | Medium   | Medium | Designed          |
| T6     | Medium    | High     | High   | Designed          |
| T7     | Low       | High     | Medium | Designed          |
| T8     | Low       | High     | Medium | Designed          |
