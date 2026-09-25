# Detection Standard

## Rule Structure

Every vulnerability detection rule must conform to the following standard.

### Rule Definition

```typescript
interface SecurityRule {
  id: string;                    // Unique rule ID, e.g., "SEC-AUTH-001"
  name: string;                  // Human-readable name
  description: string;           // What this rule detects
  category: DetectionCategory;   // e.g., AUTHENTICATION, AUTHORIZATION, XSS
  type: DetectionType;           // PASSIVE or ACTIVE
  severity: Severity;            // CRITICAL, HIGH, MEDIUM, LOW, INFO
  confidence: Confidence;        // CONFIRMED, HIGH, MEDIUM, LOW
  owasp: string[];               // OWASP Top 10 mappings
  apiOwasp: string[];            // OWASP API Security Top 10 mappings
  cwe: string[];                 // CWE IDs
  wstg: string[];                // WSTG test IDs
  portswigger: string[];         // PortSwigger reference URLs
  remediation: string;           // Remediation guidance
  references: string[];          // Additional references
  enabled: boolean;              // Whether rule is active
  tags: string[];                // Organizational tags
}
```

### Detection Categories

- ACCESS_CONTROL
- AUTHENTICATION
- AUTHORIZATION
- INJECTION
- XSS
- CSRF
- SSRF
- PATH_TRAVERSAL
- FILE_UPLOAD
- MISCONFIGURATION
- CRYPTOGRAPHY
- INFORMATION_DISCLOSURE
- API_SECURITY
- BUSINESS_LOGIC
- SESSION_MANAGEMENT

### Severity Levels

| Level    | CVSS Range | Description                                    |
|----------|-----------|------------------------------------------------|
| CRITICAL | 9.0-10.0  | Immediate exploitation risk, full compromise   |
| HIGH     | 7.0-8.9   | Significant risk, sensitive data exposure       |
| MEDIUM   | 4.0-6.9   | Moderate risk, limited impact                  |
| LOW      | 0.1-3.9   | Minor risk, minimal impact                     |
| INFO     | 0.0       | Informational, no direct security impact       |

### Confidence Levels

| Level     | Description                                          |
|-----------|------------------------------------------------------|
| CONFIRMED | Verified through multiple signals or replay          |
| HIGH      | Strong evidence, very low false-positive probability |
| MEDIUM    | Reasonable evidence, some false-positive risk        |
| LOW       | Indicator only, requires manual verification         |

### Finding States

| State      | Description                                         |
|------------|-----------------------------------------------------|
| CANDIDATE  | Potential finding, not yet verified                 |
| VERIFIED   | Confirmed through verification engine               |
| REJECTED   | Determined to be a false positive                   |
| ACCEPTED   | Manually accepted by user                           |
| MITIGATED  | Remediation applied, finding no longer valid        |
| REOPENED   | Previously mitigated, found again                   |

## Verification Requirement

Every active detection rule MUST implement a verification step:

```
Detection Phase
    │
    ▼
Candidate Finding
    │
    ▼
Verification Phase
    │
    ├──▶ CONFIRMED (evidence-backed)
    ├──▶ PROBABLE  (strong indicators)
    └──▶ REJECTED  (false positive)
```

The platform prioritizes reducing false positives over reporting quantity.

## Testing Requirements

Every rule must have:

| Test Type          | Purpose                                    |
|--------------------|--------------------------------------------|
| Positive test      | Confirms detection against known-vulnerable target |
| Negative test      | Confirms no detection against safe target  |
| False-positive test| Confirms edge cases don't trigger falsely  |
| Authenticated test | Tests with authentication where applicable |
| Unauthenticated test | Tests without authentication             |
| Regression test    | Prevents regressions in detection logic    |

## Evidence Standard

Every finding must include structured evidence:

```typescript
interface Evidence {
  request: RedactedHttpRequest;
  response: RedactedHttpResponse;
  endpoint: string;
  parameter?: string;
  authContext: string;
  comparisonResults?: ComparisonResult[];
  timestamp: Date;
  relevantHeaders: Record<string, string>;
  relevantResponseData: string;
}
```

Automatic redaction applies to: passwords, tokens, cookies, API keys, secrets, PII.

## PoC Standard

```typescript
interface ProofOfConcept {
  summary: string;
  preconditions: string[];
  steps: ReproductionStep[];
  request: RedactedHttpRequest;
  response: RedactedHttpResponse;
  evidence: Evidence;
  expectedBehavior: string;
  observedBehavior: string;
  remediation: string;
}
```

Clearly distinguish: Detection → Verification → Proof → Exploitation.
Never automatically perform destructive exploitation.
