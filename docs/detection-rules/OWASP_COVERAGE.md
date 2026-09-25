# OWASP Coverage Matrix

## OWASP Top 10 (2021)

| ID | Category | Status | Rules |
|----|----------|--------|-------|
| A01:2021 | Broken Access Control | Partial | SEC-BOLA-001, SEC-PT-001 |
| A02:2021 | Cryptographic Failures | Planned | |
| A03:2021 | Injection | Partial | SEC-SQLI-001, SEC-XSS-001 |
| A04:2021 | Insecure Design | Planned | |
| A05:2021 | Security Misconfiguration | Active | SEC-HDR-001..006, SEC-CORS-001, SEC-COOKIE-001..003 |
| A06:2021 | Vulnerable Components | Planned | |
| A07:2021 | Authentication Failures | Planned | |
| A08:2021 | Software/Data Integrity | Planned | |
| A09:2021 | Logging/Monitoring Failures | Planned | |
| A10:2021 | SSRF | Planned | |

## OWASP API Security Top 10 (2023)

| ID | Category | Status | Rules |
|----|----------|--------|-------|
| API1:2023 | Broken Object Level Authorization | Partial | SEC-BOLA-001 |
| API2:2023 | Broken Authentication | Planned | |
| API3:2023 | Broken Object Property Level Authorization | Planned | |
| API4:2023 | Unrestricted Resource Consumption | Planned | |
| API5:2023 | Broken Function Level Authorization | Planned | |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Planned | |
| API7:2023 | Server Side Request Forgery | Planned | |
| API8:2023 | Security Misconfiguration | Active | SEC-HDR-*, SEC-CORS-001 |
| API9:2023 | Improper Inventory Management | Planned | |
| API10:2023 | Unsafe Consumption of APIs | Planned | |

## Active Rules Summary

### Passive Rules (10)
- SEC-HDR-001: Missing HSTS
- SEC-HDR-002: Missing X-Content-Type-Options
- SEC-HDR-003: Missing X-Frame-Options
- SEC-HDR-004: Missing CSP
- SEC-HDR-005: Server Version Disclosure
- SEC-HDR-006: X-Powered-By Present
- SEC-CORS-001: Permissive CORS
- SEC-COOKIE-001: Cookie Without HttpOnly
- SEC-COOKIE-002: Cookie Without Secure
- SEC-COOKIE-003: Cookie Without SameSite

### Active Rules (4)
- SEC-XSS-001: Reflected XSS
- SEC-SQLI-001: SQL Injection
- SEC-PT-001: Path Traversal
- SEC-BOLA-001: Broken Object Level Authorization
