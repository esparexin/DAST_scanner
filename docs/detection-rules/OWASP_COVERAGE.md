# Security Knowledge Base & Coverage Matrix

This document provides an explicit, verified coverage matrix mapping SecurityScan's implemented detection engines and rule checks to international security standards: **OWASP Top 10 (2021)**, **OWASP API Security Top 10 (2023)**, **OWASP WSTG v4.2**, **OWASP ASVS v4.0.3**, **CWE**, and **CVSS v3.1**.

---

## 1. OWASP Top 10 (2021) Coverage

| Category | Category Name | Status | Implemented Check Rules |
|---|---|---|---|
| **A01:2021** | Broken Access Control | **Verified** | `SEC-BOLA-001`, `SEC-BFLA-001`, `SEC-PT-001`, `SEC-CSRF-001`, `SEC-AC-001`, `SEC-OAUTH-001` |
| **A02:2021** | Cryptographic Failures | **Verified** | `SEC-CRYPTO-001`, `SEC-HDR-001` |
| **A03:2021** | Injection | **Verified** | `SEC-SQLI-001`, `SEC-XSS-001` |
| **A04:2021** | Insecure Design | **Verified** | `SEC-UPL-001`, `SEC-API-003-MASS`, RateLimitEngine (Bounded) |
| **A05:2021** | Security Misconfiguration | **Verified** | `SEC-HDR-001..006`, `SEC-CORS-001`, `SEC-COOKIE-001..003`, `SEC-AC-001` |
| **A06:2021** | Vulnerable and Outdated Components | **Verified** | `SEC-HDR-005`, `SEC-HDR-006` (Component & Server Fingerprinting) |
| **A07:2021** | Identification & Authentication Failures | **Verified** | `SEC-JWT-001`, `SEC-JWT-002`, `SEC-OAUTH-001` |
| **A08:2021** | Software and Data Integrity Failures | **Verified** | `SEC-JWT-001`, `SEC-JWT-002` (Unsigned/Altered Token Ingestion) |
| **A09:2021** | Security Logging and Monitoring Failures | **Observable** | Audit trail verification and debug endpoint exposure (`SEC-AC-001`) |
| **A10:2021** | Server-Side Request Forgery (SSRF) | **Verified** | `SEC-SSRF-001` (Candidate Parameter Discovery & Private IP Egress Filtering) |

---

## 2. OWASP API Security Top 10 (2023) Coverage

| Category | Category Name | Status | Implemented Check Rules |
|---|---|---|---|
| **API1:2023** | Broken Object Level Authorization (BOLA) | **Verified** | `SEC-BOLA-001` (Identifier permutation & authorization boundary validation) |
| **API2:2023** | Broken Authentication | **Verified** | `SEC-JWT-001`, `SEC-JWT-002`, `SEC-OAUTH-001` |
| **API3:2023** | Broken Object Property Level Authorization | **Verified** | `SEC-API-003` (Excessive Data Exposure), `SEC-API-003-MASS` (Mass Assignment) |
| **API4:2023** | Unrestricted Resource Consumption | **Verified** | `RateLimitEngine` (Burst probing for 429, Retry-After, and rate limit headers) |
| **API5:2023** | Broken Function Level Authorization (BFLA) | **Verified** | `SEC-BFLA-001`, `SEC-AC-001` |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | **Verified** | `WorkflowEngine` (Multi-step business transaction modeling) |
| **API7:2023** | Server-Side Request Forgery | **Verified** | `SEC-SSRF-001` (Destination parameter analysis & SSRF pre-flight filtering) |
| **API8:2023** | Security Misconfiguration | **Verified** | `SEC-HDR-001..006`, `SEC-CORS-001`, `SEC-CRYPTO-001` |
| **API9:2023** | Improper Inventory Management | **Verified** | `SEC-API-009` (`UndocumentedEndpointDetector` shadow/deprecated route detection) |
| **API10:2023**| Unsafe Consumption of APIs | **Supported** | Schema drift analysis (`packages/schema-engine`) |

---

## 3. Detailed Rule Catalog & Standard Cross-Reference

| Rule ID | Name | Type | Severity | CVSS v3.1 | CWE | WSTG v4.2 | ASVS v4.0.3 | PortSwigger Guide |
|---|---|---|---|---|---|---|---|---|
| `SEC-HDR-001` | Missing HSTS Header | PASSIVE | MEDIUM | 3.1 | CWE-319 | WSTG-CONF-07 | V14.4.3 | - |
| `SEC-HDR-002` | Missing X-Content-Type-Options | PASSIVE | LOW | 4.3 | CWE-693 | WSTG-CONF-07 | V14.4.2 | - |
| `SEC-HDR-003` | Missing X-Frame-Options | PASSIVE | MEDIUM | 4.3 | CWE-1021 | WSTG-CONF-07 | V14.4.1 | Clickjacking |
| `SEC-HDR-004` | Missing Content-Security-Policy | PASSIVE | MEDIUM | 5.4 | CWE-693 | WSTG-CONF-07 | V14.4.1 | XSS / CSP |
| `SEC-HDR-005` | Server Version Disclosure | PASSIVE | INFO | 5.3 | CWE-200 | WSTG-INFO-02 | V14.3.3 | Reconnaissance |
| `SEC-HDR-006` | X-Powered-By Header Disclosure | PASSIVE | INFO | 5.3 | CWE-200 | WSTG-INFO-02 | V14.3.3 | Reconnaissance |
| `SEC-CORS-001` | Permissive CORS Policy | PASSIVE | MEDIUM | 5.4 | CWE-942 | WSTG-CONF-07 | V14.4.6 | CORS |
| `SEC-COOKIE-001` | Cookie Missing HttpOnly | PASSIVE | MEDIUM | 4.3 | CWE-1004 | WSTG-SESS-02 | V3.4.2 | Cookie Security |
| `SEC-COOKIE-002` | Cookie Missing Secure Flag | PASSIVE | MEDIUM | 3.1 | CWE-614 | WSTG-SESS-02 | V3.4.1 | Cookie Security |
| `SEC-COOKIE-003` | Cookie Missing SameSite | PASSIVE | LOW | 4.3 | CWE-1275 | WSTG-SESS-02 | V3.4.3 | CSRF |
| `SEC-CRYPTO-001` | Cleartext HTTP Channel | PASSIVE | HIGH | 5.9 | CWE-319 | WSTG-ATHN-01 | V9.1.1 | Transport Security |
| `SEC-SQLI-001` | SQL Injection (Error-Based) | ACTIVE | CRITICAL | 9.8 | CWE-89 | WSTG-INPV-05 | V5.3.4 | SQL Injection |
| `SEC-XSS-001` | Reflected Cross-Site Scripting | ACTIVE | HIGH | 6.1 | CWE-79 | WSTG-INPV-01 | V5.3.1 | XSS |
| `SEC-PT-001` | Path Traversal File Access | ACTIVE | HIGH | 7.5 | CWE-22 | WSTG-ATHZ-01 | V12.3.1 | Path Traversal |
| `SEC-SSRF-001` | SSRF Candidate Parameter | ACTIVE | HIGH | 8.6 | CWE-918 | WSTG-INPV-19 | V12.6.1 | SSRF |
| `SEC-CSRF-001` | Missing Anti-CSRF Token | ACTIVE | MEDIUM | 6.5 | CWE-352 | WSTG-SESS-05 | V4.2.1 | CSRF |
| `SEC-UPL-001` | Executable Upload Bypass | ACTIVE | CRITICAL | 8.8 | CWE-434 | WSTG-BUSL-09 | V12.1.1 | File Upload |
| `SEC-AC-001` | Exposed Admin / Debug File | ACTIVE | HIGH | 7.5 | CWE-285 | WSTG-CONF-04 | V4.1.3 | Access Control |
| `SEC-API-003-MASS`| API Mass Assignment | ACTIVE | HIGH | 8.1 | CWE-915 | WSTG-APIT-01 | V5.1.4 | API Testing |
| `SEC-BOLA-001` | Broken Object Level Auth | ACTIVE | HIGH | 8.1 | CWE-639 | WSTG-ATHZ-04 | V4.1.1 | IDOR |
| `SEC-BFLA-001` | Broken Function Level Auth | ACTIVE | HIGH | 9.1 | CWE-285 | WSTG-ATHZ-02 | V4.1.3 | Access Control |
| `SEC-JWT-001` | JWT None-Algorithm Bypass | ACTIVE | CRITICAL | 9.1 | CWE-287 | WSTG-ATHN-01 | V3.5.2 | JWT Attacks |
| `SEC-JWT-002` | JWT Missing Signature Verif. | ACTIVE | CRITICAL | 9.1 | CWE-347 | WSTG-ATHN-01 | V3.5.1 | JWT Attacks |
| `SEC-OAUTH-001` | OAuth Missing State Parameter | ACTIVE | HIGH | 8.1 | CWE-352 | WSTG-SESS-05 | V3.1.1 | OAuth Attacks |
| `SEC-API-009` | Undocumented Shadow API | ACTIVE | MEDIUM | 5.3 | CWE-1059| WSTG-APIT-01 | V13.1.1 | API Testing |
| `SEC-API-003` | Excessive Data Exposure | ACTIVE | HIGH | 7.5 | CWE-200 | WSTG-APIT-01 | V13.1.3 | API Testing |

---

## 4. Specialized Protocol Analyzers

* **WebSocket Security Analyzer (`packages/websocket`)**: Handshake negotiation testing, unencrypted `ws://` detection, and Cross-Site WebSocket Hijacking (CSWSH) origin validation.
* **gRPC-Web Protocol Analyzer (`packages/grpc`)**: gRPC-Web content-type inspection, `grpc-status` validation, and server reflection exposure detection.
* **SOAP / XML Web Service Analyzer (`packages/soap`)**: Automated WSDL contract discovery, operation extraction, and safe XML probe envelope generation.
