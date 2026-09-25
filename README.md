# DAST_scanner (SecurityScan)

> Production-Grade Authorized Web Application & API Security Testing (DAST) Platform

[![CI](https://github.com/esparexin/DAST_scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/esparexin/DAST_scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg)](https://nodejs.org/)
[![pnpm](https://img.shields.io/badge/pnpm-9.x-orange.svg)](https://pnpm.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-253%20passed-brightgreen.svg)]()

---

## Overview

**DAST_scanner** is an enterprise-grade dynamic application security testing (DAST) platform engineered for single-page applications (SPAs), microservices, and multi-protocol APIs (REST/OpenAPI, GraphQL, gRPC, WebSocket, SOAP).

Built on a **safety-first deterministic core**, DAST_scanner ensures every outbound network probe adheres to cryptographically verified scope boundaries, rate limits, and non-destructive testing profiles.

### Core Invariants

1. **Deterministic Verification First**: Every vulnerability finding must be deterministically reproducible with concrete request/response evidence before confirmation.
2. **Strict Scope Invariant**: `NO AUTHORIZATION + NO VALID SCOPE = NO SCAN`. Outbound traffic is physically constrained at the transport layer with private IP (SSRF) blacklisting and DNS pinning.
3. **Advisory AI Boundaries**: AI models are restricted to category recommendations, context analysis, and remediation guidance. AI can never directly transmit network requests or alter scan boundaries.
4. **Safe Canary Execution**: Injections use harmless, entropy-bounded sentinels and collision-resistant canaries—never weaponized payloads or denial-of-service triggers.

---

## Architecture

The monorepo is structured across 53 isolated workspace packages:

```text
DAST_scanner/
├── apps/
│   ├── api/                  # Express REST API (port 3001) with metrics & audit
│   ├── cli/                  # SecurityScan CLI scanner tool
│   └── web/                  # Next.js 14 Frontend Dashboard (port 3000)
├── packages/
│   ├── payload-engine/       # 7 curated catalogs, mutation pipeline, HPP, signing
│   ├── verification-engine/  # 5 deterministic replay verification strategies
│   ├── metrics/              # Prometheus metrics collector (/api/metrics)
│   ├── ai/                   # AI Payload Advisor, PII/secret redaction filter
│   ├── scope/                # Centralized ScopeValidator, SSRF & private IP guard
│   ├── http-client/          # SecureHttpClient with rate limiting and scope checks
│   ├── detection-engine/     # Active & passive security check executor
│   ├── contracts/            # Type definitions, Zod schemas, ScanProfile enums
│   ├── knowledge-base/       # OWASP Top 10, API Top 10, CWE, ASVS, WSTG, CVSS v3.1
│   └── ...                   # database, crawler, evidence, risk, etc.
├── checks/                   # 12 active detection packages (26 OWASP rules)
│   ├── injection/            # SQLi error-based & differential arithmetic
│   ├── xss/                  # Reflected HTML body & attribute breakout canaries
│   ├── path-traversal/       # Relative path canonicalization probes
│   ├── access-control/       # Forced browsing & sensitive endpoint exposure
│   ├── api/                  # Mass assignment & parameter privilege escalation
│   ├── authentication/       # JWT none-alg bypass & OAuth state checks
│   ├── authorization/        # BOLA/IDOR and BFLA access control checks
│   ├── cryptography/         # Cleartext HTTP transmission detection
│   ├── csrf/                 # State-changing CSRF token validation
│   ├── file-upload/          # Unrestricted file extension & traversal probes
│   ├── misconfiguration/     # Security headers, cookies, CORS, info disclosure
│   └── ssrf/                 # SSRF candidate parameter detection
├── workers/                  # Background workers & scan orchestrator
├── infrastructure/           # Docker Compose & Dockerfiles (API, Worker, Web)
├── tests/security-lab/       # In-memory vulnerable & safe servers regression suite
└── scripts/                  # Database seeder (seed.ts)
```

---

## Curated Safe Payload Catalogs

All test probes are cataloged in `packages/payload-engine` as declarative definitions:

| Catalog | Subcategory | CWE | Verification Strategy |
|---|---|---|---|
| **SQLi** | Error disruption (`'"`) & numeric identity (`10-0`) | CWE-89 | `REPLAY_PROBE_CONFIRMATION` |
| **XSS** | Tag canaries (`<xsscanary...>`) & attribute breakouts | CWE-79 | `TOKEN_EQUIVALENCE` |
| **Path Traversal** | Unix relative paths (`../../../../etc/passwd`) | CWE-22 | `REPLAY_PROBE_CONFIRMATION` |
| **Authentication** | JWT `alg: none` unsigned token probes | CWE-287 | `STATUS_CODE_STABILITY` |
| **NoSQL Injection** | MongoDB `$ne` / `$gt` operator injection | CWE-943 | `STATUS_CODE_STABILITY` |
| **SSTI** | Arithmetic canaries (`{{7*7}}`, `${7*7}`) | CWE-1336 | `REPLAY_PROBE_CONFIRMATION` |
| **XXE** | Benign entity declarations & parameter entities | CWE-611 | `REPLAY_PROBE_CONFIRMATION` |

All catalogs support **RSA-2048 digital signing** (`CatalogSigner`) and **Enterprise Overrides** (`CatalogOverrideManager`) for denylists, allowlists, and safety level ceilings.

---

## Quick Start

### Prerequisites
- **Node.js** >= 20.x
- **pnpm** >= 9.x
- **Docker & Docker Compose** (optional, for full containerized stack)

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/esparexin/DAST_scanner.git
cd DAST_scanner

# Install all workspace dependencies
pnpm install

# Build all packages and applications
pnpm build
```

### 2. Seed Sample Assessment Data (Optional)

```bash
# Seeds MongoDB with demo project, verified target, completed scan, and findings
pnpm seed
```

### 3. Run Locally

```bash
# Terminal 1: Start Express REST API (port 3001)
pnpm dev:api

# Terminal 2: Start Next.js Frontend (port 3000)
pnpm dev:web
```

- **Web Dashboard**: `http://localhost:3000`
- **REST API**: `http://localhost:3001/api/health`
- **Prometheus Metrics**: `http://localhost:3001/api/metrics`
- **Audit Logs**: `http://localhost:3000/audit`

### 4. Run via Docker Compose

```bash
docker compose -f infrastructure/compose/docker-compose.yml up --build
```

Includes MongoDB 7, Redis 7, Express API, Background Worker (2 replicas), and Next.js Web UI with built-in health checks and resource limits.

---

## CLI Scanner Usage

```bash
# Show CLI usage
node apps/cli/dist/index.js --help

# Execute a dry-run scan against an authorized target
node apps/cli/dist/index.js run \
  --target https://api.example.com \
  --profile QUICK \
  --dry-run
```

Available scan profiles: `PASSIVE`, `QUICK`, `WEB_STANDARD`, `API_STANDARD`, `AUTHENTICATED`, `AUTHORIZATION`, `FULL_ASSESSMENT`, `CICD`, `PRODUCTION_SAFE`, `SECURITY_LAB`.

---

## Testing & Quality Assurance

```bash
# Run all 253 tests across 44 test suites
pnpm test

# Run E2E Security Lab regression suite
pnpm test:e2e

# Typecheck (TypeScript strict mode)
pnpm typecheck

# Lint check (ESLint 9 flat config)
pnpm lint

# Code formatting check (Prettier)
pnpm format:check
```

---

## Security Standards Alignment

- **OWASP Top 10 2021**: Full mapping across A01 through A10
- **OWASP API Security Top 10 2023**: API1 (BOLA), API2 (Broken Auth), API3 (Excessive Data), API4 (Rate Limiting), API5 (BFLA), API8 (Injection)
- **OWASP ASVS v4.0.3**: Levels 1-3
- **OWASP WSTG v4.2**: 26 structured test procedures
- **CVSS v3.1**: Built-in score and vector calculation

---

## License

Released under the [MIT License](LICENSE).
