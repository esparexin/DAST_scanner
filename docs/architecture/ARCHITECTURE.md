# Architecture Overview

## System Purpose

SecurityScan is a production-grade Web Application & API Security Testing Platform.
It discovers, analyzes, tests, verifies, documents, and reports vulnerabilities
in web applications and APIs — for **authorized targets only**.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Frontend (Next.js)                          │
│  Dashboard │ Projects │ Targets │ Scans │ Findings │ Reports       │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ REST API
┌──────────────────────────────▼──────────────────────────────────────┐
│                        Backend API (Node.js)                       │
│  Auth │ Projects │ Targets │ Scans │ Findings │ Reports │ Config   │
└──────┬───────────────────────┬──────────────────────────────────────┘
       │                       │
  ┌────▼────┐            ┌─────▼─────┐
  │ MongoDB │            │   Redis   │
  │ (state) │            │ (queue +  │
  │         │            │  cache)   │
  └─────────┘            └─────┬─────┘
                               │ BullMQ
┌──────────────────────────────▼──────────────────────────────────────┐
│                     Scanner Workers                                │
│  Discovery │ Crawling │ Passive │ Active │ API │ Verification      │
│  Evidence  │ Reporting                                             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                     Core Engines (packages/)                       │
│  scope │ http-client │ crawler │ detection │ verification          │
│  evidence │ finding │ risk │ reporting │ authentication            │
│  authorization │ mutation │ schema │ poc │ workflow                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Scope Enforcement  │
                    │  (MANDATORY GATE)   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Target Systems    │
                    │ (authorized only)   │
                    └─────────────────────┘
```

## Data Flow

1. User creates a **Project** and **Target** with explicit scope and authorization.
2. User configures a **Scan** (profile, auth, limits) and optionally runs a **dry-run**.
3. Scan is **validated** (scope, authorization, limits) then **queued** via BullMQ.
4. Workers execute the scan state machine:
   CREATED → VALIDATING → QUEUED → DISCOVERING → CRAWLING → PASSIVE_ANALYSIS
   → ACTIVE_TESTING → API_TESTING → VERIFYING → EVIDENCE → REPORTING → COMPLETED
5. Every outbound request passes through the **Scope Enforcement Layer**.
6. Findings are created, deduplicated, verified, and enriched with evidence.
7. Reports are generated (HTML/PDF/JSON/SARIF).

## Design Principles

1. **Safety first**: No scan without authorization + valid scope.
2. **Modular**: Each engine is an independent package with clear contracts.
3. **Queue-driven**: Long-running work goes through BullMQ, never in request handlers.
4. **Incremental**: Capabilities are added phase by phase.
5. **Testable**: Every detection rule has positive, negative, and edge-case tests.
6. **Low false positives**: Verification over volume.
7. **Auditable**: Every action is logged; every finding has evidence.

## Monorepo Layout

```
apps/
  web/           → Next.js frontend
  api/           → Node.js/Express backend API
packages/
  contracts/     → Shared TypeScript types, Zod schemas, enums
  database/      → Mongoose models, connection management
  scanner-core/  → Scan lifecycle, state machine, orchestration
  scope/         → Scope definition, validation, enforcement
  http-client/   → Centralized HTTP engine with safety controls
  crawler/       → URL/HTML/JS crawling, sitemap, robots.txt
  browser/       → Playwright-based browser engine
  api-parser/    → API specification parsing coordinator
  openapi/       → OpenAPI/Swagger parser
  graphql/       → GraphQL engine
  websocket/     → WebSocket adapter (future)
  grpc/          → gRPC adapter (future)
  soap/          → SOAP/XML adapter (future)
  authentication/→ Auth profile management and application
  authorization/ → Multi-identity authorization testing
  workflow-engine/ → Business-logic workflow modeling
  mutation-engine/ → Request mutation generation
  schema-engine/ → Schema analysis and validation
  detection-engine/ → Rule execution framework
  verification-engine/ → Finding verification
  evidence-engine/ → Evidence capture and redaction
  poc-engine/    → Safe PoC generation
  finding-engine/→ Finding normalization and deduplication
  risk-engine/   → Severity/confidence classification
  security-rules/→ Central rule registry and definitions
  reporting/     → Report generation (HTML/PDF/JSON/SARIF)
  shared/        → Utilities, constants, helpers
  storage/       → Provider-agnostic object storage (S3/local)
  ai/            → AI remediation and context triage
  metrics/       → Prometheus metrics collection
workers/
  orchestrator/  → Scan pipeline orchestration
  discovery/     → Crawl and endpoint discovery worker
  passive-analysis/ → Passive check worker
  active-testing/→ Active check worker
  api-testing/   → API-specific test worker
  verification/  → Verification worker
  evidence/      → Evidence collection worker
  reporting/     → Report generation worker
checks/
  access-control/
  authentication/
  authorization/
  injection/
  xss/
  csrf/
  ssrf/
  path-traversal/
  file-upload/
  misconfiguration/
  cryptography/
  api/
tests/
  fixtures/      → Test servers and sample specifications
  security-lab/  → End-to-end vulnerability test laboratory
  * Note: Unit and integration tests are colocated in src/__tests__/ across packages
infrastructure/
  docker/
  compose/
  mongodb/
  redis/
  monitoring/
docs/
  architecture/
  security/
  scanner/
  api/
  detection-rules/
  runbooks/
  adrs/
```

## Technology Stack

| Layer          | Technology              |
|----------------|-------------------------|
| Frontend       | Next.js, React, Tailwind CSS, TypeScript |
| Backend API    | Node.js, Express/Fastify, TypeScript |
| Database       | MongoDB + Mongoose      |
| Queue          | Redis + BullMQ          |
| Browser Engine | Playwright              |
| Validation     | Zod                     |
| Testing        | Vitest + Playwright E2E |
| Logging        | Pino                    |
| CI/CD          | GitHub Actions          |
| Containers     | Docker + Docker Compose |
| Package Mgr    | pnpm workspaces         |
