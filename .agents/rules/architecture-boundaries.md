# Architecture Boundaries & Monorepo Single Source of Truth (SSOT)

This document establishes immutable architectural boundaries for the **securityscan (DAST_scanner)** repository. All future agents and developers MUST strictly preserve this structure without exception.

---

## 1. Single Source of Truth (SSOT) Architecture

The monorepo structure is strictly defined as:

```text
Web_scanner/
│
├── apps/
│   ├── web/                  # Dedicated Frontend (Next.js 15 App Router)
│   ├── api/                  # Dedicated Backend REST API (Express.js on :3001)
│   └── cli/                  # Command Line Interface Client
│
├── workers/                  # Background Scanner Execution (BullMQ Queue)
│   ├── orchestrator/         # Master pipeline coordinator ('securityscan:scans')
│   ├── discovery/            # Crawler & endpoint parser
│   ├── passive-analysis/     # Non-destructive header, SSL, and leak analyzer
│   ├── active-testing/       # Active attack runner
│   ├── api-testing/          # REST/GraphQL/gRPC test runner
│   ├── verification/         # False-positive elimination replay worker
│   ├── evidence/             # HTTP capture, screenshot, DOM snapshot recorder
│   └── reporting/            # Async PDF, HTML, SARIF generator
│
├── checks/                   # Pluggable Vulnerability Detection Modules
│   ├── access-control/
│   ├── api/
│   ├── authentication/
│   ├── authorization/
│   ├── cryptography/
│   ├── csrf/
│   ├── file-upload/
│   ├── injection/
│   ├── misconfiguration/
│   ├── path-traversal/
│   ├── ssrf/
│   └── xss/
│
├── packages/                 # Shared & Domain Infrastructure
│   ├── contracts/            # Schemas, enums, DTOs (Zod) - ISOMORPHIC
│   ├── shared/               # Pino logger, errors, redaction
│   ├── database/             # Mongoose data models & connection management
│   ├── storage/              # S3 & Local filesystem storage
│   ├── scanner-core/         # Pipeline state machine & lifecycle events
│   ├── detection-engine/     # Rule evaluation & diffing
│   ├── payload-engine/       # Attack payload catalog & mutator
│   └── ...                   # Specific protocol clients & engines
│
├── tests/                    # E2E Security Lab integration test harnesses
├── tools/                    # Vulnerable testbed server
└── infrastructure/           # Docker Compose, Dockerfiles, and Kubernetes manifests
```

---

## 2. Forbidden Anti-Patterns

1. **NO `/backend` Directory**:
   - `apps/api` is the dedicated backend application.
   - NEVER create a top-level `/backend`, `/api2`, `/backend-api`, or move `apps/api`.
2. **NO Backend Logic in the Frontend (`apps/web`)**:
   - `apps/web` must NEVER import `mongoose`, `mongodb`, `ioredis`, `bullmq`, or backend secrets.
   - `apps/web` communicates with the backend exclusively via HTTP (`apps/web/src/lib/api.ts`) and Server-Sent Events (`EventSource`).
3. **NO In-Process Scanner Execution**:
   - The scanner engine must NEVER execute in the web browser or directly inside the Express API request lifecycle.
   - Scans MUST be dispatched as asynchronous jobs to BullMQ (`securityscan:scans`) and executed by `workers/*`.
4. **NO Duplicate Implementations**:
   - Do NOT create duplicate API clients. `apps/web/src/lib/api.ts` is the sole frontend client.
   - Do NOT create duplicate data models. `packages/database` is the sole database model layer.
   - Do NOT create duplicate schemas/types. `packages/contracts` is the sole schema layer.

---

## 3. Standard Development Runtime

```bash
# Infrastructure
brew services start mongodb-community  # Port 27017
brew services start redis              # Port 6379

# Applications
pnpm dev:api      # Backend REST API -> http://localhost:3001
pnpm dev:worker   # Background Worker -> BullMQ 'securityscan:scans'
pnpm dev:web      # Frontend Web Console -> http://localhost:3000
```
