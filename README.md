# SecurityScan

A production-grade Web Application & API Security Testing Platform for authorized targets.

## Overview

SecurityScan discovers, analyzes, tests, verifies, documents, and reports
vulnerabilities in web applications and APIs. It enforces strict scope
boundaries and requires explicit authorization before any testing.

**Fundamental rule: NO AUTHORIZATION + NO VALID SCOPE = NO SCAN**

## Architecture

See [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) for full details.

```
Frontend (Next.js)
    |
    v
Backend API (Express/Node.js)
    |
    v
Queue (Redis/BullMQ)
    |
    v
Scanner Workers
    |
    v
[SCOPE ENFORCEMENT GATE]
    |
    v
Authorized Target Systems
```

## Quick Start

```bash
# Prerequisites: Node.js >= 20, pnpm >= 9, Docker

# Install dependencies
pnpm install

# Start infrastructure (MongoDB + Redis)
pnpm infra:up

# Run development servers
pnpm dev

# Run tests
pnpm test

# Type check
pnpm typecheck

# Build
pnpm build
```

## Project Structure

```
apps/
  web/           - Next.js frontend
  api/           - Express backend API
packages/
  contracts/     - Shared types, schemas, enums (SSOT)
  database/      - Mongoose models
  scanner-core/  - Scan lifecycle and orchestration
  scope/         - Scope validation and enforcement
  http-client/   - Centralized HTTP engine
  shared/        - Utilities, logging, errors
  ...            - Additional engine packages
workers/         - BullMQ scanner workers
checks/          - Vulnerability detection rules
tests/           - Integration, regression, security lab
infrastructure/  - Docker, compose configs
docs/            - Architecture, security, governance
```

## Documentation

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Security Policy](docs/security/SECURITY.md)
- [Threat Model](docs/security/THREAT_MODEL.md)
- [Scanner Scope](docs/scanner/SCANNER_SCOPE.md)
- [Detection Standard](docs/scanner/DETECTION_STANDARD.md)
- [API Testing](docs/scanner/API_TESTING.md)
- [Testing Strategy](docs/TESTING.md)
- [Governance](docs/GOVERNANCE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Runbook](docs/RUNBOOK.md)

## Implementation Phases

This project follows a phased approach. See [GOVERNANCE.md](docs/GOVERNANCE.md) for details.

| Phase | Description                              | Status       |
|-------|------------------------------------------|--------------|
| 0     | Architecture, governance, safety model   | Complete     |
| 1     | Monorepo, contracts, database, CI        | Next         |
| 2     | Auth, RBAC, projects, targets, scope     | Planned      |
| 3     | Scope enforcement, HTTP client, safety   | Planned      |
| ...   | See governance docs                      | Planned      |

## License

MIT
