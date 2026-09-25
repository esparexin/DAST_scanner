# ADR-0001: Monorepo with pnpm Workspaces

## Status
Accepted

## Context
The platform consists of a frontend, backend API, scanner workers, and many
shared packages. We need a structure that allows independent development of
each component while sharing types, schemas, and utilities.

## Decision
Use a pnpm workspace monorepo with the following top-level directories:
- `apps/` for deployable applications (web, api)
- `packages/` for shared libraries
- `workers/` for scanner worker processes
- `checks/` for vulnerability detection rules
- `tests/` for cross-cutting tests
- `infrastructure/` for Docker/compose configs
- `docs/` for documentation

## Consequences
- Single repository for all code.
- Shared dependencies and consistent versions.
- Atomic commits across packages.
- pnpm handles workspace linking and hoisting.
