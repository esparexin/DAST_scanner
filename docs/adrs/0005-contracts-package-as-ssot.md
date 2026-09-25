# ADR-0005: Contracts Package as SSOT for Types and Schemas

## Status
Accepted

## Context
With many packages sharing data structures, we need a single source of truth
for TypeScript types, Zod validation schemas, and enums to prevent drift
and duplication.

## Decision
Create `packages/contracts/` as the canonical source for:
- All shared TypeScript interfaces and types.
- All Zod validation schemas.
- All enums (scan states, severity levels, auth types, etc.).
- All constants.

Other packages import from contracts; they never redefine these types.

## Consequences
- Single place to update shared types.
- Breaking changes are caught at compile time across all packages.
- Slight coupling (all packages depend on contracts).
- contracts must remain lightweight (no runtime dependencies beyond Zod).
