# Project Governance

## Development Phases

This project follows a phased implementation approach (Phase 0-24).
Each phase has defined scope, dependencies, and acceptance criteria.

## Phase Gate Rules

Before implementing any phase:

1. Inspect current repository state.
2. Identify existing reusable code.
3. Check for duplicate, legacy, dead, orphaned, or conflicting implementations.
4. Confirm the correct SSOT (Single Source of Truth) for affected areas.
5. Create or update required architecture/ADR documentation.
6. Create a clean implementation plan.
7. Implement only the approved scope.
8. Do not introduce unnecessary features.
9. Do not create duplicate abstractions.
10. Do not bypass existing governance.
11. Run lint, type-check, tests, and build.
12. Run security/regression tests relevant to the phase.
13. Review changed files for dead or duplicate code.
14. Commit with a clean, descriptive message.
15. Do not mix unrelated changes.

## SSOT (Single Source of Truth)

| Concern                | SSOT Location                          |
|------------------------|----------------------------------------|
| TypeScript types/enums | packages/contracts/                    |
| Zod validation schemas | packages/contracts/                    |
| Database models        | packages/database/                     |
| Scope logic            | packages/scope/                        |
| HTTP client            | packages/http-client/                  |
| Security rules         | packages/security-rules/               |
| Detection framework    | packages/detection-engine/             |
| Finding normalization  | packages/finding-engine/               |
| Evidence handling      | packages/evidence-engine/              |
| Risk classification    | packages/risk-engine/                  |
| Report generation      | packages/reporting/                    |
| Architecture docs      | docs/architecture/                     |
| Security docs          | docs/security/                         |
| ADRs                   | docs/adrs/                             |

## ADR (Architecture Decision Records)

All significant technical decisions are recorded in `docs/adrs/`.
Format: `NNNN-short-title.md`

## Branch Strategy

- `main`: Production-ready code.
- Feature branches for phases when needed.
- Squash-merge to main.

## Code Quality

- TypeScript strict mode.
- ESLint with consistent config.
- Prettier for formatting.
- Zod for runtime validation.
- No `any` types without documented justification.
- No unused imports/variables.
- No duplicate abstractions.
