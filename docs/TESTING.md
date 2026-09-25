# Testing Strategy

## Test Layers

### Unit Tests (Vitest)
- Every package has its own unit tests.
- Tests live alongside source code or in `__tests__/` directories.
- Mock external dependencies.
- Fast execution (<30s total).

### Integration Tests
- Located in `tests/integration/`.
- Test cross-package interactions.
- Use real MongoDB (via testcontainers or in-memory) and Redis.
- Test API endpoints end-to-end.

### Detection Regression Tests
- Located in `tests/regression/`.
- Every security rule has positive/negative/false-positive tests.
- Run against controlled fixtures in `tests/fixtures/`.
- Must pass before merging.

### Security Lab Tests
- Located in `tests/security-lab/`.
- Run against intentionally vulnerable applications.
- Validate end-to-end scan accuracy.
- OWASP Juice Shop, WebGoat, custom vulnerable apps.

### E2E Tests (Playwright)
- Test the frontend application.
- Located in `apps/web/e2e/` or `tests/e2e/`.

## Test Requirements per Rule

| Test              | Required | Description                        |
|-------------------|----------|------------------------------------|
| Positive test     | YES      | Detects known vulnerability        |
| Negative test     | YES      | No false positive on safe target   |
| FP test           | YES      | Edge cases don't trigger falsely   |
| Auth test         | IF APPL. | Works with authentication          |
| Unauth test       | IF APPL. | Works without authentication       |
| Regression test   | YES      | Prevents regressions               |

## CI Pipeline

1. Lint (ESLint)
2. Type check (TypeScript)
3. Unit tests (Vitest)
4. Integration tests
5. Detection regression tests
6. Build
7. E2E tests (if applicable)

All must pass before merge.

## Coverage

Minimum coverage targets:
- Packages: 80% line coverage
- Security rules: 100% (positive + negative)
- API endpoints: 90%
