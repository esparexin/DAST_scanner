# API Testing Architecture

## Overview

API security testing is a first-class subsystem, not an afterthought bolted onto
the web scanner. APIs have different attack surfaces, authentication models,
and vulnerability patterns.

## Supported API Types

### Phase 1 (Foundation)
- REST APIs
- OpenAPI/Swagger specifications
- GraphQL APIs
- JWT authentication
- OAuth 2.0 / OpenID Connect
- API key authentication
- Cookie/session authentication

### Phase 2 (Extension)
- WebSocket APIs
- gRPC APIs
- SOAP/XML APIs

## API Discovery

1. **Specification import**: OpenAPI/Swagger JSON/YAML, GraphQL introspection
2. **Automatic discovery**: Well-known paths, response analysis
3. **Crawl-based discovery**: Link/endpoint extraction
4. **Manual definition**: User-provided endpoint lists

## OpenAPI/Swagger Support

### Import Methods
- File upload (JSON/YAML)
- URL import (with scope validation)
- Content paste
- Automatic discovery at well-known paths

### Processing Pipeline
1. Parse specification
2. Validate specification
3. Extract endpoints
4. Extract parameters
5. Extract authentication requirements
6. Extract request/response schemas
7. Map to normalized endpoint inventory
8. Generate test plan

## GraphQL Support

### Capabilities
- Introspection query
- Schema analysis
- Query construction
- Mutation construction
- Argument fuzzing
- Nested object traversal
- Authorization testing
- Query complexity analysis
- Batching analysis
- Depth limit analysis

## Mutation Engine

The mutation engine generates controlled test variants:

| Mutation Type        | Description                             |
|---------------------|------------------------------------------|
| Missing parameter    | Remove required parameters              |
| Additional parameter | Add unexpected parameters               |
| Type change          | Send wrong types (string→number, etc.)  |
| Boundary values      | Min/max/overflow values                 |
| Null values          | Send null where not expected            |
| Empty values         | Send empty strings/arrays/objects       |
| Invalid enums        | Send values outside enum range          |
| Nested changes       | Modify nested object properties         |
| Array manipulation   | Empty, single, oversized arrays         |
| Path ID changes      | Swap resource IDs (for BOLA testing)    |
| Header changes       | Modified/missing/extra headers          |
| Method changes       | Send wrong HTTP methods                 |
| Content-type changes | Send wrong content types                |
| Auth context changes | Test with different auth identities     |

All mutations pass through scope validation and rate limiting.

## API Security Checks

### Priority 1
- Authentication bypass
- BOLA/IDOR
- Broken Function Level Authorization
- Excessive data exposure
- Mass assignment

### Priority 2
- Input validation failures
- Security misconfiguration
- JWT vulnerabilities
- OAuth/OIDC issues
- CORS misconfiguration

### Priority 3
- Rate limiting absence
- Schema inconsistencies
- Undocumented endpoints
- Method authorization issues
- API versioning issues

## Authorization Testing

Multi-identity testing framework:

```
Identities:
  - Anonymous (no auth)
  - User A (regular user)
  - User B (different regular user)
  - Manager (elevated privileges)
  - Admin (full privileges)
  - Tenant A (multi-tenant isolation)
  - Tenant B (different tenant)

Test Matrix:
  For each endpoint × identity:
    1. Send request as identity
    2. Record response status + body
    3. Compare against expected access matrix
    4. Flag unauthorized access as finding
```
