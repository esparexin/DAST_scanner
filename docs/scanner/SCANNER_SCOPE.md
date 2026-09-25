# Scanner Scope & Safety Model

## Fundamental Rule

```
NO AUTHORIZATION + NO VALID SCOPE = NO SCAN
```

This rule is enforced at multiple layers and cannot be bypassed.

## Scope Definition

Every scan operates within a **Scope** that defines:

### Required Fields

| Field              | Type       | Description                              |
|--------------------|-----------|------------------------------------------|
| projectId          | ObjectId  | Owning project                           |
| targetId           | ObjectId  | Target being scanned                     |
| authorization      | Enum      | AUTHORIZED (only valid value for scanning) |
| allowedHosts       | string[]  | Domains/hosts allowed for requests       |
| excludedHosts      | string[]  | Domains/hosts explicitly excluded        |
| allowedPaths       | string[]  | URL paths allowed (default: all on host) |
| excludedPaths      | string[]  | URL paths excluded                       |
| scanProfile        | Enum      | PASSIVE, LIGHT, STANDARD, AGGRESSIVE     |
| maxRequestsPerSecond | number  | Rate limit (requests/second)             |
| maxConcurrency     | number    | Maximum concurrent requests              |
| maxRequests        | number    | Maximum total requests per scan          |
| maxCrawlDepth      | number    | Maximum crawl depth                      |
| maxResponseSize    | number    | Maximum response body size (bytes)       |
| maxScanDuration    | number    | Maximum scan duration (seconds)          |
| timeoutPerRequest  | number    | Per-request timeout (seconds)            |

## Authorization States

| State          | Can Scan? | Description                              |
|----------------|-----------|------------------------------------------|
| PENDING        | NO        | Authorization not yet confirmed          |
| AUTHORIZED     | YES       | Explicit authorization granted           |
| EXPIRED        | NO        | Authorization has expired                |
| REVOKED        | NO        | Authorization has been revoked           |

## Scan Profiles

| Profile     | Description                                                |
|-------------|------------------------------------------------------------|
| PASSIVE     | Observation only. No active testing requests.              |
| LIGHT       | Minimal active testing. Safe checks only.                  |
| STANDARD    | Standard active testing. Most checks enabled.              |
| AGGRESSIVE  | Full active testing. All checks enabled. Higher risk.      |

## Default Safety Limits

| Limit                  | Default    | Maximum    |
|------------------------|-----------|------------|
| maxRequestsPerSecond   | 10        | 100        |
| maxConcurrency         | 5         | 20         |
| maxRequests            | 10,000    | 100,000    |
| maxCrawlDepth          | 5         | 20         |
| maxResponseSize        | 10 MB     | 50 MB      |
| maxScanDuration        | 3600s     | 86400s     |
| timeoutPerRequest      | 30s       | 120s       |

## Scope Validation Flow

```
Outbound Request
      │
      ▼
┌─────────────────────┐
│ Parse URL            │
│ Resolve hostname     │
└──────────┬──────────┘
           │
      ▼
┌─────────────────────┐     ┌──────────┐
│ Is host in           │─NO─▶│ REJECT   │
│ allowedHosts?        │     └──────────┘
└──────────┬──────────┘
           │ YES
      ▼
┌─────────────────────┐     ┌──────────┐
│ Is host in           │─YES▶│ REJECT   │
│ excludedHosts?       │     └──────────┘
└──────────┬──────────┘
           │ NO
      ▼
┌─────────────────────┐     ┌──────────┐
│ Is path in           │─YES▶│ REJECT   │
│ excludedPaths?       │     └──────────┘
└──────────┬──────────┘
           │ NO
      ▼
┌─────────────────────┐     ┌──────────┐
│ Is IP private /      │─YES▶│ REJECT   │
│ internal / loopback? │     └──────────┘
└──────────┬──────────┘
           │ NO
      ▼
┌─────────────────────┐     ┌──────────┐
│ Rate limit OK?       │─NO─▶│ WAIT/    │
│ Request count OK?    │     │ REJECT   │
│ Scan duration OK?    │     └──────────┘
└──────────┬──────────┘
           │ YES
      ▼
┌─────────────────────┐
│ ALLOW REQUEST        │
└─────────────────────┘
```

## Private IP Ranges (Blocked by Default)

- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16
- 127.0.0.0/8
- 169.254.0.0/16
- ::1
- fc00::/7
- fe80::/10

## Redirect Policy

When following HTTP redirects:
1. Each redirect target URL is validated against the scope.
2. Maximum redirect chain length: 10.
3. If any redirect leaves scope, the chain is stopped and the last valid response is used.

## DNS Rebinding Protection

1. Resolve hostname to IP before connecting.
2. Validate resolved IP against private ranges.
3. Pin the resolved IP for the duration of the request.

## Kill Switch

A scan can be cancelled at any time:
1. Set scan status to CANCELLED in database.
2. Remove pending jobs from BullMQ.
3. Signal active workers via Redis pub/sub.
4. Workers check cancellation state between operations.
5. Active HTTP requests are aborted.
6. Partial results are preserved.

## Dry-Run Mode

Dry-run mode executes scope validation and discovery but does NOT:
- Send active test requests.
- Send mutation requests.
- Generate findings.

Dry-run DOES:
- Validate scope configuration.
- Show allowed/excluded hosts and paths.
- Show planned test categories.
- Show authentication profiles.
- Estimate request volume.
- Display crawl/rate limits.
