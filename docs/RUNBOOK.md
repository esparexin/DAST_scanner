# Operations Runbook

## Starting the Platform

```bash
pnpm infra:up    # Start MongoDB + Redis
pnpm dev         # Start API + Web in dev mode
```

## Stopping the Platform

```bash
pnpm infra:down
```

## Cancelling a Stuck Scan

1. Via UI: Click "Cancel" on the scan dashboard.
2. Via API: `POST /api/scans/:id/cancel`
3. Via database: Set scan status to `CANCELLED`.
4. BullMQ jobs will be cleaned up by the worker.

## Viewing Logs

Logs use Pino structured JSON format.

```bash
# Follow API logs
pnpm --filter api logs

# Follow worker logs
pnpm --filter workers logs
```

## Database Maintenance

TBD.

## Common Issues

### Scan stuck in QUEUED
- Check Redis connectivity.
- Check worker process is running.
- Check BullMQ queue status.

### Worker crashes
- Check worker logs for stack traces.
- Verify MongoDB and Redis connectivity.
- Check memory usage.

### High memory usage
- Check maxResponseSize limits.
- Check concurrent scan count.
- Review crawler depth settings.
