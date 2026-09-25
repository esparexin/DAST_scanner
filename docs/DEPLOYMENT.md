# Deployment Guide

## Prerequisites

- Node.js >= 20
- pnpm >= 9
- Docker & Docker Compose
- MongoDB 7+
- Redis 7+

## Development Setup

```bash
# Install dependencies
pnpm install

# Start infrastructure (MongoDB, Redis)
pnpm infra:up

# Run development servers
pnpm dev

# Run tests
pnpm test

# Build all packages
pnpm build
```

## Docker Compose

```bash
cd infrastructure/compose
docker compose up -d
```

## Environment Variables

See `.env.example` for required configuration.

## Production

TBD - will be detailed in Phase 24.
