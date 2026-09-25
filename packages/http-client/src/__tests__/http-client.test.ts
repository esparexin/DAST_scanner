import { describe, it, expect, vi } from 'vitest';
import { RateLimiter } from '../rate-limiter.js';
import { SecureHttpClient } from '../secure-http-client.js';
import { ScopeGuard } from '@securityscan/scope';
import { HttpMethod } from '@securityscan/contracts';

describe('RateLimiter', () => {
  it('acquires tokens without delay when available', async () => {
    const limiter = new RateLimiter(10);
    const start = Date.now();
    await limiter.acquire();
    await limiter.acquire();
    expect(Date.now() - start).toBeLessThan(100);
  });
});

describe('SecureHttpClient', () => {
  const scopeConfig = {
    scanId: 'scan-1',
    targetId: 'target-1',
    projectId: 'proj-1',
    authorized: true,
    allowedHosts: ['example.com'],
    excludedHosts: ['secret.example.com'],
    allowedPaths: ['/api'],
    excludedPaths: ['/api/admin'],
    maxRequestsPerSecond: 10,
    maxConcurrency: 5,
    maxRequests: 10,
    maxCrawlDepth: 3,
    maxResponseSize: 1024 * 1024,
    maxScanDuration: 60,
    timeoutPerRequest: 5,
  };

  const validator = ScopeGuard.createValidator(scopeConfig);
  const rateLimiter = new RateLimiter(10);
  const client = new SecureHttpClient(validator, rateLimiter);

  it('rejects requests to hosts outside allowed scope before outbound call', async () => {
    await expect(
      client.request({
        method: HttpMethod.GET,
        url: 'https://evil.com/api/test',
      }),
    ).rejects.toThrow(/not in the allowed hosts list/);
  });

  it('rejects requests to excluded subdomains', async () => {
    await expect(
      client.request({
        method: HttpMethod.GET,
        url: 'https://secret.example.com/api/test',
      }),
    ).rejects.toThrow();
  });

  it('rejects requests to excluded paths', async () => {
    await expect(
      client.request({
        method: HttpMethod.GET,
        url: 'https://example.com/api/admin',
      }),
    ).rejects.toThrow(/excluded paths list/);
  });

  it('rejects requests when client is aborted', () => {
    const freshValidator = ScopeGuard.createValidator(scopeConfig);
    const freshClient = new SecureHttpClient(freshValidator, new RateLimiter(10));
    freshClient.abort();
    expect(
      freshClient.request({
        method: HttpMethod.GET,
        url: 'https://example.com/api/test',
      }),
    ).rejects.toThrow(/aborted/);
  });
});
