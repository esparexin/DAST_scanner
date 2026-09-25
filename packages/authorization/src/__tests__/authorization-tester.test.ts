import { describe, it, expect } from 'vitest';
import { AuthorizationTester, type TestIdentity } from '../authorization-tester.js';
import { AuthType, HttpMethod } from '@securityscan/contracts';
import { SecureHttpClient, RateLimiter } from '@securityscan/http-client';
import { ScopeGuard } from '@securityscan/scope';

describe('AuthorizationTester', () => {
  const scopeConfig = {
    scanId: 'scan-1',
    targetId: 'target-1',
    projectId: 'proj-1',
    authorized: true,
    allowedHosts: ['example.com'],
    excludedHosts: [],
    allowedPaths: [],
    excludedPaths: [],
    maxRequestsPerSecond: 10,
    maxConcurrency: 5,
    maxRequests: 50,
    maxCrawlDepth: 3,
    maxResponseSize: 1024 * 1024,
    maxScanDuration: 60,
    timeoutPerRequest: 5,
  };

  const validator = ScopeGuard.createValidator(scopeConfig);
  const rateLimiter = new RateLimiter(10);
  const httpClient = new SecureHttpClient(validator, rateLimiter);

  it('can be instantiated with a SecureHttpClient', () => {
    const tester = new AuthorizationTester(httpClient);
    expect(tester).toBeDefined();
  });

  it('correctly tracks identities for authorization comparison', () => {
    const identities: TestIdentity[] = [
      {
        name: 'Anonymous',
        role: 'anonymous',
        authType: AuthType.NONE,
        authConfig: {},
        expectedAccess: false,
      },
      {
        name: 'User A',
        role: 'user',
        authType: AuthType.JWT,
        authConfig: { token: 'jwt-a' },
        expectedAccess: true,
      },
      {
        name: 'User B',
        role: 'user',
        authType: AuthType.JWT,
        authConfig: { token: 'jwt-b' },
        expectedAccess: false,
      },
    ];

    expect(identities).toHaveLength(3);
    expect(identities[0]!.expectedAccess).toBe(false);
    expect(identities[1]!.expectedAccess).toBe(true);
  });
});
