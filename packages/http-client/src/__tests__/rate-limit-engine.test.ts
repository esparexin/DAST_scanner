import { describe, it, expect, vi } from 'vitest';
import { RateLimitEngine } from '../rate-limit-engine.js';
import { HttpMethod } from '@securityscan/contracts';

describe('RateLimitEngine', () => {
  it('detects ENFORCED when target responds with 429 Too Many Requests', async () => {
    let calls = 0;
    const mockClient = {
      request: vi.fn().mockImplementation(() => {
        calls++;
        if (calls >= 3) {
          return Promise.resolve({
            statusCode: 429,
            headers: { 'retry-after': '60', 'x-ratelimit-remaining': '0' },
            responseTime: 50,
          });
        }
        return Promise.resolve({
          statusCode: 200,
          headers: { 'x-ratelimit-remaining': `${10 - calls}` },
          responseTime: 20,
        });
      }),
    };

    const engine = new RateLimitEngine(mockClient as any);
    const result = await engine.assessEndpoint('https://api.example.com/login', HttpMethod.POST, {
      maxBurstRequests: 5,
    });

    expect(result.status).toBe('ENFORCED');
    expect(result.throttlingStatusCode).toBe(429);
    expect(result.retryAfterHeader).toBe('60');
    expect(result.burstAttemptsSent).toBe(3); // Stopped early upon 429
  });

  it('detects ABSENT when target responds with 200 and no rate-limit headers', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        responseTime: 20,
      }),
    };

    const engine = new RateLimitEngine(mockClient as any);
    const result = await engine.assessEndpoint('https://api.example.com/data', HttpMethod.GET, {
      maxBurstRequests: 4,
    });

    expect(result.status).toBe('ABSENT');
    expect(result.findingDescription).toContain('No rate limiting headers');
  });
});
