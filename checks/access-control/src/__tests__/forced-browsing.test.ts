import { describe, it, expect, vi } from 'vitest';
import { ForcedBrowsingChecks } from '../forced-browsing-check.js';

describe('ForcedBrowsingChecks', () => {
  const [check] = ForcedBrowsingChecks.getChecks();

  it('detects exposed .env file at target root', async () => {
    const mockClient = {
      request: vi.fn().mockImplementation((req) => {
        if (req.url.endsWith('/.env')) {
          return Promise.resolve({ statusCode: 200, headers: {}, body: 'DB_PASSWORD=secret' });
        }
        return Promise.resolve({ statusCode: 404, headers: {}, body: 'Not found' });
      }),
    };
    const ctx: any = {
      baseUrl: 'https://example.com',
      httpClient: mockClient,
    };
    const findings = await check!.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]?.ruleId).toBe('SEC-AC-001');
    expect(findings[0]?.endpoint).toContain('/.env');
  });
});
