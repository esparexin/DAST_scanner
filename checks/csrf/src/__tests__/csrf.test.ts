import { describe, it, expect, vi } from 'vitest';
import { CsrfChecks } from '../csrf-check.js';
import { HttpMethod } from '@securityscan/contracts';

describe('CsrfChecks', () => {
  const [csrfCheck] = CsrfChecks.getChecks();

  it('flags state-changing POST endpoint accepting cross-origin requests', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({ statusCode: 200, headers: {} }),
    };
    const ctx: any = {
      endpoint: { url: 'https://example.com/api/change-password', method: HttpMethod.POST },
      httpClient: mockClient,
    };
    const findings = await csrfCheck!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-CSRF-001');
  });

  it('skips safe GET methods', async () => {
    const ctx: any = {
      endpoint: { url: 'https://example.com/api/users', method: HttpMethod.GET },
      httpClient: { request: vi.fn() },
    };
    const findings = await csrfCheck!.run(ctx);
    expect(findings).toHaveLength(0);
  });
});
