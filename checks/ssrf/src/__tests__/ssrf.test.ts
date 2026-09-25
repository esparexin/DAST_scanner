import { describe, it, expect, vi } from 'vitest';
import { SsrfCandidateChecks } from '../index.js';
import { HttpMethod } from '@securityscan/contracts';

describe('SsrfCandidateChecks', () => {
  const [ssrfCheck] = SsrfCandidateChecks.getChecks();

  it('flags potential SSRF candidate webhook URL parameter', async () => {
    const ctx: any = {
      endpoint: { url: 'https://example.com/api/subscribe?webhook=https://callback.corp/events', method: HttpMethod.GET },
      httpClient: { request: vi.fn() },
    };

    const findings = await ssrfCheck!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-SSRF-001');
    expect(findings[0]?.parameter).toBe('webhook');
  });
});
